//! The signed, hash-chained log (PRD FR-RCPT, Phase 7).
//!
//! One file per session, one JSON object per line:
//! `v, session, seq, ts, prev, policy_hash, layer, target, rule, verdict, sig`.
//!
//! - `prev` is the SHA-256 of the previous line, signature included. The
//!   first line chains to a hash of the session id.
//! - `sig` is an ed25519 signature over the line without `sig`, under a
//!   domain prefix, so an entry cannot be replayed as a checkpoint.
//! - A line is accepted only if it is exactly the canonical text this module
//!   would write. Extra whitespace, other field order, duplicate or unknown
//!   keys and CRLF endings all fail, so nothing can change without the
//!   signature noticing.
//! - A signed checkpoint, written when the session ends, records the number
//!   of entries and the hash of the last line. It is the only thing that
//!   detects a log cut short at the end, so a log without one fails
//!   verification unless the caller says the session may still be running.
//!
//! The verifying key always comes from the caller (the key directory), never
//! from the log. Whoever holds the signing key can forge a log; keeping that
//! key out of the sandbox is what the signatures rely on.

use std::fs::{File, TryLockError};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::{fsutil, hex};

/// Format version written in `v`.
pub const LOG_VERSION: u32 = 1;

const ENTRY_DOMAIN: &[u8] = b"pumpkin-shell-log-entry-v1\n";
const CHECKPOINT_DOMAIN: &[u8] = b"pumpkin-shell-log-checkpoint-v1\n";
const GENESIS_DOMAIN: &[u8] = b"pumpkin-shell-log-genesis-v1\n";

/// Longest value kept in a text field. Longer values are cut (see `clip`).
const MAX_FIELD_BYTES: usize = 1024;
/// Largest log the writer will produce and `verify_path` will read.
pub const MAX_LOG_BYTES: u64 = 256 * 1024 * 1024;
/// A checkpoint is one short line.
const MAX_CHECKPOINT_BYTES: u64 = 4096;
const MAX_SESSION_CHARS: usize = 128;

// --- wire format ---------------------------------------------------------

#[derive(Serialize)]
struct EntryBody<'a> {
    v: u32,
    session: &'a str,
    seq: u64,
    ts: u64,
    prev: &'a str,
    policy_hash: &'a str,
    layer: &'a str,
    target: &'a str,
    rule: &'a str,
    verdict: &'a str,
}

/// Same fields, same order as `EntryBody`, plus the signature.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EntryLine {
    v: u32,
    session: String,
    seq: u64,
    ts: u64,
    prev: String,
    policy_hash: String,
    layer: String,
    target: String,
    rule: String,
    verdict: String,
    sig: String,
}

impl EntryLine {
    fn body_bytes(&self) -> Vec<u8> {
        serialize(&EntryBody {
            v: self.v,
            session: &self.session,
            seq: self.seq,
            ts: self.ts,
            prev: &self.prev,
            policy_hash: &self.policy_hash,
            layer: &self.layer,
            target: &self.target,
            rule: &self.rule,
            verdict: &self.verdict,
        })
    }
}

#[derive(Serialize)]
struct CheckpointBody<'a> {
    v: u32,
    session: &'a str,
    count: u64,
    last: &'a str,
    ts: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointLine {
    v: u32,
    session: String,
    count: u64,
    last: String,
    ts: u64,
    sig: String,
}

impl CheckpointLine {
    fn body_bytes(&self) -> Vec<u8> {
        serialize(&CheckpointBody {
            v: self.v,
            session: &self.session,
            count: self.count,
            last: &self.last,
            ts: self.ts,
        })
    }
}

/// Plain structs of strings and integers always serialize.
fn serialize<T: Serialize>(value: &T) -> Vec<u8> {
    serde_json::to_vec(value).unwrap_or_default()
}

/// True when `value` serializes to exactly `line`.
fn is_canonical<T: Serialize>(value: &T, line: &str) -> bool {
    serde_json::to_string(value).is_ok_and(|text| text == line)
}

fn signed_message(domain: &[u8], body: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(domain.len() + body.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(body);
    message
}

fn genesis_hash(session: &str) -> String {
    hex::sha256(&signed_message(GENESIS_DOMAIN, session.as_bytes()))
}

/// Cuts `text` to `MAX_FIELD_BYTES`, at a character boundary, ending in `…`.
fn clip(text: &str) -> String {
    if text.len() <= MAX_FIELD_BYTES {
        return text.to_owned();
    }
    let mut end = MAX_FIELD_BYTES - '…'.len_utf8();
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &text[..end])
}

/// Where the checkpoint of `log` is stored.
#[must_use]
pub fn checkpoint_path(log: &Path) -> PathBuf {
    let mut name = log.as_os_str().to_owned();
    name.push(".checkpoint");
    PathBuf::from(name)
}

/// A new random session id: 32 lowercase hex digits.
///
/// # Errors
/// Fails if the system random number generator does.
pub fn new_session_id() -> Result<String, LogError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|e| LogError::Random(e.to_string()))?;
    Ok(hex::encode(&bytes))
}

// --- writing -------------------------------------------------------------

/// One event to record. All text is cut to 1024 bytes.
#[derive(Debug, Clone, Copy)]
pub struct Record<'a> {
    pub policy_hash: &'a str,
    pub layer: &'a str,
    pub target: &'a str,
    pub rule: &'a str,
    pub verdict: &'a str,
}

#[derive(Debug, thiserror::Error)]
pub enum LogError {
    #[error("cannot access {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("{0} already exists; a log is never overwritten")]
    Exists(String),
    #[error("{0} already has a checkpoint: that session is closed")]
    Closed(String),
    #[error("{0} is open in another writer")]
    InUse(String),
    #[error("a session id must be 1 to 128 characters of letters, digits, '-' or '_'")]
    InvalidSession,
    #[error("an earlier write failed, so this log can no longer be extended")]
    Poisoned,
    #[error("the log reached its size limit")]
    Full,
    #[error("the system random number generator failed: {0}")]
    Random(String),
}

fn io_error(path: &Path, source: io::Error) -> LogError {
    LogError::Io {
        path: path.display().to_string(),
        source,
    }
}

fn valid_session(session: &str) -> bool {
    !session.is_empty()
        && session.chars().count() <= MAX_SESSION_CHARS
        && session
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Appends signed entries to one session's log, then closes it with a
/// checkpoint. One writer at a time: the file is locked while this exists.
pub struct Logger {
    file: File,
    path: PathBuf,
    key: SigningKey,
    session: String,
    next_seq: u64,
    prev: String,
    bytes: u64,
    max_bytes: u64,
    poisoned: bool,
}

impl Logger {
    /// Starts a new log at `path`. The file must not exist.
    ///
    /// # Errors
    /// Fails if the file or its checkpoint exists, another writer holds it,
    /// or the session id is not valid.
    pub fn create(path: &Path, key: SigningKey, session: &str) -> Result<Self, LogError> {
        if !valid_session(session) {
            return Err(LogError::InvalidSession);
        }
        if checkpoint_path(path).exists() {
            return Err(LogError::Closed(path.display().to_string()));
        }
        let file = fsutil::open_new_private(path, true).map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                LogError::Exists(path.display().to_string())
            } else {
                io_error(path, error)
            }
        })?;
        Self::from_file(file, path, key, session)
    }

    fn from_file(
        file: File,
        path: &Path,
        key: SigningKey,
        session: &str,
    ) -> Result<Self, LogError> {
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(LogError::InUse(path.display().to_string()));
            }
            Err(TryLockError::Error(error)) => return Err(io_error(path, error)),
        }
        Ok(Self {
            file,
            path: path.to_path_buf(),
            key,
            session: session.to_owned(),
            next_seq: 0,
            prev: genesis_hash(session),
            bytes: 0,
            max_bytes: MAX_LOG_BYTES,
            poisoned: false,
        })
    }

    /// The session id of this log.
    #[must_use]
    pub fn session(&self) -> &str {
        &self.session
    }

    /// Signs and appends one entry. `ts_ms` is Unix time in milliseconds.
    ///
    /// # Errors
    /// Fails if the log is full or an earlier write failed. A failed write
    /// poisons the log: later calls fail, and the file will not verify.
    pub fn append(&mut self, record: &Record<'_>, ts_ms: u64) -> Result<(), LogError> {
        if self.poisoned {
            return Err(LogError::Poisoned);
        }
        let policy_hash = clip(record.policy_hash);
        let layer = clip(record.layer);
        let target = clip(record.target);
        let rule = clip(record.rule);
        let verdict = clip(record.verdict);
        let body = serialize(&EntryBody {
            v: LOG_VERSION,
            session: &self.session,
            seq: self.next_seq,
            ts: ts_ms,
            prev: &self.prev,
            policy_hash: &policy_hash,
            layer: &layer,
            target: &target,
            rule: &rule,
            verdict: &verdict,
        });
        let signature = self.key.sign(&signed_message(ENTRY_DOMAIN, &body));
        let line = EntryLine {
            v: LOG_VERSION,
            session: self.session.clone(),
            seq: self.next_seq,
            ts: ts_ms,
            prev: self.prev.clone(),
            policy_hash,
            layer,
            target,
            rule,
            verdict,
            sig: hex::encode(&signature.to_bytes()),
        };
        let mut text = serde_json::to_string(&line).unwrap_or_default();
        let new_hash = hex::sha256(text.as_bytes());
        text.push('\n');
        let new_bytes = self.bytes.saturating_add(text.len() as u64);
        if new_bytes > self.max_bytes {
            return Err(LogError::Full);
        }
        // One write call, so each line reaches the file whole or not at all
        // as far as the operating system allows.
        let result = self
            .file
            .write_all(text.as_bytes())
            .and_then(|()| self.file.sync_data());
        if let Err(error) = result {
            self.poisoned = true;
            return Err(io_error(&self.path, error));
        }
        self.bytes = new_bytes;
        self.prev = new_hash;
        self.next_seq += 1;
        Ok(())
    }

    /// Ends the session: writes the signed checkpoint next to the log.
    ///
    /// # Errors
    /// Fails if an earlier write failed or the checkpoint cannot be created.
    pub fn finish(self, ts_ms: u64) -> Result<(), LogError> {
        if self.poisoned {
            return Err(LogError::Poisoned);
        }
        let body = serialize(&CheckpointBody {
            v: LOG_VERSION,
            session: &self.session,
            count: self.next_seq,
            last: &self.prev,
            ts: ts_ms,
        });
        let signature = self.key.sign(&signed_message(CHECKPOINT_DOMAIN, &body));
        let line = CheckpointLine {
            v: LOG_VERSION,
            session: self.session.clone(),
            count: self.next_seq,
            last: self.prev.clone(),
            ts: ts_ms,
            sig: hex::encode(&signature.to_bytes()),
        };
        let mut text = serde_json::to_string(&line).unwrap_or_default();
        text.push('\n');
        let path = checkpoint_path(&self.path);
        fsutil::write_new_private(&path, text.as_bytes()).map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                LogError::Closed(self.path.display().to_string())
            } else {
                io_error(&path, error)
            }
        })
    }
}

// --- verifying -----------------------------------------------------------

/// What was wrong with one log line.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LineProblem {
    #[error("not a valid log entry")]
    Malformed,
    #[error("not in the exact form the logger writes (changed spacing, order or line ending)")]
    NotCanonical,
    #[error("unsupported version {0}")]
    WrongVersion(u32),
    #[error("signature does not match (the entry was changed, or signed with another key)")]
    BadSignature,
    #[error("belongs to a different session than the lines before it")]
    SessionChanged,
    #[error("sequence number is {found}, expected {expected} (a line was removed, added or moved)")]
    OutOfSequence { expected: u64, found: u64 },
    #[error("does not chain to the line before it")]
    ChainBroken,
}

/// What was wrong with the checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CheckpointProblem {
    #[error("not a valid checkpoint")]
    Malformed,
    #[error("not in the exact form the logger writes")]
    NotCanonical,
    #[error("unsupported version {0}")]
    WrongVersion(u32),
    #[error("signature does not match")]
    BadSignature,
    #[error("belongs to a different session than the log")]
    SessionMismatch,
    #[error(
        "records {expected} entries but the log has {found} (the log was cut short or extended)"
    )]
    CountMismatch { expected: u64, found: u64 },
    #[error("does not match the last line of the log")]
    LastMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    #[error("the log is not valid UTF-8")]
    NotUtf8,
    #[error("the log ends in the middle of line {0} (it was cut short)")]
    Unterminated(usize),
    #[error("line {line}: {problem}")]
    Line { line: usize, problem: LineProblem },
    #[error(
        "there is no signed checkpoint, so the end of the log cannot be trusted (pass --allow-open only for a session that may still be running)"
    )]
    MissingCheckpoint,
    #[error("checkpoint: {0}")]
    Checkpoint(CheckpointProblem),
}

/// A log that passed verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// Session id, or `None` for an empty log with no checkpoint.
    pub session: Option<String>,
    pub entries: u64,
    /// True when a valid checkpoint closes the log.
    pub closed: bool,
}

fn verify_line(
    line: &str,
    expected_seq: u64,
    prev: &mut Option<String>,
    session: &mut Option<String>,
    key: &VerifyingKey,
) -> Result<(), LineProblem> {
    let entry: EntryLine = serde_json::from_str(line).map_err(|_| LineProblem::Malformed)?;
    if !is_canonical(&entry, line) {
        return Err(LineProblem::NotCanonical);
    }
    if entry.v != LOG_VERSION {
        return Err(LineProblem::WrongVersion(entry.v));
    }
    let signature = hex::decode_array::<64>(&entry.sig)
        .map(|bytes| Signature::from_bytes(&bytes))
        .ok_or(LineProblem::BadSignature)?;
    key.verify_strict(
        &signed_message(ENTRY_DOMAIN, &entry.body_bytes()),
        &signature,
    )
    .map_err(|_| LineProblem::BadSignature)?;
    match session {
        Some(known) if *known != entry.session => return Err(LineProblem::SessionChanged),
        Some(_) => {}
        None => *session = Some(entry.session.clone()),
    }
    if entry.seq != expected_seq {
        return Err(LineProblem::OutOfSequence {
            expected: expected_seq,
            found: entry.seq,
        });
    }
    let expected_prev = prev.take().unwrap_or_else(|| genesis_hash(&entry.session));
    if entry.prev != expected_prev {
        return Err(LineProblem::ChainBroken);
    }
    *prev = Some(hex::sha256(line.as_bytes()));
    Ok(())
}

fn verify_checkpoint(
    bytes: &[u8],
    session: Option<&str>,
    entries: u64,
    tail: Option<&str>,
    key: &VerifyingKey,
) -> Result<(), CheckpointProblem> {
    let text = std::str::from_utf8(bytes).map_err(|_| CheckpointProblem::Malformed)?;
    let line = text
        .strip_suffix('\n')
        .ok_or(CheckpointProblem::NotCanonical)?;
    let checkpoint: CheckpointLine =
        serde_json::from_str(line).map_err(|_| CheckpointProblem::Malformed)?;
    if !is_canonical(&checkpoint, line) {
        return Err(CheckpointProblem::NotCanonical);
    }
    if checkpoint.v != LOG_VERSION {
        return Err(CheckpointProblem::WrongVersion(checkpoint.v));
    }
    let signature = hex::decode_array::<64>(&checkpoint.sig)
        .map(|bytes| Signature::from_bytes(&bytes))
        .ok_or(CheckpointProblem::BadSignature)?;
    key.verify_strict(
        &signed_message(CHECKPOINT_DOMAIN, &checkpoint.body_bytes()),
        &signature,
    )
    .map_err(|_| CheckpointProblem::BadSignature)?;
    if session.is_some_and(|known| known != checkpoint.session) {
        return Err(CheckpointProblem::SessionMismatch);
    }
    if checkpoint.count != entries {
        return Err(CheckpointProblem::CountMismatch {
            expected: checkpoint.count,
            found: entries,
        });
    }
    let expected_last = tail.map_or_else(|| genesis_hash(&checkpoint.session), str::to_owned);
    if checkpoint.last != expected_last {
        return Err(CheckpointProblem::LastMismatch);
    }
    Ok(())
}

/// Verifies a whole log and, when given, its checkpoint.
///
/// `allow_open` accepts a log with no checkpoint (a session that may still be
/// running, or that was killed). A checkpoint that is present is always
/// checked.
///
/// # Errors
/// Returns the first problem found, with its line number.
pub fn verify(
    log: &[u8],
    checkpoint: Option<&[u8]>,
    key: &VerifyingKey,
    allow_open: bool,
) -> Result<Verified, VerifyError> {
    let text = std::str::from_utf8(log).map_err(|_| VerifyError::NotUtf8)?;
    let mut lines: Vec<&str> = text.split('\n').collect();
    // `split` leaves an empty last item when the text ends with a newline.
    // Anything else there is a line without its terminator.
    let tail = lines.pop().unwrap_or_default();
    if !tail.is_empty() {
        return Err(VerifyError::Unterminated(lines.len() + 1));
    }

    let mut session = None;
    let mut prev = None;
    for (index, line) in lines.iter().enumerate() {
        verify_line(line, index as u64, &mut prev, &mut session, key).map_err(|problem| {
            VerifyError::Line {
                line: index + 1,
                problem,
            }
        })?;
    }
    let entries = lines.len() as u64;

    match checkpoint {
        Some(bytes) => {
            verify_checkpoint(bytes, session.as_deref(), entries, prev.as_deref(), key)
                .map_err(VerifyError::Checkpoint)?;
            Ok(Verified {
                session: session.or_else(|| checkpoint_session(bytes)),
                entries,
                closed: true,
            })
        }
        None if allow_open => Ok(Verified {
            session,
            entries,
            closed: false,
        }),
        None => Err(VerifyError::MissingCheckpoint),
    }
}

/// The session named by an already verified checkpoint.
fn checkpoint_session(bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?;
    let checkpoint: CheckpointLine = serde_json::from_str(text.strip_suffix('\n')?).ok()?;
    Some(checkpoint.session)
}

/// Why `verify_path` could not give an answer, or what the answer was.
#[derive(Debug, thiserror::Error)]
pub enum VerifyPathError {
    #[error("cannot read {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("{0} is larger than the {MAX_LOG_BYTES} byte limit")]
    TooLarge(String),
    #[error(transparent)]
    Invalid(#[from] VerifyError),
}

fn read_limited(path: &Path, limit: u64) -> Result<Option<Vec<u8>>, VerifyPathError> {
    let shown = || path.display().to_string();
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(VerifyPathError::Io {
                path: shown(),
                source,
            });
        }
    };
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| VerifyPathError::Io {
            path: shown(),
            source,
        })?;
    if bytes.len() as u64 > limit {
        return Err(VerifyPathError::TooLarge(shown()));
    }
    Ok(Some(bytes))
}

/// Reads the log at `path` and its checkpoint file, and verifies them.
///
/// # Errors
/// Fails if the log is missing or too large, or does not verify.
pub fn verify_path(
    path: &Path,
    key: &VerifyingKey,
    allow_open: bool,
) -> Result<Verified, VerifyPathError> {
    let log = read_limited(path, MAX_LOG_BYTES)?.ok_or_else(|| VerifyPathError::Io {
        path: path.display().to_string(),
        source: io::Error::from(io::ErrorKind::NotFound),
    })?;
    let checkpoint = read_limited(&checkpoint_path(path), MAX_CHECKPOINT_BYTES)?;
    Ok(verify(&log, checkpoint.as_deref(), key, allow_open)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::fs::{self, OpenOptions};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const POLICY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn rec(n: u64) -> (String, String, String) {
        (
            format!("net-{n}"),
            format!("host{n}.example:443"),
            format!("RULE-{n}"),
        )
    }

    /// Writes a closed log of `n` entries with key 1; returns its bytes.
    fn closed_log(n: u64) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("s.jsonl");
        let mut logger = Logger::create(&path, key(1), "session-1")?;
        for i in 0..n {
            let (layer, target, rule) = rec(i);
            logger.append(
                &Record {
                    policy_hash: POLICY,
                    layer: &layer,
                    target: &target,
                    rule: &rule,
                    verdict: "block",
                },
                1_000 + i,
            )?;
        }
        logger.finish(9_999)?;
        Ok((fs::read(&path)?, fs::read(checkpoint_path(&path))?))
    }

    fn ok(log: &[u8], cp: &[u8]) -> Result<Verified, VerifyError> {
        verify(log, Some(cp), &key(1).verifying_key(), false)
    }

    fn lines(log: &[u8]) -> Vec<String> {
        String::from_utf8_lossy(log)
            .split_terminator('\n')
            .map(str::to_owned)
            .collect()
    }

    fn join(lines: &[String]) -> Vec<u8> {
        let mut out = lines.join("\n").into_bytes();
        if !lines.is_empty() {
            out.push(b'\n');
        }
        out
    }

    // --- good logs ---

    #[test]
    fn a_closed_log_verifies() -> TestResult {
        let (log, cp) = closed_log(5)?;
        let verified = ok(&log, &cp)?;
        assert_eq!(
            verified,
            Verified {
                session: Some("session-1".into()),
                entries: 5,
                closed: true
            }
        );
        Ok(())
    }

    #[test]
    fn an_empty_closed_log_verifies() -> TestResult {
        let (log, cp) = closed_log(0)?;
        assert!(log.is_empty());
        let verified = ok(&log, &cp)?;
        assert_eq!(verified.entries, 0);
        assert_eq!(verified.session.as_deref(), Some("session-1"));
        Ok(())
    }

    #[test]
    fn lines_have_the_documented_fields_in_order() -> TestResult {
        let (log, _) = closed_log(1)?;
        let line = &lines(&log)[0];
        let order = [
            "\"v\"",
            "\"session\"",
            "\"seq\"",
            "\"ts\"",
            "\"prev\"",
            "\"policy_hash\"",
            "\"layer\"",
            "\"target\"",
            "\"rule\"",
            "\"verdict\"",
            "\"sig\"",
        ];
        let positions: Vec<_> = order.iter().map(|f| line.find(f)).collect();
        assert!(positions.iter().all(Option::is_some), "{line}");
        assert!(positions.windows(2).all(|w| w[0] < w[1]), "{line}");
        let value: serde_json::Value = serde_json::from_str(line)?;
        assert_eq!(value["v"], 1);
        assert_eq!(value["seq"], 0);
        assert_eq!(value["prev"], genesis_hash("session-1"));
        assert_eq!(value["sig"].as_str().map(str::len), Some(128));
        Ok(())
    }

    #[test]
    fn each_line_chains_to_the_hash_of_the_line_before() -> TestResult {
        let (log, _) = closed_log(3)?;
        let all = lines(&log);
        for pair in all.windows(2) {
            let next: serde_json::Value = serde_json::from_str(&pair[1])?;
            assert_eq!(next["prev"], hex::sha256(pair[0].as_bytes()));
        }
        Ok(())
    }

    #[test]
    fn an_open_log_needs_allow_open() -> TestResult {
        let (log, _) = closed_log(3)?;
        let k = key(1).verifying_key();
        assert_eq!(
            verify(&log, None, &k, false),
            Err(VerifyError::MissingCheckpoint)
        );
        let verified = verify(&log, None, &k, true)?;
        assert_eq!((verified.entries, verified.closed), (3, false));
        Ok(())
    }

    #[test]
    fn an_empty_open_log_has_no_session() -> TestResult {
        let verified = verify(b"", None, &key(1).verifying_key(), true)?;
        assert_eq!(
            verified,
            Verified {
                session: None,
                entries: 0,
                closed: false
            }
        );
        Ok(())
    }

    #[test]
    fn allow_open_still_checks_a_checkpoint_that_is_present() -> TestResult {
        let (log, cp) = closed_log(3)?;
        let cut = join(&lines(&log)[..2]);
        let result = verify(&cut, Some(&cp), &key(1).verifying_key(), true);
        assert!(matches!(
            result,
            Err(VerifyError::Checkpoint(CheckpointProblem::CountMismatch {
                expected: 3,
                found: 2
            }))
        ));
        Ok(())
    }

    // --- the Done-when list: edit, delete, reorder, truncate ---

    #[test]
    fn editing_any_field_of_any_line_fails() -> TestResult {
        let (log, cp) = closed_log(4)?;
        let all = lines(&log);
        let edits = [
            ("\"layer\":\"net-", "\"layer\":\"xet-"),
            ("\"verdict\":\"block\"", "\"verdict\":\"allow\""),
            ("\"policy_hash\":\"0", "\"policy_hash\":\"1"),
            ("\"seq\":", "\"seq\":9"),
            ("\"ts\":1", "\"ts\":2"),
            ("\"session\":\"session-1\"", "\"session\":\"session-2\""),
        ];
        for (index, original) in all.iter().enumerate() {
            for (from, to) in edits {
                let edited = original.replacen(from, to, 1);
                assert_ne!(&edited, original, "edit {from:?} did nothing");
                let mut changed = all.clone();
                changed[index] = edited;
                let result = ok(&join(&changed), &cp);
                assert!(
                    result.is_err(),
                    "line {} edit {from:?} was accepted",
                    index + 1
                );
            }
        }
        Ok(())
    }

    #[test]
    fn deleting_any_line_fails() -> TestResult {
        let (log, cp) = closed_log(5)?;
        let all = lines(&log);
        for index in 0..all.len() {
            let mut changed = all.clone();
            changed.remove(index);
            assert!(
                ok(&join(&changed), &cp).is_err(),
                "deleting line {}",
                index + 1
            );
        }
        Ok(())
    }

    #[test]
    fn reordering_any_two_lines_fails() -> TestResult {
        let (log, cp) = closed_log(5)?;
        let all = lines(&log);
        for a in 0..all.len() {
            for b in (a + 1)..all.len() {
                let mut changed = all.clone();
                changed.swap(a, b);
                assert!(ok(&join(&changed), &cp).is_err(), "swapping {a} and {b}");
            }
        }
        Ok(())
    }

    #[test]
    fn truncating_the_end_fails_with_or_without_the_checkpoint() -> TestResult {
        let (log, cp) = closed_log(5)?;
        let all = lines(&log);
        for keep in 0..all.len() {
            let cut = join(&all[..keep]);
            // With the checkpoint: the count no longer matches.
            assert!(
                matches!(
                    ok(&cut, &cp),
                    Err(VerifyError::Checkpoint(
                        CheckpointProblem::CountMismatch { .. }
                    ))
                ),
                "keeping {keep} lines"
            );
            // Without it: the missing checkpoint is the error.
            assert_eq!(
                verify(&cut, None, &key(1).verifying_key(), false),
                Err(VerifyError::MissingCheckpoint),
                "keeping {keep} lines, no checkpoint"
            );
        }
        Ok(())
    }

    #[test]
    fn truncating_in_the_middle_of_a_line_fails() -> TestResult {
        let (log, cp) = closed_log(3)?;
        for cut in [1, 10, log.len() / 2, log.len() - 2, log.len() - 1] {
            let result = ok(&log[..cut], &cp);
            assert!(result.is_err(), "cut at {cut}");
        }
        assert!(matches!(
            ok(&log[..log.len() - 1], &cp),
            Err(VerifyError::Unterminated(3))
        ));
        Ok(())
    }

    #[test]
    fn truncating_the_start_fails() -> TestResult {
        let (log, cp) = closed_log(4)?;
        let all = lines(&log);
        let result = ok(&join(&all[1..]), &cp);
        assert!(matches!(
            result,
            Err(VerifyError::Line {
                line: 1,
                problem: LineProblem::OutOfSequence {
                    expected: 0,
                    found: 1
                }
            })
        ));
        Ok(())
    }

    // --- other tampering ---

    #[test]
    fn duplicating_a_line_fails() -> TestResult {
        let (log, cp) = closed_log(3)?;
        let all = lines(&log);
        let mut changed = all.clone();
        changed.insert(2, all[1].clone());
        assert!(ok(&join(&changed), &cp).is_err());
        Ok(())
    }

    #[test]
    fn blank_lines_and_trailing_garbage_fail() -> TestResult {
        let (log, cp) = closed_log(3)?;
        let all = lines(&log);
        let mut blank = all.clone();
        blank.insert(1, String::new());
        assert!(ok(&join(&blank), &cp).is_err());
        let mut extra = log.clone();
        extra.extend_from_slice(b"garbage\n");
        assert!(ok(&extra, &cp).is_err());
        let mut newlines = log.clone();
        newlines.push(b'\n');
        assert!(ok(&newlines, &cp).is_err());
        Ok(())
    }

    #[test]
    fn a_line_signed_with_another_key_fails() -> TestResult {
        let (log, cp) = closed_log(2)?;
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("s.jsonl");
        let mut logger = Logger::create(&path, key(2), "session-1")?;
        let (l, t, r) = rec(0);
        logger.append(
            &Record {
                policy_hash: POLICY,
                layer: &l,
                target: &t,
                rule: &r,
                verdict: "block",
            },
            1_000,
        )?;
        drop(logger);
        let foreign = fs::read_to_string(&path)?;
        let mut changed = lines(&log);
        changed[0] = foreign.trim_end().to_owned();
        let result = ok(&join(&changed), &cp);
        assert!(matches!(
            result,
            Err(VerifyError::Line {
                line: 1,
                problem: LineProblem::BadSignature
            })
        ));
        Ok(())
    }

    #[test]
    fn a_whole_log_signed_with_another_key_fails() -> TestResult {
        let (log, cp) = closed_log(2)?;
        let wrong = key(9).verifying_key();
        assert!(matches!(
            verify(&log, Some(&cp), &wrong, false),
            Err(VerifyError::Line {
                line: 1,
                problem: LineProblem::BadSignature
            })
        ));
        Ok(())
    }

    #[test]
    fn spacing_order_and_line_endings_must_be_canonical() -> TestResult {
        let (log, cp) = closed_log(2)?;
        let all = lines(&log);
        // Pretty-printed, reordered, extra space, CRLF: same data, other text.
        let value: serde_json::Value = serde_json::from_str(&all[0])?;
        let pretty = serde_json::to_string_pretty(&value)?.replace('\n', " ");
        let spaced = all[0].replacen(",\"seq\"", ", \"seq\"", 1);
        let crlf = format!("{}\r", all[0]);
        for variant in [pretty, spaced, crlf] {
            let mut changed = all.clone();
            changed[0] = variant;
            assert!(
                matches!(
                    ok(&join(&changed), &cp),
                    Err(VerifyError::Line {
                        line: 1,
                        problem: LineProblem::NotCanonical | LineProblem::Malformed
                    })
                ),
                "variant accepted"
            );
        }
        Ok(())
    }

    #[test]
    fn unknown_and_duplicate_fields_fail() -> TestResult {
        let (log, cp) = closed_log(1)?;
        let line = lines(&log).remove(0);
        let extra = line.replacen('{', "{\"extra\":1,", 1);
        let duplicate = line.replacen("{\"v\":1,", "{\"v\":1,\"v\":1,", 1);
        for variant in [extra, duplicate] {
            assert!(ok(&join(&[variant]), &cp).is_err());
        }
        Ok(())
    }

    #[test]
    fn a_byte_order_mark_or_invalid_utf8_fails() -> TestResult {
        let (log, cp) = closed_log(1)?;
        let mut bom = vec![0xef, 0xbb, 0xbf];
        bom.extend_from_slice(&log);
        assert!(ok(&bom, &cp).is_err());
        let mut bad = log.clone();
        bad[5] = 0xff;
        assert_eq!(ok(&bad, &cp), Err(VerifyError::NotUtf8));
        Ok(())
    }

    #[test]
    fn a_signature_that_is_not_canonical_hex_fails() -> TestResult {
        let (log, cp) = closed_log(1)?;
        let all = lines(&log);
        let value: serde_json::Value = serde_json::from_str(&all[0])?;
        let sig = value["sig"].as_str().unwrap_or_default().to_owned();
        for bad in [
            sig.to_uppercase(),
            sig[..126].to_owned(),
            format!("{sig}00"),
            "zz".repeat(64),
        ] {
            let changed = vec![all[0].replace(&sig, &bad)];
            assert!(ok(&join(&changed), &cp).is_err(), "{bad}");
        }
        Ok(())
    }

    #[test]
    fn two_sessions_cannot_be_joined() -> TestResult {
        let dir = tempfile::tempdir()?;
        let mut parts = Vec::new();
        for (name, session) in [("a.jsonl", "session-a"), ("b.jsonl", "session-b")] {
            let path = dir.path().join(name);
            let mut logger = Logger::create(&path, key(1), session)?;
            let (l, t, r) = rec(0);
            logger.append(
                &Record {
                    policy_hash: POLICY,
                    layer: &l,
                    target: &t,
                    rule: &r,
                    verdict: "block",
                },
                1,
            )?;
            logger.finish(2)?;
            parts.push(fs::read(&path)?);
        }
        let joined = [parts[0].clone(), parts[1].clone()].concat();
        let result = verify(&joined, None, &key(1).verifying_key(), true);
        assert!(matches!(
            result,
            Err(VerifyError::Line {
                line: 2,
                problem: LineProblem::SessionChanged
            })
        ));
        Ok(())
    }

    #[test]
    fn a_line_spliced_in_from_another_log_of_the_same_session_fails() -> TestResult {
        // Same key, same session id, same sequence number, valid signature:
        // only the chain stops this.
        let dir = tempfile::tempdir()?;
        let mut logs = Vec::new();
        for (name, verdict) in [("a.jsonl", "block"), ("b.jsonl", "allow")] {
            let path = dir.path().join(name);
            let mut logger = Logger::create(&path, key(1), "shared")?;
            for i in 0..3 {
                let (l, t, r) = rec(i);
                logger.append(
                    &Record {
                        policy_hash: POLICY,
                        layer: &l,
                        target: &t,
                        rule: &r,
                        verdict,
                    },
                    1_000 + i,
                )?;
            }
            logger.finish(9_999)?;
            logs.push((fs::read(&path)?, fs::read(checkpoint_path(&path))?));
        }
        let (a, cp_a) = &logs[0];
        let (b, _) = &logs[1];
        let mut spliced = lines(a);
        spliced[1] = lines(b)[1].clone();
        let result = verify(&join(&spliced), Some(cp_a), &key(1).verifying_key(), false);
        assert!(
            matches!(
                result,
                Err(VerifyError::Line {
                    line: 2,
                    problem: LineProblem::ChainBroken
                })
            ),
            "{result:?}"
        );
        Ok(())
    }

    #[test]
    fn a_checkpoint_of_a_different_log_with_the_same_session_and_length_fails() -> TestResult {
        let dir = tempfile::tempdir()?;
        let mut logs = Vec::new();
        for (name, verdict) in [("a.jsonl", "block"), ("b.jsonl", "allow")] {
            let path = dir.path().join(name);
            let mut logger = Logger::create(&path, key(1), "shared")?;
            for i in 0..3 {
                let (l, t, r) = rec(i);
                logger.append(
                    &Record {
                        policy_hash: POLICY,
                        layer: &l,
                        target: &t,
                        rule: &r,
                        verdict,
                    },
                    1_000 + i,
                )?;
            }
            logger.finish(9_999)?;
            logs.push((fs::read(&path)?, fs::read(checkpoint_path(&path))?));
        }
        // Each log is fine with its own checkpoint, and neither is fine with the other's.
        let k = key(1).verifying_key();
        assert!(verify(&logs[0].0, Some(&logs[0].1), &k, false).is_ok());
        assert!(verify(&logs[1].0, Some(&logs[1].1), &k, false).is_ok());
        assert!(matches!(
            verify(&logs[1].0, Some(&logs[0].1), &k, false),
            Err(VerifyError::Checkpoint(CheckpointProblem::LastMismatch))
        ));
        Ok(())
    }

    #[test]
    fn a_weak_public_key_cannot_be_used_to_forge_a_log() -> TestResult {
        // With the identity point as public key, the signature R = identity,
        // S = 0 satisfies the plain ed25519 equation for any message. Strict
        // verification refuses weak keys, so the forged line must not pass.
        let identity = VerifyingKey::from_bytes(&{
            let mut bytes = [0u8; 32];
            bytes[0] = 1;
            bytes
        })?;
        assert!(identity.is_weak());
        let (log, _) = closed_log(1)?;
        let line = lines(&log).remove(0);
        let value: serde_json::Value = serde_json::from_str(&line)?;
        let real_sig = value["sig"].as_str().unwrap_or_default().to_owned();
        let forged_sig = format!("01{}", "00".repeat(63));
        let forged = line.replace(&real_sig, &forged_sig);
        let result = verify(&join(&[forged]), None, &identity, true);
        assert!(
            matches!(
                result,
                Err(VerifyError::Line {
                    line: 1,
                    problem: LineProblem::BadSignature
                })
            ),
            "{result:?}"
        );
        Ok(())
    }

    #[test]
    fn signing_domains_are_distinct_and_not_prefixes_of_each_other() {
        let domains = [ENTRY_DOMAIN, CHECKPOINT_DOMAIN, GENESIS_DOMAIN];
        for (i, a) in domains.iter().enumerate() {
            assert!(a.ends_with(b"\n"));
            for b in &domains[i + 1..] {
                assert_ne!(a, b);
                assert!(!a.starts_with(b) && !b.starts_with(a));
            }
        }
    }

    #[test]
    fn an_entry_is_not_accepted_as_a_checkpoint_and_the_reverse() -> TestResult {
        let (log, cp) = closed_log(2)?;
        // The first log line used as the checkpoint, and the checkpoint used as a log line.
        let first = lines(&log).remove(0) + "\n";
        assert!(verify(&log, Some(first.as_bytes()), &key(1).verifying_key(), false).is_err());
        assert!(verify(&cp, None, &key(1).verifying_key(), true).is_err());
        Ok(())
    }

    // --- checkpoint tampering ---

    fn checkpoint_with(
        edit: impl Fn(&mut serde_json::Value),
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let (_, cp) = closed_log(3)?;
        let mut value: serde_json::Value = serde_json::from_slice(&cp)?;
        edit(&mut value);
        let mut text = serde_json::to_string(&value)?;
        text.push('\n');
        Ok(text.into_bytes())
    }

    #[test]
    fn editing_the_checkpoint_fails() -> TestResult {
        let (log, _) = closed_log(3)?;
        // (field, new value): each change must break the checkpoint.
        let edits: [(&str, serde_json::Value); 6] = [
            ("count", 2.into()),
            ("count", 4.into()),
            ("last", "0".repeat(64).into()),
            ("session", "session-2".into()),
            ("ts", 1.into()),
            ("v", 2.into()),
        ];
        for (field, value) in edits {
            let cp = checkpoint_with(|v| v[field] = value.clone())?;
            assert!(ok(&log, &cp).is_err(), "{field} edit was accepted");
        }
        Ok(())
    }

    #[test]
    fn a_checkpoint_signed_by_another_key_fails() -> TestResult {
        let (log, _) = closed_log(3)?;
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("s.jsonl");
        let mut logger = Logger::create(&path, key(2), "session-1")?;
        for i in 0..3 {
            let (l, t, r) = rec(i);
            logger.append(
                &Record {
                    policy_hash: POLICY,
                    layer: &l,
                    target: &t,
                    rule: &r,
                    verdict: "block",
                },
                1_000 + i,
            )?;
        }
        logger.finish(9_999)?;
        let foreign = fs::read(checkpoint_path(&path))?;
        assert!(matches!(
            ok(&log, &foreign),
            Err(VerifyError::Checkpoint(CheckpointProblem::BadSignature))
        ));
        Ok(())
    }

    #[test]
    fn a_checkpoint_of_another_session_fails() -> TestResult {
        let (log, _) = closed_log(3)?;
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("o.jsonl");
        let mut logger = Logger::create(&path, key(1), "other-session")?;
        for i in 0..3 {
            let (l, t, r) = rec(i);
            logger.append(
                &Record {
                    policy_hash: POLICY,
                    layer: &l,
                    target: &t,
                    rule: &r,
                    verdict: "block",
                },
                1_000 + i,
            )?;
        }
        logger.finish(9_999)?;
        let other = fs::read(checkpoint_path(&path))?;
        assert!(matches!(
            ok(&log, &other),
            Err(VerifyError::Checkpoint(CheckpointProblem::SessionMismatch))
        ));
        Ok(())
    }

    #[test]
    fn a_checkpoint_must_be_exactly_one_canonical_line() -> TestResult {
        let (log, cp) = closed_log(3)?;
        let text = String::from_utf8(cp.clone())?;
        let variants: Vec<Vec<u8>> = vec![
            text.trim_end().as_bytes().to_vec(),
            format!("{text}{text}").into_bytes(),
            format!("{text}\n").into_bytes(),
            text.replace(",\"count\"", ", \"count\"").into_bytes(),
            text.replacen('{', "{\"extra\":1,", 1).into_bytes(),
            Vec::new(),
            vec![0xff, 0xfe],
        ];
        for variant in variants {
            assert!(
                matches!(ok(&log, &variant), Err(VerifyError::Checkpoint(_))),
                "{:?}",
                String::from_utf8_lossy(&variant)
            );
        }
        Ok(())
    }

    // --- the writer ---

    #[test]
    fn long_fields_are_cut_on_a_character_boundary() -> TestResult {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("s.jsonl");
        let mut logger = Logger::create(&path, key(1), "s")?;
        let long = "é".repeat(2000);
        logger.append(
            &Record {
                policy_hash: &long,
                layer: &long,
                target: &long,
                rule: &long,
                verdict: &long,
            },
            1,
        )?;
        logger.finish(2)?;
        let log = fs::read(&path)?;
        let cp = fs::read(checkpoint_path(&path))?;
        verify(&log, Some(&cp), &key(1).verifying_key(), false)?;
        let value: serde_json::Value =
            serde_json::from_slice(log.split(|b| *b == b'\n').next().unwrap_or_default())?;
        let target = value["target"].as_str().unwrap_or_default();
        assert!(target.len() <= MAX_FIELD_BYTES);
        assert!(target.ends_with('…'));
        assert_eq!(clip("short"), "short");
        Ok(())
    }

    #[test]
    fn special_characters_survive_signing() -> TestResult {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("s.jsonl");
        let mut logger = Logger::create(&path, key(1), "s")?;
        let nasty =
            "quote\" back\\slash \u{1b}[31m newline\n tab\t null\u{0} \u{202e} 日本語 \u{1f600}";
        logger.append(
            &Record {
                policy_hash: POLICY,
                layer: nasty,
                target: nasty,
                rule: nasty,
                verdict: nasty,
            },
            1,
        )?;
        logger.finish(2)?;
        let log = fs::read(&path)?;
        assert_eq!(
            log.iter().filter(|b| **b == b'\n').count(),
            1,
            "one line only"
        );
        let cp = fs::read(checkpoint_path(&path))?;
        verify(&log, Some(&cp), &key(1).verifying_key(), false)?;
        Ok(())
    }

    #[test]
    fn a_log_is_never_overwritten_and_a_closed_one_is_never_reopened() -> TestResult {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("s.jsonl");
        let logger = Logger::create(&path, key(1), "s")?;
        assert!(matches!(
            Logger::create(&path, key(1), "s"),
            Err(LogError::Exists(_))
        ));
        logger.finish(1)?;
        // The checkpoint exists now, so the session is closed.
        assert!(matches!(
            Logger::create(&path, key(1), "s"),
            Err(LogError::Closed(_))
        ));
        fs::remove_file(&path)?;
        assert!(matches!(
            Logger::create(&path, key(1), "s"),
            Err(LogError::Closed(_))
        ));
        Ok(())
    }

    #[test]
    fn finish_cannot_overwrite_a_checkpoint() -> TestResult {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("s.jsonl");
        let logger = Logger::create(&path, key(1), "s")?;
        fs::write(checkpoint_path(&path), "planted")?;
        assert!(matches!(logger.finish(1), Err(LogError::Closed(_))));
        assert_eq!(fs::read_to_string(checkpoint_path(&path))?, "planted");
        Ok(())
    }

    #[test]
    fn session_ids_are_checked() -> TestResult {
        let dir = tempfile::tempdir()?;
        for (index, bad) in ["", "has space", "a/b", "..", "tab\t", "é", &"a".repeat(129)]
            .iter()
            .enumerate()
        {
            let path = dir.path().join(format!("{index}.jsonl"));
            assert!(
                matches!(
                    Logger::create(&path, key(1), bad),
                    Err(LogError::InvalidSession)
                ),
                "{bad:?}"
            );
            assert!(!path.exists());
        }
        let path = dir.path().join("ok.jsonl");
        Logger::create(&path, key(1), &"a".repeat(128))?;
        Ok(())
    }

    #[test]
    fn generated_session_ids_are_valid_and_different() -> TestResult {
        let a = new_session_id()?;
        let b = new_session_id()?;
        assert_ne!(a, b);
        assert_eq!(a.len(), 32);
        assert!(valid_session(&a));
        Ok(())
    }

    #[test]
    fn a_second_writer_on_the_same_file_is_refused() -> TestResult {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("s.jsonl");
        let _first = Logger::create(&path, key(1), "s")?;
        let second = OpenOptions::new().read(true).append(true).open(&path)?;
        assert!(matches!(
            Logger::from_file(second, &path, key(1), "s"),
            Err(LogError::InUse(_))
        ));
        Ok(())
    }

    #[test]
    fn the_size_limit_stops_the_writer_before_it_writes() -> TestResult {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("s.jsonl");
        let mut logger = Logger::create(&path, key(1), "s")?;
        let record = Record {
            policy_hash: POLICY,
            layer: "l",
            target: "t",
            rule: "r",
            verdict: "v",
        };
        logger.append(&record, 1)?;
        let size = fs::metadata(&path)?.len();
        logger.max_bytes = size + 10;
        assert!(matches!(logger.append(&record, 2), Err(LogError::Full)));
        assert_eq!(fs::metadata(&path)?.len(), size, "nothing was written");
        logger.max_bytes = MAX_LOG_BYTES;
        logger.append(&record, 3)?;
        Ok(())
    }

    #[test]
    fn a_failed_write_poisons_the_log() -> TestResult {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("s.jsonl");
        fs::write(&path, "")?;
        // A read-only handle: every write fails.
        let read_only = File::open(&path)?;
        let mut logger = Logger::from_file(read_only, &path, key(1), "s")?;
        let record = Record {
            policy_hash: POLICY,
            layer: "l",
            target: "t",
            rule: "r",
            verdict: "v",
        };
        assert!(matches!(
            logger.append(&record, 1),
            Err(LogError::Io { .. })
        ));
        assert!(matches!(logger.append(&record, 2), Err(LogError::Poisoned)));
        assert!(matches!(logger.finish(3), Err(LogError::Poisoned)));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn log_and_checkpoint_files_are_private() -> TestResult {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("s.jsonl");
        let logger = Logger::create(&path, key(1), "s")?;
        logger.finish(1)?;
        for file in [path.clone(), checkpoint_path(&path)] {
            assert_eq!(fs::metadata(file)?.permissions().mode() & 0o777, 0o600);
        }
        Ok(())
    }

    #[test]
    fn checkpoint_path_appends_to_the_whole_name() {
        assert_eq!(
            checkpoint_path(Path::new("/a/b.jsonl")),
            PathBuf::from("/a/b.jsonl.checkpoint")
        );
    }

    // --- verify_path ---

    #[test]
    fn verify_path_reads_the_log_and_its_checkpoint() -> TestResult {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("s.jsonl");
        let mut logger = Logger::create(&path, key(1), "s")?;
        let record = Record {
            policy_hash: POLICY,
            layer: "l",
            target: "t",
            rule: "r",
            verdict: "v",
        };
        logger.append(&record, 1)?;
        logger.finish(2)?;
        let k = key(1).verifying_key();
        assert_eq!(verify_path(&path, &k, false)?.entries, 1);
        fs::remove_file(checkpoint_path(&path))?;
        assert!(matches!(
            verify_path(&path, &k, false),
            Err(VerifyPathError::Invalid(VerifyError::MissingCheckpoint))
        ));
        assert!(!verify_path(&path, &k, true)?.closed);
        Ok(())
    }

    #[test]
    fn verify_path_reports_missing_and_oversized_files() -> TestResult {
        let dir = tempfile::tempdir()?;
        let k = key(1).verifying_key();
        assert!(matches!(
            verify_path(&dir.path().join("nope.jsonl"), &k, true),
            Err(VerifyPathError::Io { .. })
        ));
        let path = dir.path().join("s.jsonl");
        Logger::create(&path, key(1), "s")?.finish(1)?;
        fs::write(
            checkpoint_path(&path),
            vec![b'x'; usize::try_from(MAX_CHECKPOINT_BYTES)? + 1],
        )?;
        assert!(matches!(
            verify_path(&path, &k, false),
            Err(VerifyPathError::TooLarge(_))
        ));
        Ok(())
    }

    #[test]
    fn every_error_message_is_free_of_log_content() -> TestResult {
        // A tampered value must not be echoed to the terminal.
        let (log, cp) = closed_log(1)?;
        let text = String::from_utf8(log)?;
        let marker = "\u{1b}[31mEVIL";
        let changed = text.replace("host0.example", marker);
        let error = ok(changed.as_bytes(), &cp).err().map(|e| e.to_string());
        assert!(
            error.is_some_and(|message| !message.contains("EVIL") && !message.contains('\u{1b}'))
        );
        Ok(())
    }

    #[test]
    fn all_signatures_in_a_log_are_different() -> TestResult {
        let (log, _) = closed_log(8)?;
        let sigs: HashSet<String> = lines(&log)
            .iter()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .filter_map(|v| v["sig"].as_str().map(str::to_owned))
            .collect();
        assert_eq!(sigs.len(), 8);
        Ok(())
    }
}
