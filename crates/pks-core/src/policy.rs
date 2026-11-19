//! Policy (PRD FR-POL, Phase 7).
//!
//! Two files feed one effective policy:
//! - the user policy, `policy.toml` in the config dir, never visible in the
//!   sandbox;
//! - the repo policy, `pumpkin-shell.toml`, which lives in the repo and so
//!   is attacker-controlled. It can only **tighten**, and it is ignored
//!   until its exact SHA-256 has been pinned with `pumpkin-shell trust`.
//!
//! An entry in the repo policy that would loosen a setting is ignored and
//! reported as `POL-UNTRUSTED` (PRD FR-DET: WARN, loosening ignored). The
//! rest of the repo policy still applies.
//!
//! File format, version 1:
//! ```toml
//! version = 1
//! mode = "enforce"                  # or "monitor": log instead of block
//! [rules."NET-UNKNOWN-DOMAIN"]
//! action = "block"                  # "alert" < "ask" < "block"
//! ```
//! Only the rules in [`CONFIGURABLE_RULES`] can be set. Unknown keys and
//! unknown rule IDs are errors, so a typo cannot silently do nothing.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read};
use std::path::Path;

use serde::Deserialize;

use crate::net::HostPort;
use crate::trust::TrustState;
use crate::{Finding, RuleId, Severity, hex};

/// Rule raised when a repo policy tries to loosen a setting or cannot be used.
pub const POL_UNTRUSTED: RuleId = RuleId::new("POL-UNTRUSTED");

/// Format version written in `version`.
pub const POLICY_VERSION: u32 = 1;

/// Name of the repo policy file, at the repo root.
pub const REPO_POLICY_FILE: &str = "pumpkin-shell.toml";
/// Name of the user policy file, in the config dir.
pub const USER_POLICY_FILE: &str = "policy.toml";

const MAX_POLICY_BYTES: u64 = 1024 * 1024;

/// Monitor mode logs instead of blocking. Enforce is the stricter value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Monitor,
    Enforce,
}

impl Mode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Monitor => "monitor",
            Mode::Enforce => "enforce",
        }
    }
}

/// What happens when a rule fires, from loosest to strictest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Alert,
    Ask,
    Block,
}

impl Action {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Alert => "alert",
            Action::Ask => "ask",
            Action::Block => "block",
        }
    }
}

/// Rules a policy can set, with their default action. Source: the PRD
/// FR-DET table (kept in `.kiro/steering/detection-rules.md`): "Block" gives
/// `Block`, "Ask" gives `Ask`, "Alert only" and WARN rules give `Alert`.
/// Rules with fixed behavior (staged, session killed, version hidden) and the
/// `EXEC-*` rules, which are detection only and must never block, are not
/// listed. More rules are added when a later phase needs to configure them.
pub const CONFIGURABLE_RULES: [(RuleId, Action); 10] = [
    (RuleId::new("REG-MALWARE"), Action::Block),
    (RuleId::new("REG-INTEGRITY"), Action::Block),
    (RuleId::new("REG-TOO-NEW"), Action::Block),
    (RuleId::new("REG-HALLUCINATED"), Action::Alert),
    (RuleId::new("REG-TYPOSQUAT"), Action::Alert),
    (RuleId::new("REG-DIRECT-BYPASS"), Action::Block),
    (RuleId::new("NET-UNKNOWN-DOMAIN"), Action::Ask),
    (RuleId::new("NET-PRIVATE-IP"), Action::Block),
    (RuleId::new("NET-DIRECT-CONNECT"), Action::Alert),
    (RuleId::new("NET-LARGE-UPLOAD"), Action::Alert),
];

fn configurable(name: &str) -> Option<(RuleId, Action)> {
    CONFIGURABLE_RULES
        .iter()
        .find(|(id, _)| id.as_str() == name)
        .copied()
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("{0}")]
    Invalid(String),
    #[error("unsupported policy version {0} (this build reads version 1)")]
    Version(u32),
    #[error("unknown rule {0:?}; a policy can set only: {1}")]
    UnknownRule(String, String),
    #[error("cannot read {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("{path} is not safe to use: {problem}")]
    Insecure { path: String, problem: &'static str },
    #[error("{0} is larger than the 1 MiB limit")]
    TooLarge(String),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    version: u32,
    mode: Option<Mode>,
    #[serde(default)]
    rules: BTreeMap<String, RawRule>,
    network: Option<RawNetwork>,
}

/// `[network]` in the user policy: exact `host:port` endpoints the IDE may
/// reach through the proxy without asking (PRD FR-NET).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNetwork {
    #[serde(default)]
    allow: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    action: Action,
}

/// A policy file that passed validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyFile {
    pub mode: Option<Mode>,
    pub rules: BTreeMap<RuleId, Action>,
    /// Endpoints allowed without asking. Only the user policy may set them.
    pub allow: BTreeSet<HostPort>,
}

impl PolicyFile {
    /// Parses and validates the text of a policy file.
    ///
    /// # Errors
    /// Fails on bad TOML, an unsupported version, an unknown key, an unknown
    /// rule ID or an unknown value.
    pub fn parse(text: &str) -> Result<Self, PolicyError> {
        parse_with(text, true)
    }

    /// Parses a repo policy. The same schema, except `[network]`: a repo
    /// policy cannot add endpoints, because it is written by whoever wrote
    /// the repo.
    ///
    /// # Errors
    /// The same as [`PolicyFile::parse`], plus any `[network]` section.
    pub fn parse_repo(text: &str) -> Result<Self, PolicyError> {
        parse_with(text, false)
    }
}

fn parse_with(text: &str, allow_network: bool) -> Result<PolicyFile, PolicyError> {
    {
        let raw: RawPolicy =
            toml::from_str(text).map_err(|error| PolicyError::Invalid(error.to_string()))?;
        if raw.version != POLICY_VERSION {
            return Err(PolicyError::Version(raw.version));
        }
        let mut allow = BTreeSet::new();
        if let Some(network) = raw.network {
            if !allow_network {
                return Err(PolicyError::Invalid(
                    "a repo policy cannot set [network]: only your own policy.toml may allow endpoints"
                        .to_owned(),
                ));
            }
            for entry in network.allow {
                let endpoint = HostPort::parse(&entry)
                    .map_err(|error| PolicyError::Invalid(error.to_string()))?;
                allow.insert(endpoint);
            }
        }
        let mut rules = BTreeMap::new();
        for (name, rule) in raw.rules {
            let (id, _) = configurable(&name).ok_or_else(|| {
                let known: Vec<_> = CONFIGURABLE_RULES
                    .iter()
                    .map(|(id, _)| id.as_str())
                    .collect();
                PolicyError::UnknownRule(name.clone(), known.join(", "))
            })?;
            rules.insert(id, rule.action);
        }
        Ok(PolicyFile {
            mode: raw.mode,
            rules,
            allow,
        })
    }
}

/// The policy in force: every configurable rule has an action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Effective {
    pub mode: Mode,
    pub actions: BTreeMap<RuleId, Action>,
    /// Endpoints allowed without asking, from the user policy.
    pub allow: BTreeSet<HostPort>,
}

impl Effective {
    /// Built-in defaults overlaid with the user policy. The user may loosen
    /// or tighten anything.
    #[must_use]
    pub fn from_user(user: &PolicyFile) -> Self {
        let mut actions: BTreeMap<RuleId, Action> = CONFIGURABLE_RULES.iter().copied().collect();
        actions.extend(user.rules.iter().map(|(id, action)| (*id, *action)));
        Self {
            mode: user.mode.unwrap_or(Mode::Enforce),
            actions,
            allow: user.allow.clone(),
        }
    }

    /// SHA-256 of a fixed text form of this policy, in lowercase hex. It is
    /// the `policy_hash` of log entries, so a log says which policy applied.
    #[must_use]
    pub fn hash(&self) -> String {
        let mut text = format!("pumpkin-shell-policy-v1\nmode={}\n", self.mode.as_str());
        for (id, action) in &self.actions {
            text.push_str(&format!("{}={}\n", id.as_str(), action.as_str()));
        }
        for endpoint in &self.allow {
            text.push_str(&format!("allow={endpoint}\n"));
        }
        hex::sha256(text.as_bytes())
    }
}

fn untrusted(target: &str, message: String, fix: &str) -> Finding {
    Finding {
        rule: POL_UNTRUSTED,
        severity: Severity::Warn,
        target: target.to_owned(),
        message,
        fix: fix.to_owned(),
    }
}

const LOOSEN_FIX: &str = "Remove the setting from pumpkin-shell.toml. A repo policy can only make rules stricter; to loosen one, change your own policy.toml.";

/// Applies a repo policy on top of the user's. Entries that would loosen a
/// setting are ignored and reported.
#[must_use]
pub fn merge(user: &PolicyFile, repo: &PolicyFile) -> (Effective, Vec<Finding>) {
    let mut effective = Effective::from_user(user);
    let mut findings = Vec::new();

    if let Some(wanted) = repo.mode {
        if wanted < effective.mode {
            findings.push(untrusted(
                "pumpkin-shell.toml: mode",
                format!(
                    "repo policy would change mode from {} to {}, which is looser; ignored",
                    effective.mode.as_str(),
                    wanted.as_str()
                ),
                LOOSEN_FIX,
            ));
        } else {
            effective.mode = wanted;
        }
    }
    for (id, wanted) in &repo.rules {
        let base = effective.actions.get(id).copied().unwrap_or(Action::Alert);
        if *wanted < base {
            findings.push(untrusted(
                &format!("pumpkin-shell.toml: rules.{}", id.as_str()),
                format!(
                    "repo policy would change {} from {} to {}, which is looser; ignored",
                    id.as_str(),
                    base.as_str(),
                    wanted.as_str()
                ),
                LOOSEN_FIX,
            ));
        } else {
            effective.actions.insert(*id, *wanted);
        }
    }
    (effective, findings)
}

/// A repo policy as found on disk: raw bytes and their hash. It is not
/// parsed until it is trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoPolicyFile {
    pub bytes: Vec<u8>,
    /// SHA-256 of `bytes`, lowercase hex. This is what `trust` pins.
    pub sha256: String,
}

/// What `resolve` did with the repo policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepoOutcome {
    /// There is no repo policy.
    Absent,
    /// It was trusted and applied (loosening entries excepted).
    Applied,
    /// It was not applied.
    Ignored,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    pub effective: Effective,
    pub findings: Vec<Finding>,
    pub repo: RepoOutcome,
}

/// Combines the user policy with the repo policy, given the trust state of
/// the repo policy's hash. Pure: it reads nothing.
#[must_use]
pub fn resolve(user: &PolicyFile, repo: Option<&RepoPolicyFile>, trust: TrustState) -> Resolution {
    let Some(repo) = repo else {
        return Resolution {
            effective: Effective::from_user(user),
            findings: Vec::new(),
            repo: RepoOutcome::Absent,
        };
    };
    let ignore = |message: &str| Resolution {
        effective: Effective::from_user(user),
        findings: vec![untrusted(
            "pumpkin-shell.toml",
            message.to_owned(),
            "Read pumpkin-shell.toml, then run `pumpkin-shell trust` to pin it.",
        )],
        repo: RepoOutcome::Ignored,
    };
    match trust {
        TrustState::Unpinned => return ignore("repo policy is not trusted yet; ignored"),
        TrustState::Changed => {
            return ignore("repo policy changed since it was trusted; ignored");
        }
        TrustState::Trusted => {}
    }
    let parsed = std::str::from_utf8(&repo.bytes)
        .map_err(|_| PolicyError::Invalid("not valid UTF-8".to_owned()))
        .and_then(PolicyFile::parse_repo);
    match parsed {
        Ok(file) => {
            let (effective, findings) = merge(user, &file);
            Resolution {
                effective,
                findings,
                repo: RepoOutcome::Applied,
            }
        }
        Err(error) => ignore(&format!("repo policy is not valid ({error}); ignored")),
    }
}

// --- reading files -------------------------------------------------------

fn io_error(path: &Path, source: io::Error) -> PolicyError {
    PolicyError::Io {
        path: path.display().to_string(),
        source,
    }
}

/// Reads a regular file of at most 1 MiB. `None` when it does not exist.
fn read_regular(path: &Path) -> Result<Option<Vec<u8>>, PolicyError> {
    let shown = || path.display().to_string();
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error(path, error)),
    };
    if meta.file_type().is_symlink() {
        return Err(PolicyError::Insecure {
            path: shown(),
            problem: "a symlink",
        });
    }
    if !meta.is_file() {
        return Err(PolicyError::Insecure {
            path: shown(),
            problem: "not a regular file",
        });
    }
    if meta.len() > MAX_POLICY_BYTES {
        return Err(PolicyError::TooLarge(shown()));
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .and_then(|file| file.take(MAX_POLICY_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|error| io_error(path, error))?;
    if bytes.len() as u64 > MAX_POLICY_BYTES {
        return Err(PolicyError::TooLarge(shown()));
    }
    Ok(Some(bytes))
}

/// Reads the repo policy at `repo/pumpkin-shell.toml`, without parsing it.
///
/// # Errors
/// Fails if the file is a symlink, not a regular file, too large or
/// unreadable. A missing file is `Ok(None)`.
pub fn read_repo_policy(repo: &Path) -> Result<Option<RepoPolicyFile>, PolicyError> {
    Ok(
        read_regular(&repo.join(REPO_POLICY_FILE))?.map(|bytes| RepoPolicyFile {
            sha256: hex::sha256(&bytes),
            bytes,
        }),
    )
}

/// Reads and parses `policy.toml` in `config_dir`. A missing file means
/// "no user policy" (`Ok(None)`).
///
/// # Errors
/// Fails if the file is invalid, a symlink, too large, or (Unix) writable by
/// other users, since anyone who can edit it controls the sandbox.
pub fn read_user_policy(config_dir: &Path) -> Result<Option<PolicyFile>, PolicyError> {
    let path = config_dir.join(USER_POLICY_FILE);
    #[cfg(unix)]
    if let Ok(meta) = fs::symlink_metadata(&path) {
        use std::os::unix::fs::PermissionsExt;
        // Others-writable is refused. Group-writable is allowed: Debian,
        // Ubuntu and Mint give each user a private group and `umask 002`, so
        // ordinary files are mode 0664 there.
        if !meta.file_type().is_symlink() && meta.permissions().mode() & 0o002 != 0 {
            return Err(PolicyError::Insecure {
                path: path.display().to_string(),
                problem: "writable by other users",
            });
        }
    }
    let Some(bytes) = read_regular(&path)? else {
        return Ok(None);
    };
    let text = String::from_utf8(bytes)
        .map_err(|_| PolicyError::Invalid(format!("{} is not valid UTF-8", path.display())))?;
    PolicyFile::parse(&text).map(Some)
}

/// An empty user policy: defaults only.
#[must_use]
pub fn empty_user_policy() -> PolicyFile {
    PolicyFile {
        mode: None,
        rules: BTreeMap::new(),
        allow: BTreeSet::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn file(text: &str) -> PolicyFile {
        PolicyFile::parse(text).unwrap_or_else(|e| panic!("{e}: {text}"))
    }

    fn rule(name: &str) -> RuleId {
        CONFIGURABLE_RULES
            .iter()
            .map(|(id, _)| *id)
            .find(|id| id.as_str() == name)
            .unwrap_or_else(|| panic!("no rule {name}"))
    }

    fn repo_file(text: &str) -> RepoPolicyFile {
        RepoPolicyFile {
            bytes: text.as_bytes().to_vec(),
            sha256: hex::sha256(text.as_bytes()),
        }
    }

    // --- schema ---

    #[test]
    fn parses_a_full_policy() {
        let policy = file(
            "version = 1\nmode = \"monitor\"\n[rules.\"NET-UNKNOWN-DOMAIN\"]\naction = \"block\"\n[rules.REG-TYPOSQUAT]\naction = \"ask\"\n",
        );
        assert_eq!(policy.mode, Some(Mode::Monitor));
        assert_eq!(policy.rules[&rule("NET-UNKNOWN-DOMAIN")], Action::Block);
        assert_eq!(policy.rules[&rule("REG-TYPOSQUAT")], Action::Ask);
    }

    #[test]
    fn version_alone_is_a_valid_policy() {
        let policy = file("version = 1\n");
        assert_eq!(policy, empty_user_policy());
    }

    #[test]
    fn rejects_everything_that_is_not_in_the_schema() {
        let bad = [
            ("", "missing version"),
            ("mode = \"enforce\"\n", "missing version"),
            ("version = 2\n", "future version"),
            ("version = 0\n", "version zero"),
            ("version = \"1\"\n", "version as text"),
            ("version = 1\nextra = true\n", "unknown top-level key"),
            ("version = 1\nmode = \"loud\"\n", "unknown mode"),
            ("version = 1\nmode = \"Enforce\"\n", "mode is lowercase"),
            (
                "version = 1\n[rules.NET-NOPE]\naction = \"block\"\n",
                "unknown rule",
            ),
            (
                "version = 1\n[rules.\"net-unknown-domain\"]\naction = \"block\"\n",
                "rule IDs are uppercase",
            ),
            (
                "version = 1\n[rules.NET-PRIVATE-IP]\naction = \"allow\"\n",
                "unknown action",
            ),
            (
                "version = 1\n[rules.NET-PRIVATE-IP]\n",
                "rule without action",
            ),
            (
                "version = 1\n[rules.NET-PRIVATE-IP]\naction = \"block\"\nnote = 1\n",
                "unknown rule key",
            ),
            (
                "version = 1\n[rules.EXEC-DESTRUCTIVE]\naction = \"block\"\n",
                "EXEC rules are detection only",
            ),
            (
                "version = 1\n[rules.WS-AUTOAPPROVE]\naction = \"alert\"\n",
                "fixed-behavior rule",
            ),
            ("version = 1\nversion = 1\n", "duplicate key"),
            (
                "version = 1\n[rules.NET-PRIVATE-IP]\naction = \"block\"\n[rules.NET-PRIVATE-IP]\naction = \"alert\"\n",
                "duplicate table",
            ),
            ("this is not toml", "not toml"),
        ];
        for (text, why) in bad {
            assert!(
                PolicyFile::parse(text).is_err(),
                "accepted ({why}): {text:?}"
            );
        }
    }

    #[test]
    fn unknown_rule_errors_list_what_is_allowed() {
        let error = PolicyFile::parse("version = 1\n[rules.NET-NOPE]\naction = \"block\"\n")
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(
            error.contains("NET-NOPE") && error.contains("NET-UNKNOWN-DOMAIN"),
            "{error}"
        );
    }

    #[test]
    fn the_defaults_table_matches_the_prd() {
        let expected = [
            ("REG-MALWARE", Action::Block),
            ("REG-INTEGRITY", Action::Block),
            ("REG-TOO-NEW", Action::Block),
            ("REG-HALLUCINATED", Action::Alert),
            ("REG-TYPOSQUAT", Action::Alert),
            ("REG-DIRECT-BYPASS", Action::Block),
            ("NET-UNKNOWN-DOMAIN", Action::Ask),
            ("NET-PRIVATE-IP", Action::Block),
            ("NET-DIRECT-CONNECT", Action::Alert),
            ("NET-LARGE-UPLOAD", Action::Alert),
        ];
        let actual: Vec<_> = CONFIGURABLE_RULES
            .iter()
            .map(|(id, a)| (id.as_str(), *a))
            .collect();
        assert_eq!(actual, expected);
        // No rule may be listed twice.
        let mut names: Vec<_> = actual.iter().map(|(n, _)| *n).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), expected.len());
    }

    #[test]
    fn modes_and_actions_are_ordered_loosest_first() {
        assert!(Mode::Monitor < Mode::Enforce);
        assert!(Action::Alert < Action::Ask && Action::Ask < Action::Block);
    }

    // --- merge: the Done-when behavior ---

    #[test]
    fn with_no_files_the_defaults_apply() {
        let effective = Effective::from_user(&empty_user_policy());
        assert_eq!(effective.mode, Mode::Enforce);
        assert_eq!(effective.actions.len(), CONFIGURABLE_RULES.len());
        assert_eq!(effective.actions[&rule("NET-UNKNOWN-DOMAIN")], Action::Ask);
    }

    #[test]
    fn the_user_may_loosen_or_tighten_anything() {
        let user = file(
            "version = 1\nmode = \"monitor\"\n[rules.REG-MALWARE]\naction = \"alert\"\n[rules.NET-DIRECT-CONNECT]\naction = \"block\"\n",
        );
        let effective = Effective::from_user(&user);
        assert_eq!(effective.mode, Mode::Monitor);
        assert_eq!(effective.actions[&rule("REG-MALWARE")], Action::Alert);
        assert_eq!(
            effective.actions[&rule("NET-DIRECT-CONNECT")],
            Action::Block
        );
    }

    #[test]
    fn a_repo_policy_that_tightens_is_applied() {
        let user = empty_user_policy();
        let repo = file(
            "version = 1\n[rules.NET-UNKNOWN-DOMAIN]\naction = \"block\"\n[rules.REG-TYPOSQUAT]\naction = \"block\"\n",
        );
        let (effective, findings) = merge(&user, &repo);
        assert!(findings.is_empty());
        assert_eq!(
            effective.actions[&rule("NET-UNKNOWN-DOMAIN")],
            Action::Block
        );
        assert_eq!(effective.actions[&rule("REG-TYPOSQUAT")], Action::Block);
    }

    #[test]
    fn a_repo_policy_that_loosens_a_rule_is_rejected_with_pol_untrusted() {
        let user = empty_user_policy();
        // REG-MALWARE defaults to block; the repo asks for alert.
        let repo = file("version = 1\n[rules.REG-MALWARE]\naction = \"alert\"\n");
        let (effective, findings) = merge(&user, &repo);
        assert_eq!(
            effective.actions[&rule("REG-MALWARE")],
            Action::Block,
            "loosening was applied"
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule.as_str(), "POL-UNTRUSTED");
        assert_eq!(findings[0].severity, Severity::Warn);
        assert_eq!(findings[0].target, "pumpkin-shell.toml: rules.REG-MALWARE");
        assert!(findings[0].message.contains("from block to alert"));
        assert!(findings[0].fix.contains("policy.toml"));
    }

    #[test]
    fn every_loosening_of_every_rule_is_rejected() {
        let user = empty_user_policy();
        for (id, default) in CONFIGURABLE_RULES {
            for action in [Action::Alert, Action::Ask, Action::Block] {
                let repo = file(&format!(
                    "version = 1\n[rules.{}]\naction = \"{}\"\n",
                    id.as_str(),
                    action.as_str()
                ));
                let (effective, findings) = merge(&user, &repo);
                if action < default {
                    assert_eq!(
                        effective.actions[&id],
                        default,
                        "{} loosened to {action:?}",
                        id.as_str()
                    );
                    assert_eq!(findings.len(), 1);
                } else {
                    assert_eq!(effective.actions[&id], action);
                    assert!(findings.is_empty());
                }
            }
        }
    }

    #[test]
    fn the_baseline_is_the_users_policy_not_the_default() {
        // The user already tightened the rule; the repo may not undo that.
        let user = file("version = 1\n[rules.REG-TYPOSQUAT]\naction = \"block\"\n");
        let repo = file("version = 1\n[rules.REG-TYPOSQUAT]\naction = \"ask\"\n");
        let (effective, findings) = merge(&user, &repo);
        assert_eq!(effective.actions[&rule("REG-TYPOSQUAT")], Action::Block);
        assert_eq!(findings.len(), 1);
        // And when the user loosened a rule, the repo may tighten back up.
        let user = file("version = 1\n[rules.REG-MALWARE]\naction = \"alert\"\n");
        let repo = file("version = 1\n[rules.REG-MALWARE]\naction = \"ask\"\n");
        let (effective, findings) = merge(&user, &repo);
        assert_eq!(effective.actions[&rule("REG-MALWARE")], Action::Ask);
        assert!(findings.is_empty());
    }

    #[test]
    fn a_repo_cannot_switch_to_monitor_mode_but_can_switch_to_enforce() {
        let (effective, findings) = merge(
            &empty_user_policy(),
            &file("version = 1\nmode = \"monitor\"\n"),
        );
        assert_eq!(effective.mode, Mode::Enforce);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].target, "pumpkin-shell.toml: mode");
        let user = file("version = 1\nmode = \"monitor\"\n");
        let (effective, findings) = merge(&user, &file("version = 1\nmode = \"enforce\"\n"));
        assert_eq!(effective.mode, Mode::Enforce);
        assert!(findings.is_empty());
    }

    #[test]
    fn loosening_entries_are_dropped_but_the_rest_of_the_file_applies() {
        let repo = file(
            "version = 1\nmode = \"monitor\"\n[rules.REG-MALWARE]\naction = \"alert\"\n[rules.NET-UNKNOWN-DOMAIN]\naction = \"block\"\n",
        );
        let (effective, findings) = merge(&empty_user_policy(), &repo);
        assert_eq!(findings.len(), 2);
        assert_eq!(effective.mode, Mode::Enforce);
        assert_eq!(effective.actions[&rule("REG-MALWARE")], Action::Block);
        assert_eq!(
            effective.actions[&rule("NET-UNKNOWN-DOMAIN")],
            Action::Block
        );
    }

    #[test]
    fn an_equal_setting_is_not_a_finding() {
        let repo =
            file("version = 1\nmode = \"enforce\"\n[rules.REG-MALWARE]\naction = \"block\"\n");
        let (_, findings) = merge(&empty_user_policy(), &repo);
        assert!(findings.is_empty());
    }

    #[test]
    fn merging_never_makes_anything_looser_than_the_user_policy() {
        // Property over every pair of values for one rule and the mode.
        let modes = [None, Some(Mode::Monitor), Some(Mode::Enforce)];
        let actions = [
            None,
            Some(Action::Alert),
            Some(Action::Ask),
            Some(Action::Block),
        ];
        for user_mode in modes {
            for repo_mode in modes {
                for user_action in actions {
                    for repo_action in actions {
                        let mut user_text = String::from("version = 1\n");
                        if let Some(mode) = user_mode {
                            user_text.push_str(&format!("mode = \"{}\"\n", mode.as_str()));
                        }
                        if let Some(action) = user_action {
                            user_text.push_str(&format!(
                                "[rules.NET-PRIVATE-IP]\naction = \"{}\"\n",
                                action.as_str()
                            ));
                        }
                        let mut repo_text = String::from("version = 1\n");
                        if let Some(mode) = repo_mode {
                            repo_text.push_str(&format!("mode = \"{}\"\n", mode.as_str()));
                        }
                        if let Some(action) = repo_action {
                            repo_text.push_str(&format!(
                                "[rules.NET-PRIVATE-IP]\naction = \"{}\"\n",
                                action.as_str()
                            ));
                        }
                        let user = file(&user_text);
                        let base = Effective::from_user(&user);
                        let (merged, _) = merge(&user, &file(&repo_text));
                        assert!(merged.mode >= base.mode, "{user_text} + {repo_text}");
                        for (id, action) in &merged.actions {
                            assert!(*action >= base.actions[id], "{user_text} + {repo_text}");
                        }
                    }
                }
            }
        }
    }

    // --- hash ---

    #[test]
    fn the_policy_hash_is_stable_and_follows_the_content() {
        let base = Effective::from_user(&empty_user_policy());
        assert_eq!(
            base.hash(),
            Effective::from_user(&empty_user_policy()).hash()
        );
        assert_eq!(base.hash().len(), 64);
        let tighter = Effective::from_user(&file(
            "version = 1\n[rules.NET-PRIVATE-IP]\naction = \"block\"\n",
        ));
        assert_eq!(
            base.hash(),
            tighter.hash(),
            "same effective policy, same hash"
        );
        let changed = Effective::from_user(&file(
            "version = 1\n[rules.NET-PRIVATE-IP]\naction = \"alert\"\n",
        ));
        assert_ne!(base.hash(), changed.hash());
        let monitor = Effective::from_user(&file("version = 1\nmode = \"monitor\"\n"));
        assert_ne!(base.hash(), monitor.hash());
    }

    #[test]
    fn the_policy_hash_ignores_how_the_file_was_written() {
        let a = Effective::from_user(&file(
            "version = 1\n[rules.REG-TYPOSQUAT]\naction = \"ask\"\n[rules.NET-PRIVATE-IP]\naction = \"alert\"\n",
        ));
        let b = Effective::from_user(&file(
            "# comment\nversion=1\n\n[rules.NET-PRIVATE-IP]\naction=\"alert\"\n[rules.REG-TYPOSQUAT]\n  action = \"ask\"\n",
        ));
        assert_eq!(a.hash(), b.hash());
    }

    // --- resolve: trust states ---

    #[test]
    fn no_repo_policy_means_the_user_policy_alone() {
        let resolution = resolve(&empty_user_policy(), None, TrustState::Unpinned);
        assert_eq!(resolution.repo, RepoOutcome::Absent);
        assert!(resolution.findings.is_empty());
    }

    #[test]
    fn an_unpinned_or_changed_repo_policy_is_ignored_and_reported() {
        let repo = repo_file("version = 1\n[rules.NET-UNKNOWN-DOMAIN]\naction = \"block\"\n");
        for (state, text) in [
            (TrustState::Unpinned, "not trusted yet"),
            (TrustState::Changed, "changed since it was trusted"),
        ] {
            let resolution = resolve(&empty_user_policy(), Some(&repo), state);
            assert_eq!(resolution.repo, RepoOutcome::Ignored);
            assert_eq!(
                resolution.effective,
                Effective::from_user(&empty_user_policy())
            );
            assert_eq!(resolution.findings.len(), 1);
            assert_eq!(resolution.findings[0].rule.as_str(), "POL-UNTRUSTED");
            assert!(resolution.findings[0].message.contains(text));
        }
    }

    #[test]
    fn a_trusted_repo_policy_is_applied() {
        let repo = repo_file("version = 1\n[rules.NET-UNKNOWN-DOMAIN]\naction = \"block\"\n");
        let resolution = resolve(&empty_user_policy(), Some(&repo), TrustState::Trusted);
        assert_eq!(resolution.repo, RepoOutcome::Applied);
        assert!(resolution.findings.is_empty());
        assert_eq!(
            resolution.effective.actions[&rule("NET-UNKNOWN-DOMAIN")],
            Action::Block
        );
    }

    #[test]
    fn a_trusted_but_loosening_repo_policy_still_reports_pol_untrusted() {
        let repo = repo_file("version = 1\n[rules.REG-MALWARE]\naction = \"alert\"\n");
        let resolution = resolve(&empty_user_policy(), Some(&repo), TrustState::Trusted);
        assert_eq!(resolution.repo, RepoOutcome::Applied);
        assert_eq!(resolution.findings.len(), 1);
        assert_eq!(
            resolution.effective.actions[&rule("REG-MALWARE")],
            Action::Block
        );
    }

    #[test]
    fn an_invalid_trusted_repo_policy_is_ignored_not_fatal() {
        for text in [
            "not toml",
            "version = 9\n",
            "version = 1\n[rules.NOPE]\naction = \"block\"\n",
        ] {
            let resolution = resolve(
                &empty_user_policy(),
                Some(&repo_file(text)),
                TrustState::Trusted,
            );
            assert_eq!(resolution.repo, RepoOutcome::Ignored, "{text}");
            assert!(resolution.findings[0].message.contains("not valid"));
        }
        let binary = RepoPolicyFile {
            bytes: vec![0xff, 0xfe],
            sha256: String::new(),
        };
        let resolution = resolve(&empty_user_policy(), Some(&binary), TrustState::Trusted);
        assert_eq!(resolution.repo, RepoOutcome::Ignored);
    }

    #[test]
    fn an_untrusted_repo_policy_is_never_parsed() {
        // Invalid content, untrusted: the message must be the trust one, not a parse error.
        let resolution = resolve(
            &empty_user_policy(),
            Some(&repo_file("not toml")),
            TrustState::Unpinned,
        );
        assert!(resolution.findings[0].message.contains("not trusted yet"));
        assert!(!resolution.findings[0].message.contains("not valid"));
    }

    // --- files ---

    #[test]
    fn the_repo_policy_is_read_and_hashed_without_parsing() -> TestResult {
        let dir = tempfile::tempdir()?;
        assert_eq!(read_repo_policy(dir.path())?, None);
        fs::write(dir.path().join(REPO_POLICY_FILE), "not even toml")?;
        let found = read_repo_policy(dir.path())?.map(|f| f.sha256);
        assert_eq!(found, Some(hex::sha256(b"not even toml")));
        Ok(())
    }

    #[test]
    fn the_repo_policy_must_be_a_regular_file_of_sane_size() -> TestResult {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join(REPO_POLICY_FILE);
        fs::create_dir(&path)?;
        assert!(matches!(
            read_repo_policy(dir.path()),
            Err(PolicyError::Insecure { .. })
        ));
        fs::remove_dir(&path)?;
        fs::write(&path, vec![b'#'; usize::try_from(MAX_POLICY_BYTES)? + 1])?;
        assert!(matches!(
            read_repo_policy(dir.path()),
            Err(PolicyError::TooLarge(_))
        ));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_repo_policy_is_refused() -> TestResult {
        use std::os::unix::fs::symlink;
        let outside = tempfile::tempdir()?;
        fs::write(outside.path().join("p.toml"), "version = 1\n")?;
        let repo = tempfile::tempdir()?;
        symlink(
            outside.path().join("p.toml"),
            repo.path().join(REPO_POLICY_FILE),
        )?;
        assert!(matches!(
            read_repo_policy(repo.path()),
            Err(PolicyError::Insecure { .. })
        ));
        Ok(())
    }

    #[test]
    fn the_user_policy_is_optional_and_validated() -> TestResult {
        let dir = tempfile::tempdir()?;
        assert_eq!(read_user_policy(dir.path())?, None);
        fs::write(
            dir.path().join(USER_POLICY_FILE),
            "version = 1\nmode = \"monitor\"\n",
        )?;
        assert_eq!(
            read_user_policy(dir.path())?.and_then(|p| p.mode),
            Some(Mode::Monitor)
        );
        fs::write(
            dir.path().join(USER_POLICY_FILE),
            "version = 1\nbogus = 1\n",
        )?;
        assert!(matches!(
            read_user_policy(dir.path()),
            Err(PolicyError::Invalid(_))
        ));
        fs::write(dir.path().join(USER_POLICY_FILE), [0xff, 0xfe])?;
        assert!(matches!(
            read_user_policy(dir.path()),
            Err(PolicyError::Invalid(_))
        ));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn a_user_policy_that_others_can_write_is_refused() -> TestResult {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir()?;
        let path = dir.path().join(USER_POLICY_FILE);
        fs::write(&path, "version = 1\n")?;
        for mode in [0o602, 0o666, 0o646, 0o622] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;
            assert!(
                matches!(
                    read_user_policy(dir.path()),
                    Err(PolicyError::Insecure { .. })
                ),
                "{mode:o}"
            );
        }
        // Group-writable is what `umask 002` gives on Ubuntu and Mint.
        for mode in [0o600, 0o644, 0o640, 0o664, 0o660] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;
            assert!(read_user_policy(dir.path()).is_ok(), "{mode:o}");
        }
        Ok(())
    }

    #[test]
    fn the_user_policy_may_allow_exact_endpoints() -> TestResult {
        let user = file("version = 1\n[network]\nallow = [\"API.Example.com:443\"]\n");
        let effective = Effective::from_user(&user);
        let wanted = HostPort::parse("api.example.com:443")?;
        assert!(effective.allow.contains(&wanted));
        Ok(())
    }

    #[test]
    fn a_wildcard_endpoint_in_the_user_policy_is_an_error() {
        let text = "version = 1\n[network]\nallow = [\"*.amazonaws.com:443\"]\n";
        assert!(PolicyFile::parse(text).is_err());
    }

    #[test]
    fn a_repo_policy_cannot_add_endpoints() {
        let text = "version = 1\n[network]\nallow = [\"evil.example.com:443\"]\n";
        let error = PolicyFile::parse_repo(text).err();
        assert!(
            matches!(&error, Some(PolicyError::Invalid(message)) if message.contains("[network]")),
            "{error:?}"
        );
    }

    #[test]
    fn a_repo_policy_without_network_parses() -> TestResult {
        let repo = PolicyFile::parse_repo("version = 1\nmode = \"enforce\"\n")?;
        assert!(repo.allow.is_empty());
        Ok(())
    }

    #[test]
    fn the_policy_hash_changes_when_the_allowlist_changes() -> TestResult {
        let base = Effective::from_user(&empty_user_policy());
        let mut changed = base.clone();
        changed
            .allow
            .insert(HostPort::parse("api.example.com:443")?);
        assert_ne!(base.hash(), changed.hash());
        Ok(())
    }
}
