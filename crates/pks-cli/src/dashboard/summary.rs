//! What the dashboard shows, built from the session logs (PRD FR-DASH).
//!
//! Every log is checked with the same code as `pumpkin-shell log verify`. The
//! severity of a finding is looked up from the rule's published level (PRD
//! FR-DET), because the signed log does not store one.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use pks_core::keys::load_verifying_key;
use pks_core::log::{VerifyPathError, verify_path};
use pks_detect::{PID_FILE, REPO_FILE, SessionInfo};
use serde::{Deserialize, Serialize};

/// Most events the page receives, newest first.
pub const MAX_EVENTS: usize = 200;

/// A finding's severity, from the PRD FR-DET table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Notice,
    Warn,
    High,
    Critical,
}

/// The published severity of a rule. A rule not in the table is a notice.
#[must_use]
pub fn severity_of(rule: &str) -> Severity {
    match rule {
        "WS-AUTOAPPROVE" | "NET-DECOY-EGRESS" | "REG-MALWARE" | "REG-INTEGRITY"
        | "EXEC-AGENT-YOLO" | "SBX-MONITOR-LOST" => Severity::Critical,
        "FS-DECOY-READ" | "WS-PROTECTED-WRITE" | "WS-WATCHED-CHANGE" | "WS-HIDDEN-UNICODE"
        | "WS-SECRET-WRITTEN" | "WS-MASS-DELETE" | "NET-PRIVATE-IP" | "REG-TOO-NEW"
        | "REG-DIRECT-BYPASS" | "EXEC-DESTRUCTIVE" | "EXEC-RECON" | "WIN-PERSIST"
        | "SYS-IDE-TAMPERABLE" => Severity::High,
        "NET-DIRECT-CONNECT" | "NET-UNKNOWN-DOMAIN" | "NET-LARGE-UPLOAD" | "REG-HALLUCINATED"
        | "REG-TYPOSQUAT" => Severity::Warn,
        _ => Severity::Notice,
    }
}

/// One record of a log, as the dashboard reads it. The signature is not
/// needed here: `verify_path` checks it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct Line {
    seq: u64,
    ts: u64,
    layer: String,
    target: String,
    rule: String,
    verdict: String,
}

/// One record shown on the page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EventView {
    pub session: String,
    pub seq: u64,
    pub ts: u64,
    pub layer: String,
    pub rule: String,
    pub severity: Severity,
    pub target: String,
    pub verdict: String,
}

/// The result of checking one log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Check {
    /// The chain, signatures and checkpoint are intact.
    Verified,
    /// Intact so far; the session may still be running (no checkpoint yet).
    Open,
    /// Intact, but the session has ended with no checkpoint: it was killed or
    /// crashed before it closed its log.
    Unclosed,
    /// The log was edited, reordered or truncated. The detail says where.
    Failed,
    /// The log could not be read, or no verifying key exists.
    Unavailable,
}

/// One session on the page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionView {
    pub id: String,
    pub repo: Option<String>,
    pub status: &'static str,
    pub started: Option<u64>,
    pub entries: u64,
    pub findings: u64,
    pub check: Check,
    pub check_detail: String,
}

/// Counts shown as cards.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Totals {
    pub sessions: u64,
    pub running: u64,
    pub findings: u64,
    pub critical: u64,
    pub high: u64,
    pub warn: u64,
    pub network_blocked: u64,
    pub decoy_reads: u64,
    pub registry_refused: u64,
    pub monitor_events: u64,
    pub logs_failed: u64,
}

/// A rule or layer and how many records it has.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Count {
    pub name: String,
    pub count: u64,
}

/// Everything the page needs in one response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Snapshot {
    pub generated: u64,
    pub totals: Totals,
    pub sessions: Vec<SessionView>,
    pub events: Vec<EventView>,
    pub by_rule: Vec<Count>,
    pub by_layer: Vec<Count>,
}

/// Parses the lines of one log. Lines that are not records are skipped; the
/// signature check reports any tampering separately.
#[must_use]
pub fn parse_events(session: &str, text: &str) -> Vec<EventView> {
    text.lines()
        .filter_map(|line| serde_json::from_str::<Line>(line).ok())
        .map(|line| EventView {
            session: session.to_owned(),
            seq: line.seq,
            ts: line.ts,
            layer: line.layer,
            severity: severity_of(&line.rule),
            rule: line.rule,
            target: line.target,
            verdict: line.verdict,
        })
        .collect()
}

/// Whether a record is a finding (WARN and above), as opposed to a notice.
#[must_use]
pub fn is_finding(event: &EventView) -> bool {
    event.severity >= Severity::Warn
}

/// Adds one event to the totals.
fn count(totals: &mut Totals, event: &EventView) {
    match event.severity {
        Severity::Critical => totals.critical += 1,
        Severity::High => totals.high += 1,
        Severity::Warn => totals.warn += 1,
        Severity::Notice => {}
    }
    if is_finding(event) {
        totals.findings += 1;
    }
    if event.layer == "net" && event.verdict == "block" {
        totals.network_blocked += 1;
    }
    if event.rule == "FS-DECOY-READ" {
        totals.decoy_reads += 1;
    }
    if event.layer == "registry" && (event.verdict == "block" || event.severity >= Severity::High) {
        totals.registry_refused += 1;
    }
    if matches!(event.layer.as_str(), "exec" | "sbx") {
        totals.monitor_events += 1;
    }
}

/// Sorts counts by number, largest first, then by name.
fn ranked(counts: HashMap<String, u64>) -> Vec<Count> {
    let mut list: Vec<Count> = counts
        .into_iter()
        .map(|(name, count)| Count { name, count })
        .collect();
    list.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.name.cmp(&b.name)));
    list
}

/// Whether a process with this ID is alive.
fn process_alive(pid: i32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

/// Checks logs, remembering each result until the log changes.
pub struct Checker {
    data: PathBuf,
    cache: HashMap<PathBuf, (u64, u64, Check, String)>,
}

impl Checker {
    /// A checker for the logs under `data`. The verifying key is read from
    /// `<data>/keys` when a log is checked, so a missing key shows as
    /// unavailable on the page instead of stopping the dashboard.
    #[must_use]
    pub fn new(data: PathBuf) -> Self {
        Self {
            data,
            cache: HashMap::new(),
        }
    }

    /// The data directory this checker reads.
    #[must_use]
    pub fn data(&self) -> &Path {
        &self.data
    }

    /// Checks one log. The result is kept while the log's size and time stay
    /// the same, so polling every 2 seconds does not re-verify every log.
    pub fn check(&mut self, log: &Path, open: bool) -> (Check, String) {
        let Ok(meta) = std::fs::metadata(log) else {
            return (Check::Unavailable, "log not found".to_owned());
        };
        let modified = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        if let Some((size, time, check, detail)) = self.cache.get(log)
            && *size == meta.len()
            && *time == modified
        {
            return (check.clone(), detail.clone());
        }
        let result = match load_verifying_key(&self.data.join("keys")) {
            Err(error) => (Check::Unavailable, error.to_string()),
            Ok(key) => match verify_path(log, &key, open) {
                Ok(verified) if verified.closed => (
                    Check::Verified,
                    format!("{} entries, checkpoint verified", verified.entries),
                ),
                Ok(verified) => (
                    Check::Open,
                    format!("{} entries, no checkpoint yet", verified.entries),
                ),
                Err(VerifyPathError::Invalid(problem)) => (Check::Failed, problem.to_string()),
                Err(error) => (Check::Unavailable, error.to_string()),
            },
        };
        self.cache.insert(
            log.to_path_buf(),
            (meta.len(), modified, result.0.clone(), result.1.clone()),
        );
        result
    }
}

/// Builds the snapshot for everything under the data directory.
pub fn snapshot(checker: &mut Checker, now: u64) -> Snapshot {
    let mut totals = Totals::default();
    let mut sessions = Vec::new();
    let mut events: Vec<EventView> = Vec::new();
    let mut rules: HashMap<String, u64> = HashMap::new();
    let mut layers: HashMap<String, u64> = HashMap::new();

    let data = checker.data().to_path_buf();
    for info in SessionInfo::list(&data) {
        let text = std::fs::read_to_string(&info.log).unwrap_or_default();
        let parsed = parse_events(&info.id, &text);
        let pid = std::fs::read_to_string(info.dir.join(PID_FILE))
            .ok()
            .and_then(|s| s.trim().parse::<i32>().ok());
        let running = pid.is_some_and(process_alive);
        let status = if running && info.paused.exists() {
            "paused"
        } else if running {
            "running"
        } else {
            "ended"
        };
        let (mut check, mut check_detail) = checker.check(&info.log, true);
        if status == "ended" && check == Check::Open {
            check = Check::Unclosed;
            check_detail =
                "the session ended without closing its log (killed or crashed)".to_owned();
        }
        if check == Check::Failed {
            totals.logs_failed += 1;
        }
        let mut findings = 0;
        for event in &parsed {
            count(&mut totals, event);
            *rules.entry(event.rule.clone()).or_insert(0) += 1;
            *layers.entry(event.layer.clone()).or_insert(0) += 1;
            if is_finding(event) {
                findings += 1;
            }
        }
        totals.sessions += 1;
        if status != "ended" {
            totals.running += 1;
        }
        sessions.push(SessionView {
            id: info.id.clone(),
            repo: std::fs::read_to_string(info.dir.join(REPO_FILE))
                .ok()
                .map(|s| s.trim().to_owned()),
            status,
            started: parsed.first().map(|e| e.ts),
            entries: u64::try_from(parsed.len()).unwrap_or(u64::MAX),
            findings,
            check,
            check_detail,
        });
        events.extend(parsed);
    }
    events.sort_by(|a, b| {
        b.ts.cmp(&a.ts)
            .then_with(|| a.session.cmp(&b.session))
            .then_with(|| b.seq.cmp(&a.seq))
    });
    events.truncate(MAX_EVENTS);
    sessions.sort_by_key(|s| std::cmp::Reverse(s.started));

    Snapshot {
        generated: now,
        totals,
        sessions,
        events,
        by_rule: ranked(rules),
        by_layer: ranked(layers),
    }
}
