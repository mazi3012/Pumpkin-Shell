//! Notification routing by severity (PRD FR-NOTIFY).
//!
//! - INFO/NOTICE → log only
//! - WARN → watch output
//! - HIGH → desktop notification (`notify-send`)
//! - CRITICAL → desktop notification + pause (webhook output is deferred, DECISIONS Q7)

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use pks_core::{Finding, Severity};

/// Minimum time between desktop notifications for the same rule+target (PRD: 10 s).
const DEDUP_WINDOW_SECS: u64 = 10;

/// A key for deduplication: rule + target.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct DedupKey {
    rule: &'static str,
    target: String,
}

/// Notification state for deduplication.
struct NotifyState {
    last_notification: std::collections::HashMap<DedupKey, Instant>,
}

impl NotifyState {
    fn new() -> Self {
        Self {
            last_notification: std::collections::HashMap::new(),
        }
    }
}

/// Handles notification routing by severity.
pub struct Notifier {
    /// Path to the session directory (for watch output).
    session_dir: PathBuf,
    /// Whether desktop notifications are enabled.
    desktop: bool,
    /// Pause flag for CRITICAL findings.
    pause_flag: std::sync::Arc<AtomicBool>,
    /// Deduplication state.
    state: Mutex<NotifyState>,
    /// Last desktop notification time (global, for rate limiting).
    last_desktop: AtomicU64,
}

impl Notifier {
    /// Creates a new notifier for the given session.
    pub fn new(
        session_dir: PathBuf,
        desktop: bool,
        pause_flag: std::sync::Arc<AtomicBool>,
    ) -> Self {
        Self {
            session_dir,
            desktop,
            pause_flag,
            state: Mutex::new(NotifyState::new()),
            last_desktop: AtomicU64::new(0),
        }
    }

    /// Routes a finding according to its severity.
    /// Returns true if the sandbox should pause (CRITICAL with pause action).
    pub fn notify(&self, finding: &Finding) -> bool {
        let key = DedupKey {
            rule: finding.rule.as_str(),
            target: finding.target.clone(),
        };

        // Check deduplication for desktop notifications.
        let should_show_desktop = match finding.severity {
            Severity::High | Severity::Critical => {
                let Ok(mut state) = self.state.lock() else {
                    return false;
                };
                let now = Instant::now();
                match state.last_notification.get(&key) {
                    Some(last) if now.duration_since(*last).as_secs() < DEDUP_WINDOW_SECS => false,
                    _ => {
                        state.last_notification.insert(key, now);
                        true
                    }
                }
            }
            _ => false,
        };

        // Route by severity.
        match finding.severity {
            Severity::Notice => {
                // INFO/NOTICE → log only (handled by caller)
            }
            Severity::Warn => {
                // WARN → watch output
                self.write_to_watch(finding);
            }
            Severity::High => {
                // HIGH → desktop notification
                if self.desktop && should_show_desktop {
                    self.show_desktop(finding);
                }
            }
            Severity::Critical => {
                // CRITICAL → desktop notification, then the pause.
                if should_show_desktop && self.desktop {
                    self.show_desktop(finding);
                }
                // Signal pause.
                self.pause_flag.store(true, Ordering::Release);
                return true;
            }
        }

        false
    }

    /// Writes a finding to the watch file.
    fn write_to_watch(&self, finding: &Finding) {
        let watch_file = self.session_dir.join("watch.jsonl");
        let line = serde_json::to_string(finding).unwrap_or_default();
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&watch_file)
        {
            use std::io::Write;
            let _ = writeln!(file, "{}", line);
        }
    }

    /// Shows a desktop notification via notify-send.
    fn show_desktop(&self, finding: &Finding) {
        // Rate limit: at most one notification per second globally.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let last = self.last_desktop.load(Ordering::Relaxed);
        if now.saturating_sub(last) < 1 {
            return;
        }
        self.last_desktop.store(now, Ordering::Relaxed);

        let title = format!("[{:?}] {}", finding.severity, finding.rule.as_str());
        let body = format!("{}: {}", finding.target, finding.message);

        // Try notify-send (Linux).
        let result = Command::new("notify-send")
            .arg("--app-name=pumpkin-shell")
            .arg("--urgency=normal")
            .arg(&title)
            .arg(&body)
            .status();

        if let Err(e) = result {
            eprintln!("notify: could not run notify-send: {}", e);
        }
    }

    /// Clears the pause flag.
    pub fn clear_pause(&self) {
        self.pause_flag.store(false, Ordering::Release);
    }

    /// Returns whether pause is requested.
    pub fn is_paused(&self) -> bool {
        self.pause_flag.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pks_core::RuleId;

    fn test_finding(severity: Severity) -> Finding {
        Finding {
            rule: RuleId::new("TEST-RULE"),
            severity,
            target: "test-target".to_string(),
            message: "test message".to_string(),
            fix: "test fix".to_string(),
        }
    }

    #[test]
    fn dedup_key_compares_rule_and_target() {
        let k1 = DedupKey {
            rule: "A",
            target: "x".to_string(),
        };
        let k2 = DedupKey {
            rule: "A",
            target: "y".to_string(),
        };
        let k3 = DedupKey {
            rule: "B",
            target: "x".to_string(),
        };
        assert_ne!(k1, k2);
        assert_ne!(k1, k3);
    }

    #[test]
    fn critical_returns_true_for_pause() {
        let temp = tempfile::tempdir().unwrap();
        let pause_flag = std::sync::Arc::new(AtomicBool::new(false));
        let notifier = Notifier::new(
            temp.path().to_path_buf(),
            false,
            std::sync::Arc::clone(&pause_flag),
        );
        let finding = test_finding(Severity::Critical);
        let should_pause = notifier.notify(&finding);
        assert!(should_pause);
        assert!(pause_flag.load(Ordering::Relaxed));
    }

    #[test]
    fn high_returns_false_for_pause() {
        let temp = tempfile::tempdir().unwrap();
        let pause_flag = std::sync::Arc::new(AtomicBool::new(false));
        let notifier = Notifier::new(temp.path().to_path_buf(), false, pause_flag);
        let finding = test_finding(Severity::High);
        let should_pause = notifier.notify(&finding);
        assert!(!should_pause);
    }
}
