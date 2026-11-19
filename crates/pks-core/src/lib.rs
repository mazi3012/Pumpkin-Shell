//! Types shared by every pumpkin-shell check: rule IDs, severity and findings.
//!
//! Rules are data. `doctor`, `scan`, the watcher and the proxy all report
//! problems with these types (PRD FR-DET, Phase 3 step 3.0).

pub mod keys;
pub mod log;
pub mod paths;
pub mod policy;
pub mod trust;

mod fsutil;
mod hex;

use serde::Serialize;

/// Stable identifier of a detection rule, such as `SYS-IDE-TAMPERABLE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct RuleId(&'static str);

impl RuleId {
    /// Creates a rule ID from its published name.
    #[must_use]
    pub const fn new(id: &'static str) -> Self {
        Self(id)
    }

    /// Returns the published name of the rule.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

/// How serious a finding is, from least to most serious. Levels are added in
/// the phase that first uses them; `Info` has no user yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    /// Listed for the user's information. Does not need action.
    Notice,
    /// Worth a look.
    Warn,
    /// Serious problem that needs a fix before the sandbox can be trusted.
    High,
    /// Must be handled at once.
    Critical,
}

/// One problem found by a check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// Rule that produced the finding.
    pub rule: RuleId,
    /// How serious the finding is.
    pub severity: Severity,
    /// What the finding is about, such as a path.
    pub target: String,
    /// One-line description of the problem.
    pub message: String,
    /// One-line fix the user can apply.
    pub fix: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severities_order_from_notice_to_critical() {
        assert!(Severity::Notice < Severity::Warn);
        assert!(Severity::Warn < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn rule_id_round_trips() {
        assert_eq!(RuleId::new("WS-ADS").as_str(), "WS-ADS");
    }
}
