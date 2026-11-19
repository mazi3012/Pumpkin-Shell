//! Types shared by every pumpkin-shell check: rule IDs, severity and findings.
//!
//! Rules are data. `doctor`, `scan`, the watcher and the proxy all report
//! problems with these types (PRD FR-DET, Phase 3 step 3.0).

use serde::Serialize;

/// Stable identifier of a detection rule, such as `SYS-IDE-TAMPERABLE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
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

/// How serious a finding is. Only the levels used by the code so far are
/// defined; further levels are added in the phase that first needs them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    /// Serious problem that needs a fix before the sandbox can be trusted.
    High,
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
