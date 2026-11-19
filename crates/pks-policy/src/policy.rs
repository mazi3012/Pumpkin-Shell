//! Policy schema and validation
//!
//! Policy is stored in TOML format with the following structure:
//!
//! ```toml
//! version = "1"
//!
//! [rules]
//! "NET-DIRECT-CONNECT" = { severity = "HIGH", action = "block" }
//! "EXEC-DESTRUCTIVE" = { severity = "CRITICAL", action = "block" }
//! ```
//!
//! Policy merging rules:
//! - New policy can only tighten rules (increase severity, change allow to block)
//! - Loosening attempts raise POL-UNTRUSTED and are ignored

use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use thiserror::Error;

/// Policy severity levels in increasing order of severity
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum PolicySeverity {
    Info,
    Notice,
    Warn,
    High,
    Critical,
}

/// A single policy rule
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyRule {
    pub severity: PolicySeverity,
    pub action: PolicyAction,
}

/// Policy action to take when a rule is triggered
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PolicyAction {
    Block,
    Allow,
    Warn,
    Notify,
}

/// Main policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub version: String,
    pub rules: HashMap<String, PolicyRule>,
}

impl Policy {
    /// Load policy from a TOML file
    pub fn load(path: &Path) -> Result<Self, PolicyError> {
        let content =
            fs::read_to_string(path).map_err(|e| PolicyError::ReadFailed(path.to_path_buf(), e))?;
        let policy: Policy = toml::from_str(&content)
            .map_err(|e| PolicyError::ParseFailed(path.to_path_buf(), e))?;
        Ok(policy)
    }

    /// Save policy to a TOML file
    pub fn save(&self, path: &Path) -> Result<(), PolicyError> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| PolicyError::SerializeFailed(path.to_path_buf(), e))?;
        fs::write(path, content).map_err(|e| PolicyError::WriteFailed(path.to_path_buf(), e))?;
        Ok(())
    }

    /// Merge a new policy, only allowing tightening
    /// Returns (merged_policy, any_changes, violations: Vec<PolicyRuleViolation>)
    pub fn merge_tighten(&self, new_policy: &Policy) -> PolicyMergeResult {
        let mut merged = self.clone();
        let mut violations = Vec::new();
        let mut changed = false;

        for (rule_name, new_rule) in &new_policy.rules {
            if let Some(existing_rule) = self.rules.get(rule_name) {
                // Check if the new policy tightens the rule
                if !is_tightening(existing_rule, new_rule) {
                    violations.push(PolicyRuleViolation {
                        rule_name: rule_name.clone(),
                        existing: existing_rule.clone(),
                        proposed: new_rule.clone(),
                        violation_type: PolicyViolationType::Loosening,
                    });
                    // Keep the existing rule
                    merged
                        .rules
                        .insert(rule_name.clone(), existing_rule.clone());
                } else {
                    if existing_rule != new_rule {
                        changed = true;
                    }
                    merged.rules.insert(rule_name.clone(), new_rule.clone());
                }
            } else {
                // New rule - always allowed
                merged.rules.insert(rule_name.clone(), new_rule.clone());
                changed = true;
            }
        }

        // Check for any removed rules (could be loosening if they were restrictive)
        for (rule_name, existing_rule) in &self.rules {
            if !new_policy.rules.contains_key(rule_name) {
                // A removed rule might weaken security - flag it
                violations.push(PolicyRuleViolation {
                    rule_name: rule_name.clone(),
                    existing: existing_rule.clone(),
                    proposed: PolicyRule {
                        severity: PolicySeverity::Info,
                        action: PolicyAction::Allow,
                    },
                    violation_type: PolicyViolationType::Removal,
                });
                // Keep the existing rule
                merged
                    .rules
                    .insert(rule_name.clone(), existing_rule.clone());
                changed = true;
            }
        }

        PolicyMergeResult {
            policy: merged,
            changed,
            violations,
        }
    }

    /// Calculate a hash of the policy for signing
    pub fn hash(&self) -> Vec<u8> {
        let content = toml::to_string(self).expect("Failed to serialize policy");
        let mut hasher = sha2::Sha256::new();
        hasher.update(content.as_bytes());
        hasher.finalize().to_vec()
    }
}

/// Check if a new rule tightens an existing rule
fn is_tightening(existing: &PolicyRule, new: &PolicyRule) -> bool {
    // Tightening: higher severity OR block instead of allow/warn/notify
    if new.severity > existing.severity {
        return true;
    }
    matches!(
        (&existing.action, &new.action),
        (PolicyAction::Allow, PolicyAction::Block)
            | (PolicyAction::Allow, PolicyAction::Warn)
            | (PolicyAction::Allow, PolicyAction::Notify)
            | (PolicyAction::Warn, PolicyAction::Block)
            | (PolicyAction::Notify, PolicyAction::Block)
    )
}

/// Result of a policy merge operation
pub struct PolicyMergeResult {
    pub policy: Policy,
    pub changed: bool,
    pub violations: Vec<PolicyRuleViolation>,
}

/// A violation found during policy merge
pub struct PolicyRuleViolation {
    pub rule_name: String,
    pub existing: PolicyRule,
    pub proposed: PolicyRule,
    pub violation_type: PolicyViolationType,
}

/// Type of policy violation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PolicyViolationType {
    Loosening,
    Removal,
}

/// Error types for policy operations
#[derive(Error, Debug)]
pub enum PolicyError {
    #[error("Failed to read policy file '{0}': {1}")]
    ReadFailed(std::path::PathBuf, std::io::Error),

    #[error("Failed to parse policy file '{0}': {1}")]
    ParseFailed(std::path::PathBuf, toml::de::Error),

    #[error("Failed to serialize policy to '{0}': {1}")]
    SerializeFailed(std::path::PathBuf, toml::ser::Error),

    #[error("Failed to write policy file '{0}': {1}")]
    WriteFailed(std::path::PathBuf, std::io::Error),

    #[error("POL-UNTRUSTED: Policy merge would loosen rules: {0}")]
    LooseningAttempt(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_policy_load_save() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("policy.toml");

        let policy = Policy {
            version: "1".to_string(),
            rules: HashMap::from([(
                "NET-DIRECT-CONNECT".to_string(),
                PolicyRule {
                    severity: PolicySeverity::High,
                    action: PolicyAction::Block,
                },
            )]),
        };

        policy.save(&path).unwrap();
        let loaded = Policy::load(&path).unwrap();

        assert_eq!(loaded.version, policy.version);
        assert_eq!(loaded.rules.len(), policy.rules.len());
    }

    #[test]
    fn test_policy_merge_tighten() {
        let existing = Policy {
            version: "1".to_string(),
            rules: HashMap::from([(
                "NET-DIRECT-CONNECT".to_string(),
                PolicyRule {
                    severity: PolicySeverity::Warn,
                    action: PolicyAction::Warn,
                },
            )]),
        };

        let new = Policy {
            version: "1".to_string(),
            rules: HashMap::from([(
                "NET-DIRECT-CONNECT".to_string(),
                PolicyRule {
                    severity: PolicySeverity::High,
                    action: PolicyAction::Block,
                },
            )]),
        };

        let result = existing.merge_tighten(&new);
        assert!(result.changed);
        assert!(result.violations.is_empty());
        assert_eq!(
            result.policy.rules["NET-DIRECT-CONNECT"].severity,
            PolicySeverity::High
        );
        assert_eq!(
            result.policy.rules["NET-DIRECT-CONNECT"].action,
            PolicyAction::Block
        );
    }

    #[test]
    fn test_policy_merge_loosening() {
        let existing = Policy {
            version: "1".to_string(),
            rules: HashMap::from([(
                "NET-DIRECT-CONNECT".to_string(),
                PolicyRule {
                    severity: PolicySeverity::High,
                    action: PolicyAction::Block,
                },
            )]),
        };

        let new = Policy {
            version: "1".to_string(),
            rules: HashMap::from([(
                "NET-DIRECT-CONNECT".to_string(),
                PolicyRule {
                    severity: PolicySeverity::Warn,
                    action: PolicyAction::Warn,
                },
            )]),
        };

        let result = existing.merge_tighten(&new);
        // When we keep existing rule without change, changed is false
        assert!(!result.changed);
        assert_eq!(result.violations.len(), 1);
        assert_eq!(
            result.violations[0].violation_type,
            PolicyViolationType::Loosening
        );
        assert_eq!(
            result.policy.rules["NET-DIRECT-CONNECT"].severity,
            PolicySeverity::High
        );
        assert_eq!(
            result.policy.rules["NET-DIRECT-CONNECT"].action,
            PolicyAction::Block
        );
    }

    #[test]
    fn test_policy_new_rule() {
        let existing = Policy {
            version: "1".to_string(),
            rules: HashMap::new(),
        };

        let new = Policy {
            version: "1".to_string(),
            rules: HashMap::from([(
                "NEW-RULE".to_string(),
                PolicyRule {
                    severity: PolicySeverity::High,
                    action: PolicyAction::Block,
                },
            )]),
        };

        let result = existing.merge_tighten(&new);
        assert!(result.changed);
        assert!(result.violations.is_empty());
        assert!(result.policy.rules.contains_key("NEW-RULE"));
    }
}
