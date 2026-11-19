//! Policy and signed log for Pumpkin-Shell
//!
//! This crate provides:
//! - Policy schema in TOML format
//! - Tamper-evident signed log
//! - Policy merging that only allows tightening (never loosening)

pub mod log;
pub mod policy;

pub use log::{LogChain, LogEntry, LogError};
pub use policy::{
    Policy, PolicyAction, PolicyError, PolicyMergeResult, PolicyRule, PolicyRuleViolation,
    PolicySeverity, PolicyViolationType,
};
