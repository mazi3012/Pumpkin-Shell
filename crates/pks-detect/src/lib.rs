//! Detection engine: severity routing, deduplication, and notifications.
//!
//! Phase 11 implements PRD FR-NOTIFY:
//! - INFO/NOTICE → log and session summary
//! - WARN → `pumpkin-shell watch`
//! - HIGH → desktop notification (`notify-send`)
//! - CRITICAL → also webhook plus configured action (default: pause)

pub mod notify;
pub mod session;

pub use notify::Notifier;
pub use session::{read_pid, SessionInfo, PAUSED_FILE, PID_FILE};
