//! Sandbox backends (PRD §6). The Linux backend runs an IDE in bubblewrap on a
//! nested Xephyr display. The Windows backend comes in Phase 16.
//!
//! Everything in this crate is written so that the IDE gets only what the
//! PRD allows: no host credentials, no unfiltered network, no host display,
//! and writes only where the sandbox says so. The sandbox boundary is the
//! mount namespace and Landlock; command and argument matching is never used
//! to decide what the IDE may do (PRD §4, principle 1).

pub mod spec;

#[cfg(target_os = "linux")]
pub mod linux;

pub use spec::{IdeInstall, LaunchSpec, Roots};

use std::process::ExitStatus;

/// Why a sandbox could not be used. Messages never contain secrets.
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    /// The request was refused before anything started.
    #[error("refused: {0}")]
    Refused(String),
    /// A helper program that the sandbox needs is missing or unusable.
    #[error("{tool} is needed but could not be run: {detail}")]
    Tool { tool: &'static str, detail: String },
    /// Something in the sandbox could not be set up, so the IDE did not start.
    #[error("sandbox setup failed: {0}")]
    Setup(String),
    /// The operating system returned an error.
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },
}

/// A way of running an IDE behind a sandbox.
pub trait SandboxBackend {
    /// Name shown in messages and logs.
    fn name(&self) -> &'static str;

    /// Runs the IDE described by `spec` and waits for it to exit.
    ///
    /// # Errors
    /// Fails before starting anything when the spec is refused, and fails when
    /// the sandbox cannot be set up. The IDE's own exit status is returned as
    /// `Ok`, even when it is an error.
    fn run(&self, spec: &LaunchSpec) -> Result<ExitStatus, SandboxError>;
}
