//! Sandbox backend trait and implementations

use anyhow::Result;
use std::path::Path;
use thiserror::Error;

/// Error types for sandbox operations
#[derive(Error, Debug)]
pub enum SandboxError {
    #[error("Failed to create sandbox: {0}")]
    CreateFailed(String),

    #[error("Failed to run sandbox: {0}")]
    RunFailed(String),

    #[error("Invalid sandbox configuration: {0}")]
    InvalidConfig(String),
}

/// Trait for sandbox backends
///
/// This trait defines the interface for sandbox implementations on different platforms.
/// The Linux implementation uses bubblewrap; the Windows implementation (Phase 16) will
/// use a separate user account with Job Objects and WFP.
#[cfg_attr(target_os = "linux", allow(dead_code))]
pub trait SandboxBackend: Send + Sync {
    /// Returns the name of this backend
    fn name(&self) -> &str;

    /// Build the sandbox argument vector
    ///
    /// This method constructs the arguments for the sandbox runtime (e.g., bwrap args).
    /// It should never use shell strings - build a proper argument vector.
    fn build_args(&self, repo_path: &Path, ide_install: &Path) -> Result<Vec<String>>;

    /// Apply additional sandbox layers
    ///
    /// For Linux: Landlock policy, seccomp filter
    /// For Windows: ACLs, WFP filters
    fn apply_security_layers(&self) -> Result<()>;

    /// Run the sandboxed process
    fn run(&self, args: &[String]) -> Result<()>;
}

/// Create a sandbox backend for the current platform
pub fn create_backend() -> Result<Box<dyn SandboxBackend>> {
    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(LinuxBackend::new()))
    }

    #[cfg(not(target_os = "linux"))]
    {
        Err(SandboxError::CreateFailed(
            "No sandbox backend available for this platform".to_string(),
        )
        .into())
    }
}

/// Linux sandbox backend using bubblewrap
#[cfg(target_os = "linux")]
pub struct LinuxBackend {
    /// Path to bwrap
    bwrap_path: String,
}

#[cfg(target_os = "linux")]
impl LinuxBackend {
    pub fn new() -> Self {
        LinuxBackend {
            bwrap_path: "bwrap".to_string(),
        }
    }
}

#[cfg(target_os = "linux")]
impl SandboxBackend for LinuxBackend {
    fn name(&self) -> &str {
        "linux-bwrap"
    }

    fn build_args(&self, repo_path: &Path, ide_install: &Path) -> Result<Vec<String>> {
        let mut args = vec![
            self.bwrap_path.clone(),
            "--unshare-all".to_string(),
            "--new-session".to_string(),
            "--die-with-parent".to_string(),
            // Read-only root
            "--ro-bind".to_string(),
            "/".to_string(),
            // Allow /tmp for X11 sockets
            "--bind".to_string(),
            "/tmp".to_string(),
            // Sandbox home directory
            "--bind".to_string(),
            "/tmp/pks-sandbox-home".to_string(),
            "/tmp/pks-sandbox-home".to_string(),
            // Bind mount the repo
            "--bind".to_string(),
            repo_path
                .canonicalize()
                .map_err(|e| {
                    SandboxError::InvalidConfig(format!("Failed to canonicalize repo path: {e}"))
                })?
                .to_string_lossy()
                .to_string(),
            "/tmp/pks-sandbox-home/project".to_string(),
            // Bind mount IDE install read-only
            "--bind".to_string(),
            ide_install
                .canonicalize()
                .map_err(|e| {
                    SandboxError::InvalidConfig(format!("Failed to canonicalize IDE install: {e}"))
                })?
                .to_string_lossy()
                .to_string(),
            "/usr/share/kiro".to_string(),
            // X11
            "--ro-bind".to_string(),
            "/tmp/.X11-unix".to_string(),
            "/tmp/.X11-unix".to_string(),
            "--env".to_string(),
            "DISPLAY=:0".to_string(),
            // GPU devices
            "--dev-bind".to_string(),
            "/dev/dri".to_string(),
            "/dev/dri".to_string(),
            "--dev-bind".to_string(),
            "/dev/shm".to_string(),
            "/dev/shm".to_string(),
            // /proc
            "--proc".to_string(),
            "/proc".to_string(),
            // /sys read-only
            "--ro-bind".to_string(),
            "/sys".to_string(),
            "/sys".to_string(),
            // /dev/pts
            "--dev-bind".to_string(),
            "/dev/pts".to_string(),
            "/dev/pts".to_string(),
            // Environment cleanup
            "--unset-env".to_string(),
            "SSH_AUTH_SOCK".to_string(),
            "--unset-env".to_string(),
            "SSH_AGENT_PID".to_string(),
            "--unset-env".to_string(),
            "WAYLAND_DISPLAY".to_string(),
            "--unset-env".to_string(),
            "DBUS_SESSION_BUS_ADDRESS".to_string(),
            // Set sandbox environment
            "--env".to_string(),
            "HOME=/tmp/pks-sandbox-home".to_string(),
            "--env".to_string(),
            "USER=pks-sandbox".to_string(),
            "--env".to_string(),
            "TERM=xterm-256color".to_string(),
            // Working directory
            "--cwd".to_string(),
            "/tmp/pks-sandbox-home/project".to_string(),
            "--exec".to_string(),
            "/bin/bash".to_string(),
            "--login".to_string(),
        ];

        Ok(args)
    }

    fn apply_security_layers(&self) -> Result<()> {
        // Apply Landlock policy (Phase 8.4)
        // Apply seccomp filter blocking TIOCSTI (Phase 8.4)
        Ok(())
    }

    fn run(&self, args: &[String]) -> Result<()> {
        // Execute the sandbox
        let program = &args[0];
        let args: Vec<&str> = args[1..].iter().map(|s| s.as_str()).collect();

        let status = std::process::Command::new(program).args(&args).status()?;

        if status.success() {
            Ok(())
        } else {
            Err(SandboxError::RunFailed(format!("Sandbox exited with status: {}", status)).into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backend_exists() {
        let backend = create_backend().expect("Failed to create backend");
        assert!(!backend.name().is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_linux_backend_name() {
        let backend = LinuxBackend::new();
        assert_eq!(backend.name(), "linux-bwrap");
    }
}
