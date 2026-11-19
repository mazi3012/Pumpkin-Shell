//! IDE launch commands

use std::path::Path;
use std::process::ExitCode;

/// Run an IDE in the sandbox
pub fn run(ide: &str, repo_path: &str) -> ExitCode {
    // Get the IDE install path (for Kiro, this is /usr/share/kiro)
    let ide_install = Path::new("/usr/share/kiro");

    // Create backend
    let backend = match pks_sandbox::create_backend() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Failed to create sandbox backend: {}", e);
            return ExitCode::from(2);
        }
    };

    // Convert paths
    let repo = Path::new(repo_path);

    // Build sandbox arguments
    let args = match backend.build_args(repo, ide_install) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("Failed to build sandbox args: {}", e);
            return ExitCode::from(2);
        }
    };

    // Apply security layers
    if let Err(e) = backend.apply_security_layers() {
        eprintln!("Warning: Failed to apply security layers: {}", e);
    }

    // Run the sandbox
    if let Err(e) = backend.run(&args) {
        eprintln!("Failed to run sandbox: {}", e);
        return ExitCode::from(2);
    }

    ExitCode::SUCCESS
}
