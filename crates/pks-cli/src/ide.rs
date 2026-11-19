//! `pumpkin-shell ide <kiro|code> [PATH]`: opens a repository in an IDE that
//! runs inside the sandbox (PRD §6.1, Phase 8).

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::ValueEnum;

/// The IDEs this build can launch. Only installs under `/usr` are accepted.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Ide {
    Kiro,
    Code,
}

/// Exit code for a run that could not start.
const EXIT_SETUP: u8 = 2;

#[cfg(target_os = "linux")]
fn install(ide: Ide) -> pks_sandbox::IdeInstall {
    let (name, dir, program) = match ide {
        Ide::Kiro => ("kiro", "/usr/share/kiro", "kiro"),
        Ide::Code => ("code", "/usr/share/code", "code"),
    };
    pks_sandbox::IdeInstall {
        name,
        dir: PathBuf::from(dir),
        binary: PathBuf::from(dir).join(program),
    }
}

/// Runs the IDE on `repo`. Returns the IDE's exit code, or 2 when the sandbox
/// could not start (the IDE is not started in that case).
#[cfg(target_os = "linux")]
pub fn run(ide: Ide, repo: &Path) -> ExitCode {
    use pks_core::paths::{self, process_env};
    use pks_sandbox::linux::LinuxBackend;
    use pks_sandbox::{LaunchSpec, Roots, SandboxBackend};
    use std::os::unix::process::ExitStatusExt;

    let setup = |message: String| {
        eprintln!("ide: {message}");
        ExitCode::from(EXIT_SETUP)
    };
    let Some(home) = process_env("HOME").map(PathBuf::from) else {
        return setup("HOME is not set".to_owned());
    };
    let (Some(config), Some(data)) = (
        paths::config_dir(&process_env),
        paths::data_dir(&process_env),
    ) else {
        return setup("cannot find the config and data directories".to_owned());
    };
    // Check the repo before creating anything on disk, so a typo leaves no
    // directories behind. The full checks run in the sandbox crate.
    if !repo.is_dir() {
        return setup(format!("{} is not a directory", repo.display()));
    }
    let spec_install = install(ide);
    let ide_home = data.join("ide-home").join(spec_install.name);
    if let Err(error) = create_private_dir(&ide_home) {
        return setup(format!("cannot create {}: {error}", ide_home.display()));
    }
    let spec = LaunchSpec {
        repo: repo.to_path_buf(),
        ide: spec_install,
        ide_home,
        // Platform flags: X11 (the nested display) and no keyring (there is no
        // D-Bus in the sandbox). The repo is opened at its sandbox path.
        ide_args: vec![
            "--ozone-platform=x11".into(),
            "--password-store=basic".into(),
            pks_sandbox::linux::bwrap::WORKSPACE.into(),
        ],
        roots: Roots { home, config, data },
        display_size: (1280, 800),
    };
    let init_exe = match std::env::current_exe() {
        Ok(path) => path,
        Err(error) => return setup(format!("cannot find this program: {error}")),
    };
    let backend = match LinuxBackend::locate(init_exe) {
        Ok(backend) => backend,
        Err(error) => return setup(error.to_string()),
    };
    eprintln!(
        "ide: starting {} on {} ({})",
        ide_name(ide),
        repo.display(),
        backend.name()
    );
    match backend.run(&spec) {
        Ok(status) => match status.code() {
            Some(code) => ExitCode::from(u8::try_from(code.clamp(0, 255)).unwrap_or(1)),
            None => {
                // Killed by a signal: report 128 + signal, as shells do.
                let signal = status.signal().unwrap_or(0);
                ExitCode::from(u8::try_from(128 + signal).unwrap_or(1))
            }
        },
        Err(error) => setup(error.to_string()),
    }
}

#[cfg(target_os = "linux")]
fn ide_name(ide: Ide) -> &'static str {
    match ide {
        Ide::Kiro => "Kiro",
        Ide::Code => "VS Code",
    }
}

/// Creates `dir` and missing parents, each with mode 0700.
#[cfg(target_os = "linux")]
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

/// The sandbox is Linux-only until Phase 16.
#[cfg(not(target_os = "linux"))]
pub fn run(_ide: Ide, _repo: &Path) -> ExitCode {
    eprintln!("ide: the sandbox is Linux-only until Phase 16 (Windows).");
    ExitCode::from(EXIT_SETUP)
}

/// The in-sandbox step: applies Landlock and the seccomp filter, then runs
/// `command`. Called by bubblewrap, not by users.
#[cfg(target_os = "linux")]
pub fn sandbox_init(rw: &[PathBuf], ro: &[PathBuf], command: &[std::ffi::OsString]) -> ExitCode {
    let error = pks_sandbox::linux::init::run(rw, ro, command);
    eprintln!("sandbox-init: {error}");
    ExitCode::from(126)
}

#[cfg(not(target_os = "linux"))]
pub fn sandbox_init(_rw: &[PathBuf], _ro: &[PathBuf], _command: &[std::ffi::OsString]) -> ExitCode {
    eprintln!("sandbox-init: Linux only");
    ExitCode::from(126)
}
