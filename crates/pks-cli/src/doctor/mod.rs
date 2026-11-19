//! `pumpkin-shell doctor`: tells the user whether this machine can run the
//! sandbox, and how to fix each problem (PRD FR-CLI, Phase 3).

#[cfg(target_os = "linux")]
mod checks;
#[cfg(target_os = "linux")]
mod probe;

use std::process::ExitCode;

#[cfg(target_os = "linux")]
use checks::{Check, Status};

/// Kiro install directory checked for tamperable files (PRD §1, row 12).
#[cfg(target_os = "linux")]
const KIRO_INSTALL: &str = "/usr/share/kiro";

/// Runs every check, prints the report, and returns failure when any check fails.
#[cfg(target_os = "linux")]
pub fn run(json: bool) -> ExitCode {
    let checks = collect();
    if json {
        match serde_json::to_string_pretty(&checks) {
            Ok(text) => println!("{text}"),
            Err(error) => {
                eprintln!("doctor: could not encode the report as JSON: {error}");
                return ExitCode::from(2);
            }
        }
    } else {
        print_human(&checks);
    }
    if checks.iter().any(|check| check.status == Status::Fail) {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// `doctor` checks are Linux-only in Phase 3. Windows checks come in Phase 16.
#[cfg(not(target_os = "linux"))]
pub fn run(_json: bool) -> ExitCode {
    eprintln!("doctor: only Linux checks exist yet (Windows checks come in Phase 16).");
    ExitCode::from(2)
}

#[cfg(target_os = "linux")]
fn collect() -> Vec<Check> {
    let (wayland, x11) = probe::display_session();
    let kiro = match probe::scan_ide_install(std::path::Path::new(KIRO_INSTALL)) {
        Ok(scan) => checks::ide_check(KIRO_INSTALL, scan),
        Err(error) => Check {
            name: "IDE install permissions",
            status: Status::Warn,
            detail: format!("could not scan {KIRO_INSTALL}: {error}"),
            fix: Some("Run doctor with read access to the IDE install.".to_owned()),
            finding: None,
        },
    };
    vec![
        checks::kernel_check(&probe::kernel_release().unwrap_or_default()),
        checks::bwrap_check(probe::bwrap_version().as_deref()),
        checks::userns_check(probe::bwrap_userns_ok(), probe::apparmor_restrict_userns()),
        checks::landlock_check(probe::landlock_abi()),
        checks::seccomp_check(probe::seccomp_notify_supported()),
        checks::display_check(wayland, x11),
        kiro,
    ]
}

#[cfg(target_os = "linux")]
fn print_human(checks: &[Check]) {
    for check in checks {
        let label = match check.status {
            Status::Pass => "PASS",
            Status::Warn => "WARN",
            Status::Fail => "FAIL",
        };
        println!("[{label}] {}: {}", check.name, check.detail);
        if let Some(fix) = &check.fix {
            println!("       fix: {fix}");
        }
    }
}
