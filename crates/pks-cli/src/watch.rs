//! `pumpkin-shell watch`: monitor a running session for findings.
//!
//! Phase 11: WARN and above are written to the watch file.

// Allow unsafe for libc::kill calls (SIGCONT, SIGKILL).
#![allow(unsafe_code)]

use std::process::ExitCode;

use pks_core::paths::data_dir;
use serde::Deserialize;

/// Exit code for a session not found.
const EXIT_NOT_FOUND: u8 = 2;

/// A finding entry in the watch file.
#[derive(Debug, Clone, Deserialize)]
struct WatchEntry {
    severity: pks_core::Severity,
    rule: String,
    target: String,
    message: String,
    fix: String,
}

/// Watches a session for findings.
pub fn run(session: Option<&str>) -> ExitCode {
    let session = match session {
        Some(s) => s.to_string(),
        None => {
            // Find the most recent session.
            let data = match data_dir(&pks_core::paths::process_env) {
                Some(d) => d,
                None => {
                    eprintln!("watch: cannot find the data directory");
                    return ExitCode::from(EXIT_NOT_FOUND);
                }
            };
            let sessions = pks_detect::SessionInfo::list(&data);
            match sessions.first() {
                Some(s) => s.id.clone(),
                None => {
                    eprintln!("watch: no sessions found");
                    return ExitCode::from(EXIT_NOT_FOUND);
                }
            }
        }
    };

    let data = match data_dir(&pks_core::paths::process_env) {
        Some(d) => d,
        None => {
            eprintln!("watch: cannot find the data directory");
            return ExitCode::from(EXIT_NOT_FOUND);
        }
    };

    let info = match pks_detect::SessionInfo::find(&data, &session) {
        Some(i) => i,
        None => {
            eprintln!("watch: session {} not found", session);
            return ExitCode::from(EXIT_NOT_FOUND);
        }
    };

    eprintln!("watch: watching session {}", session);

    // Tail the watch file.
    let watch_file = info.watch;
    if !watch_file.exists() {
        // Create an empty watch file.
        if let Err(e) = std::fs::File::create(&watch_file) {
            eprintln!("watch: cannot create watch file: {}", e);
            return ExitCode::from(EXIT_NOT_FOUND);
        }
    }

    // Use std::io::BufReader to read lines as they appear.
    use std::io::{BufRead, BufReader};
    let file = match std::fs::File::open(&watch_file) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("watch: cannot open watch file: {}", e);
            return ExitCode::from(EXIT_NOT_FOUND);
        }
    };

    let reader = BufReader::new(file);
    for line in reader.lines() {
        match line {
            Ok(text) => {
                if let Ok(entry) = serde_json::from_str::<WatchEntry>(&text) {
                    println!(
                        "[{:?}] {} {}: {}",
                        entry.severity, entry.rule, entry.target, entry.message
                    );
                    println!("  fix: {}", entry.fix);
                } else {
                    println!("{}", text);
                }
            }
            Err(e) => {
                eprintln!("watch: error reading: {}", e);
                break;
            }
        }
    }

    ExitCode::SUCCESS
}

/// Resumes a paused session (Linux only).
#[cfg(target_os = "linux")]
pub fn resume(session: &str) -> ExitCode {
    let data = match data_dir(&pks_core::paths::process_env) {
        Some(d) => d,
        None => {
            eprintln!("resume: cannot find the data directory");
            return ExitCode::from(EXIT_NOT_FOUND);
        }
    };

    let info = match pks_detect::SessionInfo::find(&data, session) {
        Some(i) => i,
        None => {
            eprintln!("resume: session {} not found", session);
            return ExitCode::from(EXIT_NOT_FOUND);
        }
    };

    // Send SIGCONT to the paused IDE process.
    // The pause file contains the PID.
    let pause_file = info.dir.join("pause.pid");
    let pid: i32 = match std::fs::read_to_string(&pause_file) {
        Ok(content) => content.trim().parse().unwrap_or(0),
        Err(_) => {
            eprintln!("resume: no paused session found");
            return ExitCode::from(EXIT_NOT_FOUND);
        }
    };

    if pid <= 0 {
        eprintln!("resume: invalid PID");
        return ExitCode::from(EXIT_NOT_FOUND);
    }

    // Send SIGCONT.
    let result = unsafe { libc::kill(pid, libc::SIGCONT) };
    if result < 0 {
        eprintln!(
            "resume: could not send SIGCONT: {}",
            std::io::Error::last_os_error()
        );
        return ExitCode::from(EXIT_NOT_FOUND);
    }

    // Remove the pause file.
    let _ = std::fs::remove_file(&pause_file);

    eprintln!("resume: session {} resumed", session);
    ExitCode::SUCCESS
}

/// Resumes a paused session (non-Linux stub).
#[cfg(not(target_os = "linux"))]
pub fn resume(_session: &str) -> ExitCode {
    eprintln!("resume: Linux only");
    ExitCode::from(EXIT_NOT_FOUND)
}

/// Kills a running session (Linux only).
#[cfg(target_os = "linux")]
pub fn kill(session: &str) -> ExitCode {
    let data = match data_dir(&pks_core::paths::process_env) {
        Some(d) => d,
        None => {
            eprintln!("kill: cannot find the data directory");
            return ExitCode::from(EXIT_NOT_FOUND);
        }
    };

    let info = match pks_detect::SessionInfo::find(&data, session) {
        Some(i) => i,
        None => {
            eprintln!("kill: session {} not found", session);
            return ExitCode::from(EXIT_NOT_FOUND);
        }
    };

    // The pause file contains the PID.
    let pause_file = info.dir.join("pause.pid");
    let pid: i32 = match std::fs::read_to_string(&pause_file) {
        Ok(content) => content.trim().parse().unwrap_or(0),
        Err(_) => {
            eprintln!("kill: no session found");
            return ExitCode::from(EXIT_NOT_FOUND);
        }
    };

    if pid <= 0 {
        eprintln!("kill: invalid PID");
        return ExitCode::from(EXIT_NOT_FOUND);
    }

    // Send SIGKILL.
    let result = unsafe { libc::kill(pid, libc::SIGKILL) };
    if result < 0 {
        eprintln!(
            "kill: could not send SIGKILL: {}",
            std::io::Error::last_os_error()
        );
        return ExitCode::from(EXIT_NOT_FOUND);
    }

    // Remove the pause file.
    let _ = std::fs::remove_file(&pause_file);

    eprintln!("kill: session {} killed", session);
    ExitCode::SUCCESS
}

/// Kills a running session (non-Linux stub).
#[cfg(not(target_os = "linux"))]
pub fn kill(_session: &str) -> ExitCode {
    eprintln!("kill: Linux only");
    ExitCode::from(EXIT_NOT_FOUND)
}
