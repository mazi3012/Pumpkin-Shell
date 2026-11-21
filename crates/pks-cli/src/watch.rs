//! `pumpkin-shell watch`, `resume` and `kill`: follow and control a session.
//!
//! WARN and above are written to the session's watch file. A CRITICAL finding
//! pauses the sandbox until `resume` or `kill` (PRD FR-NOTIFY).

use std::process::ExitCode;

use pks_core::paths::data_dir;
use serde::Deserialize;

/// Exit code for a session that cannot be found or controlled.
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

/// Looks up a session and its running sandbox's process ID. Prints why and
/// returns `None` when either is missing.
#[cfg(target_os = "linux")]
fn find_running(command: &str, session: &str) -> Option<(pks_detect::SessionInfo, i32)> {
    let data = data_dir(&pks_core::paths::process_env).or_else(|| {
        eprintln!("{command}: cannot find the data directory");
        None
    })?;
    let Some(info) = pks_detect::SessionInfo::find(&data, session) else {
        eprintln!("{command}: session {session} not found");
        return None;
    };
    let Some(pid) = pks_detect::read_pid(&info.dir) else {
        eprintln!("{command}: session {session} is not running");
        return None;
    };
    Some((info, pid))
}

/// Resumes a paused session (Linux only): SIGCONT to its process group.
#[cfg(target_os = "linux")]
pub fn resume(session: &str) -> ExitCode {
    use pks_sandbox::linux::signal::{Signal, signal_tree};

    let Some((info, pid)) = find_running("resume", session) else {
        return ExitCode::from(EXIT_NOT_FOUND);
    };
    if !info.paused.exists() {
        eprintln!("resume: session {session} is not paused");
        return ExitCode::from(EXIT_NOT_FOUND);
    }
    if let Err(error) = signal_tree(pid, Signal::Continue) {
        eprintln!("resume: could not send SIGCONT: {error}");
        return ExitCode::from(EXIT_NOT_FOUND);
    }
    let _ = std::fs::remove_file(&info.paused);
    eprintln!("resume: session {session} resumed");
    ExitCode::SUCCESS
}

/// Resumes a paused session (non-Linux stub).
#[cfg(not(target_os = "linux"))]
pub fn resume(_session: &str) -> ExitCode {
    eprintln!("resume: Linux only");
    ExitCode::from(EXIT_NOT_FOUND)
}

/// Kills a running session (Linux only): SIGKILL to its process group. A
/// paused session is killed the same way.
#[cfg(target_os = "linux")]
pub fn kill(session: &str) -> ExitCode {
    use pks_sandbox::linux::signal::{Signal, signal_tree};

    let Some((info, pid)) = find_running("kill", session) else {
        return ExitCode::from(EXIT_NOT_FOUND);
    };
    if let Err(error) = signal_tree(pid, Signal::Kill) {
        eprintln!("kill: could not send SIGKILL: {error}");
        return ExitCode::from(EXIT_NOT_FOUND);
    }
    let _ = std::fs::remove_file(&info.paused);
    eprintln!("kill: session {session} killed");
    ExitCode::SUCCESS
}

/// Kills a running session (non-Linux stub).
#[cfg(not(target_os = "linux"))]
pub fn kill(_session: &str) -> ExitCode {
    eprintln!("kill: Linux only");
    ExitCode::from(EXIT_NOT_FOUND)
}
