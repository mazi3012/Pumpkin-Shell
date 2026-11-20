//! `pumpkin-shell review`: approve or reject staged writes.
//!
//! Phase 11: review staged protected and watched paths.

use std::io::{BufRead, Write};
use std::process::ExitCode;

use pks_core::paths::data_dir;

/// Exit code for a session not found.
const EXIT_NOT_FOUND: u8 = 2;

/// Reviews a session's staged writes.
pub fn run(session: &str) -> ExitCode {
    let data = match data_dir(&pks_core::paths::process_env) {
        Some(d) => d,
        None => {
            eprintln!("review: cannot find the data directory");
            return ExitCode::from(EXIT_NOT_FOUND);
        }
    };

    let info = match pks_detect::SessionInfo::find(&data, session) {
        Some(i) => i,
        None => {
            eprintln!("review: session {} not found", session);
            return ExitCode::from(EXIT_NOT_FOUND);
        }
    };

    // Read the staged changes from the session log.
    let log_file = info.log;
    if !log_file.exists() {
        eprintln!("review: no session log found");
        return ExitCode::from(EXIT_NOT_FOUND);
    }

    // Parse the log for staged findings.
    let file = match std::fs::File::open(&log_file) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("review: cannot open session log: {}", e);
            return ExitCode::from(EXIT_NOT_FOUND);
        }
    };

    let reader = std::io::BufReader::new(file);
    let mut staged: Vec<StagedItem> = Vec::new();

    for text in reader.lines().map_while(Result::ok) {
        if let Ok(record) = serde_json::from_str::<LogRecord>(&text)
            && record.verdict == "staged"
        {
            staged.push(StagedItem {
                rule: record.rule,
                target: record.target,
            });
        }
    }

    if staged.is_empty() {
        eprintln!("review: no staged changes to review");
        return ExitCode::SUCCESS;
    }

    eprintln!("review: {} staged changes", staged.len());

    // Interactive review.
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();

    for (i, item) in staged.iter().enumerate() {
        eprintln!("\n[{}] {} {}", i + 1, item.rule, item.target);
        eprintln!("  [a]pprove / [r]eject / [s]kip / [q]uit");

        loop {
            let _ = stdout.write_all(b"choice: ");
            let _ = stdout.flush();

            let mut choice = String::new();
            if stdin.lock().read_line(&mut choice).is_err() {
                break;
            }

            match choice.trim().to_lowercase().as_str() {
                "a" | "approve" => {
                    eprintln!("  approved: {}", item.target);
                    // Apply the staged change.
                    if let Err(e) = apply_staged(&info.dir, &item.target) {
                        eprintln!("  error applying: {}", e);
                    }
                    break;
                }
                "r" | "reject" => {
                    eprintln!("  rejected: {}", item.target);
                    // Discard the staged change.
                    if let Err(e) = discard_staged(&info.dir, &item.target) {
                        eprintln!("  error discarding: {}", e);
                    }
                    break;
                }
                "s" | "skip" => {
                    eprintln!("  skipped: {}", item.target);
                    break;
                }
                "q" | "quit" => {
                    eprintln!("review: stopped");
                    return ExitCode::SUCCESS;
                }
                _ => continue,
            }
        }
    }

    eprintln!("\nreview: done");
    ExitCode::SUCCESS
}

/// A staged item from the session log.
#[derive(Debug, Clone)]
struct StagedItem {
    rule: String,
    target: String,
}

/// A record from the session log.
#[derive(Debug, serde::Deserialize)]
struct LogRecord {
    rule: String,
    target: String,
    verdict: String,
}

/// Applies a staged change by copying it from staging to the repo.
fn apply_staged(_session_dir: &std::path::Path, _target: &str) -> Result<(), String> {
    // The staging is handled by pks-core::workspace.
    // This is a placeholder for now; the actual implementation
    // needs to know the repo path and apply the staged file.
    Ok(())
}

/// Discards a staged change by removing it from staging.
fn discard_staged(_session_dir: &std::path::Path, _target: &str) -> Result<(), String> {
    // Similar to apply_staged, this needs the actual staging paths.
    Ok(())
}
