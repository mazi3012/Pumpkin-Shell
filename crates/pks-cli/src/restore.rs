//! `pumpkin-shell restore <session>`: writes the snapshot taken before a
//! session into a new directory (PRD FR-WS, PHASES 10.4). It never writes
//! into the repo itself.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use pks_core::paths::{self, process_env};
use pks_core::snapshot::{self, SNAPSHOT_DIR};

/// Exit code for a restore that could not be done.
const EXIT_FAILED: u8 = 2;

/// Restores the snapshot of `session` into `into`, or into
/// `<data>/restores/<session>` when `into` is not given.
pub fn run(session: &str, into: Option<&Path>) -> ExitCode {
    if !snapshot::is_session_id(session) {
        eprintln!("restore: {session} is not a session id (32 lowercase hex digits)");
        return ExitCode::from(EXIT_FAILED);
    }
    let Some(data) = paths::data_dir(&process_env) else {
        eprintln!("restore: cannot find the data directory");
        return ExitCode::from(EXIT_FAILED);
    };
    let session_dir = data.join("sessions").join(session);
    if !session_dir.join(SNAPSHOT_DIR).is_dir() {
        eprintln!("restore: no snapshot for session {session}");
        return ExitCode::from(EXIT_FAILED);
    }
    let target: PathBuf = match into {
        Some(path) => path.to_path_buf(),
        None => data.join("restores").join(session),
    };
    match snapshot::restore_into(&session_dir, &target) {
        Ok(()) => {
            println!("restored session {session} to {}", target.display());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("restore: {error}");
            ExitCode::from(EXIT_FAILED)
        }
    }
}
