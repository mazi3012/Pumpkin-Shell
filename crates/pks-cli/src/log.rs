//! `pumpkin-shell log verify`: checks a session log's chain, signatures and
//! checkpoint.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use pks_core::keys;
use pks_core::log::{self, VerifyPathError};
use pks_core::paths::{self, process_env};

const EXIT_FAILED: u8 = 1;
const EXIT_ERROR: u8 = 2;

fn fail(message: &str) -> ExitCode {
    eprintln!("{message}");
    ExitCode::from(EXIT_ERROR)
}

/// Verifies `file`. Exit 0 when it is intact, 1 when verification fails, 2
/// when it could not be checked at all (missing file or key).
pub fn verify(file: &Path, allow_open: bool, key_dir: Option<&Path>) -> ExitCode {
    let key_dir: PathBuf = match key_dir {
        Some(dir) => dir.to_path_buf(),
        None => match paths::data_dir(&process_env) {
            Some(data) => data.join("keys"),
            None => return fail("cannot find your data directory (is HOME set?); pass --key-dir"),
        },
    };
    let key = match keys::load_verifying_key(&key_dir) {
        Ok(key) => key,
        Err(error) => return fail(&format!("verifying key: {error}")),
    };
    match log::verify_path(file, &key, allow_open) {
        Ok(verified) => {
            let session = verified.session.as_deref().unwrap_or("(none yet)");
            let end = if verified.closed {
                "checkpoint verified"
            } else {
                "no checkpoint: the session may still be running"
            };
            println!("OK: session {session}, {} entries, {end}", verified.entries);
            ExitCode::SUCCESS
        }
        Err(VerifyPathError::Invalid(problem)) => {
            println!("FAILED: {problem}");
            ExitCode::from(EXIT_FAILED)
        }
        Err(error) => fail(&format!("cannot verify: {error}")),
    }
}
