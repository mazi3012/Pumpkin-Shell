//! Writes a signed sample session log, to try `pumpkin-shell log verify`.
//!
//! ```text
//! cargo run -p pks-core --example sample_log -- /tmp/pks-demo
//! cargo run -p pks-cli -- log verify /tmp/pks-demo/session.jsonl --key-dir /tmp/pks-demo/keys
//! ```
//!
//! It uses its own key directory under the given path and never touches your
//! real keys.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use pks_core::keys;
use pks_core::log::{Logger, Record, new_session_id};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

fn run(dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let key = keys::load_or_create_signing_key(&dir.join("keys"))?;
    let log = dir.join("session.jsonl");
    let mut logger = Logger::create(&log, key, &new_session_id()?)?;
    let events = [
        ("net", "api.example.com:443", "NET-UNKNOWN-DOMAIN", "ask"),
        ("net", "169.254.169.254:80", "NET-PRIVATE-IP", "block"),
        ("registry", "left-pad@99.0.0", "REG-TOO-NEW", "block"),
    ];
    let policy_hash = "0".repeat(64);
    for (layer, target, rule, verdict) in events {
        logger.append(
            &Record {
                policy_hash: &policy_hash,
                layer,
                target,
                rule,
                verdict,
            },
            now_ms(),
        )?;
    }
    logger.finish(now_ms())?;
    println!("wrote {} and its .checkpoint", log.display());
    Ok(())
}

fn main() -> ExitCode {
    let Some(dir) = std::env::args_os().nth(1).map(PathBuf::from) else {
        eprintln!("usage: sample_log <directory>");
        return ExitCode::from(2);
    };
    match run(&dir) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("sample_log: {error}");
            ExitCode::from(1)
        }
    }
}
