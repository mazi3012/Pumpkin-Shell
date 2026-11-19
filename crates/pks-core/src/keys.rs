//! The ed25519 key that signs the log (PRD FR-RCPT).
//!
//! The private key lives in a directory under the host data dir, which the
//! sandbox never mounts. The public key sits next to it. Verification takes
//! the public key from here and never from the log, so an attacker cannot
//! re-sign a log with a key of their own.
//!
//! Files hold lowercase hex and one trailing newline. On Unix the directory
//! must be mode 0700 and the key file 0600 (no access for group or others);
//! anything looser, and any symlink, is refused instead of used. On Windows
//! the files get the ACL of their parent directory; hardening it is Phase 16.

use std::fs::{self, File};
use std::io::{self, Read};
use std::path::Path;

use ed25519_dalek::{SigningKey, VerifyingKey};

use crate::{fsutil, hex};

const KEY_FILE: &str = "log-signing.key";
const PUB_FILE: &str = "log-signing.pub";
/// 64 hex digits and a newline fit in far less than this.
const MAX_KEY_FILE_BYTES: u64 = 256;

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("cannot access {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("{path} is not safe to use: {problem}")]
    Insecure { path: String, problem: &'static str },
    #[error("{0} does not hold a valid key (expected 64 lowercase hex digits)")]
    Malformed(String),
    #[error("the public key file does not match the signing key")]
    PublicKeyMismatch,
    #[error("no verifying key at {0}; sign a log first, or pass --key-dir")]
    MissingPublicKey(String),
    #[error("the system random number generator failed: {0}")]
    Random(String),
}

fn io_error(path: &Path, source: io::Error) -> KeyError {
    KeyError::Io {
        path: path.display().to_string(),
        source,
    }
}

fn insecure(path: &Path, problem: &'static str) -> KeyError {
    KeyError::Insecure {
        path: path.display().to_string(),
        problem,
    }
}

fn check_private(path: &Path, meta: &fs::Metadata) -> Result<(), KeyError> {
    if fsutil::is_private(meta) {
        Ok(())
    } else {
        Err(insecure(path, "accessible by group or others"))
    }
}

fn ensure_private_dir(dir: &Path) -> Result<(), KeyError> {
    match fs::symlink_metadata(dir) {
        Ok(meta) if meta.file_type().is_symlink() => Err(insecure(dir, "a symlink")),
        Ok(meta) if meta.is_dir() => check_private(dir, &meta),
        Ok(_) => Err(insecure(dir, "not a directory")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fsutil::create_private_dir_all(dir).map_err(|e| io_error(dir, e))
        }
        Err(error) => Err(io_error(dir, error)),
    }
}

/// Reads a small hex file. `secret` files must also be private.
fn read_hex_file(path: &Path, secret: bool) -> Result<Option<[u8; 32]>, KeyError> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error(path, error)),
    };
    if meta.file_type().is_symlink() {
        return Err(insecure(path, "a symlink"));
    }
    if !meta.is_file() {
        return Err(insecure(path, "not a regular file"));
    }
    if secret {
        check_private(path, &meta)?;
    }
    if meta.len() > MAX_KEY_FILE_BYTES {
        return Err(KeyError::Malformed(path.display().to_string()));
    }
    let mut text = String::new();
    File::open(path)
        .and_then(|mut file| file.read_to_string(&mut text))
        .map_err(|e| io_error(path, e))?;
    let body = text.strip_suffix('\n').unwrap_or(&text);
    hex::decode_array::<32>(body)
        .map(Some)
        .ok_or_else(|| KeyError::Malformed(path.display().to_string()))
}

fn ensure_public_file(dir: &Path, key: &SigningKey) -> Result<(), KeyError> {
    let path = dir.join(PUB_FILE);
    let wanted = key.verifying_key().to_bytes();
    match read_hex_file(&path, false)? {
        Some(found) if found == wanted => Ok(()),
        Some(_) => Err(KeyError::PublicKeyMismatch),
        None => {
            match fsutil::write_new_private(&path, format!("{}\n", hex::encode(&wanted)).as_bytes())
            {
                Ok(()) => Ok(()),
                // Another process wrote it first: it must match.
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    match read_hex_file(&path, false)? {
                        Some(found) if found == wanted => Ok(()),
                        _ => Err(KeyError::PublicKeyMismatch),
                    }
                }
                Err(error) => Err(io_error(&path, error)),
            }
        }
    }
}

/// Loads the signing key from `dir`, creating the directory and a new random
/// key on first use.
///
/// # Errors
/// Fails if the directory or key file is a symlink, is accessible by group or
/// others (Unix), is malformed, or does not match the public key file.
pub fn load_or_create_signing_key(dir: &Path) -> Result<SigningKey, KeyError> {
    ensure_private_dir(dir)?;
    let key_path = dir.join(KEY_FILE);
    let seed = match read_hex_file(&key_path, true)? {
        Some(seed) => seed,
        None => {
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed).map_err(|e| KeyError::Random(e.to_string()))?;
            match fsutil::write_new_private(
                &key_path,
                format!("{}\n", hex::encode(&seed)).as_bytes(),
            ) {
                Ok(()) => seed,
                // Lost a race with another process: use the key it wrote.
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    read_hex_file(&key_path, true)?
                        .ok_or_else(|| KeyError::Malformed(key_path.display().to_string()))?
                }
                Err(error) => return Err(io_error(&key_path, error)),
            }
        }
    };
    let key = SigningKey::from_bytes(&seed);
    ensure_public_file(dir, &key)?;
    Ok(key)
}

/// Loads the public key from `dir`. Never creates anything.
///
/// # Errors
/// Fails if the file is missing, a symlink, or malformed.
pub fn load_verifying_key(dir: &Path) -> Result<VerifyingKey, KeyError> {
    let path = dir.join(PUB_FILE);
    let bytes = read_hex_file(&path, false)?
        .ok_or_else(|| KeyError::MissingPublicKey(path.display().to_string()))?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| KeyError::Malformed(path.display().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn creates_a_key_then_loads_the_same_one() -> TestResult {
        let dir = tempfile::tempdir()?;
        let keys = dir.path().join("keys");
        let first = load_or_create_signing_key(&keys)?;
        let second = load_or_create_signing_key(&keys)?;
        assert_eq!(first.to_bytes(), second.to_bytes());
        assert_eq!(load_verifying_key(&keys)?, first.verifying_key());
        Ok(())
    }

    #[test]
    fn two_directories_get_two_different_keys() -> TestResult {
        let dir = tempfile::tempdir()?;
        let a = load_or_create_signing_key(&dir.path().join("a"))?;
        let b = load_or_create_signing_key(&dir.path().join("b"))?;
        assert_ne!(a.to_bytes(), b.to_bytes());
        Ok(())
    }

    #[test]
    fn files_hold_one_line_of_canonical_hex() -> TestResult {
        let dir = tempfile::tempdir()?;
        let keys = dir.path().join("keys");
        let key = load_or_create_signing_key(&keys)?;
        let secret = fs::read_to_string(keys.join(KEY_FILE))?;
        let public = fs::read_to_string(keys.join(PUB_FILE))?;
        assert_eq!(secret, format!("{}\n", hex::encode(&key.to_bytes())));
        assert_eq!(
            public,
            format!("{}\n", hex::encode(&key.verifying_key().to_bytes()))
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn new_files_are_private() -> TestResult {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir()?;
        let keys = dir.path().join("keys");
        load_or_create_signing_key(&keys)?;
        let mode = |p: &Path| fs::metadata(p).map(|m| m.permissions().mode() & 0o777);
        assert_eq!(mode(&keys)?, 0o700);
        assert_eq!(mode(&keys.join(KEY_FILE))?, 0o600);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn refuses_a_key_file_that_others_can_read() -> TestResult {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir()?;
        let keys = dir.path().join("keys");
        load_or_create_signing_key(&keys)?;
        for mode in [0o640, 0o604, 0o660, 0o644, 0o666] {
            fs::set_permissions(keys.join(KEY_FILE), fs::Permissions::from_mode(mode))?;
            assert!(
                matches!(
                    load_or_create_signing_key(&keys),
                    Err(KeyError::Insecure { .. })
                ),
                "mode {mode:o}"
            );
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn refuses_a_directory_that_others_can_use() -> TestResult {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir()?;
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755))?;
        assert!(matches!(
            load_or_create_signing_key(dir.path()),
            Err(KeyError::Insecure { .. })
        ));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlinks_for_the_directory_and_the_files() -> TestResult {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let dir = tempfile::tempdir()?;
        let real = dir.path().join("real");
        load_or_create_signing_key(&real)?;
        // A symlinked key directory.
        let link = dir.path().join("link");
        symlink(&real, &link)?;
        assert!(matches!(
            load_or_create_signing_key(&link),
            Err(KeyError::Insecure { .. })
        ));
        // A symlinked key file.
        let other = dir.path().join("other");
        fs::create_dir(&other)?;
        fs::set_permissions(&other, fs::Permissions::from_mode(0o700))?;
        symlink(real.join(KEY_FILE), other.join(KEY_FILE))?;
        assert!(matches!(
            load_or_create_signing_key(&other),
            Err(KeyError::Insecure { .. })
        ));
        // A symlinked public key file.
        symlink(real.join(PUB_FILE), other.join(PUB_FILE))?;
        assert!(matches!(
            load_verifying_key(&other),
            Err(KeyError::Insecure { .. })
        ));
        Ok(())
    }

    #[test]
    fn rejects_malformed_key_files() -> TestResult {
        let dir = tempfile::tempdir()?;
        let keys = dir.path().join("keys");
        load_or_create_signing_key(&keys)?;
        let key_path = keys.join(KEY_FILE);
        let good = fs::read_to_string(&key_path)?;
        for bad in [
            good.to_uppercase(),
            good.trim_end().chars().take(63).collect::<String>(),
            format!("{}00\n", good.trim_end()),
            format!("{good}{good}"),
            String::new(),
            "not hex at all".to_owned(),
        ] {
            fs::write(&key_path, &bad)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))?;
            }
            assert!(
                matches!(
                    load_or_create_signing_key(&keys),
                    Err(KeyError::Malformed(_))
                ),
                "{bad:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn rejects_a_public_key_that_does_not_match() -> TestResult {
        let dir = tempfile::tempdir()?;
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        load_or_create_signing_key(&a)?;
        load_or_create_signing_key(&b)?;
        fs::copy(b.join(PUB_FILE), a.join(PUB_FILE))?;
        assert!(matches!(
            load_or_create_signing_key(&a),
            Err(KeyError::PublicKeyMismatch)
        ));
        Ok(())
    }

    #[test]
    fn a_missing_public_key_is_reported_and_not_created() -> TestResult {
        let dir = tempfile::tempdir()?;
        assert!(matches!(
            load_verifying_key(dir.path()),
            Err(KeyError::MissingPublicKey(_))
        ));
        assert!(!dir.path().join(PUB_FILE).exists());
        Ok(())
    }

    #[test]
    fn a_missing_public_file_is_recreated_from_the_key() -> TestResult {
        let dir = tempfile::tempdir()?;
        let keys = dir.path().join("keys");
        let key = load_or_create_signing_key(&keys)?;
        fs::remove_file(keys.join(PUB_FILE))?;
        load_or_create_signing_key(&keys)?;
        assert_eq!(load_verifying_key(&keys)?, key.verifying_key());
        Ok(())
    }

    #[test]
    fn errors_never_contain_key_material() -> TestResult {
        let dir = tempfile::tempdir()?;
        let keys = dir.path().join("keys");
        let key = load_or_create_signing_key(&keys)?;
        let secret = hex::encode(&key.to_bytes());
        fs::write(keys.join(KEY_FILE), format!("{secret}00\n"))?;
        let error = load_or_create_signing_key(&keys)
            .err()
            .map(|e| e.to_string());
        assert!(error.is_some_and(|text| !text.contains(&secret)));
        Ok(())
    }
}
