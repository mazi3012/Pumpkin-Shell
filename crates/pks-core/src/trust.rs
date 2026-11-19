//! Trust pins for repo policies (PRD FR-POL: "`trust` pins its hash").
//!
//! A repo policy is attacker-controlled text, so a pin cannot live in the
//! repo: whoever can edit the policy could edit its pin. Pins are kept in
//! the host data dir, which the sandbox never mounts, keyed by the repo's
//! canonical path:
//!
//! ```toml
//! version = 1
//! [repos."/home/me/project"]
//! sha256 = "<64 lowercase hex digits>"
//! ```
//!
//! Moving a repo, or editing its policy by a single byte, means it has to be
//! trusted again. The store is rewritten atomically, under a lock, so two
//! `trust` runs at once cannot lose a pin.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{fsutil, hex};

const STORE_FILE: &str = "trusted-policies.toml";
const LOCK_FILE: &str = "trusted-policies.lock";
const STORE_VERSION: u32 = 1;
const MAX_STORE_BYTES: u64 = 4 * 1024 * 1024;

/// How a repo policy's hash compares with the pinned one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustState {
    /// The hash is pinned and matches.
    Trusted,
    /// A different hash is pinned for this repo.
    Changed,
    /// Nothing is pinned for this repo.
    Unpinned,
}

#[derive(Debug, thiserror::Error)]
pub enum TrustError {
    #[error("cannot access {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("{path} is not safe to use: {problem}")]
    Insecure { path: String, problem: &'static str },
    #[error("the trust file {path} is not valid: {reason}")]
    Corrupt { path: String, reason: String },
    #[error("a policy hash must be 64 lowercase hex digits")]
    BadHash,
    #[error("the repo path {0} is not valid UTF-8, so it cannot be pinned")]
    PathNotUtf8(String),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Store {
    version: u32,
    #[serde(default)]
    repos: BTreeMap<String, Pin>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pin {
    sha256: String,
}

fn io_error(path: &Path, source: io::Error) -> TrustError {
    TrustError::Io {
        path: path.display().to_string(),
        source,
    }
}

fn valid_hash(hash: &str) -> bool {
    hex::decode_array::<32>(hash).is_some()
}

/// The pin file in a data directory.
pub struct TrustStore {
    dir: PathBuf,
}

impl TrustStore {
    /// A store in `data_dir`. Nothing is created until a pin is written.
    #[must_use]
    pub fn new(data_dir: &Path) -> Self {
        Self {
            dir: data_dir.to_path_buf(),
        }
    }

    fn store_path(&self) -> PathBuf {
        self.dir.join(STORE_FILE)
    }

    /// The key for a repo: its canonical path as text.
    fn key(repo: &Path) -> Result<String, TrustError> {
        let canonical = fs::canonicalize(repo).map_err(|e| io_error(repo, e))?;
        canonical
            .to_str()
            .map(str::to_owned)
            .ok_or_else(|| TrustError::PathNotUtf8(canonical.display().to_string()))
    }

    fn load(&self) -> Result<Store, TrustError> {
        let path = self.store_path();
        let meta = match fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(Store {
                    version: STORE_VERSION,
                    repos: BTreeMap::new(),
                });
            }
            Err(error) => return Err(io_error(&path, error)),
        };
        let shown = || path.display().to_string();
        if meta.file_type().is_symlink() {
            return Err(TrustError::Insecure {
                path: shown(),
                problem: "a symlink",
            });
        }
        if !meta.is_file() {
            return Err(TrustError::Insecure {
                path: shown(),
                problem: "not a regular file",
            });
        }
        if !fsutil::is_private(&meta) {
            return Err(TrustError::Insecure {
                path: shown(),
                problem: "accessible by group or others",
            });
        }
        if meta.len() > MAX_STORE_BYTES {
            return Err(TrustError::Corrupt {
                path: shown(),
                reason: "too large".to_owned(),
            });
        }
        let mut text = String::new();
        fs::File::open(&path)
            .and_then(|mut file| file.read_to_string(&mut text))
            .map_err(|e| io_error(&path, e))?;
        let corrupt = |reason: String| TrustError::Corrupt {
            path: shown(),
            reason,
        };
        let store: Store = toml::from_str(&text).map_err(|e| corrupt(e.to_string()))?;
        if store.version != STORE_VERSION {
            return Err(corrupt(format!("unsupported version {}", store.version)));
        }
        if store.repos.values().any(|pin| !valid_hash(&pin.sha256)) {
            return Err(corrupt("a pinned hash is malformed".to_owned()));
        }
        Ok(store)
    }

    /// Compares `sha256` with the hash pinned for `repo`.
    ///
    /// # Errors
    /// Fails if the repo path cannot be resolved, the hash is malformed, or
    /// the pin file is unsafe or corrupt. A corrupt file is an error, never
    /// "unpinned": the caller must not guess.
    pub fn check(&self, repo: &Path, sha256: &str) -> Result<TrustState, TrustError> {
        if !valid_hash(sha256) {
            return Err(TrustError::BadHash);
        }
        let key = Self::key(repo)?;
        Ok(match self.load()?.repos.get(&key) {
            None => TrustState::Unpinned,
            Some(pin) if pin.sha256 == sha256 => TrustState::Trusted,
            Some(_) => TrustState::Changed,
        })
    }

    /// Pins `sha256` for `repo`, replacing any earlier pin.
    ///
    /// # Errors
    /// Fails if the repo path cannot be resolved, the hash is malformed, or
    /// the pin file is unsafe, corrupt or cannot be written.
    pub fn pin(&self, repo: &Path, sha256: &str) -> Result<(), TrustError> {
        if !valid_hash(sha256) {
            return Err(TrustError::BadHash);
        }
        let key = Self::key(repo)?;
        match fs::symlink_metadata(&self.dir) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(TrustError::Insecure {
                    path: self.dir.display().to_string(),
                    problem: "a symlink",
                });
            }
            Ok(meta) if !meta.is_dir() => {
                return Err(TrustError::Insecure {
                    path: self.dir.display().to_string(),
                    problem: "not a directory",
                });
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fsutil::create_private_dir_all(&self.dir).map_err(|e| io_error(&self.dir, e))?;
            }
            Err(error) => return Err(io_error(&self.dir, error)),
        }

        // The lock covers read, modify and replace.
        let lock_path = self.dir.join(LOCK_FILE);
        let lock = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|e| io_error(&lock_path, e))?;
        lock.lock().map_err(|e| io_error(&lock_path, e))?;

        let mut store = self.load()?;
        store.repos.insert(
            key,
            Pin {
                sha256: sha256.to_owned(),
            },
        );
        let text = toml::to_string(&store).map_err(|e| TrustError::Corrupt {
            path: self.store_path().display().to_string(),
            reason: e.to_string(),
        })?;

        let temp = self
            .dir
            .join(format!("{STORE_FILE}.tmp-{}", std::process::id()));
        let _ = fs::remove_file(&temp);
        fsutil::write_new_private(&temp, text.as_bytes()).map_err(|e| io_error(&temp, e))?;
        fs::rename(&temp, self.store_path()).map_err(|error| {
            let _ = fs::remove_file(&temp);
            io_error(&self.store_path(), error)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn setup() -> Result<(tempfile::TempDir, TrustStore, PathBuf), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let store = TrustStore::new(&dir.path().join("data"));
        let repo = dir.path().join("repo");
        fs::create_dir(&repo)?;
        Ok((dir, store, repo))
    }

    #[test]
    fn nothing_is_pinned_at_first_and_nothing_is_created_by_checking() -> TestResult {
        let (dir, store, repo) = setup()?;
        assert_eq!(store.check(&repo, HASH_A)?, TrustState::Unpinned);
        assert!(!dir.path().join("data").exists());
        Ok(())
    }

    #[test]
    fn a_pinned_hash_is_trusted_and_any_other_hash_is_changed() -> TestResult {
        let (_dir, store, repo) = setup()?;
        store.pin(&repo, HASH_A)?;
        assert_eq!(store.check(&repo, HASH_A)?, TrustState::Trusted);
        assert_eq!(store.check(&repo, HASH_B)?, TrustState::Changed);
        Ok(())
    }

    #[test]
    fn pinning_again_replaces_the_pin() -> TestResult {
        let (_dir, store, repo) = setup()?;
        store.pin(&repo, HASH_A)?;
        store.pin(&repo, HASH_B)?;
        assert_eq!(store.check(&repo, HASH_B)?, TrustState::Trusted);
        assert_eq!(store.check(&repo, HASH_A)?, TrustState::Changed);
        Ok(())
    }

    #[test]
    fn repos_are_pinned_independently() -> TestResult {
        let (dir, store, repo) = setup()?;
        let other = dir.path().join("other");
        fs::create_dir(&other)?;
        store.pin(&repo, HASH_A)?;
        assert_eq!(store.check(&other, HASH_A)?, TrustState::Unpinned);
        store.pin(&other, HASH_B)?;
        assert_eq!(store.check(&repo, HASH_A)?, TrustState::Trusted);
        assert_eq!(store.check(&other, HASH_B)?, TrustState::Trusted);
        Ok(())
    }

    #[test]
    fn the_pin_belongs_to_the_real_path_so_a_relative_spelling_matches() -> TestResult {
        let (_dir, store, repo) = setup()?;
        store.pin(&repo, HASH_A)?;
        let roundabout = repo.join("..").join("repo");
        assert_eq!(store.check(&roundabout, HASH_A)?, TrustState::Trusted);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_to_a_repo_shares_its_pin() -> TestResult {
        let (dir, store, repo) = setup()?;
        store.pin(&repo, HASH_A)?;
        let link = dir.path().join("alias");
        std::os::unix::fs::symlink(&repo, &link)?;
        assert_eq!(store.check(&link, HASH_A)?, TrustState::Trusted);
        Ok(())
    }

    #[test]
    fn a_missing_repo_is_an_error() -> TestResult {
        let (dir, store, _) = setup()?;
        assert!(matches!(
            store.check(&dir.path().join("nope"), HASH_A),
            Err(TrustError::Io { .. })
        ));
        assert!(matches!(
            store.pin(&dir.path().join("nope"), HASH_A),
            Err(TrustError::Io { .. })
        ));
        Ok(())
    }

    #[test]
    fn malformed_hashes_are_refused_before_anything_is_written() -> TestResult {
        let (dir, store, repo) = setup()?;
        for bad in [
            "",
            "abc",
            &"A".repeat(64),
            &"g".repeat(64),
            &"a".repeat(63),
            &"a".repeat(65),
            "sha256:aaaa",
        ] {
            assert!(
                matches!(store.pin(&repo, bad), Err(TrustError::BadHash)),
                "{bad}"
            );
            assert!(
                matches!(store.check(&repo, bad), Err(TrustError::BadHash)),
                "{bad}"
            );
        }
        assert!(!dir.path().join("data").exists());
        Ok(())
    }

    #[test]
    fn the_store_is_toml_with_the_documented_shape() -> TestResult {
        let (_dir, store, repo) = setup()?;
        store.pin(&repo, HASH_A)?;
        let text = fs::read_to_string(store.store_path())?;
        let value: toml::Table = toml::from_str(&text)?;
        assert_eq!(value["version"].as_integer(), Some(1));
        let key = fs::canonicalize(&repo)?.to_string_lossy().into_owned();
        assert_eq!(value["repos"][&key]["sha256"].as_str(), Some(HASH_A));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn files_are_private_and_no_temp_file_is_left() -> TestResult {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, store, repo) = setup()?;
        store.pin(&repo, HASH_A)?;
        store.pin(&repo, HASH_B)?;
        let mode = |p: &Path| fs::metadata(p).map(|m| m.permissions().mode() & 0o777);
        assert_eq!(mode(&store.store_path())?, 0o600);
        assert_eq!(mode(&store.dir)?, 0o700);
        let names: Vec<_> = fs::read_dir(&store.dir)?
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(names.iter().all(|n| !n.contains(".tmp-")), "{names:?}");
        Ok(())
    }

    #[test]
    fn a_corrupt_store_is_an_error_not_unpinned() -> TestResult {
        let (_dir, store, repo) = setup()?;
        store.pin(&repo, HASH_A)?;
        let path = store.store_path();
        let key = fs::canonicalize(&repo)?.to_string_lossy().into_owned();
        for bad in [
            "not toml".to_owned(),
            String::new(),
            "version = 2\n".to_owned(),
            "version = 1\nextra = 1\n".to_owned(),
            format!("version = 1\n[repos.\"{key}\"]\nsha256 = \"short\"\n"),
            format!("version = 1\n[repos.\"{key}\"]\nsha256 = \"{HASH_A}\"\nnote = 1\n"),
        ] {
            fs::write(&path, &bad)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
            }
            assert!(
                matches!(store.check(&repo, HASH_A), Err(TrustError::Corrupt { .. })),
                "{bad:?}"
            );
            assert!(
                matches!(store.pin(&repo, HASH_B), Err(TrustError::Corrupt { .. })),
                "{bad:?}"
            );
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn a_store_that_others_can_read_or_a_symlink_is_refused() -> TestResult {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let (_dir, store, repo) = setup()?;
        store.pin(&repo, HASH_A)?;
        let path = store.store_path();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
        assert!(matches!(
            store.check(&repo, HASH_A),
            Err(TrustError::Insecure { .. })
        ));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let real = store.dir.join("real.toml");
        fs::rename(&path, &real)?;
        symlink(&real, &path)?;
        assert!(matches!(
            store.check(&repo, HASH_A),
            Err(TrustError::Insecure { .. })
        ));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_data_directory_is_refused() -> TestResult {
        let (dir, _, repo) = setup()?;
        let real = dir.path().join("real");
        fs::create_dir(&real)?;
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link)?;
        assert!(matches!(
            TrustStore::new(&link).pin(&repo, HASH_A),
            Err(TrustError::Insecure { .. })
        ));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn a_repo_path_that_is_not_utf8_cannot_be_pinned() -> TestResult {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let (dir, store, _) = setup()?;
        let odd = dir.path().join(OsStr::from_bytes(b"bad-\xff-name"));
        fs::create_dir(&odd)?;
        assert!(matches!(
            store.pin(&odd, HASH_A),
            Err(TrustError::PathNotUtf8(_))
        ));
        Ok(())
    }

    #[test]
    fn many_pins_at_once_do_not_lose_any() -> TestResult {
        let dir = tempfile::tempdir()?;
        let store = Arc::new(TrustStore::new(&dir.path().join("data")));
        let mut repos = Vec::new();
        for i in 0..12 {
            let repo = dir.path().join(format!("repo{i}"));
            fs::create_dir(&repo)?;
            repos.push(repo);
        }
        let handles: Vec<_> = repos
            .iter()
            .cloned()
            .map(|repo| {
                let store = Arc::clone(&store);
                std::thread::spawn(move || store.pin(&repo, HASH_A).map_err(|e| e.to_string()))
            })
            .collect();
        for handle in handles {
            handle.join().map_err(|_| "thread panicked")??;
        }
        for repo in &repos {
            assert_eq!(
                store.check(repo, HASH_A)?,
                TrustState::Trusted,
                "{}",
                repo.display()
            );
        }
        Ok(())
    }
}
