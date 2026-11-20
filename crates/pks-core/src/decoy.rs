//! Decoy credentials in the sandboxed home (PRD FR-WS "Decoys", PHASES 10.6).
//!
//! The IDE has no real credential. A decoy is a file of the same name as a
//! real one, with a random marker, so nothing real is at risk and a read of it
//! is a sign of credential theft (`FS-DECOY-READ`). Decoys are written fresh
//! for every session, so the marker of one session is not valid for the next.
//!
//! The content says plainly that it is not a credential, and no marker or
//! content is printed in a finding.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::{Finding, RuleId, Severity, hex};

/// The rule for a program that opens a decoy credential (PRD FR-DET).
pub const FS_DECOY_READ: RuleId = RuleId::new("FS-DECOY-READ");

/// The decoy files, relative to the sandboxed home, with what each imitates.
pub const DECOYS: [(&str, &str); 3] = [
    (".ssh/id_ed25519", "SSH private key"),
    (".aws/credentials", "AWS credentials"),
    (".config/gh/hosts.yml", "GitHub CLI token file"),
];

/// A decoy written for this session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Planted {
    /// The name from [`DECOYS`], such as `.ssh/id_ed25519`.
    pub name: &'static str,
    /// Where it was written, on the host.
    pub path: PathBuf,
}

/// Why decoys could not be written. The session must not start.
#[derive(Debug, thiserror::Error)]
pub enum DecoyError {
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: io::Error,
    },
    #[error("{0} is a symbolic link; a decoy must be a regular file")]
    Symlink(String),
}

fn io_error(context: impl Into<String>, source: io::Error) -> DecoyError {
    DecoyError::Io {
        context: context.into(),
        source,
    }
}

/// Writes the decoy set into `home`. Each file has its own random marker.
///
/// # Errors
/// Fails when a decoy path or its parent is a symbolic link, or when a file
/// cannot be written.
pub fn plant(home: &Path) -> Result<Vec<Planted>, DecoyError> {
    let mut planted = Vec::new();
    for (name, kind) in DECOYS {
        let path = home.join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| io_error(format!("cannot create {}", parent.display()), e))?;
        }
        if path
            .symlink_metadata()
            .is_ok_and(|meta| meta.file_type().is_symlink())
        {
            return Err(DecoyError::Symlink(name.to_owned()));
        }
        let mut marker = [0u8; 16];
        getrandom::fill(&mut marker).map_err(|e| {
            io_error(
                "cannot make a decoy marker",
                io::Error::other(e.to_string()),
            )
        })?;
        let body = format!(
            "PKS DECOY, not a credential: this {kind} is a trap. Marker {}\n",
            hex::encode(&marker)
        );
        write_private(&path, body.as_bytes())
            .map_err(|e| io_error(format!("cannot write {}", path.display()), e))?;
        planted.push(Planted { name, path });
    }
    Ok(planted)
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    fs::write(path, bytes)
}

/// The finding for an access to decoy `name`. It names the decoy, not the
/// host path and never the marker.
#[must_use]
pub fn read_finding(name: &str) -> Finding {
    Finding {
        rule: FS_DECOY_READ,
        severity: Severity::High,
        target: name.to_owned(),
        message: format!(
            "the sandbox opened the decoy credential {name}; something in the IDE is looking for credentials"
        ),
        fix: "Find out which program opened it. The decoy holds nothing real, so there is no key to rotate.".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn every_decoy_is_written_with_its_own_marker() -> TestResult {
        let home = tempfile::tempdir()?;
        let planted = plant(home.path())?;
        assert_eq!(planted.len(), DECOYS.len());
        let mut markers = Vec::new();
        for item in &planted {
            let text = fs::read_to_string(&item.path)?;
            assert!(text.starts_with("PKS DECOY, not a credential"), "{text}");
            markers.push(text);
        }
        markers.sort();
        markers.dedup();
        assert_eq!(markers.len(), DECOYS.len(), "markers repeat");
        Ok(())
    }

    #[test]
    fn a_second_plant_gives_new_markers() -> TestResult {
        let home = tempfile::tempdir()?;
        let first = plant(home.path())?;
        let before = fs::read_to_string(&first[0].path)?;
        let second = plant(home.path())?;
        let after = fs::read_to_string(&second[0].path)?;
        assert_ne!(before, after);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn decoys_are_private_to_their_owner() -> TestResult {
        use std::os::unix::fs::PermissionsExt;
        let home = tempfile::tempdir()?;
        let planted = plant(home.path())?;
        let mode = fs::metadata(&planted[0].path)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn a_symbolic_link_where_a_decoy_goes_is_refused() -> TestResult {
        let home = tempfile::tempdir()?;
        let outside = home.path().join("outside");
        fs::create_dir_all(home.path().join(".ssh"))?;
        fs::write(&outside, "keep\n")?;
        std::os::unix::fs::symlink(&outside, home.path().join(".ssh/id_ed25519"))?;
        assert!(matches!(plant(home.path()), Err(DecoyError::Symlink(_))));
        assert_eq!(fs::read_to_string(&outside)?, "keep\n");
        Ok(())
    }

    #[test]
    fn the_finding_names_the_decoy_and_not_its_marker() {
        let finding = read_finding(".aws/credentials");
        assert_eq!(finding.rule.as_str(), "FS-DECOY-READ");
        assert_eq!(finding.severity, Severity::High);
        assert!(finding.message.contains(".aws/credentials"));
        assert!(!finding.message.contains("Marker"));
    }
}
