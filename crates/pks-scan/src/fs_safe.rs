//! Reads files from an untrusted tree without following symlinks.

use std::fs::{self, File};
use std::io::{self, Read as _};
use std::path::{Component, Path};

use crate::SkipReason;

/// Largest file the scanner reads (8 MiB).
pub(crate) const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;
/// How many leading bytes are checked for a NUL byte.
const BINARY_PROBE_BYTES: usize = 8 * 1024;

pub(crate) enum Read {
    Bytes(Vec<u8>),
    Skipped(SkipReason),
}

/// Reads `root/rel`. Every path component is checked with `symlink_metadata`,
/// so a symlink anywhere in the path (not only the last part) is refused.
/// Checking and reading are two steps; that gap matters only if something
/// changes the tree during the scan, which the scanner does not defend
/// against.
pub(crate) fn read_regular(root: &Path, rel: &Path) -> io::Result<Read> {
    let mut current = root.to_path_buf();
    let mut last = None;
    for component in rel.components() {
        let Component::Normal(part) = component else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path has a component that is not a plain name",
            ));
        };
        current.push(part);
        let meta = fs::symlink_metadata(&current)?;
        if meta.file_type().is_symlink() {
            return Ok(Read::Skipped(SkipReason::Symlink));
        }
        last = Some(meta);
    }
    let Some(meta) = last else {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty path"));
    };
    if !meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    if meta.len() > MAX_FILE_BYTES {
        return Ok(Read::Skipped(SkipReason::TooLarge));
    }
    let mut bytes = Vec::new();
    // One byte past the limit detects a file that grew after the check.
    File::open(&current)?
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Ok(Read::Skipped(SkipReason::TooLarge));
    }
    Ok(Read::Bytes(bytes))
}

/// A NUL byte in the first 8 KiB means the file is not text.
pub(crate) fn looks_binary(bytes: &[u8]) -> bool {
    let probe = &bytes[..bytes.len().min(BINARY_PROBE_BYTES)];
    probe.contains(&0)
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn reads_a_regular_file() -> TestResult {
        let dir = tempfile::tempdir()?;
        fs::create_dir(dir.path().join("sub"))?;
        fs::write(dir.path().join("sub/a.txt"), b"hello")?;
        match read_regular(dir.path(), Path::new("sub/a.txt"))? {
            Read::Bytes(bytes) => assert_eq!(bytes, b"hello"),
            Read::Skipped(_) => panic!("regular file must be read"),
        }
        Ok(())
    }

    #[test]
    fn rejects_parent_and_absolute_components() -> TestResult {
        let dir = tempfile::tempdir()?;
        assert!(read_regular(dir.path(), Path::new("../x")).is_err());
        assert!(read_regular(dir.path(), Path::new("/etc/passwd")).is_err());
        Ok(())
    }

    #[test]
    fn skips_files_over_the_limit() -> TestResult {
        let dir = tempfile::tempdir()?;
        let big = vec![b'a'; usize::try_from(MAX_FILE_BYTES)? + 1];
        fs::write(dir.path().join("big.txt"), big)?;
        assert!(matches!(
            read_regular(dir.path(), Path::new("big.txt"))?,
            Read::Skipped(SkipReason::TooLarge)
        ));
        Ok(())
    }

    #[test]
    fn detects_binary_by_nul_in_first_8_kib() {
        assert!(looks_binary(b"ab\0cd"));
        assert!(!looks_binary(b"plain text"));
        let mut late_nul = vec![b'a'; BINARY_PROBE_BYTES];
        late_nul.push(0);
        assert!(!looks_binary(&late_nul));
    }

    #[cfg(unix)]
    #[test]
    fn refuses_a_symlinked_file_and_a_symlinked_directory() -> TestResult {
        use std::os::unix::fs::symlink;
        let outside = tempfile::tempdir()?;
        fs::write(outside.path().join("secret.txt"), b"outside")?;
        let repo = tempfile::tempdir()?;
        symlink(
            outside.path().join("secret.txt"),
            repo.path().join("link.txt"),
        )?;
        symlink(outside.path(), repo.path().join("linkdir"))?;
        assert!(matches!(
            read_regular(repo.path(), Path::new("link.txt"))?,
            Read::Skipped(SkipReason::Symlink)
        ));
        assert!(matches!(
            read_regular(repo.path(), Path::new("linkdir/secret.txt"))?,
            Read::Skipped(SkipReason::Symlink)
        ));
        Ok(())
    }
}
