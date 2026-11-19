//! Small file helpers shared by keys, the log and the trust pins.

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

/// Creates a file that must not exist yet, with mode 0600 on Unix, writes
/// `contents` and flushes it to disk. Never overwrites.
pub(crate) fn write_new_private(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut file = open_new_private(path, false)?;
    file.write_all(contents)?;
    file.sync_all()
}

/// Opens a new file for writing, failing if it exists. With `readable`, the
/// handle is also readable and appends (the log needs both).
pub(crate) fn open_new_private(path: &Path, readable: bool) -> io::Result<fs::File> {
    let mut options = OpenOptions::new();
    options.create_new(true);
    if readable {
        options.read(true).append(true);
    } else {
        options.write(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

/// Creates `dir` and missing parents, with mode 0700 on Unix.
pub(crate) fn create_private_dir_all(dir: &Path) -> io::Result<()> {
    let mut builder = DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)
}

/// True when no access is granted to group or others (Unix). Other
/// platforms report true: their ACL hardening is Phase 16.
pub(crate) fn is_private(meta: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o077 == 0
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn write_new_private_never_overwrites() -> TestResult {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("f");
        write_new_private(&path, b"first")?;
        let error = write_new_private(&path, b"second").err().map(|e| e.kind());
        assert_eq!(error, Some(io::ErrorKind::AlreadyExists));
        assert_eq!(fs::read(&path)?, b"first");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn files_and_directories_are_created_private() -> TestResult {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir()?;
        let nested = dir.path().join("a/b");
        create_private_dir_all(&nested)?;
        write_new_private(&nested.join("f"), b"x")?;
        let mode = |p: &Path| fs::metadata(p).map(|m| m.permissions().mode() & 0o777);
        assert_eq!(mode(&nested)?, 0o700);
        assert_eq!(mode(&dir.path().join("a"))?, 0o700);
        assert_eq!(mode(&nested.join("f"))?, 0o600);
        assert!(is_private(&fs::metadata(nested.join("f"))?));
        fs::set_permissions(nested.join("f"), fs::Permissions::from_mode(0o640))?;
        assert!(!is_private(&fs::metadata(nested.join("f"))?));
        Ok(())
    }
}
