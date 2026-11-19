//! The snapshot taken before an IDE session (PRD FR-WS "Snapshot before
//! launch", PHASES 10.4).
//!
//! The snapshot is a commit in a bare git directory inside the session's data
//! directory. The repo is only the work tree, so:
//! - the repo's `.git` is never written: its index, refs and objects are not
//!   touched;
//! - the repo's own `.git/config` is never read, so its filters, hooks and
//!   `core.fsmonitor` do not run. The global and system git configs are
//!   replaced with an empty file for the same reason.
//!
//! Files listed by the repo's `.gitignore` are not in the snapshot. Restore
//! writes into a new, empty directory and never into the repo.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Name of the bare git directory inside a session directory.
pub const SNAPSHOT_DIR: &str = "snapshot.git";

/// Errors from taking or restoring a snapshot.
#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    /// `git` could not be started, or it failed. The message is its output.
    #[error("git: {0}")]
    Git(String),
    /// A file or directory could not be read or written.
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: io::Error,
    },
    /// The session id is not a session id, so it cannot name a directory.
    #[error("{0} is not a session id")]
    BadSessionId(String),
    /// The restore target exists and is not empty.
    #[error("{0} is not empty; choose a new directory")]
    TargetNotEmpty(PathBuf),
}

/// Makes a git command that cannot read any config but the snapshot's own.
/// The config file it points to is empty, and the author is fixed, so a
/// commit needs no user identity.
fn git(session_dir: &Path) -> Result<Command, SnapshotError> {
    let empty = session_dir.join("empty.gitconfig");
    fs::write(&empty, b"").map_err(|source| SnapshotError::Io {
        context: format!("cannot write {}", empty.display()),
        source,
    })?;
    let mut command = Command::new("git");
    command
        .env("GIT_CONFIG_GLOBAL", &empty)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_AUTHOR_NAME", "pumpkin-shell")
        .env("GIT_AUTHOR_EMAIL", "pumpkin-shell@localhost")
        .env("GIT_COMMITTER_NAME", "pumpkin-shell")
        .env("GIT_COMMITTER_EMAIL", "pumpkin-shell@localhost")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE");
    Ok(command)
}

fn run(mut command: Command, what: &str) -> Result<String, SnapshotError> {
    let output: Output = command.output().map_err(|source| SnapshotError::Io {
        context: format!("cannot run git for {what}"),
        source,
    })?;
    if !output.status.success() {
        return Err(SnapshotError::Git(format!(
            "{what} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// Takes the snapshot of `repo` into `session_dir`, and returns its commit id.
///
/// # Errors
/// Fails when git is missing or fails, or a directory cannot be written. The
/// session must not start without a snapshot.
pub fn create(repo: &Path, session_dir: &Path) -> Result<String, SnapshotError> {
    let bare = session_dir.join(SNAPSHOT_DIR);
    let mut init = git(session_dir)?;
    init.arg("init").arg("--bare").arg("--quiet").arg(&bare);
    run(init, "init")?;

    let mut add = git(session_dir)?;
    add.arg(format!("--git-dir={}", bare.display()))
        .arg(format!("--work-tree={}", repo.display()))
        .args(["add", "--all"]);
    run(add, "add")?;

    let mut commit = git(session_dir)?;
    // `commit` needs a work tree even though it only reads the index.
    commit
        .arg(format!("--git-dir={}", bare.display()))
        .arg(format!("--work-tree={}", repo.display()))
        .args(["commit", "--quiet", "--allow-empty", "--no-verify"])
        .args(["-m", "pumpkin-shell snapshot"]);
    run(commit, "commit")?;

    let mut head = git(session_dir)?;
    head.arg(format!("--git-dir={}", bare.display()))
        .args(["rev-parse", "HEAD"]);
    let commit_id = run(head, "rev-parse")?;
    if commit_id.len() < 40 || !commit_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(SnapshotError::Git(format!(
            "unexpected commit id: {commit_id}"
        )));
    }
    Ok(commit_id)
}

/// Whether `text` is a session id: 32 lowercase hex digits, as made by
/// `new_session_id`. Checked before it names any directory.
#[must_use]
pub fn is_session_id(text: &str) -> bool {
    text.len() == 32 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Writes the snapshot of `session_dir` into `target`. `target` must be
/// missing or empty; it is created when missing.
///
/// # Errors
/// Fails when `target` is not empty, when git fails, or when a file cannot
/// be written.
pub fn restore_into(session_dir: &Path, target: &Path) -> Result<(), SnapshotError> {
    if target.exists() {
        let mut entries = fs::read_dir(target).map_err(|source| SnapshotError::Io {
            context: format!("cannot read {}", target.display()),
            source,
        })?;
        if entries.next().is_some() {
            return Err(SnapshotError::TargetNotEmpty(target.to_path_buf()));
        }
    } else {
        fs::create_dir_all(target).map_err(|source| SnapshotError::Io {
            context: format!("cannot create {}", target.display()),
            source,
        })?;
    }
    let bare = session_dir.join(SNAPSHOT_DIR);
    let mut head = git(session_dir)?;
    head.arg(format!("--git-dir={}", bare.display()))
        .args(["rev-parse", "HEAD"]);
    let commit_id = run(head, "rev-parse")?;

    // The snapshot's own index is used, and is rebuilt from the commit.
    let mut read = git(session_dir)?;
    read.arg(format!("--git-dir={}", bare.display()))
        .args(["read-tree", &commit_id]);
    run(read, "read-tree")?;

    let mut checkout = git(session_dir)?;
    checkout
        .arg(format!("--git-dir={}", bare.display()))
        .arg(format!("--work-tree={}", target.display()))
        .args(["checkout-index", "--all", "--force"]);
    run(checkout, "checkout-index")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn write(path: &Path, text: &str) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, text)
    }

    /// A repo with a commit, an untracked file, a gitignored file, and a
    /// `core.fsmonitor` that would create a marker if git ran it.
    fn repo_with_traps(root: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let repo = root.join("repo");
        fs::create_dir_all(&repo)?;
        let plain = |args: &[&str]| -> Result<(), Box<dyn std::error::Error>> {
            let status = Command::new("git")
                .arg("-C")
                .arg(&repo)
                .args(args)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .status()?;
            assert!(status.success(), "git {args:?} failed");
            Ok(())
        };
        plain(&["init", "--quiet"])?;
        write(&repo.join("tracked.txt"), "tracked\n")?;
        write(&repo.join(".gitignore"), "ignored.log\n")?;
        plain(&["add", "tracked.txt", ".gitignore"])?;
        plain(&[
            "-c",
            "user.name=test",
            "-c",
            "user.email=test@localhost",
            "commit",
            "--quiet",
            "-m",
            "first",
        ])?;
        write(&repo.join("untracked.txt"), "untracked\n")?;
        write(&repo.join("ignored.log"), "ignored\n")?;
        let marker = root.join("fsmonitor-ran");
        let config = repo.join(".git/config");
        let mut text = fs::read_to_string(&config)?;
        text.push_str(&format!(
            "[core]\n\tfsmonitor = touch {}\n",
            marker.display()
        ));
        fs::write(&config, text)?;
        Ok(repo)
    }

    #[test]
    fn the_snapshot_holds_tracked_and_untracked_files_but_not_ignored_ones() -> TestResult {
        let root = tempfile::tempdir()?;
        let repo = repo_with_traps(root.path())?;
        let session = root.path().join("session");
        fs::create_dir_all(&session)?;
        let commit = create(&repo, &session)?;
        assert!(commit.len() >= 40);
        let target = root.path().join("restored");
        restore_into(&session, &target)?;
        assert_eq!(fs::read_to_string(target.join("tracked.txt"))?, "tracked\n");
        assert_eq!(
            fs::read_to_string(target.join("untracked.txt"))?,
            "untracked\n"
        );
        assert!(target.join(".gitignore").is_file());
        assert!(!target.join("ignored.log").exists());
        Ok(())
    }

    #[test]
    fn the_repo_is_not_written_by_the_snapshot() -> TestResult {
        let root = tempfile::tempdir()?;
        let repo = repo_with_traps(root.path())?;
        let index_before = fs::read(repo.join(".git/index"))?;
        let config_before = fs::read(repo.join(".git/config"))?;
        let session = root.path().join("session");
        fs::create_dir_all(&session)?;
        create(&repo, &session)?;
        assert_eq!(fs::read(repo.join(".git/index"))?, index_before);
        assert_eq!(fs::read(repo.join(".git/config"))?, config_before);
        Ok(())
    }

    #[test]
    fn the_repos_own_git_config_does_not_run_during_the_snapshot() -> TestResult {
        let root = tempfile::tempdir()?;
        let repo = repo_with_traps(root.path())?;
        let session = root.path().join("session");
        fs::create_dir_all(&session)?;
        create(&repo, &session)?;
        assert!(
            !root.path().join("fsmonitor-ran").exists(),
            "the repo's core.fsmonitor was run"
        );
        Ok(())
    }

    #[test]
    fn restoring_into_a_non_empty_directory_is_refused() -> TestResult {
        let root = tempfile::tempdir()?;
        let repo = repo_with_traps(root.path())?;
        let session = root.path().join("session");
        fs::create_dir_all(&session)?;
        create(&repo, &session)?;
        let target = root.path().join("occupied");
        write(&target.join("keep.txt"), "mine\n")?;
        assert!(matches!(
            restore_into(&session, &target),
            Err(SnapshotError::TargetNotEmpty(_))
        ));
        assert_eq!(fs::read_to_string(target.join("keep.txt"))?, "mine\n");
        Ok(())
    }

    #[test]
    fn only_32_lowercase_hex_digits_are_session_ids() {
        assert!(is_session_id("a718a3b91b21d03e806200a10513a1a0"));
        assert!(!is_session_id("../../etc"));
        assert!(!is_session_id("A718A3B91B21D03E806200A10513A1A0"));
        assert!(!is_session_id("a718a3b91b21d03e806200a10513a1a"));
        assert!(!is_session_id(""));
    }
}
