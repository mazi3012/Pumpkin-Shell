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

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use crate::{Finding, RuleId, Severity};

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
pub(crate) fn git(session_dir: &Path) -> Result<Command, SnapshotError> {
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

/// The rule for many files gone from the repo during a session (PRD FR-DET).
pub const WS_MASS_DELETE: RuleId = RuleId::new("WS-MASS-DELETE");

/// The paths in the snapshot, as git stores them (`/`-separated, relative to
/// the repo root).
///
/// # Errors
/// Fails when git fails or its output is not read.
pub fn paths(session_dir: &Path) -> Result<Vec<String>, SnapshotError> {
    let bare = session_dir.join(SNAPSHOT_DIR);
    let mut list = git(session_dir)?;
    list.arg(format!("--git-dir={}", bare.display())).args([
        "ls-tree",
        "-r",
        "-z",
        "--name-only",
        "HEAD",
    ]);
    let output = list.output().map_err(|source| SnapshotError::Io {
        context: "cannot run git ls-tree".to_owned(),
        source,
    })?;
    if !output.status.success() {
        return Err(SnapshotError::Git(format!(
            "ls-tree failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
        .map(|name| String::from_utf8_lossy(name).into_owned())
        .collect())
}

/// The paths that are no longer in `repo`. A path counts as present when
/// anything is at it, including a symlink.
#[must_use]
pub fn missing_in(repo: &Path, paths: &[String]) -> Vec<String> {
    paths
        .iter()
        .filter(|path| repo.join(path.as_str()).symlink_metadata().is_err())
        .cloned()
        .collect()
}

/// Whether `missing` files out of `total` is a mass delete: more than 50
/// files, or more than 20% of the files (PRD FR-DET, WS-MASS-DELETE).
#[must_use]
pub fn is_mass_delete(total: usize, missing: usize) -> bool {
    missing > 50 || missing.saturating_mul(5) > total
}

/// Checks the repo against its snapshot. Returns a HIGH finding with a
/// restore hint when the session deleted too many files.
///
/// # Errors
/// Fails when the snapshot cannot be read.
pub fn check_mass_delete(
    repo: &Path,
    session_dir: &Path,
    session_id: &str,
) -> Result<Option<Finding>, SnapshotError> {
    let all = paths(session_dir)?;
    let missing = missing_in(repo, &all);
    if !is_mass_delete(all.len(), missing.len()) {
        return Ok(None);
    }
    Ok(Some(Finding {
        rule: WS_MASS_DELETE,
        severity: Severity::High,
        target: repo.display().to_string(),
        message: format!(
            "{} of {} files from the start of the session are gone",
            missing.len(),
            all.len()
        ),
        fix: format!("Restore them with: pumpkin-shell restore {session_id}"),
    }))
}

/// The blob id of every file in the snapshot, by path (PRD FR-WS, watched
/// paths). Symbolic links are blobs in git too, so they are included.
///
/// # Errors
/// Fails when git fails or its output is not read.
pub fn blob_ids(session_dir: &Path) -> Result<BTreeMap<String, String>, SnapshotError> {
    let bare = session_dir.join(SNAPSHOT_DIR);
    let mut list = git(session_dir)?;
    list.arg(format!("--git-dir={}", bare.display()))
        .args(["ls-tree", "-r", "-z", "HEAD"]);
    let output = list.output().map_err(|source| SnapshotError::Io {
        context: "cannot run git ls-tree".to_owned(),
        source,
    })?;
    if !output.status.success() {
        return Err(SnapshotError::Git(format!(
            "ls-tree failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let mut out = BTreeMap::new();
    for record in output.stdout.split(|byte| *byte == 0) {
        // `<mode> SP <type> SP <sha> TAB <path>`
        let Some(tab) = record.iter().position(|byte| *byte == b'\t') else {
            continue;
        };
        let (meta, path) = record.split_at(tab);
        let fields: Vec<&[u8]> = meta.split(|byte| *byte == b' ').collect();
        if fields.len() == 3 && fields[1] == b"blob" {
            let sha = String::from_utf8_lossy(fields[2]).into_owned();
            out.insert(String::from_utf8_lossy(&path[1..]).into_owned(), sha);
        }
    }
    Ok(out)
}

/// The paths in `repo` that git ignores under its `.gitignore` rules, read
/// with the snapshot's empty config. They are not part of any snapshot.
///
/// # Errors
/// Fails when git fails or its output is not read.
pub fn ignored_paths(session_dir: &Path, repo: &Path) -> Result<BTreeSet<String>, SnapshotError> {
    let bare = session_dir.join(SNAPSHOT_DIR);
    let mut list = git(session_dir)?;
    list.arg(format!("--git-dir={}", bare.display()))
        .arg(format!("--work-tree={}", repo.display()))
        .args([
            "ls-files",
            "-z",
            "--others",
            "--ignored",
            "--exclude-standard",
        ]);
    let output = list.output().map_err(|source| SnapshotError::Io {
        context: "cannot run git ls-files".to_owned(),
        source,
    })?;
    if !output.status.success() {
        return Err(SnapshotError::Git(format!(
            "ls-files failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
        .map(|name| String::from_utf8_lossy(name).into_owned())
        .collect())
}

/// The git blob id of each file, as git would store it. Filters are off, so
/// the bytes are hashed as they are. Paths with a newline cannot be sent
/// through stdin and are reported as an error.
///
/// # Errors
/// Fails when git fails, or a path has a newline.
pub fn hash_files(session_dir: &Path, files: &[PathBuf]) -> Result<Vec<String>, SnapshotError> {
    if files.is_empty() {
        return Ok(Vec::new());
    }
    let mut input = Vec::new();
    for file in files {
        let text = file.to_string_lossy();
        if text.contains('\n') {
            return Err(SnapshotError::Git(format!(
                "{} has a newline in its name",
                file.display()
            )));
        }
        input.extend_from_slice(text.as_bytes());
        input.push(b'\n');
    }
    let mut hash = git(session_dir)?;
    hash.args(["hash-object", "--no-filters", "--stdin-paths"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = hash.spawn().map_err(|source| SnapshotError::Io {
        context: "cannot run git hash-object".to_owned(),
        source,
    })?;
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        stdin
            .write_all(&input)
            .map_err(|source| SnapshotError::Io {
                context: "cannot send paths to git hash-object".to_owned(),
                source,
            })?;
    }
    let output = child
        .wait_with_output()
        .map_err(|source| SnapshotError::Io {
            context: "cannot read git hash-object".to_owned(),
            source,
        })?;
    if !output.status.success() {
        return Err(SnapshotError::Git(format!(
            "hash-object failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let ids: Vec<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::to_owned)
        .collect();
    if ids.len() != files.len() {
        return Err(SnapshotError::Git(format!(
            "hash-object returned {} ids for {} files",
            ids.len(),
            files.len()
        )));
    }
    Ok(ids)
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

    #[test]
    fn the_mass_delete_thresholds_follow_the_prd() {
        // 20% of 100 is 20; more than 20% is 21.
        assert!(!is_mass_delete(100, 20));
        assert!(is_mass_delete(100, 21));
        // Over 50 files is a mass delete on its own.
        assert!(is_mass_delete(1000, 51));
        assert!(!is_mass_delete(1000, 50));
        assert!(is_mass_delete(1000, 150));
        assert!(!is_mass_delete(0, 0));
        assert!(is_mass_delete(10, 3));
    }

    #[test]
    fn deleting_a_whole_source_directory_is_a_high_finding_with_a_restore_hint() -> TestResult {
        let root = tempfile::tempdir()?;
        let repo = root.path().join("repo");
        for index in 0..60 {
            write(&repo.join(format!("src/file{index}.rs")), "x\n")?;
        }
        write(&repo.join("README.md"), "keep\n")?;
        let session = root.path().join("session");
        fs::create_dir_all(&session)?;
        create(&repo, &session)?;
        assert!(check_mass_delete(&repo, &session, "sid")?.is_none());
        fs::remove_dir_all(repo.join("src"))?;
        let finding = check_mass_delete(&repo, &session, "sid")?
            .ok_or("expected a finding after the delete")?;
        assert_eq!(finding.rule.as_str(), "WS-MASS-DELETE");
        assert_eq!(finding.severity, Severity::High);
        assert!(
            finding.message.starts_with("60 of 61"),
            "{}",
            finding.message
        );
        assert_eq!(finding.fix, "Restore them with: pumpkin-shell restore sid");
        Ok(())
    }

    #[test]
    fn a_few_deleted_files_in_a_large_repo_are_not_a_mass_delete() -> TestResult {
        let root = tempfile::tempdir()?;
        let repo = root.path().join("repo");
        for index in 0..100 {
            write(&repo.join(format!("f{index}.txt")), "x\n")?;
        }
        let session = root.path().join("session");
        fs::create_dir_all(&session)?;
        create(&repo, &session)?;
        for index in 0..5 {
            fs::remove_file(repo.join(format!("f{index}.txt")))?;
        }
        assert!(check_mass_delete(&repo, &session, "sid")?.is_none());
        Ok(())
    }
}
