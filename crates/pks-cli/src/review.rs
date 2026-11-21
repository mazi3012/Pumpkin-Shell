//! `pumpkin-shell review <session>` and `pumpkin-shell allow-write <session> <path>`.
//!
//! The sandbox never writes a protected path in the repo. Its writes stay in
//! the session's staging copies (PRD FR-WS). Approving a staged write copies it
//! into the repo. Approval is refused when the repo file changed after the
//! session started, so a later edit by the user is never overwritten.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use pks_core::paths::data_dir;
use pks_detect::SessionInfo;

/// Exit code for a session that cannot be found or reviewed.
const EXIT_NOT_FOUND: u8 = 2;
/// Exit code for a write that could not be applied.
const EXIT_FAILED: u8 = 1;

/// Where a staged file stands against the session's starting state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    /// The sandbox left the file as it was at the start. Nothing to review.
    Unchanged,
    /// The sandbox added or changed the file, and the repo still matches the
    /// start, so approval can apply it.
    Pending,
    /// The repo file changed after the session started. Approval is refused.
    Conflict,
}

/// Compares a staged file with its baseline (the snapshot copy, `None` for a
/// new file) and with the repo's current file (`None` when absent). Pure.
fn classify(staged: &[u8], baseline: Option<&[u8]>, repo: Option<&[u8]>) -> Status {
    if baseline == Some(staged) {
        Status::Unchanged
    } else if repo == baseline {
        Status::Pending
    } else {
        Status::Conflict
    }
}

/// One staged file the sandbox changed.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Item {
    /// Path from the repo root, `/`-separated.
    rel: String,
    staged: PathBuf,
    status: Status,
}

/// The session's repo and every staged file that differs from the start.
struct Review {
    repo: PathBuf,
    items: Vec<Item>,
}

/// Looks up the session, prints why and returns `None` when it cannot be used.
fn find_session(session: &str) -> Option<SessionInfo> {
    let Some(data) = data_dir(&pks_core::paths::process_env) else {
        eprintln!("review: cannot find the data directory");
        return None;
    };
    let Some(info) = SessionInfo::find(&data, session) else {
        eprintln!("review: session {session} not found");
        return None;
    };
    Some(info)
}

/// Every regular file under `root`, as (path relative to `root`, path). Links
/// are not followed.
fn staged_files(root: &Path) -> std::io::Result<Vec<(String, PathBuf)>> {
    let mut out = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            let meta = std::fs::symlink_metadata(&path)?;
            if meta.file_type().is_dir() {
                pending.push(path);
            } else if meta.file_type().is_file() {
                let rel = path.strip_prefix(root).map_err(std::io::Error::other)?;
                let text = rel
                    .components()
                    .map(|part| part.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/");
                out.push((text, path));
            }
        }
    }
    out.sort();
    Ok(out)
}

/// Works out what the session changed. Reads the repo and the staging copies,
/// and compares them with the snapshot restored into a folder of the session.
fn gather(info: &SessionInfo) -> Result<Review, String> {
    let repo_text = std::fs::read_to_string(info.dir.join(pks_detect::REPO_FILE)).map_err(|e| {
        format!(
            "cannot read the repo path (sessions from before this version cannot be reviewed): {e}"
        )
    })?;
    let repo = PathBuf::from(repo_text.trim_end());
    let baseline = info.dir.join("review-baseline");
    // A folder left by an earlier review that was cut short is replaced.
    let _ = std::fs::remove_dir_all(&baseline);
    let items = compare(info, &repo, &baseline);
    let _ = std::fs::remove_dir_all(&baseline);
    Ok(Review {
        repo,
        items: items?,
    })
}

/// The staged files that differ from the start. `baseline` is an empty folder
/// the snapshot is restored into.
fn compare(info: &SessionInfo, repo: &Path, baseline: &Path) -> Result<Vec<Item>, String> {
    let staging = info.dir.join("staging");
    if !staging.is_dir() {
        return Ok(Vec::new());
    }
    pks_core::snapshot::restore_into(&info.dir, baseline)
        .map_err(|e| format!("cannot read the session snapshot: {e}"))?;
    let mut items = Vec::new();
    let files = staged_files(&staging).map_err(|e| format!("cannot list the staged files: {e}"))?;
    for (rel, staged) in files {
        let staged_bytes = std::fs::read(&staged).map_err(|e| format!("cannot read {rel}: {e}"))?;
        let start = read_optional(&baseline.join(&rel))?;
        let repo_file = read_optional(&repo.join(&rel))?;
        let status = classify(&staged_bytes, start.as_deref(), repo_file.as_deref());
        if status != Status::Unchanged {
            items.push(Item {
                rel,
                staged,
                status,
            });
        }
    }
    Ok(items)
}

/// The file's bytes, or `None` when it does not exist. A symbolic link is an
/// error: it is never followed for a comparison.
fn read_optional(path: &Path) -> Result<Option<Vec<u8>>, String> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(format!(
            "{} is a symbolic link; it is not compared",
            path.display()
        )),
        Ok(_) => std::fs::read(path)
            .map(Some)
            .map_err(|e| format!("cannot read {}: {e}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("cannot inspect {}: {error}", path.display())),
    }
}

/// Copies one staged file into the repo. Refused when the target or a parent
/// inside the repo is a symbolic link.
fn apply(repo: &Path, item: &Item) -> Result<(), String> {
    let target = repo.join(&item.rel);
    let mut current = repo.to_path_buf();
    for part in item.rel.split('/') {
        current.push(part);
        if let Ok(meta) = std::fs::symlink_metadata(&current)
            && meta.file_type().is_symlink()
        {
            return Err(format!(
                "{} is a symbolic link; not writing through it",
                current.display()
            ));
        }
    }
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    }
    // fs::copy keeps the staged file's permissions, so an executable hook
    // stays executable.
    std::fs::copy(&item.staged, &target)
        .map(|_| ())
        .map_err(|e| format!("cannot write {}: {e}", target.display()))
}

fn print_item(number: usize, total: usize, item: &Item) {
    let note = match item.status {
        Status::Pending => "changed by the sandbox",
        Status::Conflict => "the repo file changed after the session started; approval is refused",
        Status::Unchanged => "unchanged",
    };
    eprintln!("[{number}/{total}] {}: {note}", item.rel);
}

/// `pumpkin-shell review <session>`: approve or reject each staged write.
pub fn run(session: &str) -> ExitCode {
    let Some(info) = find_session(session) else {
        return ExitCode::from(EXIT_NOT_FOUND);
    };
    let review = match gather(&info) {
        Ok(review) => review,
        Err(message) => {
            eprintln!("review: {message}");
            return ExitCode::from(EXIT_NOT_FOUND);
        }
    };
    if review.items.is_empty() {
        eprintln!("review: no staged writes to review");
        return ExitCode::SUCCESS;
    }

    let total = review.items.len();
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut failed = false;
    for (index, item) in review.items.iter().enumerate() {
        print_item(index + 1, total, item);
        if item.status == Status::Conflict {
            continue;
        }
        eprintln!("  [a]pprove / [r]eject / [s]kip / [q]uit");
        loop {
            let _ = stdout.write_all(b"choice: ");
            let _ = stdout.flush();
            let mut line = String::new();
            if stdin.lock().read_line(&mut line).unwrap_or(0) == 0 {
                return finish(failed);
            }
            match line.trim().to_lowercase().as_str() {
                "a" | "approve" => {
                    match apply(&review.repo, item) {
                        Ok(()) => eprintln!("  applied: {}", item.rel),
                        Err(message) => {
                            failed = true;
                            eprintln!("  not applied: {message}");
                        }
                    }
                    break;
                }
                "r" | "reject" => {
                    eprintln!("  rejected: {} (the repo is unchanged)", item.rel);
                    break;
                }
                "s" | "skip" => {
                    eprintln!("  skipped: {}", item.rel);
                    break;
                }
                "q" | "quit" => return finish(failed),
                _ => {}
            }
        }
    }
    finish(failed)
}

/// Ends a review. Exit 1 when an approved write could not be applied.
fn finish(failed: bool) -> ExitCode {
    eprintln!("review: done");
    if failed {
        ExitCode::from(EXIT_FAILED)
    } else {
        ExitCode::SUCCESS
    }
}

/// `pumpkin-shell allow-write <session> <path>`: approves one staged write,
/// with the same checks as `review`. `path` is relative to the repo root.
pub fn allow_write(session: &str, path: &str) -> ExitCode {
    let Some(info) = find_session(session) else {
        return ExitCode::from(EXIT_NOT_FOUND);
    };
    let review = match gather(&info) {
        Ok(review) => review,
        Err(message) => {
            eprintln!("allow-write: {message}");
            return ExitCode::from(EXIT_NOT_FOUND);
        }
    };
    let wanted = path.trim_start_matches("./").trim_end_matches('/');
    let Some(item) = review.items.iter().find(|item| item.rel == wanted) else {
        eprintln!("allow-write: session {session} has no staged write to {wanted}");
        return ExitCode::from(EXIT_NOT_FOUND);
    };
    if item.status == Status::Conflict {
        eprintln!(
            "allow-write: {wanted} changed in the repo after the session started, so it is not applied. Check the file, then run `pumpkin-shell review {session}`."
        );
        return ExitCode::from(EXIT_FAILED);
    }
    match apply(&review.repo, item) {
        Ok(()) => {
            eprintln!("allow-write: applied {wanted}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("allow-write: not applied: {message}");
            ExitCode::from(EXIT_FAILED)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_the_sandbox_did_not_change_is_not_reviewed() {
        assert_eq!(classify(b"a", Some(b"a"), Some(b"a")), Status::Unchanged);
        assert_eq!(classify(b"a", Some(b"a"), None), Status::Unchanged);
    }

    #[test]
    fn a_change_to_a_file_the_repo_still_matches_is_pending() {
        assert_eq!(
            classify(b"new", Some(b"old"), Some(b"old")),
            Status::Pending
        );
    }

    #[test]
    fn a_new_file_is_pending_only_while_the_repo_has_no_such_file() {
        assert_eq!(classify(b"new", None, None), Status::Pending);
        assert_eq!(
            classify(b"new", None, Some(b"someone else's")),
            Status::Conflict
        );
    }

    #[test]
    fn a_repo_edit_made_after_the_start_is_a_conflict_and_a_deletion_too() {
        assert_eq!(
            classify(b"new", Some(b"old"), Some(b"edited")),
            Status::Conflict
        );
        assert_eq!(classify(b"new", Some(b"old"), None), Status::Conflict);
    }

    #[test]
    fn approve_copies_the_staged_bytes_and_keeps_the_mode() -> Result<(), Box<dyn std::error::Error>>
    {
        let dir = tempfile::tempdir()?;
        let repo = dir.path().join("repo");
        let staged = dir.path().join("staged-hook");
        std::fs::create_dir_all(repo.join(".git/hooks"))?;
        std::fs::write(&staged, "#!/bin/sh\necho hi\n")?;
        let item = Item {
            rel: ".git/hooks/pre-commit".to_owned(),
            staged,
            status: Status::Pending,
        };
        apply(&repo, &item)?;
        assert_eq!(
            std::fs::read_to_string(repo.join(".git/hooks/pre-commit"))?,
            "#!/bin/sh\necho hi\n"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn approve_refuses_to_write_through_a_symbolic_link() -> Result<(), Box<dyn std::error::Error>>
    {
        let dir = tempfile::tempdir()?;
        let repo = dir.path().join("repo");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&repo)?;
        std::fs::create_dir_all(&outside)?;
        std::os::unix::fs::symlink(&outside, repo.join(".vscode"))?;
        let staged = dir.path().join("staged");
        std::fs::write(&staged, "{}")?;
        let item = Item {
            rel: ".vscode/settings.json".to_owned(),
            staged,
            status: Status::Pending,
        };
        assert!(apply(&repo, &item).is_err());
        assert!(!outside.join("settings.json").exists());
        Ok(())
    }
}
