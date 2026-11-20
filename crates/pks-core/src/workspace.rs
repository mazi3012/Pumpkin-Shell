//! Protected paths: files and directories that run later on the host, or
//! that switch on auto-approve. The sandbox gets a staged copy of each, so a
//! write lands in the session directory and never in the repo (PRD FR-WS,
//! PHASES 10.1).
//!
//! How it works:
//! - each protected path that exists is copied to `<session>/staging/<path>`;
//! - each protected path that does not exist gets an empty staged file or
//!   directory, and an empty mount point is made in the repo for the sandbox
//!   to mount over. Mount points made here are removed again at the end, when
//!   they are still empty;
//! - the parent directories (`.git`, `.kiro`) are mounted over themselves, so
//!   the sandbox cannot rename them away and put a new, unprotected one in
//!   their place (checked with bubblewrap on this machine: a mount does not
//!   protect its parent);
//! - at the end, each staged copy is compared with what it was at the start,
//!   and every change is a `WS-PROTECTED-WRITE` finding.
//!
//! Symlinks are refused anywhere on a protected path, because a mount over a
//! symlink would follow it out of the repo.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

use crate::snapshot::{SnapshotError, git as git_in};
use crate::{Finding, RuleId, Severity, hex};

/// The rule for a write to a protected path (PRD FR-DET).
pub const WS_PROTECTED_WRITE: RuleId = RuleId::new("WS-PROTECTED-WRITE");

/// Most files that may be staged. A repo cannot make the session copy more.
const MAX_FILES: usize = 10_000;
/// Most bytes that may be staged.
const MAX_BYTES: u64 = 64 * 1024 * 1024;
/// Changes named in one finding's message.
const MAX_NAMED: usize = 5;

/// Whether a protected path is a file or a directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    File,
    Dir,
}

/// The protected paths, relative to the repo root (PRD FR-WS "Protected").
const PROTECTED: [(&str, Kind); 12] = [
    (".git/hooks", Kind::Dir),
    (".git/config", Kind::File),
    (".envrc", Kind::File),
    (".yarnrc.yml", Kind::File),
    (".npmrc", Kind::File),
    (".vscode", Kind::Dir),
    (".cursor", Kind::Dir),
    (".windsurf", Kind::Dir),
    (".kiro/settings", Kind::Dir),
    (".kiro/hooks", Kind::Dir),
    (".mcp.json", Kind::File),
    ("pumpkin-shell.toml", Kind::File),
];

/// Why staging could not be prepared. The session must not start.
#[derive(Debug, thiserror::Error)]
pub enum WorkspaceError {
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: io::Error,
    },
    #[error(
        "{0} is a symbolic link; a protected path cannot be one. Replace it with the real file or directory"
    )]
    Symlink(String),
    #[error("{0} is a {1}, but a protected path of that name must be a {2}")]
    WrongType(String, &'static str, &'static str),
    #[error("{0} is not a regular file, directory or symbolic link, so it cannot be staged")]
    Special(String),
    #[error("the protected paths hold more than {MAX_FILES} files or {MAX_BYTES} bytes")]
    TooLarge,
    #[error("core.hooksPath points at the whole repo, which cannot be protected")]
    HooksPathIsRepo,
    #[error("core.hooksPath inside the repo is not valid UTF-8")]
    HooksPathNotUtf8,
    #[error("{0}")]
    Git(String),
}

fn io_error(context: impl Into<String>, source: io::Error) -> WorkspaceError {
    WorkspaceError::Io {
        context: context.into(),
        source,
    }
}

impl From<SnapshotError> for WorkspaceError {
    fn from(error: SnapshotError) -> Self {
        Self::Git(error.to_string())
    }
}

/// One path to bind inside the sandbox, below the repo's mount point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    /// Path from the repo root, `/`-separated.
    pub rel: String,
    /// Host path bound there: the staged copy, or for a parent directory,
    /// the directory itself.
    pub source: PathBuf,
}

/// What changed in a staged path since the session started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChangeKind {
    Added,
    Modified,
    Removed,
}

/// One change inside a protected path.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Change {
    /// Path from the repo root.
    path: String,
    kind: ChangeKind,
}

/// A protected path with its staged copy and its starting state.
#[derive(Debug)]
struct Protected {
    rel: String,
    staged: PathBuf,
    baseline: BTreeMap<String, String>,
}

/// The staging of one session.
#[derive(Debug)]
pub struct Staging {
    mounts: Vec<Mount>,
    protected: Vec<Protected>,
    /// Paths made in the repo as mount points, in creation order.
    created: Vec<PathBuf>,
}

fn is_symlink(path: &Path) -> bool {
    path.symlink_metadata()
        .is_ok_and(|meta| meta.file_type().is_symlink())
}

/// Resolves a `core.hooksPath` value to a repo-relative path. `None` when it
/// points outside the repo, where the sandbox cannot write.
fn hooks_path_in_repo(repo: &Path, value: &str) -> Result<Option<String>, WorkspaceError> {
    // Git expands a leading `~` to the user's home, which is not in the repo.
    if value.starts_with('~') {
        return Ok(None);
    }
    let path = Path::new(value);
    let relative: PathBuf = if path.is_absolute() {
        let resolved = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        match resolved.strip_prefix(repo) {
            Ok(inside) => inside.to_path_buf(),
            Err(_) => return Ok(None),
        }
    } else {
        path.to_path_buf()
    };
    let mut parts: Vec<String> = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(name) => {
                parts.push(
                    name.to_str()
                        .ok_or(WorkspaceError::HooksPathNotUtf8)?
                        .to_owned(),
                );
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if parts.pop().is_none() {
                    return Ok(None);
                }
            }
            Component::RootDir | Component::Prefix(_) => return Ok(None),
        }
    }
    if parts.is_empty() {
        return Err(WorkspaceError::HooksPathIsRepo);
    }
    Ok(Some(parts.join("/")))
}

/// The repo's `core.hooksPath`, read from `.git/config` without running git
/// hooks or filters.
fn configured_hooks_path(
    repo: &Path,
    session_dir: &Path,
) -> Result<Option<String>, WorkspaceError> {
    let config = repo.join(".git").join("config");
    if !config.is_file() {
        return Ok(None);
    }
    let mut read = git_in(session_dir)?;
    read.arg("config")
        .arg("--file")
        .arg(&config)
        .args(["--get", "core.hooksPath"]);
    let output = read
        .output()
        .map_err(|source| io_error("cannot run git config", source))?;
    match output.status.code() {
        Some(0) => {
            let value = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            if value.is_empty() {
                Ok(None)
            } else {
                hooks_path_in_repo(repo, &value)
            }
        }
        // Exit code 1: the key is not set.
        Some(1) => Ok(None),
        _ => Err(WorkspaceError::Git(format!(
            "git config failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))),
    }
}

/// Every proper parent of `rel`: `.git/hooks` has `.git`.
fn parents(rel: &str) -> Vec<String> {
    let parts: Vec<&str> = rel.split('/').collect();
    (1..parts.len()).map(|n| parts[..n].join("/")).collect()
}

/// Refuses a symlink anywhere along `rel`, and a leaf of the wrong type.
fn check_path(repo: &Path, rel: &str, kind: Kind) -> Result<(), WorkspaceError> {
    let mut current = repo.to_path_buf();
    let parts: Vec<&str> = rel.split('/').collect();
    for (index, part) in parts.iter().enumerate() {
        current.push(part);
        let Ok(meta) = current.symlink_metadata() else {
            // Missing from here on: nothing below it exists either.
            return Ok(());
        };
        let shown = parts[..=index].join("/");
        if meta.file_type().is_symlink() {
            return Err(WorkspaceError::Symlink(shown));
        }
        let last = index + 1 == parts.len();
        if last {
            match (kind, meta.is_dir()) {
                (Kind::Dir, false) => {
                    return Err(WorkspaceError::WrongType(shown, "file", "directory"));
                }
                (Kind::File, true) => {
                    return Err(WorkspaceError::WrongType(shown, "directory", "file"));
                }
                _ => {}
            }
        } else if !meta.is_dir() {
            return Err(WorkspaceError::WrongType(shown, "file", "directory"));
        }
    }
    Ok(())
}

/// Counts what a tree adds up to, so a repo cannot make staging huge.
#[derive(Default)]
struct Budget {
    files: usize,
    bytes: u64,
}

impl Budget {
    fn take(&mut self, bytes: u64) -> Result<(), WorkspaceError> {
        self.files += 1;
        self.bytes = self.bytes.saturating_add(bytes);
        if self.files > MAX_FILES || self.bytes > MAX_BYTES {
            return Err(WorkspaceError::TooLarge);
        }
        Ok(())
    }
}

#[cfg(unix)]
fn make_symlink(target: &Path, link: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(not(unix))]
fn make_symlink(_target: &Path, _link: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "symbolic links are not staged on this platform",
    ))
}

/// Copies `source` to `dest`, recursively. Symlinks are copied as links and
/// never followed. Anything but a file, directory or link is refused.
fn copy_tree(source: &Path, dest: &Path, budget: &mut Budget) -> Result<(), WorkspaceError> {
    let meta = source
        .symlink_metadata()
        .map_err(|e| io_error(format!("cannot read {}", source.display()), e))?;
    let shown = source.display().to_string();
    if meta.file_type().is_symlink() {
        budget.take(0)?;
        let target =
            fs::read_link(source).map_err(|e| io_error(format!("cannot read link {shown}"), e))?;
        make_symlink(&target, dest).map_err(|e| io_error(format!("cannot copy link {shown}"), e))
    } else if meta.is_dir() {
        budget.take(0)?;
        fs::create_dir(dest)
            .map_err(|e| io_error(format!("cannot create {}", dest.display()), e))?;
        let entries = fs::read_dir(source)
            .map_err(|e| io_error(format!("cannot read directory {shown}"), e))?;
        for entry in entries {
            let entry = entry.map_err(|e| io_error(format!("cannot read directory {shown}"), e))?;
            copy_tree(&entry.path(), &dest.join(entry.file_name()), budget)?;
        }
        fs::set_permissions(dest, meta.permissions())
            .map_err(|e| io_error(format!("cannot set permissions on {}", dest.display()), e))
    } else if meta.is_file() {
        budget.take(meta.len())?;
        fs::copy(source, dest)
            .map(drop)
            .map_err(|e| io_error(format!("cannot copy {shown}"), e))
    } else {
        Err(WorkspaceError::Special(shown))
    }
}

#[cfg(unix)]
fn mode_text(meta: &fs::Metadata) -> String {
    use std::os::unix::fs::PermissionsExt;
    format!("{:o}", meta.permissions().mode() & 0o7777)
}

#[cfg(not(unix))]
fn mode_text(meta: &fs::Metadata) -> String {
    if meta.permissions().readonly() {
        "ro"
    } else {
        "rw"
    }
    .to_owned()
}

/// A fingerprint of every entry under `root`, keyed by path from `root`
/// (`""` for `root` itself). The mode is part of it, so making a hook
/// executable counts as a change.
fn digest(root: &Path) -> Result<BTreeMap<String, String>, WorkspaceError> {
    let mut out = BTreeMap::new();
    let mut budget = Budget::default();
    digest_into(root, "", &mut out, &mut budget)?;
    Ok(out)
}

fn digest_into(
    path: &Path,
    key: &str,
    out: &mut BTreeMap<String, String>,
    budget: &mut Budget,
) -> Result<(), WorkspaceError> {
    let meta = path
        .symlink_metadata()
        .map_err(|e| io_error(format!("cannot read {}", path.display()), e))?;
    let shown = path.display().to_string();
    if meta.file_type().is_symlink() {
        budget.take(0)?;
        let target =
            fs::read_link(path).map_err(|e| io_error(format!("cannot read link {shown}"), e))?;
        out.insert(key.to_owned(), format!("link:{}", target.display()));
    } else if meta.is_dir() {
        budget.take(0)?;
        out.insert(key.to_owned(), format!("dir:{}", mode_text(&meta)));
        let entries = fs::read_dir(path)
            .map_err(|e| io_error(format!("cannot read directory {shown}"), e))?;
        for entry in entries {
            let entry = entry.map_err(|e| io_error(format!("cannot read directory {shown}"), e))?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let child = if key.is_empty() {
                name.into_owned()
            } else {
                format!("{key}/{name}")
            };
            digest_into(&entry.path(), &child, out, budget)?;
        }
    } else if meta.is_file() {
        budget.take(meta.len())?;
        let bytes = fs::read(path).map_err(|e| io_error(format!("cannot read {shown}"), e))?;
        out.insert(
            key.to_owned(),
            format!("file:{}:{}", hex::sha256(&bytes), mode_text(&meta)),
        );
    } else {
        return Err(WorkspaceError::Special(shown));
    }
    Ok(())
}

/// Removes mount points made by `prepare`, newest first, when they are still
/// empty. Anything with content is left alone: it is not ours to delete.
fn remove_created(created: &[PathBuf]) {
    for path in created.iter().rev() {
        let Ok(meta) = path.symlink_metadata() else {
            continue;
        };
        if meta.is_dir() {
            let _ = fs::remove_dir(path);
        } else if meta.is_file() && meta.len() == 0 {
            let _ = fs::remove_file(path);
        }
    }
}

/// Makes the mount point for a protected path that is missing, with any
/// missing parents. Everything made is recorded in `created`.
fn make_mount_point(
    repo: &Path,
    rel: &str,
    kind: Kind,
    created: &mut Vec<PathBuf>,
) -> Result<(), WorkspaceError> {
    for parent in parents(rel) {
        let path = repo.join(&parent);
        if !path.exists() {
            fs::create_dir(&path)
                .map_err(|e| io_error(format!("cannot create {}", path.display()), e))?;
            created.push(path);
        }
    }
    let leaf = repo.join(rel);
    match kind {
        Kind::Dir => fs::create_dir(&leaf),
        Kind::File => fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&leaf)
            .map(drop),
    }
    .map_err(|e| io_error(format!("cannot create {}", leaf.display()), e))?;
    created.push(leaf);
    Ok(())
}

/// The protected paths for this repo: the fixed list, plus the target of
/// `core.hooksPath` when it is inside the repo. Paths under another
/// protected path, and `.git` paths when `.git` is not a directory, are left
/// out. Sorted, so a parent comes before what is under it.
fn plan(repo: &Path, session_dir: &Path) -> Result<Vec<(String, Kind)>, WorkspaceError> {
    let git_dir = repo.join(".git");
    if is_symlink(&git_dir) {
        return Err(WorkspaceError::Symlink(".git".to_owned()));
    }
    // A worktree has a `.git` file, and a plain directory has no `.git`. In
    // both cases there is no `.git/hooks` here to protect, and making a
    // `.git` directory would change what the repo is.
    let has_git_dir = git_dir.is_dir();
    let mut paths: Vec<(String, Kind)> = PROTECTED
        .iter()
        .filter(|(rel, _)| has_git_dir || !rel.starts_with(".git/"))
        .map(|(rel, kind)| ((*rel).to_owned(), *kind))
        .collect();
    if has_git_dir && let Some(extra) = configured_hooks_path(repo, session_dir)? {
        paths.push((extra, Kind::Dir));
    }
    paths.sort();
    paths.dedup();
    let all: Vec<String> = paths.iter().map(|(rel, _)| rel.clone()).collect();
    paths.retain(|(rel, _)| !parents(rel).iter().any(|parent| all.contains(parent)));
    Ok(paths)
}

/// Stages the protected paths of `repo` for a session whose files are in
/// `session_dir`.
///
/// # Errors
/// Fails when a protected path is a symlink or the wrong type, when a staged
/// tree is too large or holds a special file, or when a copy fails. Nothing
/// made in the repo is left behind on failure, and the session must not
/// start.
pub fn prepare(repo: &Path, session_dir: &Path) -> Result<Staging, WorkspaceError> {
    let mut created = Vec::new();
    match prepare_inner(repo, session_dir, &mut created) {
        Ok(staging) => Ok(staging),
        Err(error) => {
            remove_created(&created);
            Err(error)
        }
    }
}

fn prepare_inner(
    repo: &Path,
    session_dir: &Path,
    created: &mut Vec<PathBuf>,
) -> Result<Staging, WorkspaceError> {
    let paths = plan(repo, session_dir)?;
    for (rel, kind) in &paths {
        check_path(repo, rel, *kind)?;
    }
    let root = session_dir.join("staging");
    fs::create_dir_all(&root)
        .map_err(|e| io_error(format!("cannot create {}", root.display()), e))?;

    let mut budget = Budget::default();
    let mut protected = Vec::new();
    let mut mounts: Vec<Mount> = Vec::new();
    for (rel, kind) in &paths {
        let host = repo.join(rel);
        let staged = root.join(rel);
        if let Some(parent) = staged.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| io_error(format!("cannot create {}", parent.display()), e))?;
        }
        if host.symlink_metadata().is_ok() {
            copy_tree(&host, &staged, &mut budget)?;
        } else {
            make_mount_point(repo, rel, *kind, created)?;
            match kind {
                Kind::Dir => fs::create_dir(&staged),
                Kind::File => fs::write(&staged, b""),
            }
            .map_err(|e| io_error(format!("cannot create {}", staged.display()), e))?;
        }
        protected.push(Protected {
            rel: rel.clone(),
            baseline: digest(&staged)?,
            staged: staged.clone(),
        });
        mounts.push(Mount {
            rel: rel.clone(),
            source: staged,
        });
    }
    // Each parent directory is mounted over itself so it cannot be renamed.
    let mut parent_rels: Vec<String> = paths.iter().flat_map(|(rel, _)| parents(rel)).collect();
    parent_rels.sort();
    parent_rels.dedup();
    for rel in parent_rels {
        mounts.push(Mount {
            source: repo.join(&rel),
            rel,
        });
    }
    // A parent comes before what is under it.
    mounts.sort_by(|a, b| {
        let depth = |m: &Mount| m.rel.matches('/').count();
        depth(a).cmp(&depth(b)).then_with(|| a.rel.cmp(&b.rel))
    });
    Ok(Staging {
        mounts,
        protected,
        created: created.clone(),
    })
}

/// The changes between a starting fingerprint and the staged copy now.
fn changes_in(
    rel: &str,
    baseline: &BTreeMap<String, String>,
    staged: &Path,
) -> Result<Vec<Change>, WorkspaceError> {
    let now = digest(staged)?;
    let named = |key: &str| {
        if key.is_empty() {
            rel.to_owned()
        } else {
            format!("{rel}/{key}")
        }
    };
    let mut out = Vec::new();
    for (key, value) in &now {
        match baseline.get(key) {
            None => out.push(Change {
                path: named(key),
                kind: ChangeKind::Added,
            }),
            Some(before) if before != value => out.push(Change {
                path: named(key),
                kind: ChangeKind::Modified,
            }),
            Some(_) => {}
        }
    }
    for key in baseline.keys() {
        if !now.contains_key(key) {
            out.push(Change {
                path: named(key),
                kind: ChangeKind::Removed,
            });
        }
    }
    Ok(out)
}

impl Staging {
    /// What the sandbox binds, parents first.
    #[must_use]
    pub fn mounts(&self) -> &[Mount] {
        &self.mounts
    }

    /// Ends the session's staging: reports what the sandbox wrote to a
    /// protected path. The empty mount points that were made in the repo are
    /// removed when the staging is dropped. The staged copies stay in the
    /// session directory.
    ///
    /// A path that cannot be compared is reported as a finding too, so a
    /// write is never silently missed.
    #[must_use]
    pub fn finish(self) -> Vec<Finding> {
        let mut findings = Vec::new();
        for item in &self.protected {
            match changes_in(&item.rel, &item.baseline, &item.staged) {
                Ok(changes) if changes.is_empty() => {}
                Ok(changes) => findings.push(finding_for(&item.rel, &item.staged, &changes)),
                Err(error) => findings.push(Finding {
                    rule: WS_PROTECTED_WRITE,
                    severity: Severity::High,
                    target: item.rel.clone(),
                    message: format!("the staged copy could not be compared: {error}"),
                    fix: format!("Check {} by hand.", item.staged.display()),
                }),
            }
        }
        findings
    }
}

/// The mount points made in the repo are removed whenever the staging ends,
/// including when the session fails to start or `finish` is never called.
impl Drop for Staging {
    fn drop(&mut self) {
        remove_created(&self.created);
    }
}

fn finding_for(rel: &str, staged: &Path, changes: &[Change]) -> Finding {
    let word = |kind: ChangeKind| match kind {
        ChangeKind::Added => "added",
        ChangeKind::Modified => "changed",
        ChangeKind::Removed => "removed",
    };
    let named: Vec<String> = changes
        .iter()
        .take(MAX_NAMED)
        .map(|change| format!("{} {}", word(change.kind), change.path))
        .collect();
    let more = changes.len().saturating_sub(MAX_NAMED);
    let mut message = format!(
        "the sandbox wrote to a protected path; {} change(s) were kept in staging, not in the repo: {}",
        changes.len(),
        named.join(", ")
    );
    if more > 0 {
        message.push_str(&format!(", and {more} more"));
    }
    Finding {
        rule: WS_PROTECTED_WRITE,
        severity: Severity::High,
        target: rel.to_owned(),
        message,
        fix: format!(
            "The staged copy is {}. Copy what you accept into the repo yourself; `pumpkin-shell review` arrives in Phase 11.",
            staged.display()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn write(path: &Path, text: &str) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, text)
    }

    /// A repo with a `.git` directory (hooks and config) and `.vscode`.
    fn repo(root: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let repo = root.join("repo");
        write(&repo.join(".git/hooks/pre-commit.sample"), "#!/bin/sh\n")?;
        write(&repo.join(".git/config"), "[core]\n\tbare = false\n")?;
        write(&repo.join(".vscode/settings.json"), "{}\n")?;
        write(&repo.join("src/main.rs"), "fn main() {}\n")?;
        Ok(repo)
    }

    fn session(root: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let dir = root.join("session");
        fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    fn rels(staging: &Staging) -> Vec<&str> {
        staging.mounts().iter().map(|m| m.rel.as_str()).collect()
    }

    #[test]
    fn existing_paths_are_staged_copies_and_missing_ones_get_empty_mount_points() -> TestResult {
        let root = tempfile::tempdir()?;
        let repo = repo(root.path())?;
        let dir = session(root.path())?;
        let staging = prepare(&repo, &dir)?;
        let staged = dir.join("staging");
        assert_eq!(
            fs::read_to_string(staged.join(".vscode/settings.json"))?,
            "{}\n"
        );
        assert!(staged.join(".git/hooks/pre-commit.sample").is_file());
        // Missing ones: a directory, a file, and a missing parent.
        assert!(staged.join(".kiro/hooks").is_dir());
        assert!(staged.join(".envrc").is_file());
        assert!(repo.join(".kiro/hooks").is_dir(), "mount point not made");
        assert!(repo.join(".envrc").is_file(), "mount point not made");
        // Every mount's source exists.
        for mount in staging.mounts() {
            assert!(mount.source.exists(), "{mount:?}");
        }
        Ok(())
    }

    #[test]
    fn parents_are_mounted_over_themselves_and_come_first() -> TestResult {
        let root = tempfile::tempdir()?;
        let repo = repo(root.path())?;
        let staging = prepare(&repo, &session(root.path())?)?;
        let order = rels(&staging);
        let position = |name: &str| order.iter().position(|r| *r == name);
        let (git, hooks, config) = (
            position(".git"),
            position(".git/hooks"),
            position(".git/config"),
        );
        assert!(git < hooks && git < config, "{order:?}");
        assert!(position(".kiro") < position(".kiro/hooks"), "{order:?}");
        let parent = staging
            .mounts()
            .iter()
            .find(|m| m.rel == ".git")
            .map(|m| m.source.clone());
        assert_eq!(parent, Some(repo.join(".git")));
        Ok(())
    }

    #[test]
    fn nothing_written_means_no_findings_and_the_mount_points_are_removed() -> TestResult {
        let root = tempfile::tempdir()?;
        let repo = repo(root.path())?;
        let staging = prepare(&repo, &session(root.path())?)?;
        assert!(staging.finish().is_empty());
        assert!(!repo.join(".kiro").exists(), ".kiro was left behind");
        assert!(!repo.join(".envrc").exists(), ".envrc was left behind");
        assert!(!repo.join(".cursor").exists());
        // What was there before is still there.
        assert!(repo.join(".vscode/settings.json").is_file());
        assert!(repo.join(".git/hooks/pre-commit.sample").is_file());
        Ok(())
    }

    #[test]
    fn added_modified_and_removed_files_are_each_reported() -> TestResult {
        let root = tempfile::tempdir()?;
        let repo = repo(root.path())?;
        let dir = session(root.path())?;
        let staging = prepare(&repo, &dir)?;
        let staged = dir.join("staging");
        write(&staged.join(".git/hooks/post-commit"), "#!/bin/sh\nevil\n")?;
        write(&staged.join(".vscode/settings.json"), "{\"x\":1}\n")?;
        fs::remove_file(staged.join(".git/hooks/pre-commit.sample"))?;
        write(&staged.join(".envrc"), "export X=1\n")?;
        let findings = staging.finish();
        let targets: Vec<&str> = findings.iter().map(|f| f.target.as_str()).collect();
        assert_eq!(targets, [".envrc", ".git/hooks", ".vscode"]);
        assert!(findings.iter().all(|f| f.rule == WS_PROTECTED_WRITE));
        assert!(findings.iter().all(|f| f.severity == Severity::High));
        let hooks = &findings[1];
        assert!(
            hooks.message.contains("added .git/hooks/post-commit"),
            "{}",
            hooks.message
        );
        assert!(
            hooks
                .message
                .contains("removed .git/hooks/pre-commit.sample"),
            "{}",
            hooks.message
        );
        assert!(
            findings[2]
                .message
                .contains("changed .vscode/settings.json")
        );
        // The repo itself was never written.
        assert_eq!(
            fs::read_to_string(repo.join(".vscode/settings.json"))?,
            "{}\n"
        );
        assert!(!repo.join(".git/hooks/post-commit").exists());
        assert!(!repo.join(".envrc").exists());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn making_a_staged_hook_executable_is_a_change() -> TestResult {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir()?;
        let repo = repo(root.path())?;
        let dir = session(root.path())?;
        let staging = prepare(&repo, &dir)?;
        let sample = dir.join("staging/.git/hooks/pre-commit.sample");
        fs::set_permissions(&sample, fs::Permissions::from_mode(0o755))?;
        let findings = staging.finish();
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0]
                .message
                .contains("changed .git/hooks/pre-commit.sample")
        );
        Ok(())
    }

    #[test]
    fn a_long_list_of_changes_names_a_few_and_counts_the_rest() -> TestResult {
        let root = tempfile::tempdir()?;
        let repo = repo(root.path())?;
        let dir = session(root.path())?;
        let staging = prepare(&repo, &dir)?;
        for index in 0..9 {
            write(&dir.join(format!("staging/.vscode/f{index}.json")), "{}\n")?;
        }
        let findings = staging.finish();
        assert!(
            findings[0].message.contains("9 change(s)"),
            "{}",
            findings[0].message
        );
        assert!(
            findings[0].message.contains("and 4 more"),
            "{}",
            findings[0].message
        );
        assert!(findings[0].fix.contains("staging"), "{}", findings[0].fix);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_protected_path_or_parent_is_refused_and_nothing_is_left_behind() -> TestResult {
        for link in [".vscode", ".git", ".kiro"] {
            let root = tempfile::tempdir()?;
            let repo = repo(root.path())?;
            let outside = root.path().join("outside");
            fs::create_dir_all(&outside)?;
            let at = repo.join(link);
            if at.is_dir() {
                fs::remove_dir_all(&at)?;
            }
            std::os::unix::fs::symlink(&outside, &at)?;
            let result = prepare(&repo, &session(root.path())?);
            assert!(
                matches!(result, Err(WorkspaceError::Symlink(_))),
                "{link}: {result:?}"
            );
            assert!(
                !repo.join(".envrc").exists(),
                "{link}: mount point left behind"
            );
            assert_eq!(fs::read_dir(&outside)?.count(), 0);
        }
        Ok(())
    }

    #[test]
    fn a_protected_path_of_the_wrong_type_is_refused() -> TestResult {
        let root = tempfile::tempdir()?;
        let first = repo(root.path())?;
        fs::remove_dir_all(first.join(".vscode"))?;
        write(&first.join(".vscode"), "not a directory\n")?;
        assert!(matches!(
            prepare(&first, &session(root.path())?),
            Err(WorkspaceError::WrongType(..))
        ));
        let root = tempfile::tempdir()?;
        let second = repo(root.path())?;
        fs::create_dir_all(second.join(".npmrc"))?;
        assert!(matches!(
            prepare(&second, &session(root.path())?),
            Err(WorkspaceError::WrongType(..))
        ));
        Ok(())
    }

    #[test]
    fn a_repo_without_a_git_directory_gets_no_git_mounts_and_no_new_git_directory() -> TestResult {
        let root = tempfile::tempdir()?;
        let repo = root.path().join("plain");
        write(&repo.join("a.txt"), "a\n")?;
        let staging = prepare(&repo, &session(root.path())?)?;
        assert!(
            rels(&staging).iter().all(|r| !r.starts_with(".git")),
            "{:?}",
            rels(&staging)
        );
        assert!(!repo.join(".git").exists());
        let _ = staging.finish();
        Ok(())
    }

    #[test]
    fn a_git_file_as_in_a_worktree_is_left_alone() -> TestResult {
        let root = tempfile::tempdir()?;
        let repo = root.path().join("tree");
        write(&repo.join(".git"), "gitdir: /elsewhere\n")?;
        let staging = prepare(&repo, &session(root.path())?)?;
        assert!(rels(&staging).iter().all(|r| !r.starts_with(".git")));
        assert_eq!(
            fs::read_to_string(repo.join(".git"))?,
            "gitdir: /elsewhere\n"
        );
        let _ = staging.finish();
        Ok(())
    }

    #[test]
    fn a_hooks_path_inside_the_repo_is_protected_too() -> TestResult {
        let root = tempfile::tempdir()?;
        let repo = repo(root.path())?;
        write(&repo.join(".githooks/pre-push"), "#!/bin/sh\n")?;
        write(
            &repo.join(".git/config"),
            "[core]\n\thooksPath = .githooks\n",
        )?;
        let staging = prepare(&repo, &session(root.path())?)?;
        assert!(
            rels(&staging).contains(&".githooks"),
            "{:?}",
            rels(&staging)
        );
        let _ = staging.finish();
        Ok(())
    }

    #[test]
    fn hooks_paths_are_resolved_against_the_repo() -> TestResult {
        let root = tempfile::tempdir()?;
        let repo = fs::canonicalize(root.path())?;
        let inside = |value: &str| hooks_path_in_repo(&repo, value);
        assert_eq!(inside(".githooks")?, Some(".githooks".to_owned()));
        assert_eq!(inside("./a/../.githooks/")?, Some(".githooks".to_owned()));
        // An absolute path inside the repo. Unix only: Windows resolves
        // paths to a `\\?\` form that is not worth matching by hand here.
        #[cfg(unix)]
        assert_eq!(
            inside(&format!("{}/tools/hooks", repo.display()))?,
            Some("tools/hooks".to_owned())
        );
        // Outside the repo: the sandbox cannot write there, so nothing to do.
        assert_eq!(inside("../elsewhere")?, None);
        assert_eq!(inside("/usr/share/hooks")?, None);
        // Git expands `~`, which is the home directory, not part of the repo.
        assert_eq!(inside("~/hooks")?, None);
        // The repo root cannot be protected.
        assert!(matches!(inside("."), Err(WorkspaceError::HooksPathIsRepo)));
        assert!(matches!(
            inside("a/.."),
            Err(WorkspaceError::HooksPathIsRepo)
        ));
        Ok(())
    }

    #[test]
    fn a_too_large_protected_tree_is_refused_and_cleaned_up() -> TestResult {
        let root = tempfile::tempdir()?;
        let repo = repo(root.path())?;
        let big = fs::File::create(repo.join(".vscode/big.bin"))?;
        big.set_len(MAX_BYTES + 1)?;
        let result = prepare(&repo, &session(root.path())?);
        assert!(
            matches!(result, Err(WorkspaceError::TooLarge)),
            "{result:?}"
        );
        assert!(!repo.join(".kiro").exists(), "mount point left behind");
        assert!(!repo.join(".envrc").exists(), "mount point left behind");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn a_special_file_in_a_protected_directory_is_refused() -> TestResult {
        let root = tempfile::tempdir()?;
        let repo = repo(root.path())?;
        let _socket = std::os::unix::net::UnixListener::bind(repo.join(".vscode/s.sock"))?;
        assert!(matches!(
            prepare(&repo, &session(root.path())?),
            Err(WorkspaceError::Special(_))
        ));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_inside_a_protected_directory_is_copied_as_a_link_not_followed() -> TestResult {
        let root = tempfile::tempdir()?;
        let repo = repo(root.path())?;
        std::os::unix::fs::symlink("/etc/passwd", repo.join(".vscode/link"))?;
        let dir = session(root.path())?;
        let staging = prepare(&repo, &dir)?;
        let staged = dir.join("staging/.vscode/link");
        assert!(is_symlink(&staged));
        assert_eq!(fs::read_link(&staged)?, PathBuf::from("/etc/passwd"));
        assert!(staging.finish().is_empty());
        Ok(())
    }

    #[test]
    fn a_mount_point_that_gained_content_is_not_deleted() -> TestResult {
        let root = tempfile::tempdir()?;
        let repo = repo(root.path())?;
        let staging = prepare(&repo, &session(root.path())?)?;
        write(&repo.join(".kiro/hooks/user-added.json"), "{}\n")?;
        let _ = staging.finish();
        assert!(repo.join(".kiro/hooks/user-added.json").is_file());
        Ok(())
    }

    #[test]
    fn a_path_already_under_another_protected_path_is_not_listed_twice() -> TestResult {
        let root = tempfile::tempdir()?;
        let repo = repo(root.path())?;
        write(
            &repo.join(".git/config"),
            "[core]\n\thooksPath = .git/hooks/custom\n",
        )?;
        let staging = prepare(&repo, &session(root.path())?)?;
        assert!(
            !rels(&staging).contains(&".git/hooks/custom"),
            "{:?}",
            rels(&staging)
        );
        let _ = staging.finish();
        Ok(())
    }
}
