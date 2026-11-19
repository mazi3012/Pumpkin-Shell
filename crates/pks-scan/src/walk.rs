//! Lists the files to scan.
//!
//! Two passes, merged:
//! 1. The whole repo, honoring `.gitignore` when asked. `.ignore` files,
//!    global git ignores and `.git/info/exclude` are never read: they depend
//!    on the machine, and a committed `.ignore` containing `*` would hide
//!    every file from the scan.
//! 2. The agent config files and directories, always, with no ignore rules.
//!    A `.gitignore` that lists `.kiro/` must not hide `.kiro/steering`.
//!
//! Symlinks are listed but not followed. `.git` is skipped here; `git.rs`
//! reads the few files in it that matter.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use ignore::WalkBuilder;

use crate::{ScanIssue, clean};

/// Directories scanned even when an ignore file lists them.
const ALWAYS_DIRS: [&str; 5] = [".kiro", ".vscode", ".cursor", ".windsurf", ".github"];
/// Files scanned even when an ignore file lists them.
const ALWAYS_FILES: [&str; 4] = ["AGENTS.md", ".cursorrules", ".mcp.json", ".yarnrc.yml"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    File,
    Dir,
    Symlink,
}

/// True for files that steer an agent or the IDE. These are scanned even when
/// they look binary.
pub(crate) fn is_agent_config(rel: &Path) -> bool {
    let first = rel.components().next().map(|c| c.as_os_str());
    ALWAYS_DIRS
        .iter()
        .any(|dir| first == Some(std::ffi::OsStr::new(dir)))
        || ALWAYS_FILES.iter().any(|file| rel == Path::new(file))
}

/// Returns every entry below `root` (relative paths, sorted) and the problems
/// met while walking.
pub(crate) fn collect(
    root: &Path,
    respect_gitignore: bool,
) -> (BTreeMap<PathBuf, Kind>, Vec<ScanIssue>) {
    let mut entries = BTreeMap::new();
    let mut issues = Vec::new();

    let mut main = WalkBuilder::new(root);
    main.hidden(false)
        .parents(false)
        .ignore(false)
        .git_global(false)
        .git_exclude(false)
        .git_ignore(respect_gitignore)
        .require_git(false)
        .follow_links(false)
        .filter_entry(|entry| entry.depth() == 0 || entry.file_name() != ".git");
    walk(root, main, &mut entries, &mut issues);

    for name in ALWAYS_DIRS {
        let path = root.join(name);
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_symlink() => {
                entries.insert(PathBuf::from(name), Kind::Symlink);
            }
            Ok(meta) if meta.is_dir() => {
                let mut builder = WalkBuilder::new(&path);
                builder
                    .standard_filters(false)
                    .follow_links(false)
                    .filter_entry(|entry| entry.depth() == 0 || entry.file_name() != ".git");
                walk(root, builder, &mut entries, &mut issues);
            }
            Ok(_) | Err(_) => {}
        }
    }
    for name in ALWAYS_FILES {
        if let Ok(meta) = fs::symlink_metadata(root.join(name)) {
            let kind = if meta.file_type().is_symlink() {
                Kind::Symlink
            } else if meta.is_file() {
                Kind::File
            } else {
                continue;
            };
            entries.insert(PathBuf::from(name), kind);
        }
    }
    (entries, issues)
}

fn walk(
    root: &Path,
    builder: WalkBuilder,
    entries: &mut BTreeMap<PathBuf, Kind>,
    issues: &mut Vec<ScanIssue>,
) {
    for result in builder.build() {
        let entry = match result {
            Ok(entry) => entry,
            Err(error) => {
                issues.push(ScanIssue {
                    path: String::new(),
                    message: clean(&error.to_string()),
                });
                continue;
            }
        };
        let Ok(rel) = entry.path().strip_prefix(root) else {
            continue;
        };
        if rel.as_os_str().is_empty() {
            continue;
        }
        let Some(file_type) = entry.file_type() else {
            continue;
        };
        let kind = if file_type.is_symlink() {
            Kind::Symlink
        } else if file_type.is_dir() {
            Kind::Dir
        } else if file_type.is_file() {
            Kind::File
        } else {
            continue;
        };
        entries.insert(rel.to_path_buf(), kind);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn names(entries: &BTreeMap<PathBuf, Kind>) -> Vec<String> {
        entries
            .iter()
            .filter(|(_, kind)| **kind == Kind::File)
            .map(|(path, _)| path.to_string_lossy().replace('\\', "/"))
            .collect()
    }

    #[test]
    fn agent_config_is_matched_by_component_not_by_prefix() {
        assert!(is_agent_config(Path::new(".kiro/steering/a.md")));
        assert!(is_agent_config(Path::new(".mcp.json")));
        assert!(is_agent_config(Path::new("AGENTS.md")));
        // CVE-2025-54794 pattern: a sibling that merely starts with the name.
        assert!(!is_agent_config(Path::new(".kiro-evil/a.md")));
        assert!(!is_agent_config(Path::new(".vscode_evil/settings.json")));
        assert!(!is_agent_config(Path::new("AGENTS.md.bak")));
        assert!(!is_agent_config(Path::new("docs/.kiro/a.md")));
    }

    #[test]
    fn gitignore_hides_ordinary_files_only_when_asked() -> TestResult {
        let dir = tempfile::tempdir()?;
        fs::write(dir.path().join(".gitignore"), "build/\n")?;
        fs::create_dir(dir.path().join("build"))?;
        fs::write(dir.path().join("build/out.txt"), "x")?;
        fs::write(dir.path().join("src.txt"), "x")?;

        let (honored, _) = collect(dir.path(), true);
        assert!(names(&honored).contains(&"src.txt".to_owned()));
        assert!(!names(&honored).contains(&"build/out.txt".to_owned()));

        let (all, _) = collect(dir.path(), false);
        assert!(names(&all).contains(&"build/out.txt".to_owned()));
        Ok(())
    }

    #[test]
    fn dot_ignore_files_never_hide_anything() -> TestResult {
        let dir = tempfile::tempdir()?;
        fs::write(dir.path().join(".ignore"), "*\n")?;
        fs::write(dir.path().join("a.txt"), "x")?;
        let (entries, _) = collect(dir.path(), true);
        assert!(names(&entries).contains(&"a.txt".to_owned()));
        Ok(())
    }

    #[test]
    fn gitignore_cannot_hide_agent_config() -> TestResult {
        let dir = tempfile::tempdir()?;
        fs::write(
            dir.path().join(".gitignore"),
            ".kiro/\n.vscode/\nAGENTS.md\n",
        )?;
        fs::create_dir_all(dir.path().join(".kiro/steering"))?;
        fs::write(dir.path().join(".kiro/steering/a.md"), "x")?;
        fs::create_dir(dir.path().join(".vscode"))?;
        fs::write(dir.path().join(".vscode/settings.json"), "{}")?;
        fs::write(dir.path().join("AGENTS.md"), "x")?;
        let (entries, _) = collect(dir.path(), true);
        let found = names(&entries);
        assert!(found.contains(&".kiro/steering/a.md".to_owned()));
        assert!(found.contains(&".vscode/settings.json".to_owned()));
        assert!(found.contains(&"AGENTS.md".to_owned()));
        Ok(())
    }

    #[test]
    fn dot_git_is_skipped() -> TestResult {
        let dir = tempfile::tempdir()?;
        fs::create_dir_all(dir.path().join(".git/hooks"))?;
        fs::write(dir.path().join(".git/config"), "x")?;
        fs::create_dir_all(dir.path().join("sub/.git"))?;
        fs::write(dir.path().join("sub/.git/config"), "x")?;
        fs::write(dir.path().join("a.txt"), "x")?;
        let (entries, _) = collect(dir.path(), false);
        assert_eq!(names(&entries), vec!["a.txt".to_owned()]);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_listed_but_not_followed() -> TestResult {
        use std::os::unix::fs::symlink;
        let outside = tempfile::tempdir()?;
        fs::write(outside.path().join("secret.txt"), "x")?;
        let repo = tempfile::tempdir()?;
        symlink(outside.path(), repo.path().join("link"))?;
        let (entries, _) = collect(repo.path(), false);
        assert_eq!(entries.get(Path::new("link")), Some(&Kind::Symlink));
        assert!(!entries.contains_key(Path::new("link/secret.txt")));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_agent_directory_is_reported_not_entered() -> TestResult {
        use std::os::unix::fs::symlink;
        let outside = tempfile::tempdir()?;
        fs::write(outside.path().join("a.md"), "x")?;
        let repo = tempfile::tempdir()?;
        symlink(outside.path(), repo.path().join(".kiro"))?;
        let (entries, _) = collect(repo.path(), true);
        assert_eq!(entries.get(Path::new(".kiro")), Some(&Kind::Symlink));
        assert!(!entries.contains_key(Path::new(".kiro/a.md")));
        Ok(())
    }
}
