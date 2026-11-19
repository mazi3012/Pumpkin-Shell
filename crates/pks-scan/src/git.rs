//! Rule WS-GIT-HOOK: git settings and files that run programs.
//!
//! Git runs `core.fsmonitor` (when it is a path, not a boolean) and the hooks
//! in `core.hooksPath` or `.git/hooks` as the user. A repo-local `include`
//! can pull in a config file that sets them, so includes are reported too.
//! Source: `man git-config` (core.fsmonitor, core.hooksPath), git 2.43.

use std::fs;
use std::io;
use std::path::Path;

use pks_core::{Finding, Severity};

use crate::fs_safe::{self, Read};
use crate::{Report, ScanIssue, SkipReason, Skipped, clean, finding, rule};

/// Reads `.git/config` and `.git/hooks` of the repo at `root`.
pub(crate) fn scan(root: &Path, report: &mut Report) {
    let git_dir = root.join(".git");
    match fs::symlink_metadata(&git_dir) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return,
        Err(error) => {
            push_error(report, ".git", &error);
            return;
        }
        Ok(meta) if meta.file_type().is_symlink() => {
            push_skipped(report, ".git", SkipReason::Symlink);
            return;
        }
        Ok(meta) if meta.is_file() => {
            push_skipped(report, ".git", SkipReason::GitFile);
            return;
        }
        Ok(meta) if !meta.is_dir() => return,
        Ok(_) => {}
    }

    match fs_safe::read_regular(root, Path::new(".git/config")) {
        Ok(Read::Bytes(bytes)) => report
            .findings
            .extend(config_findings(&String::from_utf8_lossy(&bytes))),
        Ok(Read::Skipped(reason)) => push_skipped(report, ".git/config", reason),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => push_error(report, ".git/config", &error),
    }

    hook_files(&git_dir.join("hooks"), report);
}

fn push_skipped(report: &mut Report, path: &str, reason: SkipReason) {
    report.skipped.push(Skipped {
        path: path.to_owned(),
        reason,
    });
}

fn push_error(report: &mut Report, path: &str, error: &io::Error) {
    report.errors.push(ScanIssue {
        path: path.to_owned(),
        message: clean(&error.to_string()),
    });
}

/// Every file in `.git/hooks` that git would run, and every symlink there.
/// Git skips names ending in `.sample`.
fn hook_files(dir: &Path, report: &mut Report) {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return,
        Err(error) => {
            push_error(report, ".git/hooks", &error);
            return;
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                push_error(report, ".git/hooks", &error);
                continue;
            }
        };
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.ends_with(".sample") {
            continue;
        }
        let meta = match fs::symlink_metadata(entry.path()) {
            Ok(meta) => meta,
            Err(error) => {
                push_error(report, ".git/hooks", &error);
                continue;
            }
        };
        let kind = if meta.file_type().is_symlink() {
            "a symlink"
        } else if meta.is_file() && is_executable(&meta) {
            "an executable file"
        } else {
            continue;
        };
        let shown = clean(&name);
        report.findings.push(finding(
            rule::GIT_HOOK,
            Severity::High,
            format!(".git/hooks/{shown}"),
            format!("git hook `{shown}` is {kind} that git runs on the matching event"),
            "Delete the hook if you did not add it.",
        ));
    }
}

#[cfg(unix)]
fn is_executable(meta: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o111 != 0
}

/// Windows has no execute bit; Git for Windows runs any hook file it finds.
#[cfg(not(unix))]
fn is_executable(_meta: &fs::Metadata) -> bool {
    true
}

fn is_boolean(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "" | "true" | "yes" | "on" | "false" | "no" | "off"
    ) || lower.parse::<i64>().is_ok()
}

/// Cuts a value at the first `#` or `;` that is outside double quotes.
fn strip_comment(value: &str) -> &str {
    let mut in_quotes = false;
    for (index, c) in value.char_indices() {
        match c {
            '"' => in_quotes = !in_quotes,
            '#' | ';' if !in_quotes => return &value[..index],
            _ => {}
        }
    }
    value
}

/// Looks for `core.hooksPath`, a program in `core.fsmonitor`, and `include`
/// paths. This is a small reader for git's config format, enough to find
/// those keys, including `[core] key = value` on one line.
fn config_findings(text: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut in_core = false;
    let mut in_include = false;
    for (index, raw) in text.lines().enumerate() {
        let line_no = index + 1;
        let mut line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(header) = line.strip_prefix('[') {
            let Some(end) = header.find(']') else {
                continue;
            };
            let inside = header[..end].trim();
            let (name, has_subsection) = match inside.split_once(char::is_whitespace) {
                Some((name, _)) => (name, true),
                None => (inside, false),
            };
            let name = name.to_ascii_lowercase();
            in_core = name == "core" && !has_subsection;
            in_include = name == "include" || name == "includeif" || name.starts_with("includeif.");
            line = header[end + 1..].trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
        }
        let (key, value) = match line.split_once('=') {
            Some((key, value)) => (key, Some(strip_comment(value).trim().trim_matches('"'))),
            None => (strip_comment(line), None),
        };
        let key = key.trim().to_ascii_lowercase();
        let target = format!(".git/config:{line_no}");
        if in_core && key == "hookspath" {
            out.push(finding(
                rule::GIT_HOOK,
                Severity::High,
                target,
                "`core.hooksPath` makes git run hooks from another directory".to_owned(),
                "Run `git config --unset core.hooksPath` unless you set it yourself.",
            ));
        } else if in_core && key == "fsmonitor" && value.is_some_and(|v| !is_boolean(v)) {
            out.push(finding(
                rule::GIT_HOOK,
                Severity::High,
                target,
                "`core.fsmonitor` names a program that git runs on many commands".to_owned(),
                "Run `git config --unset core.fsmonitor` unless you set it yourself.",
            ));
        } else if in_include && key == "path" {
            out.push(finding(
                rule::GIT_HOOK,
                Severity::High,
                target,
                "git config includes another file that this scan does not read".to_owned(),
                "Remove the include, or read the included file for hooksPath and fsmonitor.",
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn lines(text: &str) -> Vec<String> {
        config_findings(text)
            .into_iter()
            .map(|f| f.target)
            .collect()
    }

    #[test]
    fn finds_hookspath_in_any_case_and_form() {
        assert_eq!(lines("[core]\n\thooksPath = /tmp/h\n"), [".git/config:2"]);
        assert_eq!(lines("[CORE]\nHOOKSPATH=/x\n"), [".git/config:2"]);
        assert_eq!(lines("[core] hooksPath = /x\n"), [".git/config:1"]);
        assert_eq!(lines("[core]\n  hooksPath\n"), [".git/config:2"]);
    }

    #[test]
    fn fsmonitor_is_a_finding_only_when_it_names_a_program() {
        assert_eq!(lines("[core]\nfsmonitor = /tmp/evil\n"), [".git/config:2"]);
        assert_eq!(
            lines("[core]\nfsmonitor = \".git/hooks/fsm\"\n"),
            [".git/config:2"]
        );
        for boolean in ["true", "false", "yes", "no", "on", "off", "1", "0", "TRUE"] {
            assert!(
                lines(&format!("[core]\nfsmonitor = {boolean}\n")).is_empty(),
                "{boolean}"
            );
        }
        assert!(lines("[core]\nfsmonitor\n").is_empty());
        assert!(lines("[core]\nfsmonitor = true # builtin\n").is_empty());
    }

    #[test]
    fn keys_outside_core_or_in_comments_are_ignored() {
        assert!(lines("[alias]\nhooksPath = x\n").is_empty());
        assert!(lines("[core \"sub\"]\nhooksPath = x\n").is_empty());
        assert!(lines("[core]\n# hooksPath = x\n; hooksPath = x\n").is_empty());
        assert!(lines("[core]\nbare = false\n").is_empty());
    }

    #[test]
    fn includes_are_reported() {
        assert_eq!(lines("[include]\npath = ../evil.cfg\n"), [".git/config:2"]);
        assert_eq!(
            lines("[includeIf \"gitdir:/\"]\npath = x\n"),
            [".git/config:2"]
        );
        assert_eq!(lines("[includeIf.foo]\npath = x\n"), [".git/config:2"]);
    }

    #[test]
    fn a_clean_config_has_no_findings() {
        let text = "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n[remote \"origin\"]\n\turl = https://example.com/r.git\n";
        assert!(lines(text).is_empty());
    }

    #[test]
    fn a_missing_git_dir_is_not_an_error() -> TestResult {
        let dir = tempfile::tempdir()?;
        let mut report = Report::default();
        scan(dir.path(), &mut report);
        assert!(
            report.findings.is_empty() && report.errors.is_empty() && report.skipped.is_empty()
        );
        Ok(())
    }

    #[test]
    fn a_dot_git_file_is_reported_as_skipped() -> TestResult {
        let dir = tempfile::tempdir()?;
        fs::write(dir.path().join(".git"), "gitdir: ../elsewhere\n")?;
        let mut report = Report::default();
        scan(dir.path(), &mut report);
        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.skipped[0].reason, SkipReason::GitFile);
        Ok(())
    }

    #[test]
    fn hooks_ignore_samples_and_flag_other_files() -> TestResult {
        let dir = tempfile::tempdir()?;
        fs::create_dir_all(dir.path().join(".git/hooks"))?;
        fs::write(
            dir.path().join(".git/hooks/pre-commit.sample"),
            "#!/bin/sh\n",
        )?;
        fs::write(dir.path().join(".git/hooks/pre-commit"), "#!/bin/sh\nid\n")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                dir.path().join(".git/hooks/pre-commit"),
                fs::Permissions::from_mode(0o755),
            )?;
            fs::write(dir.path().join(".git/hooks/not-executable"), "text")?;
            fs::set_permissions(
                dir.path().join(".git/hooks/not-executable"),
                fs::Permissions::from_mode(0o644),
            )?;
        }
        let mut report = Report::default();
        scan(dir.path(), &mut report);
        let targets: Vec<_> = report.findings.iter().map(|f| f.target.as_str()).collect();
        assert!(targets.contains(&".git/hooks/pre-commit"));
        assert!(!targets.iter().any(|t| t.ends_with(".sample")));
        #[cfg(unix)]
        assert!(!targets.contains(&".git/hooks/not-executable"));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_hook_is_a_finding_and_is_not_followed() -> TestResult {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir()?;
        fs::create_dir_all(dir.path().join(".git/hooks"))?;
        symlink("/bin/true", dir.path().join(".git/hooks/post-merge"))?;
        let mut report = Report::default();
        scan(dir.path(), &mut report);
        assert_eq!(report.findings.len(), 1);
        assert!(report.findings[0].message.contains("a symlink"));
        Ok(())
    }

    #[test]
    fn config_in_a_real_git_dir_is_read() -> TestResult {
        let dir = tempfile::tempdir()?;
        fs::create_dir_all(dir.path().join(".git"))?;
        fs::write(dir.path().join(".git/config"), "[core]\nhooksPath = /x\n")?;
        let mut report = Report::default();
        scan(dir.path(), &mut report);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].rule.as_str(), "WS-GIT-HOOK");
        Ok(())
    }
}
