//! Static scanner for agent-escape setups in a repository (PRD FR-DET,
//! Phase 4). Pure Rust, no sandbox needed.
//!
//! Everything in the scanned tree is untrusted input. The scanner never
//! follows symlinks, compares paths by component (never by string prefix,
//! CVE-2025-54794), keeps going when one file is unreadable, and escapes
//! control and invisible characters before they reach a finding.

#[cfg(windows)]
mod ads;
mod configs;
mod fs_safe;
mod git;
pub mod staged;
mod unicode;
mod walk;

use std::path::Path;

use pks_core::{Finding, RuleId, Severity};
use serde::Serialize;

/// Rule IDs reported by the scanner. They are listed in the PRD (FR-DET).
pub mod rule {
    use pks_core::RuleId;

    pub const HIDDEN_UNICODE: RuleId = RuleId::new("WS-HIDDEN-UNICODE");
    pub const AUTOAPPROVE: RuleId = RuleId::new("WS-AUTOAPPROVE");
    pub const MCP_SERVER: RuleId = RuleId::new("WS-MCP-SERVER");
    pub const KIRO_HOOK: RuleId = RuleId::new("WS-KIRO-HOOK");
    pub const FOLDER_OPEN_TASK: RuleId = RuleId::new("WS-FOLDER-OPEN-TASK");
    pub const YARNPATH: RuleId = RuleId::new("WS-YARNPATH");
    pub const GIT_HOOK: RuleId = RuleId::new("WS-GIT-HOOK");
    #[cfg(windows)]
    pub const ADS: RuleId = RuleId::new("WS-ADS");
}

/// Options for [`scan`].
#[derive(Debug, Clone, Copy)]
pub struct ScanOptions {
    /// Skip files matched by `.gitignore` when looking for hidden characters.
    /// A committed `.gitignore` can hide tracked files from the scan, so CI
    /// should turn this off. Agent config directories are always scanned.
    pub respect_gitignore: bool,
}

/// Why a path was not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SkipReason {
    /// Contains a NUL byte in its first 8 KiB, so it is not text.
    Binary,
    /// Larger than the 8 MiB read limit.
    TooLarge,
    /// A symlink. Symlinks are never followed.
    Symlink,
    /// `.git` is a file (worktree or submodule), not a directory.
    GitFile,
}

/// A path the scanner chose not to read. Nothing is skipped silently.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Skipped {
    pub path: String,
    pub reason: SkipReason,
}

/// A problem that made the scan incomplete, such as an unreadable file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScanIssue {
    pub path: String,
    pub message: String,
}

/// Result of a scan.
#[derive(Debug, Default, Serialize)]
pub struct Report {
    pub findings: Vec<Finding>,
    pub skipped: Vec<Skipped>,
    pub errors: Vec<ScanIssue>,
    pub files_scanned: usize,
}

impl Report {
    /// True when every file the scanner meant to read was read.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.errors.is_empty()
    }

    /// True when any finding has at least severity `min`.
    #[must_use]
    pub fn has_findings_at_least(&self, min: Severity) -> bool {
        self.findings.iter().any(|finding| finding.severity >= min)
    }
}

/// The scan could not start.
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("{0} is not a directory")]
    NotADirectory(String),
    #[error("cannot read {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

/// Scans the repository at `root`.
///
/// # Errors
/// Returns an error only when `root` is not a readable directory. Problems
/// with individual files are collected in [`Report::errors`].
pub fn scan(root: &Path, options: &ScanOptions) -> Result<Report, ScanError> {
    let shown = clean(&root.to_string_lossy());
    let meta = std::fs::metadata(root).map_err(|source| ScanError::Io {
        path: shown.clone(),
        source,
    })?;
    if !meta.is_dir() {
        return Err(ScanError::NotADirectory(shown));
    }

    let mut report = Report::default();
    let (entries, walk_issues) = walk::collect(root, options.respect_gitignore);
    report.errors.extend(walk_issues);

    for (rel, kind) in &entries {
        let shown = show_path(rel);
        match kind {
            walk::Kind::Dir => {
                #[cfg(windows)]
                ads::check(root, rel, &shown, &mut report);
            }
            walk::Kind::Symlink => report.skipped.push(Skipped {
                path: shown,
                reason: SkipReason::Symlink,
            }),
            walk::Kind::File => {
                #[cfg(windows)]
                ads::check(root, rel, &shown, &mut report);
                scan_file(root, rel, &shown, &mut report);
            }
        }
    }

    git::scan(root, &mut report);
    report
        .findings
        .sort_by(|a, b| (&a.target, a.rule.as_str()).cmp(&(&b.target, b.rule.as_str())));
    Ok(report)
}

fn scan_file(root: &Path, rel: &Path, shown: &str, report: &mut Report) {
    let bytes = match fs_safe::read_regular(root, rel) {
        Ok(fs_safe::Read::Bytes(bytes)) => bytes,
        Ok(fs_safe::Read::Skipped(reason)) => {
            report.skipped.push(Skipped {
                path: shown.to_owned(),
                reason,
            });
            return;
        }
        Err(error) => {
            report.errors.push(ScanIssue {
                path: shown.to_owned(),
                message: clean(&error.to_string()),
            });
            return;
        }
    };
    if fs_safe::looks_binary(&bytes) && !walk::is_agent_config(rel) {
        report.skipped.push(Skipped {
            path: shown.to_owned(),
            reason: SkipReason::Binary,
        });
        return;
    }
    report.files_scanned += 1;
    // Lossy decoding keeps every valid UTF-8 sequence intact, so invisible
    // characters are still found in files with a few bad bytes.
    let text = String::from_utf8_lossy(&bytes);
    report.findings.extend(unicode::findings(shown, &text));
    if let Some(kind) = configs::kind_of(rel) {
        match configs::check(kind, shown, &text) {
            Ok(findings) => report.findings.extend(findings),
            Err(message) => report.errors.push(ScanIssue {
                path: shown.to_owned(),
                message,
            }),
        }
    }
}

/// Builds a finding. `target` and `message` must already be cleaned.
pub(crate) fn finding(
    rule: RuleId,
    severity: Severity,
    target: String,
    message: String,
    fix: &str,
) -> Finding {
    Finding {
        rule,
        severity,
        target,
        message,
        fix: fix.to_owned(),
    }
}

const MAX_SHOWN_CHARS: usize = 160;

/// Makes untrusted text safe to print. Control characters (such as ESC, which
/// starts terminal escape sequences) and invisible or direction-changing
/// characters are written as `\u{..}`, and long text is cut.
pub(crate) fn clean(text: &str) -> String {
    let mut out = String::new();
    for (count, c) in text.chars().enumerate() {
        if count >= MAX_SHOWN_CHARS {
            out.push('…');
            break;
        }
        if c.is_control() || unicode::classify(c).is_some() {
            out.push_str(&format!("\\u{{{:04x}}}", u32::from(c)));
        } else {
            out.push(c);
        }
    }
    out
}

/// Path shown to the user: components joined with `/`, each one cleaned.
pub(crate) fn show_path(rel: &Path) -> String {
    rel.components()
        .map(|component| clean(&component.as_os_str().to_string_lossy()))
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_escapes_control_and_invisible_characters() {
        assert_eq!(clean("a\u{1b}[31mb"), "a\\u{001b}[31mb");
        assert_eq!(clean("x\u{202e}y"), "x\\u{202e}y");
        assert_eq!(clean("tag\u{e0041}"), "tag\\u{e0041}");
        assert_eq!(clean("plain ascii"), "plain ascii");
    }

    #[test]
    fn clean_cuts_long_text() {
        let long = "a".repeat(500);
        let shown = clean(&long);
        assert_eq!(shown.chars().count(), MAX_SHOWN_CHARS + 1);
        assert!(shown.ends_with('…'));
    }

    #[test]
    fn show_path_joins_components_with_slash() {
        assert_eq!(
            show_path(Path::new(".kiro/hooks/a.json")),
            ".kiro/hooks/a.json"
        );
    }
}
