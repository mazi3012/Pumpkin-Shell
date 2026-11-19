//! Static scanner for agent-escape setups in a repository.
//!
//! Phase 4: pure Rust, cross-platform, useful on day one. Rules are shared
//! with `doctor`, the watcher and the proxy via `pks-core` (PRD FR-DET).

use std::path::{Path, PathBuf};

use globset::{Glob, GlobSetBuilder};
use walkdir::WalkDir;

use pks_core::Finding;
pub mod rules;
use rules::{RuleError, RuleProvider};

/// Scan a repository for agent-escape setups.
///
/// - Respects `.gitignore`
/// - Never follows symlinks out of the repo
/// - Compares paths by component to avoid CVE-2025-54794 prefix bypasses
pub fn scan(repo_root: &Path) -> Result<Vec<Finding>, ScanError> {
    let rules = RuleProvider::all();
    let mut findings = Vec::new();

    // Build a globset that matches files in the repo, respecting .gitignore
    let gitignore_path = repo_root.join(".gitignore");
    let mut glob_builder = GlobSetBuilder::new();

    // Always exclude the .git directory
    glob_builder.add(Glob::new("**/.git/**")?);

    // If .gitignore exists, read and add its patterns
    if gitignore_path.exists() {
        let content = std::fs::read_to_string(&gitignore_path)?;
        for line in content.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                // Convert gitignore pattern to glob
                let glob_pattern = if let Some(stripped) = trimmed.strip_prefix('/') {
                    stripped.to_string()
                } else {
                    "**/".to_string() + trimmed
                };
                if let Ok(glob) = Glob::new(&glob_pattern) {
                    glob_builder.add(glob);
                }
            }
        }
    }

    let gitignore_glob = glob_builder.build()?;

    // Walk the directory
    for entry in WalkDir::new(repo_root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            // Skip .git directories
            !(e.depth() > 0 && e.file_name() == ".git")
        })
    {
        let entry = entry.map_err(ScanError::from_walkdir)?;
        if !entry.file_type().is_file() {
            continue;
        }

        let rel_path = entry
            .path()
            .strip_prefix(repo_root)
            .map_err(|_| ScanError::InvalidPath(entry.path().to_path_buf()))?
            .to_string_lossy()
            .to_string();

        // Skip files matching .gitignore
        if gitignore_glob.is_match(&rel_path) {
            continue;
        }

        // Apply each rule
        for rule in &rules {
            if let Some(finding) = rule.check(repo_root, &rel_path)? {
                findings.push(finding);
            }
        }
    }

    Ok(findings)
}

/// Error types for the scanner.
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("invalid path: {0}")]
    InvalidPath(PathBuf),
    #[error("glob error: {0}")]
    Glob(#[from] globset::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("walkdir error: {0}")]
    Walkdir(#[from] walkdir::Error),
    #[error("rule error: {0}")]
    Rule(#[from] RuleError),
}

impl ScanError {
    /// Helper to convert walkdir error to ScanError.
    fn from_walkdir(err: walkdir::Error) -> Self {
        ScanError::Walkdir(err)
    }
}
