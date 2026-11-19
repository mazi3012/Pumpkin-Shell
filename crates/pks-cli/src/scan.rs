//! `pumpkin-shell scan`: static scanner for agent-escape setups.
//!
//! Phase 4: pure Rust, cross-platform, useful on day one. Reports findings
//! in human and JSON format, with CI-friendly exit codes.

use std::process::ExitCode;

use pks_core::Finding;
use pks_scan::scan as do_scan;

/// Runs the scanner on the given repository path.
pub fn run(path: &str, json: bool, ci: bool) -> ExitCode {
    let repo_root = std::path::Path::new(path);

    match do_scan(repo_root) {
        Ok(findings) => {
            if findings.is_empty() {
                if json {
                    println!("[]");
                } else if !ci {
                    println!("No agent-escape setups found.");
                }
                ExitCode::SUCCESS
            } else {
                if json {
                    if let Ok(text) = serde_json::to_string_pretty(&findings) {
                        println!("{text}");
                    } else {
                        eprintln!("scan: could not encode findings as JSON");
                        return ExitCode::from(2);
                    }
                } else {
                    print_human(&findings);
                }

                if ci {
                    ExitCode::FAILURE
                } else {
                    ExitCode::SUCCESS
                }
            }
        }
        Err(error) => {
            eprintln!("scan: {error}");
            if ci {
                ExitCode::from(2)
            } else {
                ExitCode::from(2)
            }
        }
    }
}

fn print_human(findings: &[Finding]) {
    println!("Found {} agent-escape setup(s):\n", findings.len());
    for (i, finding) in findings.iter().enumerate() {
        println!("[{}] {}", i + 1, finding.rule.as_str());
        println!("    Severity: {:?}", finding.severity);
        println!("    Target: {}", finding.target);
        println!("    {}", finding.message);
        println!("    Fix: {}", finding.fix);
        println!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn create_test_repo(files: &[(&str, &str)]) -> TempDir {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        for (path, content) in files {
            let full_path = root.join(path);
            if let Some(parent) = full_path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(full_path, content).unwrap();
        }

        // Create .git/config to avoid git errors
        let git_dir = root.join(".git");
        fs::create_dir_all(&git_dir).unwrap();
        fs::write(
            git_dir.join("config"),
            "[core]\n    repositoryformatversion = 0\n",
        )
        .unwrap();

        temp
    }

    #[test]
    fn test_scan_with_findings() {
        let temp = create_test_repo(&[(
            ".vscode/settings.json",
            r#"{"chat": {"tools": {"autoApprove": true}}}"#,
        )]);

        let result = run(temp.path().to_str().unwrap(), false, false);
        assert_eq!(result, ExitCode::SUCCESS);
    }

    #[test]
    fn test_scan_clean_repo() {
        let temp = create_test_repo(&[("README.md", "# Test\n")]);

        let result = run(temp.path().to_str().unwrap(), false, false);
        assert_eq!(result, ExitCode::SUCCESS);
    }

    #[test]
    fn test_scan_json_output() {
        let temp = create_test_repo(&[(".vscode/settings.json", r#"{}"#)]);

        let result = run(temp.path().to_str().unwrap(), true, false);
        assert_eq!(result, ExitCode::SUCCESS);
    }
}
