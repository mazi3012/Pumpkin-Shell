//! Review of what the sandbox wrote to protected paths (PRD FR-DET,
//! PHASES 10.2 and 10.3). The config rules of `scan` run on each staged file
//! that the session added or changed. A change that enables auto-approve, or
//! adds an MCP server or a command hook, is CRITICAL (WS-AUTOAPPROVE). Pausing
//! on CRITICAL is Phase 11; here the change is only kept in staging and logged.
//!
//! A staged file that cannot be read or parsed is reported, never passed.

use std::fs;
use std::path::Path;

use pks_core::workspace::{Staging, WS_PROTECTED_WRITE};
use pks_core::{Finding, Severity};

use crate::configs;
use crate::fs_safe::{self, Read};
use crate::rule;
use crate::secrets;

/// Runs the config rules on one staged file. `rel` is the path from the repo
/// root. `None` when the path is not a config file the rules read.
pub fn config_findings(rel: &str, text: &str) -> Option<Result<Vec<Finding>, String>> {
    let kind = configs::kind_of(Path::new(rel))?;
    Some(configs::check(kind, rel, text).map(|list| list.into_iter().map(escalate).collect()))
}

/// In a session change, an MCP server or a command hook is a new way to run
/// code, so it is CRITICAL under WS-AUTOAPPROVE, as the PRD lists it.
fn escalate(finding: Finding) -> Finding {
    if finding.rule == rule::MCP_SERVER || finding.rule == rule::KIRO_HOOK {
        return Finding {
            rule: rule::AUTOAPPROVE,
            severity: Severity::Critical,
            message: format!(
                "the sandbox added or changed a file that runs an MCP server or command hook: {}",
                finding.message
            ),
            fix: "Remove it, or add it to the repo yourself after reviewing it.".to_owned(),
            ..finding
        };
    }
    finding
}

fn high(target: &str, message: String) -> Finding {
    Finding {
        rule: WS_PROTECTED_WRITE,
        severity: Severity::High,
        target: target.to_owned(),
        message,
        fix: "Check the staged copy by hand before copying it into the repo.".to_owned(),
    }
}

/// One finding for each kind of secret in `text`, naming the file and the
/// first line. The secret itself is never in the finding.
fn secret_findings_in(rel: &str, text: &str) -> Vec<Finding> {
    let mut by_kind: Vec<(secrets::Kind, usize, usize)> = Vec::new();
    for hit in secrets::find(text) {
        match by_kind.iter_mut().find(|(kind, _, _)| *kind == hit.kind) {
            Some((_, _, count)) => *count += 1,
            None => by_kind.push((hit.kind, hit.line, 1)),
        }
    }
    by_kind
        .into_iter()
        .map(|(kind, line, count)| Finding {
            rule: rule::SECRET_WRITTEN,
            severity: Severity::High,
            target: rel.to_owned(),
            message: format!(
                "the sandbox wrote {} at line {line}{}",
                kind.describe(),
                if count > 1 {
                    format!(" and {} more place(s)", count - 1)
                } else {
                    String::new()
                }
            ),
            fix:
                "Remove it from the file and rotate it if it is real. The value is not shown here."
                    .to_owned(),
        })
        .collect()
}

/// Looks for secrets in the files the sandbox added or changed in the repo
/// since the snapshot. Files that git ignores (such as `.env`) are not
/// listed, so they are not scanned: they exist to hold secrets. A file that
/// is too large to read is reported at NOTICE; binary files and symbolic
/// links are skipped, since they cannot be read as text.
#[must_use]
pub fn repo_secret_findings(repo: &Path, session_dir: &Path) -> Vec<Finding> {
    let changed = match pks_core::snapshot::changed_files(repo, session_dir) {
        Ok(changed) => changed,
        Err(error) => {
            return vec![Finding {
                rule: rule::SECRET_WRITTEN,
                severity: Severity::High,
                target: "repo".to_owned(),
                message: format!(
                    "the files written during the session could not be listed: {error}"
                ),
                fix: "Check the repo by hand with git status.".to_owned(),
            }];
        }
    };
    let mut findings = Vec::new();
    for rel in changed {
        match fs_safe::read_regular(repo, Path::new(&rel)) {
            Ok(Read::Bytes(bytes)) => {
                if !fs_safe::looks_binary(&bytes) {
                    findings.extend(secret_findings_in(&rel, &String::from_utf8_lossy(&bytes)));
                }
            }
            Ok(Read::Skipped(crate::SkipReason::TooLarge)) => findings.push(Finding {
                rule: rule::SECRET_WRITTEN,
                severity: Severity::Notice,
                target: rel.clone(),
                message: "the file is too large to scan for secrets".to_owned(),
                fix: "Scan it with a dedicated tool such as ggshield.".to_owned(),
            }),
            Ok(Read::Skipped(_)) => {}
            Err(error) => findings.push(Finding {
                rule: rule::SECRET_WRITTEN,
                severity: Severity::High,
                target: rel.clone(),
                message: format!("the file could not be read to scan it: {error}"),
                fix: "Check the file by hand.".to_owned(),
            }),
        }
    }
    findings
}

/// Everything found about the session's writes to protected paths: the config
/// rules on each changed file, then the staging findings of
/// `Staging::finish`. Consumes the staging, so its mount points are removed.
#[must_use]
pub fn review(staging: Staging) -> Vec<Finding> {
    let mut findings = Vec::new();
    match staging.changed_files() {
        Ok(files) => {
            for file in files {
                let bytes = match fs::read(&file.staged) {
                    Ok(bytes) => bytes,
                    Err(error) => {
                        findings.push(high(
                            &file.rel,
                            format!("the staged copy could not be read: {error}"),
                        ));
                        continue;
                    }
                };
                let text = match String::from_utf8(bytes) {
                    Ok(text) => text,
                    Err(_) => {
                        findings.push(high(
                            &file.rel,
                            "the staged copy is not UTF-8, so its settings cannot be checked"
                                .to_owned(),
                        ));
                        continue;
                    }
                };
                findings.extend(secret_findings_in(&file.rel, &text));
                match config_findings(&file.rel, &text) {
                    None => {}
                    Some(Ok(list)) => findings.extend(list),
                    Some(Err(message)) => findings.push(high(
                        &file.rel,
                        format!("the staged copy could not be checked: {message}"),
                    )),
                }
            }
        }
        Err(error) => findings.push(high(
            "protected paths",
            format!("the changed files could not be listed: {error}"),
        )),
    }
    findings.extend(staging.finish());
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn rules(findings: &[Finding]) -> Vec<&'static str> {
        findings.iter().map(|f| f.rule.as_str()).collect()
    }

    #[test]
    fn auto_approve_turned_on_is_critical() -> TestResult {
        let findings = config_findings(
            ".vscode/settings.json",
            r#"{ "chat.tools.autoApprove": true }"#,
        )
        .ok_or("settings are a config file")??;
        assert_eq!(rules(&findings), ["WS-AUTOAPPROVE"]);
        assert_eq!(findings[0].severity, Severity::Critical);
        Ok(())
    }

    #[test]
    fn auto_approve_turned_off_is_not_a_finding() -> TestResult {
        let findings = config_findings(
            ".vscode/settings.json",
            r#"{ "chat.tools.autoApprove": false }"#,
        )
        .ok_or("settings are a config file")??;
        assert!(findings.is_empty());
        Ok(())
    }

    #[test]
    fn a_new_mcp_server_is_critical_under_auto_approve() -> TestResult {
        let findings = config_findings(
            ".kiro/settings/mcp.json",
            r#"{ "mcpServers": { "evil": { "command": "sh", "args": ["-c", "x"] } } }"#,
        )
        .ok_or("mcp is a config file")??;
        assert!(findings.iter().any(|f| f.rule.as_str() == "WS-AUTOAPPROVE"
            && f.severity == Severity::Critical
            && f.message.contains("`evil`")));
        assert!(!findings.iter().any(|f| f.rule.as_str() == "WS-MCP-SERVER"));
        Ok(())
    }

    #[test]
    fn a_new_command_hook_is_critical_under_auto_approve() -> TestResult {
        let findings = config_findings(
            ".kiro/hooks/test-on-save.json",
            r#"{ "version": "v1", "hooks": [
                { "name": "test", "trigger": "Save", "action": { "type": "command", "command": "rm -rf ~" } }
            ] }"#,
        )
        .ok_or("hooks are a config file")??;
        assert!(
            findings
                .iter()
                .any(|f| f.rule.as_str() == "WS-AUTOAPPROVE" && f.severity == Severity::Critical)
        );
        assert!(!findings.iter().any(|f| f.message.contains("rm -rf")));
        Ok(())
    }

    #[test]
    fn a_file_that_is_not_a_config_is_not_checked() {
        assert!(config_findings("src/main.rs", "fn main() {}").is_none());
    }

    #[test]
    fn invalid_json_in_a_config_is_an_error_not_a_pass() -> TestResult {
        let result = config_findings(".vscode/settings.json", "{ not json");
        assert!(matches!(result, Some(Err(_))), "{result:?}");
        Ok(())
    }

    // Test secrets are built at run time, so this file holds nothing that
    // looks like a real token.
    fn fake_github_token() -> String {
        format!("ghp_{}", "A1b2".repeat(9))
    }

    fn repo_with_snapshot(
        root: &Path,
    ) -> Result<(std::path::PathBuf, std::path::PathBuf), Box<dyn std::error::Error>> {
        let repo = root.join("repo");
        fs::create_dir_all(repo.join("src"))?;
        fs::write(repo.join("src/main.rs"), "fn main() {}\n")?;
        fs::write(repo.join(".gitignore"), ".env\n")?;
        let session = root.join("session");
        fs::create_dir_all(&session)?;
        pks_core::snapshot::create(&repo, &session)?;
        Ok((repo, session))
    }

    #[test]
    fn a_secret_written_into_the_repo_is_reported_without_its_value() -> TestResult {
        let root = tempfile::tempdir()?;
        let (repo, session) = repo_with_snapshot(root.path())?;
        let token = fake_github_token();
        fs::write(
            repo.join("src/config.rs"),
            format!("// ok\nconst T: &str = \"{token}\";\n"),
        )?;
        let findings = repo_secret_findings(&repo, &session);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].rule.as_str(), "WS-SECRET-WRITTEN");
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].target, "src/config.rs");
        assert!(
            findings[0].message.contains("a GitHub token at line 2"),
            "{}",
            findings[0].message
        );
        let shown = format!("{findings:?}");
        assert!(!shown.contains(&token), "the secret was printed");
        Ok(())
    }

    #[test]
    fn a_clean_session_and_a_gitignored_env_file_report_nothing() -> TestResult {
        let root = tempfile::tempdir()?;
        let (repo, session) = repo_with_snapshot(root.path())?;
        assert!(repo_secret_findings(&repo, &session).is_empty());
        fs::write(
            repo.join(".env"),
            format!("TOKEN={}\n", fake_github_token()),
        )?;
        fs::write(
            repo.join("src/main.rs"),
            "fn main() { println!(\"hi\"); }\n",
        )?;
        assert!(repo_secret_findings(&repo, &session).is_empty());
        Ok(())
    }

    #[test]
    fn a_secret_that_was_already_in_the_repo_is_not_blamed_on_the_session() -> TestResult {
        let root = tempfile::tempdir()?;
        let repo = root.path().join("repo");
        fs::create_dir_all(&repo)?;
        fs::write(repo.join("old.txt"), format!("{}\n", fake_github_token()))?;
        let session = root.path().join("session");
        fs::create_dir_all(&session)?;
        pks_core::snapshot::create(&repo, &session)?;
        assert!(repo_secret_findings(&repo, &session).is_empty());
        Ok(())
    }

    #[test]
    fn several_hits_of_one_kind_in_a_file_are_one_finding() -> TestResult {
        let root = tempfile::tempdir()?;
        let (repo, session) = repo_with_snapshot(root.path())?;
        let token = fake_github_token();
        fs::write(repo.join("two.txt"), format!("{token}\n{token}\n{token}\n"))?;
        let findings = repo_secret_findings(&repo, &session);
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].message.contains("line 1 and 2 more place(s)"),
            "{}",
            findings[0].message
        );
        Ok(())
    }

    #[test]
    fn a_binary_file_is_skipped() -> TestResult {
        let root = tempfile::tempdir()?;
        let (repo, session) = repo_with_snapshot(root.path())?;
        let mut bytes = vec![0u8, 1, 2, 3];
        bytes.extend_from_slice(fake_github_token().as_bytes());
        fs::write(repo.join("blob.bin"), bytes)?;
        assert!(repo_secret_findings(&repo, &session).is_empty());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn a_symbolic_link_is_never_followed() -> TestResult {
        let root = tempfile::tempdir()?;
        let (repo, session) = repo_with_snapshot(root.path())?;
        let outside = root.path().join("outside.txt");
        fs::write(&outside, format!("{}\n", fake_github_token()))?;
        std::os::unix::fs::symlink(&outside, repo.join("link.txt"))?;
        assert!(repo_secret_findings(&repo, &session).is_empty());
        Ok(())
    }
}
