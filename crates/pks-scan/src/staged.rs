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
use crate::rule;

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
}
