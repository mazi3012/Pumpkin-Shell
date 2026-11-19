//! Detection rules for agent-escape setups.
//!
//! Each rule implements the `Rule` trait and checks a specific attack vector
//! from PRD §1 (rows 1-12) and FR-DET.

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use pks_core::{Finding, RuleId, Severity};

/// A detection rule that can check a file for problems.
pub trait Rule {
    /// Returns the rule ID.
    fn rule_id(&self) -> RuleId;

    /// Returns the severity level.
    fn severity(&self) -> Severity;

    /// Check if the file matches this rule.
    /// Returns Some(Finding) if a problem is found, None otherwise.
    fn check(&self, repo_root: &Path, rel_path: &str) -> Result<Option<Finding>, RuleError>;

    /// Returns a human-readable name for the rule.
    fn name(&self) -> &str;
}

/// Error type for rule execution.
#[derive(Debug, thiserror::Error)]
pub enum RuleError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("UTF-8 error: {0}")]
    Utf8(#[from] std::str::Utf8Error),
}

/// Hidden Unicode characters that can hide malicious instructions.
/// U+E0000–U+E007F (tag characters), bidi controls, zero-width chars.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HiddenUnicode {
    /// The problematic Unicode code point.
    pub codepoint: u32,
    /// The character itself (for display).
    pub character: char,
    /// The line number where it was found.
    pub line: usize,
    /// The column where it was found.
    pub column: usize,
}

impl HiddenUnicode {
    pub fn new(codepoint: u32, character: char, line: usize, column: usize) -> Self {
        Self {
            codepoint,
            character,
            line,
            column,
        }
    }
}

/// Rule: WS-HIDDEN-UNICODE
/// Detects tag characters U+E0000–U+E007F, bidi controls, and zero-width chars.
pub struct HiddenUnicodeRule;

impl Rule for HiddenUnicodeRule {
    fn rule_id(&self) -> RuleId {
        RuleId::new("WS-HIDDEN-UNICODE")
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn check(&self, repo_root: &Path, rel_path: &str) -> Result<Option<Finding>, RuleError> {
        let file_path = repo_root.join(rel_path);
        let content = fs::read_to_string(&file_path)?;

        let mut found: Option<Finding> = None;
        let mut first_problem: Option<HiddenUnicode> = None;

        for (line_idx, line) in content.lines().enumerate() {
            for (char_idx, ch) in line.chars().enumerate() {
                let cp = ch as u32;
                // Check tag characters U+E0000–U+E007F
                if (0xE0000..=0xE007F).contains(&cp) {
                    let problem = HiddenUnicode::new(cp, ch, line_idx + 1, char_idx + 1);
                    if first_problem.is_none() {
                        first_problem = Some(problem);
                    }
                }
                // Check bidi controls: U+200E, U+200F, U+202A–U+202E, U+2066–U+2069
                matches!(
                    cp,
                    0x200E | 0x200F | 0x202A..=0x202E | 0x2066..=0x2069
                )
                .then(|| {
                    let problem = HiddenUnicode::new(cp, ch, line_idx + 1, char_idx + 1);
                    if first_problem.is_none() {
                        first_problem = Some(problem);
                    }
                });
                // Check zero-width chars: U+200B, U+200C, U+200D, U+FEFF
                matches!(cp, 0x200B | 0x200C | 0x200D | 0xFEFF).then(|| {
                    let problem = HiddenUnicode::new(cp, ch, line_idx + 1, char_idx + 1);
                    if first_problem.is_none() {
                        first_problem = Some(problem);
                    }
                });
            }
        }

        if let Some(problem) = first_problem {
            found = Some(Finding {
                rule: self.rule_id(),
                severity: self.severity(),
                target: rel_path.to_string(),
                message: format!(
                    "hidden Unicode character U+{:05X} ({}) found at line {}, column {}",
                    problem.codepoint, problem.character, problem.line, problem.column
                ),
                fix: "Remove the hidden Unicode characters from the file.".to_string(),
            });
        }

        Ok(found)
    }

    fn name(&self) -> &str {
        "hidden Unicode characters"
    }
}

/// Rule: WS-AUTOAPPROVE
/// Detects auto-approve configurations in various IDE settings.
pub struct AutoApproveRule;

impl Rule for AutoApproveRule {
    fn rule_id(&self) -> RuleId {
        RuleId::new("WS-AUTOAPPROVE")
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn check(&self, repo_root: &Path, rel_path: &str) -> Result<Option<Finding>, RuleError> {
        // Check paths that might contain auto-approve settings
        let paths_to_check = [
            ".vscode/settings.json",
            ".cursor/settings.json",
            ".windsurf/settings.json",
            ".kiro/settings/mcp.json",
            ".mcp.json",
            ".cursor/mcp.json",
        ];

        if !paths_to_check.contains(&rel_path) {
            return Ok(None);
        }

        let file_path = repo_root.join(rel_path);
        let content = fs::read_to_string(&file_path)?;
        let value: Value = serde_json::from_str(&content)?;

        // Check for auto-approve patterns
        if let Some(obj) = value.as_object() {
            // Check chat.tools.autoApprove
            if let Some(settings) = obj.get("chat").and_then(|c| c.get("tools"))
                && let Some(auto_approve) = settings.get("autoApprove")
                && *auto_approve == Value::Bool(true)
            {
                return Ok(Some(Finding {
                    rule: self.rule_id(),
                    severity: self.severity(),
                    target: rel_path.to_string(),
                    message: "auto-approve enabled: chat.tools.autoApprove = true".to_string(),
                    fix: format!("Remove 'chat.tools.autoApprove: true' from {}", rel_path),
                }));
            }

            // Check MCP autoApprove: ["*"]
            if let Some(mcp) = obj.get("autoApprove")
                && let Some(arr) = mcp.as_array()
                && arr.iter().any(|v| *v == Value::String("*".to_string()))
            {
                return Ok(Some(Finding {
                    rule: self.rule_id(),
                    severity: self.severity(),
                    target: rel_path.to_string(),
                    message: "auto-approve enabled: autoApprove contains \"*\"".to_string(),
                    fix: format!("Remove auto-approve: [\"*\"] from {}", rel_path),
                }));
            }
        }

        Ok(None)
    }

    fn name(&self) -> &str {
        "auto-approve configurations"
    }
}

/// Rule: MCP-SERVER-INVENTORY
/// Lists all configured MCP servers.
pub struct McpServerInventoryRule;

impl Rule for McpServerInventoryRule {
    fn rule_id(&self) -> RuleId {
        RuleId::new("MCP-SERVER-INVENTORY")
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn check(&self, repo_root: &Path, rel_path: &str) -> Result<Option<Finding>, RuleError> {
        let mcp_paths = [".kiro/settings/mcp.json", ".mcp.json", ".cursor/mcp.json"];

        if !mcp_paths.contains(&rel_path) {
            return Ok(None);
        }

        let file_path = repo_root.join(rel_path);
        let content = fs::read_to_string(&file_path)?;
        let value: Value = serde_json::from_str(&content)?;

        if let Some(obj) = value.as_object()
            && let Some(servers) = obj.get("servers")
            && let Some(arr) = servers.as_array()
        {
            let server_names: Vec<String> = arr
                .iter()
                .filter_map(|s| {
                    s.get("name")
                        .and_then(|n| n.as_str().map(|s| s.to_string()))
                })
                .collect();

            if !server_names.is_empty() {
                return Ok(Some(Finding {
                    rule: self.rule_id(),
                    severity: self.severity(),
                    target: rel_path.to_string(),
                    message: format!("MCP servers configured: {}", server_names.join(", ")),
                    fix: format!(
                        "Review MCP servers in {}: ensure only trusted servers are configured",
                        rel_path
                    ),
                }));
            }
        }

        Ok(None)
    }

    fn name(&self) -> &str {
        "MCP server inventory"
    }
}

/// Rule: KIRO-COMMAND-HOOK
/// Detects Kiro command hooks that run shell commands.
pub struct KiroCommandHookRule;

impl Rule for KiroCommandHookRule {
    fn rule_id(&self) -> RuleId {
        RuleId::new("KIRO-COMMAND-HOOK")
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn check(&self, repo_root: &Path, rel_path: &str) -> Result<Option<Finding>, RuleError> {
        if !rel_path.starts_with(".kiro/hooks/") {
            return Ok(None);
        }

        let file_path = repo_root.join(rel_path);
        let content = fs::read_to_string(&file_path)?;
        let value: Value = serde_json::from_str(&content)?;

        if let Some(obj) = value.as_object()
            && let Some(hooks) = obj.get("hooks")
            && let Some(arr) = hooks.as_array()
        {
            for hook in arr {
                if let Some(action) = hook.get("action")
                    && let Some(action_obj) = action.as_object()
                    && let Some(action_type) = action_obj.get("type").and_then(|t| t.as_str())
                    && action_type == "command"
                {
                    let hook_name = hook
                        .get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or("unnamed");
                    return Ok(Some(Finding {
                        rule: self.rule_id(),
                        severity: self.severity(),
                        target: rel_path.to_string(),
                        message: format!("Kiro command hook detected: {}", hook_name),
                        fix: format!(
                            "Review command hooks in {}: remove any hooks that run untrusted commands",
                            rel_path
                        ),
                    }));
                }
            }
        }

        Ok(None)
    }

    fn name(&self) -> &str {
        "Kiro command hooks"
    }
}

/// Rule: FOLDEROPEN-TASK
/// Detects VS Code/Cursor tasks that run on folder open.
pub struct FolderOpenTaskRule;

impl Rule for FolderOpenTaskRule {
    fn rule_id(&self) -> RuleId {
        RuleId::new("FOLDEROPEN-TASK")
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn check(&self, repo_root: &Path, rel_path: &str) -> Result<Option<Finding>, RuleError> {
        let task_paths = [
            ".vscode/tasks.json",
            ".cursor/tasks.json",
            ".windsurf/tasks.json",
        ];

        if !task_paths.contains(&rel_path) {
            return Ok(None);
        }

        let file_path = repo_root.join(rel_path);
        let content = fs::read_to_string(&file_path)?;
        let value: Value = serde_json::from_str(&content)?;

        if let Some(obj) = value.as_object()
            && let Some(tasks) = obj.get("tasks")
            && let Some(arr) = tasks.as_array()
        {
            for task in arr {
                if let Some(run_options) = task.get("runOptions")
                    && let Some(run_on) = run_options.get("runOn")
                    && *run_on == Value::String("folderOpen".to_string())
                {
                    let task_name = task
                        .get("label")
                        .and_then(|l| l.as_str())
                        .unwrap_or("unnamed");
                    return Ok(Some(Finding {
                        rule: self.rule_id(),
                        severity: self.severity(),
                        target: format!("{} (task: {})", rel_path, task_name),
                        message: format!("Folder-open task detected: {}", task_name),
                        fix: format!(
                            "Review folder-open task '{}' in {}: ensure it doesn't run untrusted code",
                            task_name, rel_path
                        ),
                    }));
                }
            }
        }

        Ok(None)
    }

    fn name(&self) -> &str {
        "folder-open tasks"
    }
}

/// Rule: YARNPATH
/// Detects custom yarn paths that could be used for persistence.
pub struct YarnPathRule;

impl Rule for YarnPathRule {
    fn rule_id(&self) -> RuleId {
        RuleId::new("YARNPATH")
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn check(&self, repo_root: &Path, rel_path: &str) -> Result<Option<Finding>, RuleError> {
        if rel_path != ".yarnrc.yml" {
            return Ok(None);
        }

        // Check .yarnrc.yml exists and has yarnPath
        let file_path = repo_root.join(rel_path);
        let content = fs::read_to_string(&file_path)?;

        // Simple YAML parsing for yarnPath
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("yarnPath") {
                return Ok(Some(Finding {
                    rule: self.rule_id(),
                    severity: self.severity(),
                    target: rel_path.to_string(),
                    message: "Custom yarnPath detected".to_string(),
                    fix: "Review .yarnrc.yml yarnPath: ensure it points to a trusted version"
                        .to_string(),
                }));
            }
        }

        Ok(None)
    }

    fn name(&self) -> &str {
        "yarnPath configuration"
    }
}

/// Rule: GIT-HOOKS
/// Detects git hooks and fsmonitor configuration.
pub struct GitHooksRule;

impl Rule for GitHooksRule {
    fn rule_id(&self) -> RuleId {
        RuleId::new("GIT-HOOKS")
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn check(&self, repo_root: &Path, rel_path: &str) -> Result<Option<Finding>, RuleError> {
        // Check .git/config for hooksPath
        if rel_path == ".git/config" {
            let file_path = repo_root.join(rel_path);
            let content = fs::read_to_string(&file_path)?;

            if content.contains("hooksPath") || content.contains("fsmonitor") {
                return Ok(Some(Finding {
                    rule: self.rule_id(),
                    severity: self.severity(),
                    target: rel_path.to_string(),
                    message: "Git hooksPath or fsmonitor configured".to_string(),
                    fix: "Review .git/config for hooksPath or fsmonitor entries and remove them"
                        .to_string(),
                }));
            }
        }

        // Check .git/hooks directory (not in repo root, so check separately)
        if rel_path.starts_with(".git/hooks/") {
            let file_path = repo_root.join(rel_path);
            if file_path.is_file() {
                return Ok(Some(Finding {
                    rule: self.rule_id(),
                    severity: self.severity(),
                    target: rel_path.to_string(),
                    message: "Custom git hook detected".to_string(),
                    fix: format!("Remove or review custom git hook: {}", rel_path),
                }));
            }
        }

        Ok(None)
    }

    fn name(&self) -> &str {
        "git hooks configuration"
    }
}

/// Rule: ADS-WINDOWS
/// Detects NTFS alternate data streams on Windows.
#[cfg(target_os = "windows")]
pub struct AlternateDataStreamRule;

#[cfg(target_os = "windows")]
impl Rule for AlternateDataStreamRule {
    fn rule_id(&self) -> RuleId {
        RuleId::new("ADS-WINDOWS")
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn check(&self, repo_root: &Path, rel_path: &str) -> Result<Option<Finding>, RuleError> {
        // Check for alternate data streams (file:stream format)
        if rel_path.contains(':') {
            return Ok(Some(Finding {
                rule: self.rule_id(),
                severity: self.severity(),
                target: rel_path.to_string(),
                message: "NTFS alternate data stream detected".to_string(),
                fix: format!("Remove alternate data stream from: {}", rel_path),
            }));
        }

        Ok(None)
    }

    fn name(&self) -> &str {
        "NTFS alternate data streams"
    }
}

/// All available rules.
pub struct RuleProvider;

impl RuleProvider {
    /// Returns a list of all detection rules.
    pub fn all() -> Vec<Box<dyn Rule>> {
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(HiddenUnicodeRule),
            Box::new(AutoApproveRule),
            Box::new(McpServerInventoryRule),
            Box::new(KiroCommandHookRule),
            Box::new(FolderOpenTaskRule),
            Box::new(YarnPathRule),
            Box::new(GitHooksRule),
        ];

        #[cfg(target_os = "windows")]
        rules.push(Box::new(AlternateDataStreamRule));

        rules
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

        temp
    }

    #[test]
    fn test_hidden_unicode() {
        let temp = create_test_repo(&[
            ("test.txt", "normal text\n"),
            ("hidden.txt", "hello\u{e0000}world\n"), // tag character
        ]);

        let rule = HiddenUnicodeRule;
        let result = rule.check(temp.path(), "hidden.txt").unwrap();

        assert!(result.is_some());
        let finding = result.unwrap();
        assert_eq!(finding.rule.as_str(), "WS-HIDDEN-UNICODE");
    }

    #[test]
    fn test_auto_approve() {
        let temp = create_test_repo(&[
            (
                ".vscode/settings.json",
                r#"{"chat": {"tools": {"autoApprove": true}}}"#,
            ),
            (".cursor/mcp.json", r#"{"autoApprove": ["*"]}"#),
        ]);

        let rule = AutoApproveRule;

        // Test chat.tools.autoApprove
        let result = rule.check(temp.path(), ".vscode/settings.json").unwrap();
        assert!(result.is_some());
        assert!(result.unwrap().message.contains("auto-approve"));

        // Test MCP autoApprove: ["*"]
        let result = rule.check(temp.path(), ".cursor/mcp.json").unwrap();
        assert!(result.is_some());
    }

    #[test]
    fn test_clean_repo() {
        let temp = create_test_repo(&[
            ("README.md", "# Test\n"),
            ("Cargo.toml", "[package]\nname = \"test\"\n"),
        ]);

        let rules = RuleProvider::all();
        let mut findings = Vec::new();

        for rule in rules {
            for path in ["README.md", "Cargo.toml"] {
                if let Some(finding) = rule.check(temp.path(), path).unwrap() {
                    findings.push(finding);
                }
            }
        }

        assert!(findings.is_empty(), "Clean repo should have no findings");
    }
}
