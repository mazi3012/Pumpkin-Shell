//! Rules for IDE and agent config files. Formats come from vendor docs:
//! Kiro MCP (`mcpServers`, `autoApprove`) and Kiro hooks (`hooks[].action`)
//! from kiro.dev/docs; VS Code MCP (`servers`), `runOptions.runOn` and
//! `chat.tools.*` settings from code.visualstudio.com/docs.
//!
//! JSON config files may contain comments and trailing commas (JSONC), so
//! they are read with a JSONC parser, never plain `serde_json`.

use std::path::Path;

use jsonc_parser::ParseOptions;
use pks_core::{Finding, Severity};
use serde_json::Value;

use crate::{clean, finding, rule};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Settings,
    Mcp,
    KiroHooks,
    Tasks,
    YarnRc,
}

const SETTINGS_FILES: [&str; 3] = [
    ".vscode/settings.json",
    ".cursor/settings.json",
    ".windsurf/settings.json",
];
const MCP_FILES: [&str; 4] = [
    ".kiro/settings/mcp.json",
    ".mcp.json",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
];
/// Settings that let the agent run tools without asking. Both names appear in
/// vendor material: `chat.tools.autoApprove` in CVE-2025-53773 and
/// `chat.tools.global.autoApprove` in the VS Code security docs.
const AUTO_APPROVE_SETTINGS: [&str; 2] =
    ["chat.tools.autoApprove", "chat.tools.global.autoApprove"];

/// Decides which rule, if any, applies to `rel`. Paths are compared by
/// component, so `.kiro/hooks-evil/a.json` does not match `.kiro/hooks`.
pub(crate) fn kind_of(rel: &Path) -> Option<Kind> {
    let is_one_of = |names: &[&str]| names.iter().any(|name| rel == Path::new(name));
    if is_one_of(&SETTINGS_FILES) {
        Some(Kind::Settings)
    } else if is_one_of(&MCP_FILES) {
        Some(Kind::Mcp)
    } else if rel == Path::new(".vscode/tasks.json") {
        Some(Kind::Tasks)
    } else if rel == Path::new(".yarnrc.yml") {
        Some(Kind::YarnRc)
    } else if rel.parent() == Some(Path::new(".kiro/hooks"))
        && rel.extension().is_some_and(|ext| ext == "json")
    {
        Some(Kind::KiroHooks)
    } else {
        None
    }
}

/// Runs the rule for `kind` on file `text`. `path` is already cleaned.
/// Returns an error message when the file cannot be parsed, so the scan is
/// marked incomplete instead of silently passing.
pub(crate) fn check(kind: Kind, path: &str, text: &str) -> Result<Vec<Finding>, String> {
    match kind {
        Kind::YarnRc => Ok(yarnrc(path, text)),
        Kind::Settings => Ok(settings(path, &parse(path, text)?)),
        Kind::Mcp => Ok(mcp(path, &parse(path, text)?)),
        Kind::KiroHooks => Ok(kiro_hooks(path, &parse(path, text)?)),
        Kind::Tasks => Ok(tasks(path, &parse(path, text)?)),
    }
}

fn parse(path: &str, text: &str) -> Result<Value, String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    jsonc_parser::parse_to_serde_value::<Value>(text, &ParseOptions::default())
        .map_err(|error| format!("{path} is not valid JSON: {}", clean(&error.to_string())))
}

fn settings(path: &str, root: &Value) -> Vec<Finding> {
    let mut out = Vec::new();
    for key in AUTO_APPROVE_SETTINGS {
        if root.get(key) == Some(&Value::Bool(true)) {
            out.push(finding(
                rule::AUTOAPPROVE,
                Severity::Critical,
                path.to_owned(),
                format!("`{key}` is true: the agent can run tools without asking"),
                "Remove the setting or set it to false (CVE-2025-53773 pattern).",
            ));
        }
    }
    out
}

fn mcp(path: &str, root: &Value) -> Vec<Finding> {
    let mut out = Vec::new();
    // Kiro and the portable format use `mcpServers`; VS Code uses `servers`.
    for list in ["mcpServers", "servers"] {
        let Some(servers) = root.get(list).and_then(Value::as_object) else {
            continue;
        };
        for (name, server) in servers {
            let name = clean(name);
            out.push(finding(
                rule::MCP_SERVER,
                Severity::Notice,
                path.to_owned(),
                format!("MCP server `{name}`: {}", describe_server(server)),
                "Check that you trust this server before opening the project in an agent.",
            ));
            let approves_all = server
                .get("autoApprove")
                .and_then(Value::as_array)
                .is_some_and(|tools| tools.iter().any(|tool| tool.as_str() == Some("*")));
            if approves_all {
                out.push(finding(
                    rule::AUTOAPPROVE,
                    Severity::Critical,
                    path.to_owned(),
                    format!("MCP server `{name}` has autoApprove [\"*\"]: every tool runs without asking"),
                    "Replace \"*\" with the exact tool names that are safe to auto-approve.",
                ));
            }
        }
    }
    out
}

/// One-line description of a server. Arguments are never printed (they often
/// carry tokens), and URLs lose their credentials and query.
fn describe_server(server: &Value) -> String {
    let disabled = if server.get("disabled") == Some(&Value::Bool(true)) {
        " (disabled)"
    } else {
        ""
    };
    if let Some(command) = server.get("command").and_then(Value::as_str) {
        let args = server
            .get("args")
            .and_then(Value::as_array)
            .map_or(0, Vec::len);
        format!(
            "command `{}` with {args} argument(s){disabled}",
            clean(command)
        )
    } else if let Some(url) = server.get("url").and_then(Value::as_str) {
        format!("url `{}`{disabled}", clean(&strip_url_secrets(url)))
    } else {
        format!("no command or url{disabled}")
    }
}

/// Keeps scheme, host and path. Drops `user:password@`, the query and the
/// fragment, where tokens usually are.
fn strip_url_secrets(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.split(['?', '#']).next().unwrap_or_default().to_owned();
    };
    let rest = rest.split(['?', '#']).next().unwrap_or_default();
    let (authority, path) = match rest.find('/') {
        Some(index) => rest.split_at(index),
        None => (rest, ""),
    };
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    format!("{scheme}://{host}{path}")
}

fn kiro_hooks(path: &str, root: &Value) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(hooks) = root.get("hooks").and_then(Value::as_array) else {
        return out;
    };
    for hook in hooks {
        let runs_command = hook
            .get("action")
            .and_then(|action| action.get("type"))
            .and_then(Value::as_str)
            == Some("command");
        let enabled = hook.get("enabled") != Some(&Value::Bool(false));
        if runs_command && enabled {
            let name = clean(
                hook.get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("unnamed"),
            );
            let trigger = clean(
                hook.get("trigger")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown"),
            );
            out.push(finding(
                rule::KIRO_HOOK,
                Severity::Warn,
                path.to_owned(),
                format!("hook `{name}` runs a shell command on trigger `{trigger}`"),
                "Open the file and check the command. Hooks are a way to keep code running across sessions.",
            ));
        }
    }
    out
}

fn tasks(path: &str, root: &Value) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(tasks) = root.get("tasks").and_then(Value::as_array) else {
        return out;
    };
    for task in tasks {
        let run_on = task
            .get("runOptions")
            .and_then(|options| options.get("runOn"))
            .and_then(Value::as_str);
        if run_on == Some("folderOpen") {
            let label = clean(
                task.get("label")
                    .and_then(Value::as_str)
                    .unwrap_or("unnamed"),
            );
            out.push(finding(
                rule::FOLDER_OPEN_TASK,
                Severity::High,
                path.to_owned(),
                format!("task `{label}` runs when the folder is opened"),
                "Remove runOptions.runOn \"folderOpen\", or review the task command.",
            ));
        }
    }
    out
}

/// Finds a top-level `yarnPath` key. This is a line check, not a YAML parser
/// (no maintained YAML crate is in use), so a root written in flow style
/// (`{ yarnPath: x }`) is not seen.
fn yarnrc(path: &str, text: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.starts_with(char::is_whitespace) || line.starts_with('#') {
            continue;
        }
        let key = line.split(':').next().unwrap_or_default().trim();
        let key = key.trim_matches(['"', '\'']);
        if key == "yarnPath" {
            out.push(finding(
                rule::YARNPATH,
                Severity::High,
                format!("{path}:{}", index + 1),
                "`yarnPath` makes Yarn run the JavaScript file it names".to_owned(),
                "Remove yarnPath, or check that the file it points to is trusted.",
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(kind: Kind, text: &str) -> Vec<Finding> {
        check(kind, "f", text).unwrap_or_default()
    }

    fn rules(findings: &[Finding]) -> Vec<&'static str> {
        findings.iter().map(|f| f.rule.as_str()).collect()
    }

    #[test]
    fn kind_of_matches_exact_components_only() {
        assert_eq!(
            kind_of(Path::new(".vscode/settings.json")),
            Some(Kind::Settings)
        );
        assert_eq!(
            kind_of(Path::new(".kiro/settings/mcp.json")),
            Some(Kind::Mcp)
        );
        assert_eq!(
            kind_of(Path::new(".kiro/hooks/a.json")),
            Some(Kind::KiroHooks)
        );
        assert_eq!(kind_of(Path::new(".vscode/tasks.json")), Some(Kind::Tasks));
        assert_eq!(kind_of(Path::new(".yarnrc.yml")), Some(Kind::YarnRc));
        // Look-alikes (CVE-2025-54794 pattern) and wrong places.
        assert_eq!(kind_of(Path::new(".kiro/hooks-evil/a.json")), None);
        assert_eq!(kind_of(Path::new(".vscode-evil/settings.json")), None);
        assert_eq!(kind_of(Path::new("sub/.vscode/settings.json")), None);
        assert_eq!(kind_of(Path::new(".kiro/hooks/sub/a.json")), None);
        assert_eq!(kind_of(Path::new(".kiro/hooks/a.txt")), None);
        assert_eq!(kind_of(Path::new("x/.yarnrc.yml")), None);
    }

    #[test]
    fn settings_flags_true_only_and_reads_jsonc() {
        let on = "// note\n{ \"chat.tools.autoApprove\": true, /* c */ }";
        let out = run(Kind::Settings, on);
        assert_eq!(rules(&out), ["WS-AUTOAPPROVE"]);
        assert_eq!(out[0].severity, Severity::Critical);
        assert!(run(Kind::Settings, "{\"chat.tools.autoApprove\": false}").is_empty());
        assert!(run(Kind::Settings, "{\"chat.tools.autoApprove\": \"true\"}").is_empty());
        assert_eq!(
            rules(&run(
                Kind::Settings,
                "{\"chat.tools.global.autoApprove\": true}"
            )),
            ["WS-AUTOAPPROVE"]
        );
    }

    #[test]
    fn a_later_duplicate_key_wins_like_the_ide() {
        let text = "{\"chat.tools.autoApprove\": true, \"chat.tools.autoApprove\": false}";
        assert!(run(Kind::Settings, text).is_empty());
        let text = "{\"chat.tools.autoApprove\": false, \"chat.tools.autoApprove\": true}";
        assert_eq!(rules(&run(Kind::Settings, text)), ["WS-AUTOAPPROVE"]);
    }

    #[test]
    fn mcp_lists_servers_and_flags_wildcard_per_server() {
        let text = r#"{ "mcpServers": {
            "a": { "command": "npx", "args": ["-y", "pkg", "--token=NOT-A-REAL-TOKEN"], "autoApprove": ["*"] },
            "b": { "command": "node", "autoApprove": ["read_file"] },
            "c": { "url": "https://user:pw@example.com/mcp?key=NOT-A-REAL-KEY#frag", "disabled": true }
        } }"#;
        let out = run(Kind::Mcp, text);
        assert_eq!(
            rules(&out),
            [
                "WS-MCP-SERVER",
                "WS-AUTOAPPROVE",
                "WS-MCP-SERVER",
                "WS-MCP-SERVER"
            ]
        );
        let joined = out.iter().map(|f| f.message.clone()).collect::<String>();
        assert!(joined.contains("command `npx` with 3 argument(s)"));
        assert!(joined.contains("url `https://example.com/mcp` (disabled)"));
        assert!(!joined.contains("NOT-A-REAL-TOKEN"));
        assert!(!joined.contains("NOT-A-REAL-KEY"));
        assert!(!joined.contains("pw@"));
        assert_eq!(out[1].severity, Severity::Critical);
        assert_eq!(out[0].severity, Severity::Notice);
    }

    #[test]
    fn mcp_reads_the_vscode_servers_key() {
        let out = run(
            Kind::Mcp,
            r#"{ "servers": { "x": { "type": "stdio", "command": "npx" } } }"#,
        );
        assert_eq!(rules(&out), ["WS-MCP-SERVER"]);
    }

    #[test]
    fn mcp_ignores_a_top_level_auto_approve() {
        // Kiro documents autoApprove per server only.
        assert!(run(Kind::Mcp, r#"{ "autoApprove": ["*"] }"#).is_empty());
    }

    #[test]
    fn wildcard_only_counts_as_the_exact_string() {
        let text =
            r#"{ "mcpServers": { "a": { "command": "x", "autoApprove": ["read*", "*x"] } } }"#;
        assert_eq!(rules(&run(Kind::Mcp, text)), ["WS-MCP-SERVER"]);
    }

    #[test]
    fn url_secrets_are_stripped() {
        assert_eq!(
            strip_url_secrets("https://h.example/p?a=b"),
            "https://h.example/p"
        );
        assert_eq!(
            strip_url_secrets("https://u:p@h.example:8080/x#y"),
            "https://h.example:8080/x"
        );
        assert_eq!(strip_url_secrets("https://h.example"), "https://h.example");
        assert_eq!(
            strip_url_secrets("unix:///tmp/s.sock#/sub"),
            "unix:///tmp/s.sock"
        );
        assert_eq!(strip_url_secrets("no-scheme?token=x"), "no-scheme");
    }

    #[test]
    fn kiro_hooks_flag_enabled_command_actions_only() {
        let text = r#"{ "version": "v1", "hooks": [
            { "name": "a", "trigger": "Stop", "action": { "type": "command", "command": "echo hi" } },
            { "name": "b", "trigger": "Stop", "action": { "type": "agent", "prompt": "hi" } },
            { "name": "c", "trigger": "Stop", "enabled": false, "action": { "type": "command", "command": "x" } }
        ] }"#;
        let out = run(Kind::KiroHooks, text);
        assert_eq!(rules(&out), ["WS-KIRO-HOOK"]);
        assert!(out[0].message.contains("`a`"));
        assert!(!out[0].message.contains("echo hi"));
        assert_eq!(out[0].severity, Severity::Warn);
    }

    #[test]
    fn tasks_flag_folder_open_only() {
        let text = r#"{ "version": "2.0.0", "tasks": [
            { "label": "build", "type": "shell", "command": "make" },
            { "label": "evil", "type": "shell", "command": "id", "runOptions": { "runOn": "folderOpen" } },
            { "label": "later", "type": "shell", "command": "id", "runOptions": { "runOn": "default" } }
        ] }"#;
        let out = run(Kind::Tasks, text);
        assert_eq!(rules(&out), ["WS-FOLDER-OPEN-TASK"]);
        assert!(out[0].message.contains("`evil`"));
    }

    #[test]
    fn yarnrc_finds_top_level_yarnpath_only() {
        let text = "# yarnPath: .yarn/ignored.cjs\nnodeLinker: node-modules\nyarnPath: .yarn/releases/x.cjs\nplugins:\n  - yarnPath: nested\n";
        let out = run(Kind::YarnRc, text);
        assert_eq!(rules(&out), ["WS-YARNPATH"]);
        assert_eq!(out[0].target, "f:3");
        assert_eq!(
            rules(&run(Kind::YarnRc, "\"yarnPath\": x\n")),
            ["WS-YARNPATH"]
        );
        assert!(run(Kind::YarnRc, "nodeLinker: pnp\n").is_empty());
    }

    #[test]
    fn invalid_json_is_an_error_not_a_pass() {
        assert!(check(Kind::Settings, "f", "{ not json").is_err());
        assert!(check(Kind::Mcp, "f", "").is_ok());
    }

    #[test]
    fn a_byte_order_mark_does_not_break_parsing() {
        let out = run(Kind::Settings, "\u{feff}{\"chat.tools.autoApprove\": true}");
        assert_eq!(rules(&out), ["WS-AUTOAPPROVE"]);
    }

    #[test]
    fn untrusted_names_are_cleaned() {
        let text = "{ \"mcpServers\": { \"bad\\u001b[31m\": { \"command\": \"x\" } } }";
        let out = run(Kind::Mcp, text);
        assert!(!out[0].message.contains('\u{1b}'));
    }
}
