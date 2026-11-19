//! Fixture repos under `tests/fixtures/scan/` (one per rule, plus a clean
//! repo) and evasion cases. Fixtures are copied to a temp dir first, so a
//! `dot-git` directory can become a real `.git`.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use pks_scan::{Report, ScanOptions, SkipReason, scan};
use tempfile::TempDir;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const HONOR_GITIGNORE: ScanOptions = ScanOptions {
    respect_gitignore: true,
};
const ALL_FILES: ScanOptions = ScanOptions {
    respect_gitignore: false,
};

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/scan")
}

fn copy_tree(from: &Path, to: &Path) -> io::Result<()> {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = if name == "dot-git" {
            ".git".into()
        } else {
            name
        };
        let target = to.join(name);
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else {
            fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

fn fixture(name: &str) -> io::Result<TempDir> {
    let dir = tempfile::tempdir()?;
    copy_tree(&fixture_root().join(name), dir.path())?;
    Ok(dir)
}

fn write(root: &Path, rel: &str, content: &str) -> io::Result<()> {
    let path = root.join(rel);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, content)
}

/// `(rule, target)` of every finding, in report order.
fn found(report: &Report) -> Vec<(&str, &str)> {
    report
        .findings
        .iter()
        .map(|f| (f.rule.as_str(), f.target.as_str()))
        .collect()
}

#[test]
fn clean_repo_has_no_findings_skips_or_errors() -> TestResult {
    let dir = fixture("clean")?;
    let report = scan(dir.path(), &ALL_FILES)?;
    assert!(report.findings.is_empty(), "{:?}", report.findings);
    assert!(report.skipped.is_empty(), "{:?}", report.skipped);
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    assert!(report.files_scanned >= 5);
    Ok(())
}

#[test]
fn ws_hidden_unicode_fixture() -> TestResult {
    let dir = fixture("ws-hidden-unicode")?;
    let report = scan(dir.path(), &ALL_FILES)?;
    assert_eq!(
        found(&report),
        [
            ("WS-HIDDEN-UNICODE", ".kiro/steering/rules.md:3"),
            ("WS-HIDDEN-UNICODE", ".kiro/steering/rules.md:3"),
            ("WS-HIDDEN-UNICODE", "docs/bidi.md:3"),
            ("WS-HIDDEN-UNICODE", "docs/zero-width.md:2"),
        ]
    );
    let messages: Vec<_> = report.findings.iter().map(|f| f.message.as_str()).collect();
    assert!(messages.iter().any(|m| m.contains("tag character U+E0041")));
    assert!(messages.iter().any(|m| m.contains("U+202E")));
    assert!(messages.iter().any(|m| m.contains("U+200B")));
    assert!(report.errors.is_empty());
    Ok(())
}

#[test]
fn ws_autoapprove_fixture() -> TestResult {
    let dir = fixture("ws-autoapprove")?;
    let report = scan(dir.path(), &ALL_FILES)?;
    assert_eq!(
        found(&report),
        [
            ("WS-AUTOAPPROVE", ".kiro/settings/mcp.json"),
            ("WS-MCP-SERVER", ".kiro/settings/mcp.json"),
            ("WS-AUTOAPPROVE", ".vscode/settings.json"),
        ]
    );
    assert!(report.errors.is_empty(), "JSONC settings must parse");
    Ok(())
}

#[test]
fn ws_mcp_server_fixture_lists_servers_without_secrets() -> TestResult {
    let dir = fixture("ws-mcp-server")?;
    let report = scan(dir.path(), &ALL_FILES)?;
    assert_eq!(
        found(&report),
        [
            ("WS-MCP-SERVER", ".mcp.json"),
            ("WS-MCP-SERVER", ".mcp.json"),
            ("WS-MCP-SERVER", ".vscode/mcp.json"),
        ]
    );
    let all = format!("{:?}", report.findings);
    for secret in ["NOT-A-REAL-TOKEN", "NOT-A-REAL-PASSWORD", "NOT-A-REAL-KEY"] {
        assert!(!all.contains(secret), "{secret} leaked into a finding");
    }
    assert!(all.contains("command `npx` with 3 argument(s)"));
    assert!(all.contains("url `https://example.com/mcp`"));
    Ok(())
}

#[test]
fn ws_kiro_hook_fixture() -> TestResult {
    let dir = fixture("ws-kiro-hook")?;
    let report = scan(dir.path(), &ALL_FILES)?;
    assert_eq!(found(&report), [("WS-KIRO-HOOK", ".kiro/hooks/lint.json")]);
    Ok(())
}

#[test]
fn ws_folder_open_task_fixture() -> TestResult {
    let dir = fixture("ws-folder-open-task")?;
    let report = scan(dir.path(), &ALL_FILES)?;
    assert_eq!(
        found(&report),
        [("WS-FOLDER-OPEN-TASK", ".vscode/tasks.json")]
    );
    Ok(())
}

#[test]
fn ws_yarnpath_fixture() -> TestResult {
    let dir = fixture("ws-yarnpath")?;
    let report = scan(dir.path(), &ALL_FILES)?;
    assert_eq!(found(&report), [("WS-YARNPATH", ".yarnrc.yml:2")]);
    Ok(())
}

#[test]
fn ws_git_hook_fixture() -> TestResult {
    let dir = fixture("ws-git-hook")?;
    let report = scan(dir.path(), &ALL_FILES)?;
    assert_eq!(
        found(&report),
        [
            ("WS-GIT-HOOK", ".git/config:3"),
            ("WS-GIT-HOOK", ".git/config:4"),
            ("WS-GIT-HOOK", ".git/config:6"),
            ("WS-GIT-HOOK", ".git/hooks/pre-commit"),
        ]
    );
    assert!(report.errors.is_empty());
    Ok(())
}

// --- evasion cases -------------------------------------------------------

#[test]
fn a_binary_file_does_not_abort_or_hide_other_findings() -> TestResult {
    let dir = fixture("evasion-binary")?;
    let report = scan(dir.path(), &ALL_FILES)?;
    assert_eq!(found(&report), [("WS-HIDDEN-UNICODE", "notes.md:2")]);
    assert_eq!(report.skipped.len(), 1);
    assert_eq!(report.skipped[0].path, "blob.bin");
    assert_eq!(report.skipped[0].reason, SkipReason::Binary);
    assert!(report.errors.is_empty());
    Ok(())
}

#[test]
fn a_file_with_bad_utf8_is_still_scanned() -> TestResult {
    let dir = tempfile::tempdir()?;
    let mut bytes = b"latin1 caf\xe9 then ".to_vec();
    bytes.extend_from_slice("\u{200b}".as_bytes());
    fs::write(dir.path().join("a.md"), bytes)?;
    let report = scan(dir.path(), &ALL_FILES)?;
    assert_eq!(found(&report), [("WS-HIDDEN-UNICODE", "a.md:1")]);
    Ok(())
}

#[test]
fn a_nul_byte_cannot_hide_a_steering_file() -> TestResult {
    let dir = tempfile::tempdir()?;
    let mut bytes = b"rules\0\n".to_vec();
    bytes.extend_from_slice("\u{e0041}".as_bytes());
    fs::create_dir_all(dir.path().join(".kiro/steering"))?;
    fs::write(dir.path().join(".kiro/steering/a.md"), &bytes)?;
    // The same bytes in an ordinary path are skipped as binary and listed.
    fs::write(dir.path().join("plain.md"), &bytes)?;
    let report = scan(dir.path(), &ALL_FILES)?;
    assert_eq!(
        found(&report),
        [("WS-HIDDEN-UNICODE", ".kiro/steering/a.md:2")]
    );
    assert_eq!(report.skipped.len(), 1);
    assert_eq!(report.skipped[0].path, "plain.md");
    Ok(())
}

#[test]
fn gitignore_hides_ordinary_files_only_when_honored() -> TestResult {
    let dir = tempfile::tempdir()?;
    write(dir.path(), ".gitignore", "secret.md\n")?;
    write(dir.path(), "secret.md", "hidden\u{200b}\n")?;
    assert!(scan(dir.path(), &HONOR_GITIGNORE)?.findings.is_empty());
    assert_eq!(
        found(&scan(dir.path(), &ALL_FILES)?),
        [("WS-HIDDEN-UNICODE", "secret.md:1")]
    );
    Ok(())
}

#[test]
fn a_committed_dot_ignore_file_cannot_hide_anything() -> TestResult {
    let dir = tempfile::tempdir()?;
    write(dir.path(), ".ignore", "*\n")?;
    write(dir.path(), "a.md", "x\u{200b}\n")?;
    let report = scan(dir.path(), &HONOR_GITIGNORE)?;
    assert_eq!(found(&report), [("WS-HIDDEN-UNICODE", "a.md:1")]);
    Ok(())
}

#[test]
fn gitignore_cannot_hide_agent_config_directories() -> TestResult {
    let dir = tempfile::tempdir()?;
    write(dir.path(), ".gitignore", ".kiro/\n.vscode/\n")?;
    write(dir.path(), ".kiro/steering/a.md", "x\u{e0041}\n")?;
    write(
        dir.path(),
        ".vscode/settings.json",
        "{\"chat.tools.autoApprove\": true}",
    )?;
    let report = scan(dir.path(), &HONOR_GITIGNORE)?;
    assert_eq!(
        found(&report),
        [
            ("WS-HIDDEN-UNICODE", ".kiro/steering/a.md:1"),
            ("WS-AUTOAPPROVE", ".vscode/settings.json"),
        ]
    );
    Ok(())
}

#[test]
fn look_alike_paths_are_not_treated_as_config() -> TestResult {
    let dir = tempfile::tempdir()?;
    let hook =
        r#"{ "hooks": [ { "name": "x", "action": { "type": "command", "command": "id" } } ] }"#;
    write(dir.path(), ".kiro/hooks-evil/a.json", hook)?;
    write(dir.path(), "sub/.kiro/hooks/a.json", hook)?;
    write(
        dir.path(),
        ".vscode-evil/settings.json",
        "{\"chat.tools.autoApprove\": true}",
    )?;
    let report = scan(dir.path(), &ALL_FILES)?;
    assert!(report.findings.is_empty(), "{:?}", report.findings);
    Ok(())
}

#[test]
fn an_unparsable_config_makes_the_scan_incomplete_but_other_findings_remain() -> TestResult {
    let dir = tempfile::tempdir()?;
    write(dir.path(), ".vscode/settings.json", "{ not json")?;
    write(dir.path(), ".yarnrc.yml", "yarnPath: x.cjs\n")?;
    let report = scan(dir.path(), &ALL_FILES)?;
    assert_eq!(found(&report), [("WS-YARNPATH", ".yarnrc.yml:1")]);
    assert_eq!(report.errors.len(), 1);
    assert_eq!(report.errors[0].path, ".vscode/settings.json");
    assert!(!report.is_complete());
    Ok(())
}

#[cfg(unix)]
#[test]
fn an_unreadable_file_is_an_error_and_the_scan_continues() -> TestResult {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir()?;
    write(dir.path(), "locked.md", "x")?;
    write(dir.path(), "other.md", "x\u{200b}")?;
    let locked = dir.path().join("locked.md");
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000))?;
    if fs::File::open(&locked).is_ok() {
        // Running as root: permissions are not enforced, nothing to test.
        return Ok(());
    }
    let report = scan(dir.path(), &ALL_FILES)?;
    assert_eq!(found(&report), [("WS-HIDDEN-UNICODE", "other.md:1")]);
    assert_eq!(report.errors.len(), 1);
    assert_eq!(report.errors[0].path, "locked.md");
    Ok(())
}

#[cfg(unix)]
#[test]
fn symlinks_are_never_followed() -> TestResult {
    use std::os::unix::fs::symlink;
    let outside = tempfile::tempdir()?;
    write(
        outside.path(),
        "settings.json",
        "{\"chat.tools.autoApprove\": true}",
    )?;
    write(outside.path(), "bad.md", "x\u{200b}")?;
    let repo = tempfile::tempdir()?;
    fs::create_dir(repo.path().join(".vscode"))?;
    symlink(
        outside.path().join("settings.json"),
        repo.path().join(".vscode/settings.json"),
    )?;
    symlink(outside.path(), repo.path().join("linked-dir"))?;
    symlink(outside.path().join("bad.md"), repo.path().join("linked.md"))?;
    let report = scan(repo.path(), &ALL_FILES)?;
    assert!(report.findings.is_empty(), "{:?}", report.findings);
    let mut skipped: Vec<_> = report.skipped.iter().map(|s| s.path.as_str()).collect();
    skipped.sort_unstable();
    assert_eq!(
        skipped,
        [".vscode/settings.json", "linked-dir", "linked.md"]
    );
    assert!(
        report
            .skipped
            .iter()
            .all(|s| s.reason == SkipReason::Symlink)
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn control_characters_in_file_names_do_not_reach_the_report() -> TestResult {
    let dir = tempfile::tempdir()?;
    write(dir.path(), "evil\u{1b}[31m\u{202e}name.md", "x\u{200b}")?;
    let report = scan(dir.path(), &ALL_FILES)?;
    assert_eq!(report.findings.len(), 1);
    let target = &report.findings[0].target;
    assert!(
        !target.contains('\u{1b}') && !target.contains('\u{202e}'),
        "{target}"
    );
    assert!(target.contains("\\u{001b}"));
    Ok(())
}

#[test]
fn files_over_the_size_limit_are_listed_as_skipped() -> TestResult {
    let dir = tempfile::tempdir()?;
    let big = vec![b'a'; 8 * 1024 * 1024 + 1];
    fs::write(dir.path().join("big.txt"), big)?;
    let report = scan(dir.path(), &ALL_FILES)?;
    assert_eq!(report.skipped.len(), 1);
    assert_eq!(report.skipped[0].reason, SkipReason::TooLarge);
    Ok(())
}

#[test]
fn scanning_twice_gives_the_same_report() -> TestResult {
    let dir = fixture("ws-git-hook")?;
    let first = serde_json::to_string(&scan(dir.path(), &ALL_FILES)?)?;
    let second = serde_json::to_string(&scan(dir.path(), &ALL_FILES)?)?;
    assert_eq!(first, second);
    Ok(())
}

#[test]
fn json_report_uses_uppercase_severities_and_rule_ids() -> TestResult {
    let dir = fixture("ws-autoapprove")?;
    let value = serde_json::to_value(scan(dir.path(), &ALL_FILES)?)?;
    let first = &value["findings"][0];
    assert_eq!(first["rule"], "WS-AUTOAPPROVE");
    assert_eq!(first["severity"], "CRITICAL");
    assert_eq!(value["findings"][1]["severity"], "NOTICE");
    assert!(value["errors"].as_array().is_some_and(Vec::is_empty));
    Ok(())
}

#[test]
fn a_missing_or_non_directory_root_is_an_error() -> TestResult {
    let dir = tempfile::tempdir()?;
    assert!(scan(&dir.path().join("nope"), &ALL_FILES).is_err());
    let file = dir.path().join("f.txt");
    fs::write(&file, "x")?;
    assert!(scan(&file, &ALL_FILES).is_err());
    Ok(())
}
