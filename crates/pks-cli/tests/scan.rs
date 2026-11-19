//! Runs `pumpkin-shell scan` on the fixture repos and checks exit codes and
//! output. PRD scenario 11: `scan --ci` must fail on hidden Unicode in
//! `.kiro/steering`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/scan")
        .join(name)
}

fn scan(args: &[&str], path: &Path) -> std::io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_pumpkin-shell"))
        .arg("scan")
        .args(args)
        .arg(path)
        .output()
}

fn code(output: &Output) -> Option<i32> {
    output.status.code()
}

#[test]
fn ci_fails_on_hidden_unicode_in_kiro_steering() -> TestResult {
    let out = scan(&["--ci"], &fixture("ws-hidden-unicode"))?;
    assert_eq!(code(&out), Some(1));
    let stdout = String::from_utf8(out.stdout)?;
    assert!(
        stdout.contains("WS-HIDDEN-UNICODE .kiro/steering/rules.md:3"),
        "{stdout}"
    );
    assert!(stdout.contains("tag character U+E0041"));
    Ok(())
}

#[test]
fn ci_passes_on_the_clean_repo() -> TestResult {
    let out = scan(&["--ci"], &fixture("clean"))?;
    assert_eq!(code(&out), Some(0));
    let stdout = String::from_utf8(out.stdout)?;
    assert!(stdout.contains("0 finding(s)"), "{stdout}");
    Ok(())
}

#[test]
fn without_ci_findings_do_not_change_the_exit_code() -> TestResult {
    let out = scan(&[], &fixture("ws-hidden-unicode"))?;
    assert_eq!(code(&out), Some(0));
    assert!(String::from_utf8(out.stdout)?.contains("WS-HIDDEN-UNICODE"));
    Ok(())
}

#[test]
fn fail_on_sets_the_threshold() -> TestResult {
    // The MCP fixture has NOTICE findings only.
    let mcp = fixture("ws-mcp-server");
    assert_eq!(code(&scan(&["--ci"], &mcp)?), Some(0));
    assert_eq!(code(&scan(&["--ci", "--fail-on", "warn"], &mcp)?), Some(0));
    assert_eq!(
        code(&scan(&["--ci", "--fail-on", "notice"], &mcp)?),
        Some(1)
    );
    // Hidden Unicode is HIGH: below CRITICAL passes, at HIGH fails.
    let unicode = fixture("ws-hidden-unicode");
    assert_eq!(
        code(&scan(&["--ci", "--fail-on", "critical"], &unicode)?),
        Some(0)
    );
    assert_eq!(
        code(&scan(&["--ci", "--fail-on", "high"], &unicode)?),
        Some(1)
    );
    // Auto-approve is CRITICAL.
    let auto = fixture("ws-autoapprove");
    assert_eq!(
        code(&scan(&["--ci", "--fail-on", "critical"], &auto)?),
        Some(1)
    );
    Ok(())
}

#[test]
fn json_output_is_valid_and_has_the_report_fields() -> TestResult {
    let out = scan(&["--json"], &fixture("ws-yarnpath"))?;
    assert_eq!(code(&out), Some(0));
    let value: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    assert_eq!(value["findings"][0]["rule"], "WS-YARNPATH");
    assert_eq!(value["findings"][0]["severity"], "HIGH");
    assert_eq!(value["findings"][0]["target"], ".yarnrc.yml:2");
    assert!(value["skipped"].is_array() && value["errors"].is_array());
    assert!(value["files_scanned"].is_number());
    Ok(())
}

#[test]
fn secrets_in_mcp_config_never_reach_the_output() -> TestResult {
    for flag in [&[][..], &["--json"][..]] {
        let out = scan(flag, &fixture("ws-mcp-server"))?;
        let stdout = String::from_utf8(out.stdout)?;
        for secret in ["NOT-A-REAL-TOKEN", "NOT-A-REAL-PASSWORD", "NOT-A-REAL-KEY"] {
            assert!(!stdout.contains(secret), "{secret} leaked with {flag:?}");
        }
    }
    Ok(())
}

#[test]
fn an_incomplete_scan_exits_2_even_without_ci() -> TestResult {
    let dir = tempfile::tempdir()?;
    fs::create_dir(dir.path().join(".vscode"))?;
    fs::write(dir.path().join(".vscode/settings.json"), "{ not json")?;
    for args in [&[][..], &["--ci"][..]] {
        let out = scan(args, dir.path())?;
        assert_eq!(code(&out), Some(2), "{args:?}");
        let stdout = String::from_utf8(out.stdout)?;
        assert!(stdout.contains("[ERROR] .vscode/settings.json"), "{stdout}");
    }
    Ok(())
}

#[test]
fn a_missing_path_exits_2_with_a_message() -> TestResult {
    let dir = tempfile::tempdir()?;
    let out = scan(&["--ci"], &dir.path().join("nope"))?;
    assert_eq!(code(&out), Some(2));
    assert!(String::from_utf8(out.stderr)?.starts_with("scan: "));
    Ok(())
}

#[test]
fn no_ignore_scans_files_that_gitignore_lists() -> TestResult {
    let dir = tempfile::tempdir()?;
    fs::write(dir.path().join(".gitignore"), "hidden.md\n")?;
    fs::write(dir.path().join("hidden.md"), "x\u{200b}\n")?;
    assert_eq!(code(&scan(&["--ci"], dir.path())?), Some(0));
    assert_eq!(code(&scan(&["--ci", "--no-ignore"], dir.path())?), Some(1));
    Ok(())
}

#[test]
fn scan_defaults_to_the_current_directory() -> TestResult {
    let out = Command::new(env!("CARGO_BIN_EXE_pumpkin-shell"))
        .args(["scan", "--ci"])
        .current_dir(fixture("clean"))
        .output()?;
    assert_eq!(code(&out), Some(0));
    Ok(())
}
