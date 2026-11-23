//! Runs the built `pumpkin-shell` binary and checks its basic behavior.

use std::io;
use std::process::{Command, Output};

fn run(args: &[&str]) -> io::Result<Output> {
    // Clap wraps command names in color codes when color is forced, which breaks
    // substring checks such as "kiro [PATH]". Turn color off for every run.
    Command::new(env!("CARGO_BIN_EXE_pumpkin-shell"))
        .args(args)
        .env_remove("CLICOLOR_FORCE")
        .env("NO_COLOR", "1")
        .output()
}

#[test]
fn version_prints_name_and_version() {
    let out = run(&["--version"]).unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(
        stdout.trim_end(),
        format!("pumpkin-shell {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn help_shows_description() {
    let out = run(&["--help"]).unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("Sandbox and tripwire system for AI-powered IDEs"));
    assert!(stdout.contains("Usage: pumpkin-shell"));
}

#[test]
fn unknown_argument_is_rejected() {
    let out = run(&["--no-such-flag"]).unwrap();
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("--no-such-flag"));
}

#[test]
fn no_arguments_succeeds() {
    let out = run(&[]).unwrap();
    assert!(out.status.success());
}

#[test]
fn kiro_is_a_one_word_shortcut_that_takes_a_path() {
    let out = run(&["kiro", "--help"]).unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    // The program is pumpkin-shell.exe on Windows, so check the part that is the same.
    assert!(stdout.contains("kiro [OPTIONS] [PATH]"), "{stdout}");
}

#[test]
fn kiro_without_a_folder_and_without_zenity_names_the_command_to_run() {
    // With no zenity on PATH, no window can open. The command must say what to type.
    let out = Command::new(env!("CARGO_BIN_EXE_pumpkin-shell"))
        .arg("kiro")
        .env("PATH", "/nonexistent")
        .env_remove("CLICOLOR_FORCE")
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("pumpkin-shell kiro /yourfolderhere"),
        "{stderr}"
    );
}

#[test]
fn kiro_help_lists_the_no_dashboard_flag() {
    let out = run(&["kiro", "--help"]).unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("--no-dashboard"), "{stdout}");
}
