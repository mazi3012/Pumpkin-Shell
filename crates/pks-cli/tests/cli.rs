//! Runs the built `pumpkin-shell` binary and checks its basic behavior.

use std::io;
use std::process::{Command, Output};

fn run(args: &[&str]) -> io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_pumpkin-shell"))
        .args(args)
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
