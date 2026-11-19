//! `pumpkin-shell restore`: runs the real binary against a temporary data
//! directory. The snapshot is taken with the same library call `ide` uses.
//!
//! Linux only for now: the data directory is found through `XDG_DATA_HOME`
//! here. Windows finds it through `LOCALAPPDATA` and is covered with the
//! Windows backend (Phase 16).

#![cfg(target_os = "linux")]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const SESSION: &str = "0123456789abcdef0123456789abcdef";

/// Runs `pumpkin-shell restore` with the data directory set to `data`.
fn restore(data: &Path, args: &[&str]) -> std::io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_pumpkin-shell"))
        .arg("restore")
        .args(args)
        .env("XDG_DATA_HOME", data)
        .env("HOME", data.join("home"))
        .output()
}

/// A repo with one tracked and one untracked file, and a session whose
/// snapshot was taken from it. Returns the value of `XDG_DATA_HOME`; the
/// program's data directory is `pumpkin-shell` inside it.
fn data_with_snapshot(root: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let repo = root.join("repo");
    fs::create_dir_all(&repo)?;
    fs::write(repo.join("main.rs"), "fn main() {}\n")?;
    fs::write(repo.join("notes.txt"), "not yet committed\n")?;
    let git = |args: &[&str]| -> Result<(), Box<dyn std::error::Error>> {
        let status = Command::new("git")
            .arg("-C")
            .arg(&repo)
            .args(args)
            .status()?;
        assert!(status.success(), "git {args:?}");
        Ok(())
    };
    git(&["init", "--quiet"])?;
    git(&["add", "main.rs"])?;
    git(&[
        "-c",
        "user.name=test",
        "-c",
        "user.email=test@localhost",
        "commit",
        "--quiet",
        "-m",
        "first",
    ])?;
    let xdg = root.join("xdg");
    let session = xdg.join("pumpkin-shell").join("sessions").join(SESSION);
    fs::create_dir_all(&session)?;
    pks_core::snapshot::create(&repo, &session)?;
    Ok(xdg)
}

#[test]
fn restore_writes_the_snapshot_into_a_new_directory() -> TestResult {
    let root = tempfile::tempdir()?;
    let data = data_with_snapshot(root.path())?;
    let target = root.path().join("out");
    let output = restore(&data, &[SESSION, "--into", target.to_str().unwrap_or("")])?;
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        fs::read_to_string(target.join("main.rs"))?,
        "fn main() {}\n"
    );
    assert_eq!(
        fs::read_to_string(target.join("notes.txt"))?,
        "not yet committed\n"
    );
    Ok(())
}

#[test]
fn restore_without_into_uses_the_data_directory() -> TestResult {
    let root = tempfile::tempdir()?;
    let data = data_with_snapshot(root.path())?;
    let output = restore(&data, &[SESSION])?;
    assert!(output.status.success(), "{output:?}");
    let default = data.join("pumpkin-shell").join("restores").join(SESSION);
    assert!(default.join("main.rs").is_file());
    Ok(())
}

#[test]
fn restore_refuses_a_session_id_that_is_not_hex() -> TestResult {
    let root = tempfile::tempdir()?;
    let data = data_with_snapshot(root.path())?;
    for bad in ["../../etc", "ABCDEF", "0123"] {
        let output = restore(
            &data,
            &[bad, "--into", root.path().join("x").to_str().unwrap_or("")],
        )?;
        assert_eq!(output.status.code(), Some(2), "{bad}");
    }
    assert!(!root.path().join("x").exists());
    Ok(())
}

#[test]
fn restore_refuses_a_session_without_a_snapshot() -> TestResult {
    let root = tempfile::tempdir()?;
    let data = root.path().join("xdg");
    fs::create_dir_all(data.join("pumpkin-shell").join("sessions").join(SESSION))?;
    let output = restore(&data, &[SESSION])?;
    assert_eq!(output.status.code(), Some(2));
    Ok(())
}

#[test]
fn restore_refuses_a_target_that_is_not_empty() -> TestResult {
    let root = tempfile::tempdir()?;
    let data = data_with_snapshot(root.path())?;
    let target = root.path().join("occupied");
    fs::create_dir_all(&target)?;
    fs::write(target.join("mine.txt"), "keep\n")?;
    let output = restore(&data, &[SESSION, "--into", target.to_str().unwrap_or("")])?;
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(fs::read_to_string(target.join("mine.txt"))?, "keep\n");
    assert!(!target.join("main.rs").exists());
    Ok(())
}
