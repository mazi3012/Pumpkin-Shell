//! `pumpkin-shell review` and `allow-write` against a real session layout: a
//! snapshot taken with git, a repo, and staged writes. Each test runs the
//! built binary with its home and data directories in a temp dir.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The data folder pumpkin-shell uses under `home`. Keep in step with
/// `pks_core::paths`: Linux uses XDG-style folders, Windows uses LOCALAPPDATA.
fn data_dir(home: &Path) -> PathBuf {
    if cfg!(windows) {
        home.join("localappdata").join("Pumpkin-Shell")
    } else {
        home.join("data").join("pumpkin-shell")
    }
}

const SESSION: &str = "sess-review-test";
const SETTINGS: &str = ".vscode/settings.json";
const CHANGED: &str = "{\"chat.tools.autoApprove\": true}\n";

/// A repo with one protected file, a snapshot of it, and the sandbox's
/// staged change to that file. Returns (home, repo).
fn session_with_staged_write() -> Result<(tempfile::TempDir, PathBuf), Box<dyn std::error::Error>> {
    let home = tempfile::tempdir()?;
    let repo = home.path().join("repo");
    fs::create_dir_all(repo.join(".vscode"))?;
    fs::write(repo.join(SETTINGS), "{}\n")?;
    let session = data_dir(home.path()).join("sessions").join(SESSION);
    fs::create_dir_all(&session)?;
    pks_core::snapshot::create(&repo, &session)?;
    fs::write(
        session.join("repo"),
        repo.to_str().ok_or("repo path is not UTF-8")?,
    )?;
    let staged = session.join("staging").join(SETTINGS);
    fs::create_dir_all(staged.parent().ok_or("no parent")?)?;
    fs::write(&staged, CHANGED)?;
    Ok((home, repo))
}

fn cli(home: &Path, args: &[&str], stdin: &str) -> std::io::Result<std::process::Output> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_pumpkin-shell"))
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("APPDATA", home.join("appdata"))
        .env("LOCALAPPDATA", home.join("localappdata"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut input) = child.stdin.take() {
        input.write_all(stdin.as_bytes())?;
    }
    child.wait_with_output()
}

#[test]
fn allow_write_copies_the_staged_write_into_the_repo() -> TestResult {
    let (home, repo) = session_with_staged_write()?;
    let out = cli(home.path(), &["allow-write", SESSION, SETTINGS], "")?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(fs::read_to_string(repo.join(SETTINGS))?, CHANGED);
    Ok(())
}

#[test]
fn allow_write_refuses_when_the_repo_file_changed_after_the_session_started() -> TestResult {
    let (home, repo) = session_with_staged_write()?;
    fs::write(repo.join(SETTINGS), "{\"edited\": \"by the user\"}\n")?;
    let out = cli(home.path(), &["allow-write", SESSION, SETTINGS], "")?;
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        fs::read_to_string(repo.join(SETTINGS))?,
        "{\"edited\": \"by the user\"}\n",
        "the user's edit was overwritten"
    );
    Ok(())
}

#[test]
fn allow_write_names_a_path_with_no_staged_write() -> TestResult {
    let (home, repo) = session_with_staged_write()?;
    let out = cli(home.path(), &["allow-write", SESSION, "src/main.rs"], "")?;
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(fs::read_to_string(repo.join(SETTINGS))?, "{}\n");
    Ok(())
}

#[test]
fn review_rejecting_a_write_leaves_the_repo_unchanged() -> TestResult {
    let (home, repo) = session_with_staged_write()?;
    let out = cli(home.path(), &["review", SESSION], "r\n")?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(fs::read_to_string(repo.join(SETTINGS))?, "{}\n");
    Ok(())
}

#[test]
fn review_approving_a_write_applies_it() -> TestResult {
    let (home, repo) = session_with_staged_write()?;
    let out = cli(home.path(), &["review", SESSION], "a\n")?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(fs::read_to_string(repo.join(SETTINGS))?, CHANGED);
    Ok(())
}

#[test]
fn review_leaves_no_baseline_folder_behind() -> TestResult {
    let (home, _repo) = session_with_staged_write()?;
    let out = cli(home.path(), &["review", SESSION], "s\n")?;
    assert!(out.status.success());
    let session = data_dir(home.path()).join("sessions").join(SESSION);
    assert!(!session.join("review-baseline").exists());
    Ok(())
}
