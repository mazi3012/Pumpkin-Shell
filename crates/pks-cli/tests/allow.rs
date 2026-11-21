//! `pumpkin-shell allow <host:port>` writes the endpoint to the user policy
//! once, and the policy stays readable afterwards.

use std::fs;
use std::process::{Command, Output};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn cli(home: &std::path::Path, args: &[&str]) -> std::io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_pumpkin-shell"))
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .output()
}

#[test]
fn allow_adds_the_endpoint_once_and_the_policy_still_loads() -> TestResult {
    let home = tempfile::tempdir()?;
    let first = cli(home.path(), &["allow", "api.example.com:443"])?;
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );

    let second = cli(home.path(), &["allow", "api.example.com:443"])?;
    assert!(second.status.success());
    assert!(String::from_utf8_lossy(&second.stdout).contains("already in the policy"));

    let policy = home
        .path()
        .join("config")
        .join("pumpkin-shell")
        .join("policy.toml");
    let text = fs::read_to_string(&policy)?;
    assert_eq!(
        text.matches("api.example.com:443").count(),
        1,
        "the endpoint is listed more than once:\n{text}"
    );

    // The file written by `allow` must be accepted by the policy loader.
    let check = cli(
        home.path(),
        &["policy", "check", home.path().to_str().ok_or("path")?],
    )?;
    assert!(
        check.status.code() != Some(2),
        "policy check could not read the written policy: {}",
        String::from_utf8_lossy(&check.stderr)
    );
    Ok(())
}

#[test]
fn allow_refuses_a_value_that_is_not_host_and_port() -> TestResult {
    let home = tempfile::tempdir()?;
    let out = cli(home.path(), &["allow", "not a host"])?;
    assert_eq!(out.status.code(), Some(2));
    assert!(
        !home
            .path()
            .join("config")
            .join("pumpkin-shell")
            .join("policy.toml")
            .exists()
    );
    Ok(())
}
