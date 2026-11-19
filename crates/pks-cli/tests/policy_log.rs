//! Runs `trust`, `policy check` and `log verify` through the real binary,
//! with config and data directories in a temp dir. These are the Phase 7
//! Done-when checks.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use pks_core::keys;
use pks_core::log::{Logger, Record, checkpoint_path};
use tempfile::TempDir;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// An isolated home: its own config dir, data dir and repo.
struct Env {
    _root: TempDir,
    config: PathBuf,
    data: PathBuf,
    repo: PathBuf,
}

impl Env {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let base = root.path().to_path_buf();
        let config = base.join("config");
        let data = base.join("data");
        let repo = base.join("repo");
        fs::create_dir_all(&config)?;
        fs::create_dir_all(&repo)?;
        Ok(Self {
            _root: root,
            config,
            data,
            repo,
        })
    }

    fn pks(&self, args: &[&str]) -> std::io::Result<Output> {
        Command::new(env!("CARGO_BIN_EXE_pumpkin-shell"))
            .args(args)
            .env("HOME", &self.config)
            .env("XDG_CONFIG_HOME", &self.config)
            .env("XDG_DATA_HOME", &self.data)
            .env("APPDATA", &self.config)
            .env("LOCALAPPDATA", &self.data)
            .output()
    }

    fn repo_arg(&self) -> String {
        self.repo.display().to_string()
    }

    fn write_repo_policy(&self, text: &str) -> std::io::Result<()> {
        fs::write(self.repo.join("pumpkin-shell.toml"), text)
    }

    /// Where the CLI looks for the user policy.
    fn user_policy_path(&self) -> PathBuf {
        #[cfg(windows)]
        let dir = self.config.join("Pumpkin-Shell");
        #[cfg(not(windows))]
        let dir = self.config.join("pumpkin-shell");
        dir.join("policy.toml")
    }

    fn key_dir(&self) -> PathBuf {
        #[cfg(windows)]
        let dir = self.data.join("Pumpkin-Shell");
        #[cfg(not(windows))]
        let dir = self.data.join("pumpkin-shell");
        dir.join("keys")
    }
}

fn code(output: &Output) -> Option<i32> {
    output.status.code()
}

fn out(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn err(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

// --- policy --------------------------------------------------------------

#[test]
fn a_repo_without_a_policy_checks_clean() -> TestResult {
    let env = Env::new()?;
    let result = env.pks(&["policy", "check", &env.repo_arg()])?;
    assert_eq!(code(&result), Some(0), "{}{}", out(&result), err(&result));
    let text = out(&result);
    assert!(text.contains("repo policy: none") && text.contains("mode: enforce"));
    assert!(text.contains("NET-UNKNOWN-DOMAIN = ask"));
    assert!(text.contains("REG-MALWARE = block"));
    Ok(())
}

#[test]
fn an_untrusted_repo_policy_is_ignored_until_it_is_trusted() -> TestResult {
    let env = Env::new()?;
    env.write_repo_policy("version = 1\n[rules.NET-UNKNOWN-DOMAIN]\naction = \"block\"\n")?;
    let before = env.pks(&["policy", "check", &env.repo_arg()])?;
    assert_eq!(code(&before), Some(1));
    let text = out(&before);
    assert!(text.contains("repo policy: not applied") && text.contains("POL-UNTRUSTED"));
    assert!(text.contains("not trusted yet") && text.contains("NET-UNKNOWN-DOMAIN = ask"));

    let trusted = env.pks(&["trust", &env.repo_arg()])?;
    assert_eq!(code(&trusted), Some(0), "{}", err(&trusted));
    assert!(out(&trusted).contains("sha256: "));

    let after = env.pks(&["policy", "check", &env.repo_arg()])?;
    assert_eq!(code(&after), Some(0), "{}", out(&after));
    let text = out(&after);
    assert!(text.contains("repo policy: trusted and applied"));
    assert!(text.contains("NET-UNKNOWN-DOMAIN = block"));
    Ok(())
}

#[test]
fn editing_a_trusted_repo_policy_by_one_byte_unpins_it() -> TestResult {
    let env = Env::new()?;
    let policy = "version = 1\n[rules.NET-UNKNOWN-DOMAIN]\naction = \"block\"\n";
    env.write_repo_policy(policy)?;
    assert_eq!(code(&env.pks(&["trust", &env.repo_arg()])?), Some(0));
    assert_eq!(
        code(&env.pks(&["policy", "check", &env.repo_arg()])?),
        Some(0)
    );
    env.write_repo_policy(&format!("{policy}\n"))?;
    let changed = env.pks(&["policy", "check", &env.repo_arg()])?;
    assert_eq!(code(&changed), Some(1));
    let text = out(&changed);
    assert!(
        text.contains("changed since it was trusted") && text.contains("NET-UNKNOWN-DOMAIN = ask")
    );
    // Trusting again brings it back.
    assert_eq!(code(&env.pks(&["trust", &env.repo_arg()])?), Some(0));
    assert_eq!(
        code(&env.pks(&["policy", "check", &env.repo_arg()])?),
        Some(0)
    );
    Ok(())
}

#[test]
fn a_repo_policy_that_loosens_a_rule_is_rejected_with_pol_untrusted() -> TestResult {
    let env = Env::new()?;
    // REG-MALWARE blocks by default. The repo asks for alert.
    env.write_repo_policy(
        "version = 1\n[rules.REG-MALWARE]\naction = \"alert\"\n[rules.NET-PRIVATE-IP]\naction = \"block\"\n",
    )?;
    let trust = env.pks(&["trust", &env.repo_arg()])?;
    assert_eq!(code(&trust), Some(0));
    let text = out(&trust);
    assert!(
        text.contains("will be ignored") && text.contains("POL-UNTRUSTED"),
        "{text}"
    );

    let check = env.pks(&["policy", "check", &env.repo_arg()])?;
    assert_eq!(code(&check), Some(1));
    let text = out(&check);
    assert!(
        text.contains("POL-UNTRUSTED pumpkin-shell.toml: rules.REG-MALWARE"),
        "{text}"
    );
    assert!(text.contains("from block to alert"));
    assert!(
        text.contains("REG-MALWARE = block"),
        "loosening was applied: {text}"
    );
    Ok(())
}

#[test]
fn a_repo_policy_cannot_switch_to_monitor_mode() -> TestResult {
    let env = Env::new()?;
    env.write_repo_policy("version = 1\nmode = \"monitor\"\n")?;
    assert_eq!(code(&env.pks(&["trust", &env.repo_arg()])?), Some(0));
    let check = env.pks(&["policy", "check", &env.repo_arg()])?;
    assert_eq!(code(&check), Some(1));
    let text = out(&check);
    assert!(
        text.contains("mode: enforce") && text.contains("pumpkin-shell.toml: mode"),
        "{text}"
    );
    Ok(())
}

#[test]
fn the_user_policy_is_the_baseline_the_repo_cannot_go_below() -> TestResult {
    let env = Env::new()?;
    fs::create_dir_all(env.user_policy_path().parent().unwrap_or(Path::new(".")))?;
    fs::write(
        env.user_policy_path(),
        "version = 1\n[rules.REG-TYPOSQUAT]\naction = \"block\"\n",
    )?;
    env.write_repo_policy("version = 1\n[rules.REG-TYPOSQUAT]\naction = \"ask\"\n")?;
    assert_eq!(code(&env.pks(&["trust", &env.repo_arg()])?), Some(0));
    let check = env.pks(&["policy", "check", &env.repo_arg()])?;
    assert_eq!(code(&check), Some(1));
    assert!(out(&check).contains("REG-TYPOSQUAT = block"));
    Ok(())
}

#[test]
fn trust_refuses_a_missing_or_invalid_repo_policy_and_pins_nothing() -> TestResult {
    let env = Env::new()?;
    let missing = env.pks(&["trust", &env.repo_arg()])?;
    assert_eq!(code(&missing), Some(2));
    assert!(err(&missing).contains("no pumpkin-shell.toml"));

    for bad in [
        "not toml",
        "version = 9\n",
        "version = 1\n[rules.NOPE]\naction = \"block\"\n",
    ] {
        env.write_repo_policy(bad)?;
        let result = env.pks(&["trust", &env.repo_arg()])?;
        assert_eq!(code(&result), Some(2), "{bad}");
        assert!(err(&result).contains("not trusting"), "{bad}");
    }
    assert!(
        !env.data.exists(),
        "a failed trust must not create anything"
    );
    Ok(())
}

#[test]
fn an_invalid_user_policy_is_an_error_not_silently_ignored() -> TestResult {
    let env = Env::new()?;
    fs::create_dir_all(env.user_policy_path().parent().unwrap_or(Path::new(".")))?;
    fs::write(env.user_policy_path(), "version = 1\nbogus = true\n")?;
    let result = env.pks(&["policy", "check", &env.repo_arg()])?;
    assert_eq!(code(&result), Some(2));
    assert!(err(&result).contains("user policy"));
    Ok(())
}

#[test]
fn the_policy_hash_changes_with_the_policy() -> TestResult {
    let env = Env::new()?;
    let hash = |result: &Output| {
        out(result)
            .lines()
            .find_map(|line| line.strip_prefix("policy hash: ").map(str::to_owned))
    };
    let plain = hash(&env.pks(&["policy", "check", &env.repo_arg()])?);
    env.write_repo_policy("version = 1\n[rules.NET-UNKNOWN-DOMAIN]\naction = \"block\"\n")?;
    env.pks(&["trust", &env.repo_arg()])?;
    let tighter = hash(&env.pks(&["policy", "check", &env.repo_arg()])?);
    assert!(plain.is_some() && tighter.is_some());
    assert_ne!(plain, tighter);
    assert_eq!(plain.as_deref().map(str::len), Some(64));
    Ok(())
}

// --- log verify ----------------------------------------------------------

/// Writes a closed 4-entry log with a fresh key; returns (log path, key dir).
fn make_log(env: &Env) -> Result<(PathBuf, PathBuf), Box<dyn std::error::Error>> {
    let key_dir = env.key_dir();
    let key = keys::load_or_create_signing_key(&key_dir)?;
    let log = env.data.join("session.jsonl");
    let mut logger = Logger::create(&log, key, "demo-session")?;
    for i in 0..4 {
        logger.append(
            &Record {
                policy_hash: &"0".repeat(64),
                layer: "net",
                target: &format!("host{i}.example:443"),
                rule: "NET-UNKNOWN-DOMAIN",
                verdict: "block",
            },
            1_000 + i,
        )?;
    }
    logger.finish(9_999)?;
    Ok((log, key_dir))
}

fn verify(env: &Env, log: &Path, key_dir: &Path, extra: &[&str]) -> std::io::Result<Output> {
    let log = log.display().to_string();
    let key_dir = key_dir.display().to_string();
    let mut args = vec!["log", "verify", log.as_str(), "--key-dir", key_dir.as_str()];
    args.extend_from_slice(extra);
    env.pks(&args)
}

#[test]
fn a_good_log_verifies() -> TestResult {
    let env = Env::new()?;
    let (log, keys) = make_log(&env)?;
    let result = verify(&env, &log, &keys, &[])?;
    assert_eq!(code(&result), Some(0), "{}{}", out(&result), err(&result));
    assert_eq!(
        out(&result).trim_end(),
        "OK: session demo-session, 4 entries, checkpoint verified"
    );
    Ok(())
}

#[test]
fn log_verify_fails_after_editing_deleting_reordering_or_truncating_a_line() -> TestResult {
    let env = Env::new()?;
    let (log, keys) = make_log(&env)?;
    let original = fs::read_to_string(&log)?;
    let lines: Vec<&str> = original.lines().collect();
    let write = |lines: &[String]| -> std::io::Result<()> {
        let mut text = lines.join("\n");
        text.push('\n');
        fs::write(&log, text)
    };
    let as_strings = |lines: &[&str]| lines.iter().map(|l| (*l).to_owned()).collect::<Vec<_>>();

    let mut edited = as_strings(&lines);
    edited[1] = edited[1].replace("\"verdict\":\"block\"", "\"verdict\":\"allow\"");
    let mut deleted = as_strings(&lines);
    deleted.remove(1);
    let mut reordered = as_strings(&lines);
    reordered.swap(1, 2);
    let truncated = as_strings(&lines[..3]);
    let mut cut_mid_line = original.clone().into_bytes();
    cut_mid_line.truncate(original.len() / 2);

    for (name, tampered) in [
        ("edit", edited),
        ("delete", deleted),
        ("reorder", reordered),
        ("truncate", truncated),
    ] {
        write(&tampered)?;
        let result = verify(&env, &log, &keys, &[])?;
        assert_eq!(code(&result), Some(1), "{name}: {}", out(&result));
        assert!(
            out(&result).starts_with("FAILED: "),
            "{name}: {}",
            out(&result)
        );
    }
    fs::write(&log, &cut_mid_line)?;
    assert_eq!(
        code(&verify(&env, &log, &keys, &[])?),
        Some(1),
        "cut mid-line"
    );

    // And the untouched log still passes.
    fs::write(&log, &original)?;
    assert_eq!(code(&verify(&env, &log, &keys, &[])?), Some(0));
    Ok(())
}

#[test]
fn a_missing_checkpoint_fails_unless_allow_open_is_given() -> TestResult {
    let env = Env::new()?;
    let (log, keys) = make_log(&env)?;
    fs::remove_file(checkpoint_path(&log))?;
    let strict = verify(&env, &log, &keys, &[])?;
    assert_eq!(code(&strict), Some(1));
    assert!(out(&strict).contains("no signed checkpoint"));
    let open = verify(&env, &log, &keys, &["--allow-open"])?;
    assert_eq!(code(&open), Some(0));
    assert!(out(&open).contains("no checkpoint: the session may still be running"));
    Ok(())
}

#[test]
fn truncating_the_log_and_deleting_the_checkpoint_is_still_caught() -> TestResult {
    let env = Env::new()?;
    let (log, keys) = make_log(&env)?;
    let text = fs::read_to_string(&log)?;
    let kept: String = text.lines().take(2).map(|l| format!("{l}\n")).collect();
    fs::write(&log, kept)?;
    fs::remove_file(checkpoint_path(&log))?;
    assert_eq!(code(&verify(&env, &log, &keys, &[])?), Some(1));
    Ok(())
}

#[test]
fn a_log_signed_with_another_key_fails() -> TestResult {
    let env = Env::new()?;
    let (log, _) = make_log(&env)?;
    let other = env.data.join("other-keys");
    keys::load_or_create_signing_key(&other)?;
    let result = verify(&env, &log, &other, &[])?;
    assert_eq!(code(&result), Some(1));
    assert!(out(&result).contains("signature does not match"));
    Ok(())
}

#[test]
fn problems_that_stop_verification_exit_2_and_say_why() -> TestResult {
    let env = Env::new()?;
    let (log, keys) = make_log(&env)?;
    let no_keys = env.data.join("empty-keys");
    fs::create_dir_all(&no_keys)?;
    let result = verify(&env, &log, &no_keys, &[])?;
    assert_eq!(code(&result), Some(2));
    assert!(err(&result).contains("no verifying key"));
    let missing = verify(&env, &env.data.join("nope.jsonl"), &keys, &[])?;
    assert_eq!(code(&missing), Some(2));
    assert!(err(&missing).contains("cannot verify"));
    Ok(())
}

#[test]
fn log_verify_never_prints_log_contents_or_key_material() -> TestResult {
    let env = Env::new()?;
    let (log, keys) = make_log(&env)?;
    let text = fs::read_to_string(&log)?;
    fs::write(&log, text.replace("host0.example", "\u{1b}[31mINJECTED"))?;
    let result = verify(&env, &log, &keys, &[])?;
    let shown = format!("{}{}", out(&result), err(&result));
    assert!(
        !shown.contains("INJECTED") && !shown.contains('\u{1b}'),
        "{shown}"
    );
    let secret = fs::read_to_string(keys.join("log-signing.key"))?;
    assert!(!shown.contains(secret.trim()));
    Ok(())
}

#[test]
fn verify_does_not_create_keys() -> TestResult {
    let env = Env::new()?;
    let (log, _) = make_log(&env)?;
    let fresh = env.data.join("not-created");
    let result = verify(&env, &log, &fresh, &[])?;
    assert_eq!(code(&result), Some(2));
    assert!(!fresh.exists());
    Ok(())
}
