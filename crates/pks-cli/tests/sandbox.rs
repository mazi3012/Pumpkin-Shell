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

use pks_sandbox::linux::LinuxBackend;
use pks_sandbox::{IdeInstall, LaunchSpec, Roots, SandboxBackend};
use std::os::unix::net::UnixListener;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

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
