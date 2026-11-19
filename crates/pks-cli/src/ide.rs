//! `pumpkin-shell ide <kiro|code> [PATH]`: opens a repository in an IDE that
//! runs inside the sandbox (PRD §6.1, Phases 8 and 9).
//!
//! A session does four things: it loads the user policy (refusing to start
//! if the policy is invalid), starts the egress proxy on a session socket,
//! records every decision in a signed log, and runs the IDE.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::ValueEnum;
#[cfg(target_os = "linux")]
use pks_core::log::Record;

/// The IDEs this build can launch. Only installs under `/usr` are accepted.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Ide {
    Kiro,
    Code,
}

/// Exit code for a run that could not start.
const EXIT_SETUP: u8 = 2;

#[cfg(target_os = "linux")]
fn install(ide: Ide) -> pks_sandbox::IdeInstall {
    let (name, dir, program) = match ide {
        Ide::Kiro => ("kiro", "/usr/share/kiro", "kiro"),
        Ide::Code => ("code", "/usr/share/code", "code"),
    };
    pks_sandbox::IdeInstall {
        name,
        dir: PathBuf::from(dir),
        binary: PathBuf::from(dir).join(program),
    }
}

/// Creates `dir` and missing parents, each with mode 0700.
#[cfg(target_os = "linux")]
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

/// Runs the IDE on `repo`. Returns the IDE's exit code, or 2 when the session
/// could not start (the IDE is not started in that case).
#[cfg(target_os = "linux")]
pub fn run(ide: Ide, repo: &Path) -> ExitCode {
    use pks_core::paths::{self, process_env};
    use pks_sandbox::linux::LinuxBackend;
    use pks_sandbox::{LaunchSpec, Roots, SandboxBackend};
    use std::os::unix::process::ExitStatusExt;

    let setup = |message: String| {
        eprintln!("ide: {message}");
        ExitCode::from(EXIT_SETUP)
    };
    let Some(home) = process_env("HOME").map(PathBuf::from) else {
        return setup("HOME is not set".to_owned());
    };
    let (Some(config), Some(data)) = (
        paths::config_dir(&process_env),
        paths::data_dir(&process_env),
    ) else {
        return setup("cannot find the config and data directories".to_owned());
    };
    // Check the repo before creating anything on disk, so a typo leaves no
    // directories behind. The full checks run in the sandbox crate.
    if !repo.is_dir() {
        return setup(format!("{} is not a directory", repo.display()));
    }
    let policy = match pks_core::policy::read_user_policy(&config) {
        Ok(found) => found.unwrap_or_else(pks_core::policy::empty_user_policy),
        Err(error) => return setup(format!("your policy is not valid: {error}")),
    };
    let effective = pks_core::policy::Effective::from_user(&policy);
    let session = match Session::start(&data, &effective) {
        Ok(session) => session,
        Err(message) => return setup(message),
    };

    let spec_install = install(ide);
    let ide_home = data.join("ide-home").join(spec_install.name);
    if let Err(error) = create_private_dir(&ide_home) {
        return setup(format!("cannot create {}: {error}", ide_home.display()));
    }
    let spec = LaunchSpec {
        repo: repo.to_path_buf(),
        ide: spec_install,
        ide_home,
        // Platform flags: X11 (the nested display) and no keyring (there is no
        // D-Bus in the sandbox). The repo is opened at its sandbox path.
        ide_args: vec![
            "--ozone-platform=x11".into(),
            "--password-store=basic".into(),
            pks_sandbox::linux::bwrap::WORKSPACE.into(),
        ],
        roots: Roots { home, config, data },
        display_size: (1280, 800),
        proxy_socket: session.socket.clone(),
        host_ports: effective.host_ports.iter().copied().collect(),
    };
    let init_exe = match std::env::current_exe() {
        Ok(path) => path,
        Err(error) => return setup(format!("cannot find this program: {error}")),
    };
    let backend = match LinuxBackend::locate(init_exe) {
        Ok(backend) => backend,
        Err(error) => return setup(error.to_string()),
    };
    eprintln!(
        "ide: starting {} on {} ({}; session {})",
        ide_name(ide),
        repo.display(),
        backend.name(),
        session.id
    );
    let result = backend.run(&spec);
    session.close();
    match result {
        Ok(status) => match status.code() {
            Some(code) => ExitCode::from(u8::try_from(code.clamp(0, 255)).unwrap_or(1)),
            None => {
                // Killed by a signal: report 128 + signal, as shells do.
                let signal = status.signal().unwrap_or(0);
                ExitCode::from(u8::try_from(128 + signal).unwrap_or(1))
            }
        },
        Err(error) => setup(error.to_string()),
    }
}

#[cfg(target_os = "linux")]
fn ide_name(ide: Ide) -> &'static str {
    match ide {
        Ide::Kiro => "Kiro",
        Ide::Code => "VS Code",
    }
}

/// One session: the proxy, its socket, and the signed log of its decisions.
#[cfg(target_os = "linux")]
struct Session {
    id: String,
    socket: PathBuf,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    server: Option<std::thread::JoinHandle<()>>,
    log: std::sync::Arc<std::sync::Mutex<Option<pks_core::log::Logger>>>,
}

#[cfg(target_os = "linux")]
impl Session {
    fn start(data: &Path, effective: &pks_core::policy::Effective) -> Result<Self, String> {
        use pks_core::keys;
        use pks_core::log::{Logger, new_session_id};
        use pks_proxy::{Config, Engine, serve};
        use std::os::unix::net::UnixListener;
        use std::sync::atomic::AtomicBool;
        use std::sync::{Arc, Mutex};

        let id = new_session_id().map_err(|e| format!("cannot make a session id: {e}"))?;
        let sessions = data.join("sessions");
        create_private_dir(&sessions)
            .map_err(|e| format!("cannot create {}: {e}", sessions.display()))?;
        let dir = sessions.join(&id);
        create_private_dir(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        let key = keys::load_or_create_signing_key(&data.join("keys"))
            .map_err(|e| format!("signing key: {e}"))?;
        let logger = Logger::create(&dir.join("session.jsonl"), key, &id)
            .map_err(|e| format!("cannot open the session log: {e}"))?;
        let log = Arc::new(Mutex::new(Some(logger)));
        let socket = dir.join("proxy.sock");
        let listener = UnixListener::bind(&socket)
            .map_err(|e| format!("cannot open the proxy socket: {e}"))?;

        let policy_hash = effective.hash();
        let sink_log = Arc::clone(&log);
        let events: pks_proxy::EventSink = Arc::new(move |finding| {
            eprintln!(
                "[{:?}] {} {}: {}",
                finding.severity,
                finding.rule.as_str(),
                finding.target,
                finding.message
            );
            if let Ok(mut guard) = sink_log.lock()
                && let Some(logger) = guard.as_mut()
            {
                let verdict = verdict_of(finding.rule.as_str(), &finding.message);
                let _ = logger.append(
                    &Record {
                        policy_hash: &policy_hash,
                        layer: "net",
                        target: &finding.target,
                        rule: finding.rule.as_str(),
                        verdict,
                    },
                    now_ms(),
                );
            }
        });
        let engine = Engine::new(Config {
            allow: effective.allow.clone(),
            host_ports: effective.host_ports.clone(),
            mode: effective.mode,
            resolver: Arc::new(pks_proxy::SystemResolver),
            dialer: Arc::new(pks_proxy::TcpDialer),
            asker: Arc::new(TerminalAsker),
            events,
            hold: pks_proxy::engine::ASK_HOLD,
        });
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop);
        let server = std::thread::spawn(move || {
            let _ = serve(listener, Arc::new(engine), stop_flag);
        });
        Ok(Self {
            id,
            socket,
            stop,
            server: Some(server),
            log,
        })
    }

    /// Stops the proxy, closes the log with its signed checkpoint, and removes
    /// the socket.
    fn close(mut self) {
        use std::sync::atomic::Ordering;
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.server.take() {
            let _ = handle.join();
        }
        let _ = std::fs::remove_file(&self.socket);
        if let Ok(mut guard) = self.log.lock()
            && let Some(logger) = guard.take()
            && let Err(error) = logger.finish(now_ms())
        {
            eprintln!("ide: could not close the session log: {error}");
        }
    }
}

/// The verdict a finding records. Blocked connections are `block`; monitor
/// mode lets them through and records them as `monitor`.
#[cfg(target_os = "linux")]
fn verdict_of(rule: &str, message: &str) -> &'static str {
    match rule {
        "NET-UNKNOWN-DOMAIN" if message.contains("monitor mode") => "monitor",
        "NET-LARGE-UPLOAD" => "warn",
        _ => "block",
    }
}

#[cfg(target_os = "linux")]
fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

/// Asks in the terminal. With no terminal (headless), nobody can answer, and
/// the engine denies (PRD FR-NET: "deny when headless").
#[cfg(target_os = "linux")]
struct TerminalAsker;

#[cfg(target_os = "linux")]
impl pks_proxy::Asker for TerminalAsker {
    fn ask(&self, endpoint: &pks_core::net::HostPort) -> Option<pks_proxy::Answer> {
        use std::io::IsTerminal;
        if !std::io::stdin().is_terminal() {
            return None;
        }
        prompt_on(std::io::stdin().lock(), std::io::stderr(), endpoint)
    }
}

/// Writes the question to `output` and reads one line from `input`. Any
/// answer other than "o", "once", "s" or "session" (including an empty line
/// or end of input) is a deny: the connection fails closed. `None` only when
/// the input cannot be read at all.
#[cfg(target_os = "linux")]
fn prompt_on<R: std::io::BufRead, W: std::io::Write>(
    mut input: R,
    mut output: W,
    endpoint: &pks_core::net::HostPort,
) -> Option<pks_proxy::Answer> {
    let _ = write!(
        output,
        "ide: allow connection to {endpoint}? [o]nce / [s]ession / [d]eny (default deny, 20 s): "
    );
    let _ = output.flush();
    let mut line = String::new();
    input.read_line(&mut line).ok()?;
    match line.trim().to_ascii_lowercase().as_str() {
        "o" | "once" => Some(pks_proxy::Answer::AllowOnce),
        "s" | "session" => Some(pks_proxy::Answer::AllowSession),
        _ => Some(pks_proxy::Answer::Deny),
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use pks_proxy::Answer;

    fn endpoint() -> pks_core::net::HostPort {
        pks_core::net::HostPort::parse("unknown.example.org:443").unwrap_or_else(|e| panic!("{e}"))
    }

    fn answer(line: &str) -> Option<Answer> {
        let mut output = Vec::new();
        prompt_on(line.as_bytes(), &mut output, &endpoint())
    }

    #[test]
    fn once_and_session_allow_and_everything_else_denies() {
        assert_eq!(answer("o\n"), Some(Answer::AllowOnce));
        assert_eq!(answer("once\n"), Some(Answer::AllowOnce));
        assert_eq!(answer("S\n"), Some(Answer::AllowSession));
        assert_eq!(answer("session\n"), Some(Answer::AllowSession));
        assert_eq!(answer("d\n"), Some(Answer::Deny));
        assert_eq!(answer("maybe\n"), Some(Answer::Deny));
    }

    #[test]
    fn an_empty_line_or_end_of_input_denies() {
        assert_eq!(answer("\n"), Some(Answer::Deny));
        assert_eq!(answer(""), Some(Answer::Deny));
    }

    #[test]
    fn the_question_names_the_endpoint_and_the_default() {
        let mut output = Vec::new();
        let _ = prompt_on(&b"d\n"[..], &mut output, &endpoint());
        let text = String::from_utf8_lossy(&output);
        assert!(text.contains("unknown.example.org:443"), "{text}");
        assert!(text.contains("default deny"), "{text}");
    }
}

/// The sandbox is Linux-only until Phase 16.
#[cfg(not(target_os = "linux"))]
pub fn run(_ide: Ide, _repo: &Path) -> ExitCode {
    eprintln!("ide: the sandbox is Linux-only until Phase 16 (Windows).");
    ExitCode::from(EXIT_SETUP)
}

/// The in-sandbox step: applies Landlock, starts the relay if given, applies
/// seccomp, then runs `command`. Called by bubblewrap, not by users.
#[cfg(target_os = "linux")]
pub fn sandbox_init(
    rw: &[PathBuf],
    ro: &[PathBuf],
    relay_listen: Option<std::net::SocketAddr>,
    relay_socket: Option<PathBuf>,
    relay_host_ports: &[u16],
    command: &[std::ffi::OsString],
) -> ExitCode {
    let relay = match (relay_listen, relay_socket) {
        (Some(listen), Some(socket)) => Some(pks_sandbox::linux::init::Relay {
            listen,
            socket,
            host_ports: relay_host_ports.to_vec(),
        }),
        _ => None,
    };
    let error = pks_sandbox::linux::init::run(rw, ro, command, relay.as_ref());
    eprintln!("sandbox-init: {error}");
    ExitCode::from(126)
}

#[cfg(not(target_os = "linux"))]
pub fn sandbox_init(
    _rw: &[PathBuf],
    _ro: &[PathBuf],
    _relay_listen: Option<std::net::SocketAddr>,
    _relay_socket: Option<PathBuf>,
    _relay_host_ports: &[u16],
    _command: &[std::ffi::OsString],
) -> ExitCode {
    eprintln!("sandbox-init: Linux only");
    ExitCode::from(126)
}

/// The relay inside the sandbox. Runs until the sandbox ends.
#[cfg(target_os = "linux")]
pub fn sandbox_relay(listen: std::net::SocketAddr, socket: &Path, host_ports: &[u16]) -> ExitCode {
    match pks_sandbox::linux::relay::run(listen, socket, host_ports) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("sandbox-relay: {error}");
            ExitCode::from(1)
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub fn sandbox_relay(
    _listen: std::net::SocketAddr,
    _socket: &Path,
    _host_ports: &[u16],
) -> ExitCode {
    eprintln!("sandbox-relay: Linux only");
    ExitCode::from(1)
}
