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
    // One canonical path for the snapshot, the staging and the sandbox, so a
    // path inside the repo compares the same everywhere.
    let repo = match std::fs::canonicalize(repo) {
        Ok(path) => path,
        Err(error) => return setup(format!("cannot resolve {}: {error}", repo.display())),
    };
    let repo = repo.as_path();
    let policy = match pks_core::policy::read_user_policy(&config) {
        Ok(found) => found.unwrap_or_else(pks_core::policy::empty_user_policy),
        Err(error) => return setup(format!("your policy is not valid: {error}")),
    };
    let effective = pks_core::policy::Effective::from_user(&policy);
    let mut session = match Session::start(&data, &effective, repo) {
        Ok(session) => session,
        Err(message) => return setup(message),
    };

    let spec_install = install(ide);
    let ide_home = data.join("ide-home").join(spec_install.name);
    if let Err(error) = create_private_dir(&ide_home) {
        return setup(format!("cannot create {}: {error}", ide_home.display()));
    }
    // Decoy credentials in the IDE's home (PRD FR-WS). They are written fresh
    // for this session, and an access to one is reported while the IDE runs.
    let decoys = match pks_core::decoy::plant(&ide_home) {
        Ok(decoys) => decoys,
        Err(error) => return setup(format!("cannot write the decoy credentials: {error}")),
    };
    let decoy_watch = match pks_sandbox::linux::watch::AccessWatch::new(
        &decoys.iter().map(|d| d.path.clone()).collect::<Vec<_>>(),
    ) {
        Ok(watch) => watch,
        Err(error) => return setup(format!("cannot watch the decoy credentials: {error}")),
    };
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
        binds: session.binds(),
        pid_file: Some(session.dir.join(pks_detect::PID_FILE)),
        broker_dir: Some(session.dir.join("broker")),
        display_file: Some(session.dir.join(crate::clipboard::DISPLAY_FILE)),
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
    let stop_watch = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let watch_thread = {
        let stop = std::sync::Arc::clone(&stop_watch);
        let log = std::sync::Arc::clone(&session.log);
        let policy_hash = session.policy_hash.clone();
        let notifier = std::sync::Arc::clone(&session.notifier);
        let session_dir = session.dir.clone();
        let names: Vec<(PathBuf, &'static str)> =
            decoys.iter().map(|d| (d.path.clone(), d.name)).collect();
        std::thread::spawn(move || {
            let mut reported: Vec<&'static str> = Vec::new();
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                match decoy_watch.wait(200) {
                    Ok(paths) => {
                        for path in paths {
                            let Some((_, name)) = names.iter().find(|(p, _)| *p == path) else {
                                continue;
                            };
                            if !reported.contains(name) {
                                reported.push(name);
                                let finding = pks_core::decoy::read_finding(name);
                                emit(&log, &policy_hash, &finding, "alert");
                                route(&notifier, &session_dir, &finding);
                            }
                        }
                    }
                    Err(error) => {
                        eprintln!("ide: the decoy watch stopped: {error}");
                        break;
                    }
                }
            }
        })
    };
    let poll_thread = {
        let stop = std::sync::Arc::clone(&stop_watch);
        let log = std::sync::Arc::clone(&session.log);
        let policy_hash = session.policy_hash.clone();
        let notifier = std::sync::Arc::clone(&session.notifier);
        let session_dir = session.dir.clone();
        let staging = session.staging_handle();
        std::thread::spawn(move || {
            let Some(staging) = staging else { return };
            let mut reported: std::collections::HashSet<(String, String)> =
                std::collections::HashSet::new();
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                std::thread::sleep(STAGING_POLL);
                for finding in live_findings(&staging) {
                    let key = (finding.rule.as_str().to_owned(), finding.target.clone());
                    if reported.insert(key) {
                        emit(&log, &policy_hash, &finding, "staged");
                        route(&notifier, &session_dir, &finding);
                    }
                }
            }
        })
    };
    // Clipboard copy and paste (Phase 12). Not joined: it may be waiting on a
    // popup, and the session should not wait for that.
    {
        let stop = std::sync::Arc::clone(&stop_watch);
        let session_dir = session.dir.clone();
        let log = std::sync::Arc::clone(&session.log);
        let policy_hash = session.policy_hash.clone();
        std::thread::spawn(move || {
            crate::clipboard::watch(stop, session_dir, move |rule, bytes, allowed| {
                let target = format!("{bytes} bytes");
                let verdict = if allowed { "allow" } else { "deny" };
                if let Ok(mut guard) = log.lock()
                    && let Some(logger) = guard.as_mut()
                {
                    let _ = logger.append(
                        &Record {
                            policy_hash: &policy_hash,
                            layer: "clip",
                            target: &target,
                            rule,
                            verdict,
                        },
                        now_ms(),
                    );
                }
            })
        });
    }
    let result = backend.run(&spec);
    stop_watch.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = watch_thread.join();
    let _ = poll_thread.join();
    session.check_workspace(repo);
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
    /// The session directory: holds the snapshot and the session log.
    dir: PathBuf,
    /// Hash of the policy in force, written into every log record.
    policy_hash: String,
    /// The staged protected paths. Dropping it removes the mount points that
    /// were made in the repo, so every way out of a session cleans up.
    staging: Option<std::sync::Arc<pks_core::workspace::Staging>>,
    socket: PathBuf,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    server: Option<std::thread::JoinHandle<()>>,
    log: std::sync::Arc<std::sync::Mutex<Option<pks_core::log::Logger>>>,
    /// Severity routing and desktop notifications (PRD FR-NOTIFY).
    notifier: std::sync::Arc<pks_detect::Notifier>,
    /// Stops the broker request listener and the callback listener.
    broker_stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

#[cfg(target_os = "linux")]
impl Session {
    fn start(
        data: &Path,
        effective: &pks_core::policy::Effective,
        repo: &Path,
    ) -> Result<Self, String> {
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
        // Review and approval need the repo path later, after the IDE exits.
        let repo_text = repo.to_str().ok_or_else(|| {
            format!(
                "{} is not valid UTF-8, so the session cannot be reviewed",
                repo.display()
            )
        })?;
        std::fs::write(dir.join(pks_detect::REPO_FILE), repo_text)
            .map_err(|e| format!("cannot record the repo path: {e}"))?;
        // The snapshot comes before the IDE starts. Without it, the session
        // does not start (PRD FR-WS: snapshot before launch).
        let commit = pks_core::snapshot::create(repo, &dir)
            .map_err(|e| format!("cannot take the snapshot of {}: {e}", repo.display()))?;
        eprintln!("ide: snapshot {} taken", &commit[..12]);
        // Staging comes after the snapshot, so the mount points it makes in
        // the repo are not in the snapshot.
        let staging = pks_core::workspace::prepare(repo, &dir)
            .map_err(|e| format!("cannot protect the workspace: {e}"))?;
        let key = keys::load_or_create_signing_key(&data.join("keys"))
            .map_err(|e| format!("signing key: {e}"))?;
        let logger = Logger::create(&dir.join("session.jsonl"), key, &id)
            .map_err(|e| format!("cannot open the session log: {e}"))?;
        let log = Arc::new(Mutex::new(Some(logger)));
        // Desktop notifications are on for every session. Webhook output is
        // deferred (DECISIONS Q7), so CRITICAL findings only pause the session.
        let notifier = Arc::new(pks_detect::Notifier::new(
            dir.clone(),
            true,
            Arc::new(AtomicBool::new(false)),
        ));
        // The brokers (Phase 12). Requests from the sandbox arrive on a socket
        // in the broker directory, which is the only host path shared with it.
        let broker_stop = Arc::new(AtomicBool::new(false));
        let broker_dir = dir.join("broker");
        create_private_dir(&broker_dir)
            .map_err(|e| format!("cannot create {}: {e}", broker_dir.display()))?;
        let request_listener = UnixListener::bind(broker_dir.join("request.sock"))
            .map_err(|e| format!("cannot open the broker socket: {e}"))?;
        let broker_host: Arc<dyn pks_sandbox::linux::broker::Handler + Send + Sync> =
            Arc::new(crate::broker::Host::new(repo));
        let request_stop = Arc::clone(&broker_stop);
        std::thread::spawn(move || {
            let _ = pks_sandbox::linux::broker::serve(request_listener, broker_host, request_stop);
        });
        // The OAuth callback (Phase 12.2): the host's port 3128 is passed to
        // the IDE's listener inside the sandbox on the same port.
        match std::net::TcpListener::bind("127.0.0.1:3128") {
            Ok(listener) => {
                let agent_socket = broker_dir.join("callback.sock");
                let callback_stop = Arc::clone(&broker_stop);
                std::thread::spawn(move || {
                    let _ = pks_sandbox::linux::broker::callback_host(
                        listener,
                        agent_socket,
                        callback_stop,
                    );
                });
            }
            Err(error) => eprintln!(
                "ide: 127.0.0.1:3128 is not free ({error}), so OAuth sign-in cannot finish in the IDE"
            ),
        }

        let socket = dir.join("proxy.sock");
        let listener = UnixListener::bind(&socket)
            .map_err(|e| format!("cannot open the proxy socket: {e}"))?;

        let policy_hash = effective.hash();
        let session_policy_hash = policy_hash.clone();
        let sink_log = Arc::clone(&log);
        let sink_notifier = Arc::clone(&notifier);
        let sink_dir = dir.clone();
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
            route(&sink_notifier, &sink_dir, &finding);
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
            dir,
            policy_hash: session_policy_hash,
            staging: Some(std::sync::Arc::new(staging)),
            socket,
            stop,
            server: Some(server),
            log,
            notifier,
            broker_stop,
        })
    }

    /// A shared handle to the staging, for the live check while the IDE runs.
    fn staging_handle(&self) -> Option<std::sync::Arc<pks_core::workspace::Staging>> {
        self.staging.clone()
    }

    /// The staged protected paths, as binds for the sandbox.
    fn binds(&self) -> Vec<pks_sandbox::Bind> {
        self.staging
            .as_ref()
            .map(|staging| {
                staging
                    .mounts()
                    .iter()
                    .map(|mount| pks_sandbox::Bind {
                        rel: mount.rel.clone(),
                        source: mount.source.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Prints a finding and writes it to the signed log.
    fn report(&self, finding: &pks_core::Finding, verdict: &str) {
        emit(&self.log, &self.policy_hash, finding, verdict);
    }

    /// After the IDE exits: reports writes to protected and watched paths (kept
    /// in staging, verdict `staged`), secrets written into the repo, and a
    /// mass delete against the snapshot (`alert`).
    fn check_workspace(&mut self, repo: &Path) {
        if let Some(staging) = self.staging.take() {
            // Checks the sandbox's writes to protected paths, then ends the staging.
            // The live thread has been joined, so this is the last handle.
            match std::sync::Arc::try_unwrap(staging) {
                Ok(staging) => {
                    for finding in pks_scan::staged::review(staging) {
                        self.report(&finding, "staged");
                    }
                }
                Err(_) => eprintln!("ide: the staged writes could not be checked: still in use"),
            }
        }
        // Secrets the sandbox wrote into the repo (values are never printed).
        for finding in pks_scan::staged::repo_secret_findings(repo, &self.dir) {
            self.report(&finding, "alert");
        }
        match pks_core::snapshot::check_mass_delete(repo, &self.dir, &self.id) {
            Ok(Some(finding)) => self.report(&finding, "alert"),
            Ok(None) => {}
            Err(error) => {
                eprintln!("ide: could not check the workspace against the snapshot: {error}");
            }
        }
    }
    /// Stops the proxy, closes the log with its signed checkpoint, and removes
    /// the socket.
    fn close(mut self) {
        use std::sync::atomic::Ordering;
        self.stop.store(true, Ordering::Relaxed);
        self.broker_stop.store(true, Ordering::Relaxed);
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

/// How often the staged copies are checked while the IDE runs.
#[cfg(target_os = "linux")]
const STAGING_POLL: std::time::Duration = std::time::Duration::from_millis(500);

/// Config findings in the staged copies the sandbox has changed so far. Only
/// the config rules run live, because they are the ones that must pause the
/// session at once (WS-AUTOAPPROVE). The full review still runs when the IDE
/// exits. A file that is still being written may not parse yet; it is checked
/// again on the next pass.
#[cfg(target_os = "linux")]
fn live_findings(staging: &pks_core::workspace::Staging) -> Vec<pks_core::Finding> {
    let Ok(files) = staging.changed_files() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for file in files {
        let Ok(text) = std::fs::read_to_string(&file.staged) else {
            continue;
        };
        if let Some(Ok(findings)) = pks_scan::staged::config_findings(&file.rel, &text) {
            out.extend(findings);
        }
    }
    out
}

/// Routes a finding by severity (PRD FR-NOTIFY). A CRITICAL finding pauses
/// the session until `resume` or `kill`.
#[cfg(target_os = "linux")]
fn route(notifier: &pks_detect::Notifier, session_dir: &Path, finding: &pks_core::Finding) {
    if notifier.notify(finding) {
        pause_session(session_dir);
    }
}

/// Pauses the sandbox of the session in `dir`: SIGSTOP to its process group,
/// then the paused marker. It stays paused until `resume` sends SIGCONT.
#[cfg(target_os = "linux")]
fn pause_session(dir: &Path) {
    use pks_sandbox::linux::signal::{Signal, signal_tree};
    let session = dir.file_name().map_or_else(
        || "this session".to_owned(),
        |name| name.to_string_lossy().into_owned(),
    );
    let Some(pid) = pks_detect::read_pid(dir) else {
        eprintln!("ide: could not pause {session}: the IDE is not running");
        return;
    };
    match signal_tree(pid, Signal::Stop) {
        Ok(_) => {
            let marker = dir.join(pks_detect::PAUSED_FILE);
            if let Err(error) = std::fs::write(&marker, b"") {
                eprintln!(
                    "ide: paused, but cannot write {}: {error}",
                    marker.display()
                );
            }
            eprintln!(
                "ide: paused {session}. Run 'pumpkin-shell resume {session}' to continue or 'pumpkin-shell kill {session}' to stop."
            );
        }
        Err(error) => eprintln!("ide: could not pause {session}: {error}"),
    }
}

/// Prints a finding and writes it to the session's signed log. Used by the
/// session and by the decoy watch thread, so both log the same way.
#[cfg(target_os = "linux")]
fn emit(
    log: &std::sync::Mutex<Option<pks_core::log::Logger>>,
    policy_hash: &str,
    finding: &pks_core::Finding,
    verdict: &str,
) {
    eprintln!(
        "[{:?}] {} {}: {}",
        finding.severity,
        finding.rule.as_str(),
        finding.target,
        finding.message
    );
    eprintln!("ide: {}", finding.fix);
    if let Ok(mut guard) = log.lock()
        && let Some(logger) = guard.as_mut()
    {
        let _ = logger.append(
            &Record {
                policy_hash,
                layer: "ws",
                target: &finding.target,
                rule: finding.rule.as_str(),
                verdict,
            },
            now_ms(),
        );
    }
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

    /// PRD scenario 3, while the IDE runs: the sandbox turns on auto-approve in
    /// a staged copy. The live check reports it as CRITICAL, and the repo is
    /// not changed.
    #[test]
    fn a_staged_auto_approve_switch_is_critical_while_the_ide_runs()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let repo = root.path().join("repo");
        let session = root.path().join("session");
        std::fs::create_dir_all(repo.join(".vscode"))?;
        std::fs::write(repo.join(".vscode/settings.json"), "{}\n")?;
        std::fs::create_dir_all(&session)?;
        let staging = pks_core::workspace::prepare(&repo, &session)?;

        assert!(
            live_findings(&staging).is_empty(),
            "nothing has been written yet"
        );

        std::fs::write(
            session.join("staging/.vscode/settings.json"),
            "{\"chat.tools.autoApprove\": true}\n",
        )?;
        let findings = live_findings(&staging);
        assert!(
            findings.iter().any(|f| f.rule.as_str() == "WS-AUTOAPPROVE"
                && f.severity == pks_core::Severity::Critical),
            "{findings:?}"
        );
        assert_eq!(
            std::fs::read_to_string(repo.join(".vscode/settings.json"))?,
            "{}\n"
        );
        Ok(())
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
    callback: Option<(PathBuf, std::net::SocketAddr)>,
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
    let callback =
        callback.map(|(socket, target)| pks_sandbox::linux::init::Callback { socket, target });
    let error = pks_sandbox::linux::init::run(rw, ro, command, relay.as_ref(), callback.as_ref());
    eprintln!("sandbox-init: {error}");
    ExitCode::from(126)
}

/// The callback agent inside the sandbox. Runs until the sandbox ends.
#[cfg(target_os = "linux")]
pub fn sandbox_callback(socket: &Path, target: std::net::SocketAddr) -> ExitCode {
    match pks_sandbox::linux::broker::sandbox_callback(socket, target) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("sandbox-callback: {error}");
            ExitCode::from(1)
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub fn sandbox_callback(_socket: &Path, _target: std::net::SocketAddr) -> ExitCode {
    eprintln!("sandbox-callback: Linux only");
    ExitCode::from(1)
}

#[cfg(not(target_os = "linux"))]
pub fn sandbox_init(
    _rw: &[PathBuf],
    _ro: &[PathBuf],
    _relay_listen: Option<std::net::SocketAddr>,
    _relay_socket: Option<PathBuf>,
    _relay_host_ports: &[u16],
    _callback: Option<(PathBuf, std::net::SocketAddr)>,
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
