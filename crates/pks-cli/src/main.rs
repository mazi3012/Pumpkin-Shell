//! `pumpkin-shell`: sandbox and tripwire system for AI-powered IDEs.

#[cfg(target_os = "linux")]
mod ask;
#[cfg(target_os = "linux")]
mod broker;
#[cfg(target_os = "linux")]
mod clipboard;
mod dashboard;
mod doctor;
mod ide;
mod log;
mod picker;
mod policy;
mod restore;
mod review;
mod scan;
mod watch;

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use pks_core::Severity;

/// Sandbox and tripwire system for AI-powered IDEs (Linux, Kiro first).
#[derive(Parser)]
#[command(name = "pumpkin-shell", version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
// Parsed once at startup, so the size of the largest variant does not matter.
#[allow(clippy::large_enum_variant)]
enum Command {
    /// Check whether this machine can run the sandbox, and how to fix each problem.
    Doctor {
        /// Print the report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Scan a repository for setups that let an agent escape its workspace.
    Scan {
        /// Repository to scan.
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Print the report as JSON.
        #[arg(long)]
        json: bool,
        /// Exit 1 when a finding reaches --fail-on. Exit 2 when the scan is incomplete.
        #[arg(long)]
        ci: bool,
        /// Lowest severity that fails a --ci run.
        #[arg(long, value_enum, default_value_t = FailOn::High)]
        fail_on: FailOn,
        /// Also scan files that .gitignore lists. Use this in CI: a committed
        /// .gitignore can otherwise hide tracked files from the scan.
        #[arg(long)]
        no_ignore: bool,
    },
    /// Live, read-only dashboard of sessions and findings on this machine.
    Dashboard {
        /// Port on 127.0.0.1 to serve the page on.
        #[arg(long, default_value_t = dashboard::DEFAULT_PORT)]
        port: u16,
    },
    /// Open a repository in Kiro inside the sandbox. Same as 'ide kiro'.
    #[command(after_help = "Example: pumpkin-shell kiro /yourfolderhere\n\
Leave out the folder to choose it in a window (needs zenity).")]
    Kiro {
        /// Repository to open. Leave out to choose it in a window.
        path: Option<PathBuf>,
    },
    /// Open a repository in an IDE that runs inside the sandbox.
    Ide {
        /// The IDE to start.
        #[arg(value_enum)]
        ide: ide::Ide,
        /// Repository to open. Leave out to choose it in a window.
        path: Option<PathBuf>,
    },
    /// Internal: the step inside the sandbox that applies Landlock and seccomp, then runs the IDE.
    #[command(hide = true)]
    SandboxInit {
        /// Path that may be written (repeatable).
        #[arg(long = "rw")]
        rw: Vec<PathBuf>,
        /// Path that may only be read (repeatable).
        #[arg(long = "ro")]
        ro: Vec<PathBuf>,
        /// Loopback address the in-sandbox mirror relay listens on (Phase 14). Needs --mirror-socket.
        #[arg(long = "mirror-listen", requires = "mirror_socket")]
        mirror_listen: Option<std::net::SocketAddr>,
        /// The mirror's Unix socket, as seen inside the sandbox. Needs --mirror-listen.
        #[arg(long = "mirror-socket", requires = "mirror_listen")]
        mirror_socket: Option<PathBuf>,
        /// Socket the OAuth callback agent creates (Phase 12.2). Needs --callback-target.
        #[arg(long = "callback-socket", requires = "callback_target")]
        callback_socket: Option<PathBuf>,
        /// The IDE's listener inside the sandbox for the callback. Needs --callback-socket.
        #[arg(long = "callback-target", requires = "callback_socket")]
        callback_target: Option<std::net::SocketAddr>,
        /// Loopback address the in-sandbox relay listens on (Phase 9).
        #[arg(long = "relay-listen", requires = "relay_socket")]
        relay_listen: Option<std::net::SocketAddr>,
        /// Unix socket of the egress proxy, as seen inside the sandbox.
        #[arg(long = "relay-socket")]
        relay_socket: Option<PathBuf>,
        /// Host port the IDE may reach on loopback (repeatable, PRD FR-NET).
        #[arg(long = "relay-host-port", requires = "relay_socket")]
        relay_host_ports: Vec<u16>,
        /// The host socket that receives the monitor's listener (Phase 15).
        #[arg(long = "supervisor-socket")]
        supervisor_socket: Option<PathBuf>,
        /// The program to run after the restrictions are applied.
        #[arg(last = true, required = true, num_args = 1..)]
        command: Vec<OsString>,
    },
    /// Internal: passes connections from a Unix socket to the IDE's loopback listener.
    #[command(hide = true)]
    SandboxCallback {
        /// Unix socket to create in the broker directory.
        #[arg(long)]
        socket: PathBuf,
        /// The IDE's listener inside the sandbox.
        #[arg(long)]
        target: std::net::SocketAddr,
    },
    /// Internal: forwards loopback TCP to the proxy's Unix socket, inside the sandbox.
    #[command(hide = true)]
    SandboxRelay {
        /// Loopback address to listen on.
        #[arg(long)]
        listen: std::net::SocketAddr,
        /// Unix socket to forward to.
        #[arg(long)]
        socket: PathBuf,
        /// Host port to listen on and forward to the host's loopback (repeatable).
        #[arg(long = "host-port")]
        host_port: Vec<u16>,
    },
    /// Write the snapshot of a session to a new directory (default: under the data dir).
    Restore {
        /// The session id printed by `ide`.
        session: String,
        /// Directory to write into. It must not exist or must be empty.
        #[arg(long)]
        into: Option<PathBuf>,
    },
    /// Watch a running session for findings (WARN and above).
    Watch {
        /// The session id to watch.
        #[arg(long)]
        session: Option<String>,
    },
    /// Resume a paused session.
    Resume {
        /// The session id to resume.
        session: String,
    },
    /// Kill a running session.
    Kill {
        /// The session id to kill.
        session: String,
    },
    /// Review staged writes and approve or reject them.
    Review {
        /// The session id to review.
        session: String,
    },
    /// Allow a domain in the policy.
    Allow {
        /// Domain to allow (host:port).
        domain: String,
    },
    /// Approve one staged write of a session: copy it into the repo.
    AllowWrite {
        /// The session id printed by `ide`.
        session: String,
        /// Path from the repo root, as listed by `review`.
        path: String,
    },
    /// Pin the repo's pumpkin-shell.toml so it is applied. Run it again after any edit.
    Trust {
        /// Repository whose pumpkin-shell.toml to pin.
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    /// Show and check the policy that applies to a repository.
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    /// Work with session logs.
    Log {
        #[command(subcommand)]
        command: LogCommand,
    },
}

#[derive(Subcommand)]
enum PolicyCommand {
    /// Print the effective policy. Exit 1 when the repo policy is not applied or tries to loosen a rule.
    Check {
        /// Repository to check.
        #[arg(default_value = ".")]
        path: PathBuf,
    },
}

#[derive(Subcommand)]
enum LogCommand {
    /// Check a session log's chain, signatures and checkpoint. Exit 1 when it fails, 2 when it cannot be checked.
    Verify {
        /// The session log (.jsonl). Its checkpoint is read from `<file>.checkpoint`.
        file: PathBuf,
        /// Accept a log with no checkpoint (a session that may still be running).
        #[arg(long)]
        allow_open: bool,
        /// Directory holding log-signing.pub (default: the pumpkin-shell data dir, under keys).
        #[arg(long)]
        key_dir: Option<PathBuf>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum FailOn {
    Notice,
    Warn,
    High,
    Critical,
}

impl From<FailOn> for Severity {
    fn from(value: FailOn) -> Self {
        match value {
            FailOn::Notice => Severity::Notice,
            FailOn::Warn => Severity::Warn,
            FailOn::High => Severity::High,
            FailOn::Critical => Severity::Critical,
        }
    }
}

fn main() -> ExitCode {
    // Inside the sandbox, `xdg-open` and `git` are this binary under those
    // names (Phase 12). It acts on the name it was started under.
    #[cfg(target_os = "linux")]
    if let Some(name) = std::env::args_os().next().and_then(|arg| {
        PathBuf::from(arg)
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
    }) && (name == "xdg-open" || name == "git")
    {
        let args: Vec<OsString> = std::env::args_os().collect();
        return pks_sandbox::linux::shim::run(&name, &args);
    }
    match Cli::parse().command {
        Some(Command::Doctor { json }) => doctor::run(json),
        Some(Command::Scan {
            path,
            json,
            ci,
            fail_on,
            no_ignore,
        }) => scan::run(&path, json, ci, fail_on.into(), no_ignore),
        Some(Command::Ide { ide, path }) => open_project(ide, path),
        Some(Command::Kiro { path }) => open_project(ide::Ide::Kiro, path),
        Some(Command::Dashboard { port }) => dashboard::run(port),
        Some(Command::SandboxInit {
            rw,
            ro,
            relay_listen,
            relay_socket,
            relay_host_ports,
            mirror_listen,
            mirror_socket,
            callback_socket,
            callback_target,
            supervisor_socket,
            command,
        }) => ide::sandbox_init(
            &rw,
            &ro,
            relay_listen
                .zip(relay_socket)
                .map(|(listen, socket)| (listen, socket, relay_host_ports)),
            mirror_listen.zip(mirror_socket),
            callback_socket.zip(callback_target),
            supervisor_socket,
            &command,
        ),
        Some(Command::SandboxCallback { socket, target }) => ide::sandbox_callback(&socket, target),
        Some(Command::SandboxRelay {
            listen,
            socket,
            host_port,
        }) => ide::sandbox_relay(listen, &socket, &host_port),
        Some(Command::Restore { session, into }) => restore::run(&session, into.as_deref()),
        Some(Command::Watch { session }) => watch::run(session.as_deref()),
        Some(Command::Resume { session }) => watch::resume(&session),
        Some(Command::Kill { session }) => watch::kill(&session),
        Some(Command::Review { session }) => review::run(&session),
        Some(Command::Allow { domain }) => policy::allow_domain(&domain),
        Some(Command::AllowWrite { session, path }) => review::allow_write(&session, &path),
        Some(Command::Trust { path }) => policy::trust(&path),
        Some(Command::Policy {
            command: PolicyCommand::Check { path },
        }) => policy::check(&path),
        Some(Command::Log {
            command:
                LogCommand::Verify {
                    file,
                    allow_open,
                    key_dir,
                },
        }) => log::verify(&file, allow_open, key_dir.as_deref()),
        None => ExitCode::SUCCESS,
    }
}

/// Opens the project in an IDE. Without a folder, a window asks for one. The
/// command to type next time is printed first.
fn open_project(ide: ide::Ide, path: Option<PathBuf>) -> ExitCode {
    if let Some(path) = path {
        return ide::run(ide, &path);
    }
    let usage = match ide {
        ide::Ide::Kiro => "pumpkin-shell kiro /yourfolderhere",
        ide::Ide::Code => "pumpkin-shell ide code /yourfolderhere",
    };
    eprintln!("Opening a folder window. To skip it next time, run:\n  {usage}");
    match picker::choose_folder(usage) {
        Ok(path) => ide::run(ide, &path),
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Cli, FailOn};
    use clap::CommandFactory;
    use pks_core::Severity;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn fail_on_maps_to_the_matching_severity() {
        assert_eq!(Severity::from(FailOn::Notice), Severity::Notice);
        assert_eq!(Severity::from(FailOn::Warn), Severity::Warn);
        assert_eq!(Severity::from(FailOn::High), Severity::High);
        assert_eq!(Severity::from(FailOn::Critical), Severity::Critical);
    }
}
