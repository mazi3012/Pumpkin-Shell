//! The step that runs inside the sandbox, before the IDE (`sandbox-init`).
//!
//! 1. Landlock: the process may write only under the listed `--rw` paths.
//!    Read access is limited to the `--ro` paths. The ruleset requires at
//!    least ABI 1 (Linux 5.13) and uses newer rights when the kernel has
//!    them. If the kernel enforces nothing, startup fails.
//! 2. seccomp: `ioctl(_, TIOCSTI, _)` returns EPERM. TIOCSTI pushes bytes
//!    into a terminal's input queue, which is how a program can type commands
//!    into the terminal it shares with another program.
//! 3. exec: the IDE replaces this process. Both layers stay in place.
//!
//! Both layers are applied in the process before exec, so the IDE and every
//! child it starts inherit them.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

use landlock::{
    ABI, Access, AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr, RulesetCreatedAttr,
    RulesetStatus, path_beneath_rules,
};
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule,
};

use crate::SandboxError;

/// Applies Landlock with the given write and read paths.
///
/// # Errors
/// Fails if the kernel does not support the minimum ABI, if a path does not
/// exist, or if nothing could be enforced.
pub fn restrict_filesystem(rw: &[PathBuf], ro: &[PathBuf]) -> Result<(), SandboxError> {
    let setup = |what: &str, error: &dyn std::fmt::Display| {
        SandboxError::Setup(format!("landlock: {what}: {error}"))
    };
    let created = Ruleset::default()
        // Refuse to run without the rights of ABI 1 (Linux 5.13).
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(ABI::V1))
        .map_err(|e| setup("this kernel is too old (needs 5.13)", &e))?
        // Newer rights are used when the kernel has them.
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(ABI::V9))
        .map_err(|e| setup("handle_access", &e))?
        .create()
        .map_err(|e| setup("create", &e))?;
    let created = created
        .add_rules(path_beneath_rules(rw, AccessFs::from_all(ABI::V9)))
        .map_err(|e| setup("adding write paths", &e))?;
    let created = created
        .add_rules(path_beneath_rules(ro, AccessFs::from_read(ABI::V9)))
        .map_err(|e| setup("adding read paths", &e))?;
    let status = created
        .restrict_self()
        .map_err(|e| setup("restrict_self", &e))?;
    if status.ruleset == RulesetStatus::NotEnforced {
        return Err(SandboxError::Setup(
            "landlock: the kernel did not enforce any rule".to_owned(),
        ));
    }
    if !status.no_new_privs {
        return Err(SandboxError::Setup(
            "landlock: no_new_privs was not set".to_owned(),
        ));
    }
    Ok(())
}

/// Installs the seccomp filter that makes TIOCSTI fail with EPERM. Every
/// other system call is allowed.
///
/// # Errors
/// Fails if the filter cannot be built or installed.
pub fn block_tiocsti() -> Result<(), SandboxError> {
    let setup = |what: &str, error: &dyn std::fmt::Display| {
        SandboxError::Setup(format!("seccomp: {what}: {error}"))
    };
    // ioctl(fd, request, arg): TIOCSTI is the second argument.
    let condition =
        SeccompCondition::new(1, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, libc::TIOCSTI)
            .map_err(|e| setup("condition", &e))?;
    let rule = SeccompRule::new(vec![condition]).map_err(|e| setup("rule", &e))?;
    let rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::from([(libc::SYS_ioctl, vec![rule])]);
    let arch = std::env::consts::ARCH
        .try_into()
        .map_err(|e| setup("architecture", &e))?;
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM.unsigned_abs()),
        arch,
    )
    .map_err(|e| setup("filter", &e))?;
    let program: BpfProgram = filter.try_into().map_err(|e| setup("compile", &e))?;
    seccompiler::apply_filter(&program).map_err(|e| setup("install", &e))
}

/// Applies both layers, then replaces this process with `command`.
/// Returns only on failure.
///
/// # Errors
/// Fails before exec if either layer cannot be applied (fail closed), if the
/// command is empty, or if exec fails.
pub fn run(
    rw: &[PathBuf],
    ro: &[PathBuf],
    command: &[OsString],
    relays: &[Relay],
    callback: Option<&Callback>,
) -> SandboxError {
    if let Err(error) = restrict_filesystem(rw, ro) {
        return error;
    }
    for relay in relays {
        if let Err(error) = start_relay(relay) {
            return error;
        }
    }
    if let Some(callback) = callback
        && let Err(error) = start_callback(callback)
    {
        return error;
    }
    if let Err(error) = block_tiocsti() {
        return error;
    }
    let Some((program, args)) = command.split_first() else {
        return SandboxError::Setup("sandbox-init: no command given".to_owned());
    };
    let error = Command::new(program).args(args).exec();
    SandboxError::Io {
        context: format!("cannot run {}", PathBuf::from(program).display()),
        source: error,
    }
}

/// The OAuth callback agent to start before the IDE (Phase 12.2).
#[derive(Debug, Clone)]
pub struct Callback {
    /// Socket the agent creates in the shared broker directory.
    pub socket: PathBuf,
    /// The IDE's listener inside the sandbox.
    pub target: std::net::SocketAddr,
}

/// Starts the callback agent as a child process and waits until its socket
/// exists. Like the relay, it ends with the sandbox.
fn start_callback(callback: &Callback) -> Result<(), SandboxError> {
    let setup = |what: &str| SandboxError::Setup(format!("callback: {what}"));
    let exe = std::env::current_exe().map_err(|e| SandboxError::Io {
        context: "cannot find the in-sandbox binary".to_owned(),
        source: e,
    })?;
    let _child = Command::new(exe)
        .arg("sandbox-callback")
        .arg("--socket")
        .arg(&callback.socket)
        .arg("--target")
        .arg(callback.target.to_string())
        .spawn()
        .map_err(|e| SandboxError::Io {
            context: "cannot start the callback agent".to_owned(),
            source: e,
        })?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if callback.socket.exists() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    Err(setup("its socket did not appear within 5 seconds"))
}

/// A relay to start before the IDE: listen address and the proxy socket.
#[derive(Debug, Clone)]
pub struct Relay {
    pub listen: std::net::SocketAddr,
    pub socket: PathBuf,
    /// Host ports the IDE may reach on its loopback (PRD FR-NET).
    pub host_ports: Vec<u16>,
}

/// Starts the relay as a child process and waits until it accepts
/// connections. The child inherits the Landlock and seccomp layers, and it
/// ends when the IDE does (the sandbox's process namespace ends with it).
fn start_relay(relay: &Relay) -> Result<(), SandboxError> {
    let setup = |what: &str| SandboxError::Setup(format!("relay: {what}"));
    let exe = std::env::current_exe().map_err(|e| SandboxError::Io {
        context: "cannot find the in-sandbox binary".to_owned(),
        source: e,
    })?;
    let _child = Command::new(exe)
        .arg("sandbox-relay")
        .arg("--listen")
        .arg(relay.listen.to_string())
        .arg("--socket")
        .arg(&relay.socket)
        .args(
            relay
                .host_ports
                .iter()
                .flat_map(|port| ["--host-port".to_owned(), port.to_string()]),
        )
        .spawn()
        .map_err(|e| SandboxError::Io {
            context: "cannot start the relay".to_owned(),
            source: e,
        })?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if std::net::TcpStream::connect(relay.listen).is_ok() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    Err(setup("it did not start listening within 5 seconds"))
}
