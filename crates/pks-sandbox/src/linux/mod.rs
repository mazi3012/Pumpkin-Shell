//! The Linux backend (PRD §6.1): bubblewrap, a nested Xephyr display, Landlock
//! and a seccomp filter. No root is needed at runtime.

pub mod bwrap;
pub mod display;
pub mod init;
pub mod relay;

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, ExitStatus};

use crate::spec::{self, LaunchSpec};
use crate::{SandboxBackend, SandboxError};
use bwrap::Plan;
use display::{NestedDisplay, Tools};

/// Runs IDEs with bubblewrap.
pub struct LinuxBackend {
    bwrap: std::path::PathBuf,
    tools: Tools,
    /// The Pumpkin-Shell binary, run inside the sandbox for the setup step.
    init_exe: std::path::PathBuf,
}

impl LinuxBackend {
    /// Finds bubblewrap, Xephyr and xauth on `PATH`. `init_exe` is the
    /// Pumpkin-Shell binary that runs the in-sandbox setup step; the caller
    /// passes it, since only the caller knows which binary it is.
    ///
    /// # Errors
    /// Fails with the name of the first missing tool.
    pub fn locate(init_exe: std::path::PathBuf) -> Result<Self, SandboxError> {
        let path = std::env::var_os("PATH").unwrap_or_default();
        Ok(Self {
            bwrap: display::find_in(&path, "bwrap")?,
            tools: Tools {
                xephyr: display::find_in(&path, "Xephyr")?,
                xauth: display::find_in(&path, "xauth")?,
            },
            init_exe,
        })
    }
}

/// A `passwd` and `group` with one entry: the sandbox's uid, named `sandbox`.
fn write_identity(dir: &Path) -> Result<(std::path::PathBuf, std::path::PathBuf), SandboxError> {
    let uid = process_ids();
    let passwd = dir.join("passwd");
    let group = dir.join("group");
    write_private(
        &passwd,
        format!(
            "sandbox:x:{}:{}:sandbox:/home/sandbox:/bin/bash\n",
            uid.0, uid.1
        )
        .as_bytes(),
    )?;
    write_private(&group, format!("sandbox:x:{}:\n", uid.1).as_bytes())?;
    Ok((passwd, group))
}

/// Real uid and gid of this process, from `/proc/self/status`. The libc
/// functions that return them are `unsafe` to call, and this crate allows
/// `unsafe` only in documented FFI wrappers, so the status file is read
/// instead.
fn process_ids() -> (u32, u32) {
    let text = fs::read_to_string("/proc/self/status").unwrap_or_default();
    let field = |name: &str| {
        text.lines()
            .find(|line| line.starts_with(name))
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|value| value.parse().ok())
            .unwrap_or(0)
    };
    (field("Uid:"), field("Gid:"))
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), SandboxError> {
    let mut file = fs::File::create(path).map_err(|source| SandboxError::Io {
        context: format!("cannot create {}", path.display()),
        source,
    })?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .and_then(|()| file.write_all(bytes))
        .map_err(|source| SandboxError::Io {
            context: format!("cannot write {}", path.display()),
            source,
        })
}

impl SandboxBackend for LinuxBackend {
    fn name(&self) -> &'static str {
        "linux-bwrap"
    }

    fn run(&self, spec: &LaunchSpec) -> Result<ExitStatus, SandboxError> {
        spec::check(spec)?;
        let session = tempfile::Builder::new()
            .prefix("pks-session-")
            .tempdir()
            .map_err(|source| SandboxError::Io {
                context: "cannot create the session directory".to_owned(),
                source,
            })?;
        let display = NestedDisplay::start(&self.tools, session.path(), spec.display_size)?;
        let (passwd, group) = write_identity(session.path())?;
        let plan = Plan {
            repo: spec.repo.clone(),
            ide_home: spec.ide_home.clone(),
            ide_binary: spec.ide.binary.clone(),
            ide_args: spec.ide_args.clone(),
            display: display.number(),
            display_socket: display.socket().to_path_buf(),
            xauthority: display.xauthority().to_path_buf(),
            passwd,
            group,
            init_exe: self.init_exe.clone(),
            proxy_socket: spec.proxy_socket.clone(),
            host_ports: spec.host_ports.clone(),
        };
        let status = Command::new(&self.bwrap)
            .args(bwrap::bwrap_args(&plan))
            .status()
            .map_err(|source| SandboxError::Io {
                context: "cannot start bubblewrap".to_owned(),
                source,
            })?;
        // The display stops when `display` is dropped, after the IDE exits.
        drop(display);
        drop(session);
        Ok(status)
    }
}
