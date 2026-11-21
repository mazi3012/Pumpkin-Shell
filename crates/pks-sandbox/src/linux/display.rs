//! A nested X server (Xephyr) for one IDE session (Phase 5, Q4 decided).
//!
//! The IDE talks only to its own display, never to the host's `:0`, so it
//! cannot read the host's keystrokes or inject input into host windows.
//!
//! The access cookie is written with `xauth`, which reads the command from
//! stdin. That keeps the secret out of the process arguments, which any
//! process of the same user could read from `/proc`.

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::SandboxError;

/// Host directory holding the X server sockets.
pub const X11_DIR: &str = "/tmp/.X11-unix";
const FIRST_DISPLAY: u32 = 20;
const LAST_DISPLAY: u32 = 99;
const START_TIMEOUT: Duration = Duration::from_secs(10);
const POLL: Duration = Duration::from_millis(50);

/// Paths of the helper programs, found on `PATH` before anything starts.
#[derive(Debug, Clone)]
pub struct Tools {
    pub xephyr: PathBuf,
    pub xauth: PathBuf,
}

/// A running nested X server. Dropping it stops the server.
pub struct NestedDisplay {
    child: Child,
    number: u32,
    socket: PathBuf,
    xauthority: PathBuf,
}

/// Returns the first directory of `path_var` that holds an executable `name`,
/// resolved to its real path.
pub fn find_in(path_var: &std::ffi::OsStr, name: &'static str) -> Result<PathBuf, SandboxError> {
    for dir in std::env::split_paths(path_var) {
        let candidate = dir.join(name);
        if is_executable_file(&candidate) {
            return fs::canonicalize(&candidate).map_err(|source| SandboxError::Io {
                context: format!("cannot resolve {}", candidate.display()),
                source,
            });
        }
    }
    Err(SandboxError::Tool {
        tool: name,
        detail: "not found on PATH; install it (see docs/poc/linux-kiro.md)".to_owned(),
    })
}

/// [`find_in`] with the process's own `PATH`.
pub fn find_program(name: &'static str) -> Result<PathBuf, SandboxError> {
    find_in(&std::env::var_os("PATH").unwrap_or_default(), name)
}

fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

fn random_hex(bytes: usize) -> Result<String, SandboxError> {
    let mut buffer = vec![0u8; bytes];
    getrandom::fill(&mut buffer).map_err(|e| SandboxError::Setup(format!("random: {e}")))?;
    Ok(buffer.iter().map(|b| format!("{b:02x}")).collect())
}

fn log_tail(path: &Path) -> String {
    let mut text = String::new();
    if let Ok(mut file) = File::open(path) {
        let _ = file.read_to_string(&mut text);
    }
    let lines: Vec<&str> = text.lines().rev().take(3).collect();
    lines.into_iter().rev().collect::<Vec<_>>().join(" | ")
}

impl NestedDisplay {
    /// Starts a nested server on the first free display number. Files go in
    /// `dir`, which must be private.
    ///
    /// # Errors
    /// Fails when no number is free, when a helper cannot run, or when the
    /// server does not come up within ten seconds.
    pub fn start(tools: &Tools, dir: &Path, size: (u32, u32)) -> Result<Self, SandboxError> {
        // Xephyr is a nested server: it runs inside a host X display. Without
        // one it cannot start at all, so say so instead of trying every number.
        if std::env::var_os("DISPLAY").is_none_or(|value| value.is_empty()) {
            return Err(SandboxError::Setup(
                "Xephyr runs inside a host X display, and DISPLAY is not set. \
                 Start your desktop session, or start a virtual one (Xvfb)."
                    .to_owned(),
            ));
        }
        let cookie = random_hex(16)?;
        let mut last_error = String::from("no display number was free");
        for number in FIRST_DISPLAY..=LAST_DISPLAY {
            let socket = PathBuf::from(format!("{X11_DIR}/X{number}"));
            let lock = PathBuf::from(format!("/tmp/.X{number}-lock"));
            if socket.exists() || lock.exists() {
                continue;
            }
            let xauthority = dir.join(format!("Xauthority-{number}"));
            add_cookie(tools, &xauthority, number, &cookie)?;
            let log = dir.join(format!("xephyr-{number}.log"));
            let mut child = spawn_xephyr(tools, number, &xauthority, size, &log)?;
            match wait_for_socket(&mut child, &socket) {
                Ok(()) => {
                    return Ok(Self {
                        child,
                        number,
                        socket,
                        xauthority,
                    });
                }
                Err(reason) => {
                    last_error = format!("display :{number}: {reason} ({})", log_tail(&log));
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }
        Err(SandboxError::Setup(format!(
            "could not start Xephyr: {last_error}"
        )))
    }

    /// The display number, for example 20 for `:20`.
    #[must_use]
    pub fn number(&self) -> u32 {
        self.number
    }

    /// Host path of the server's socket.
    #[must_use]
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Host path of the cookie file.
    #[must_use]
    pub fn xauthority(&self) -> &Path {
        &self.xauthority
    }
}

impl Drop for NestedDisplay {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn add_cookie(tools: &Tools, file: &Path, number: u32, cookie: &str) -> Result<(), SandboxError> {
    use std::io::Write;
    let mut child = Command::new(&tools.xauth)
        .arg("-q")
        .arg("-f")
        .arg(file)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|source| SandboxError::Io {
            context: "cannot run xauth".to_owned(),
            source,
        })?;
    if let Some(mut stdin) = child.stdin.take() {
        // The command goes over stdin, not in the arguments.
        writeln!(stdin, "add :{number} . {cookie}").map_err(|source| SandboxError::Io {
            context: "cannot write to xauth".to_owned(),
            source,
        })?;
    }
    let status = child.wait().map_err(|source| SandboxError::Io {
        context: "cannot wait for xauth".to_owned(),
        source,
    })?;
    if !status.success() {
        return Err(SandboxError::Tool {
            tool: "xauth",
            detail: format!("exited with {status}"),
        });
    }
    Ok(())
}

fn spawn_xephyr(
    tools: &Tools,
    number: u32,
    xauthority: &Path,
    size: (u32, u32),
    log: &Path,
) -> Result<Child, SandboxError> {
    let log_file = File::create(log).map_err(|source| SandboxError::Io {
        context: format!("cannot create {}", log.display()),
        source,
    })?;
    let log_err = log_file.try_clone().map_err(|source| SandboxError::Io {
        context: "cannot duplicate the log file".to_owned(),
        source,
    })?;
    Command::new(&tools.xephyr)
        .arg(format!(":{number}"))
        .arg("-screen")
        .arg(format!("{}x{}", size.0, size.1))
        // No TCP: the server is reachable only through its Unix socket.
        .arg("-nolisten")
        .arg("tcp")
        // No -terminate: the server must outlive the short connections of the
        // host's clipboard watcher. It is stopped when NestedDisplay is dropped.
        .arg("-auth")
        .arg(xauthority)
        .arg("-title")
        .arg("Pumpkin-Shell")
        .stdin(Stdio::null())
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(log_err))
        .spawn()
        .map_err(|source| SandboxError::Io {
            context: "cannot start Xephyr".to_owned(),
            source,
        })
}

/// Waits until `socket` exists, or fails if the server exits first.
fn wait_for_socket(child: &mut Child, socket: &Path) -> Result<(), String> {
    use std::os::unix::fs::FileTypeExt;
    let deadline = Instant::now() + START_TIMEOUT;
    loop {
        if fs::symlink_metadata(socket).is_ok_and(|meta| meta.file_type().is_socket()) {
            return Ok(());
        }
        if let Ok(Some(status)) = child.try_wait() {
            return Err(format!("exited with {status}"));
        }
        if Instant::now() >= deadline {
            return Err("timed out".to_owned());
        }
        thread::sleep(POLL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_cookies_are_hex_of_the_right_length_and_differ() -> Result<(), SandboxError> {
        let a = random_hex(16)?;
        let b = random_hex(16)?;
        assert_eq!(a.len(), 32);
        assert!(
            a.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        assert_ne!(a, b);
        Ok(())
    }

    #[test]
    fn programs_are_found_only_when_executable() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir()?;
        let plain = dir.path().join("plain-tool");
        fs::write(&plain, "x")?;
        fs::set_permissions(&plain, fs::Permissions::from_mode(0o644))?;
        let runnable = dir.path().join("run-tool");
        fs::write(&runnable, "x")?;
        fs::set_permissions(&runnable, fs::Permissions::from_mode(0o755))?;
        let path = std::env::join_paths([dir.path()])?;

        assert!(find_in(&path, "run-tool").is_ok());
        assert!(matches!(
            find_in(&path, "plain-tool"),
            Err(SandboxError::Tool { .. })
        ));
        assert!(matches!(
            find_in(&path, "absent-tool"),
            Err(SandboxError::Tool {
                tool: "absent-tool",
                ..
            })
        ));
        Ok(())
    }
}
