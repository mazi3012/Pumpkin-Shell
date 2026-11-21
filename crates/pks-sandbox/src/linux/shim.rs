//! The programs `xdg-open` and `git` as they appear inside the sandbox
//! (Phase 12). The Pumpkin-Shell binary is mounted over each of these paths,
//! and it acts on the name it was started under.
//!
//! - `xdg-open URL` asks the host to open the URL, after the user agrees.
//! - `git push REMOTE BRANCH` asks the host to push, after the user agrees.
//!   Any other `push` form (options, `-C`, a push that is not the subcommand)
//!   is refused, so a push can only happen through the approval prompt.
//! - Every other `git` command runs the real git, which is mounted at
//!   `REAL_GIT_IN`.

use std::ffi::OsString;
use std::os::unix::process::CommandExt;
use std::process::{Command, ExitCode};

use super::broker;
use super::bwrap::{BROKER_REQUEST_IN, REAL_GIT_IN};

/// Exit code for a request the host refused or could not perform.
const EXIT_FAILED: u8 = 1;
/// Exit code for a command that is not allowed here.
const EXIT_REFUSED: u8 = 2;

/// Runs the wrapper for `program`, with the full argument list (argv[0]
/// first).
pub fn run(program: &str, args: &[OsString]) -> ExitCode {
    let mut rest = Vec::with_capacity(args.len());
    for arg in args.iter().skip(1) {
        match arg.to_str() {
            Some(text) => rest.push(text.to_owned()),
            None => {
                eprintln!("{program}: arguments must be valid text");
                return ExitCode::from(EXIT_REFUSED);
            }
        }
    }
    match program {
        "xdg-open" => open(&rest),
        "git" => git(&rest),
        other => {
            eprintln!("pumpkin-shell: cannot act as {other}");
            ExitCode::from(EXIT_REFUSED)
        }
    }
}

fn open(args: &[String]) -> ExitCode {
    let Some(url) = args.iter().find(|arg| !arg.starts_with('-')) else {
        eprintln!("xdg-open: give a URL to open");
        return ExitCode::from(EXIT_REFUSED);
    };
    send(&format!("open\t{url}"))
}

fn git(args: &[String]) -> ExitCode {
    let pushes = args.iter().any(|arg| arg == "push");
    if !pushes {
        return exec_real_git(args);
    }
    if args.first().map(String::as_str) != Some("push") {
        eprintln!("git: push only as `git push REMOTE BRANCH`; other forms are not allowed");
        return ExitCode::from(EXIT_REFUSED);
    }
    let fields = &args[1..];
    if fields.len() != 2 || fields.iter().any(|arg| arg.starts_with('-')) {
        let forced = fields
            .iter()
            .any(|arg| arg == "-f" || arg.starts_with("--force"));
        let message = if forced {
            "blocked: a forced push is not allowed through the broker"
        } else {
            "blocked: push takes a remote and a branch and no options: git push REMOTE BRANCH"
        };
        // The host shows a warning on the desktop; the terminal gets the same text.
        let _ = broker::request(
            std::path::Path::new(BROKER_REQUEST_IN),
            &format!("refuse\t{message}"),
        );
        eprintln!("git: {message}");
        return ExitCode::from(EXIT_REFUSED);
    }
    send(&format!("push\t{}\t{}", fields[0], fields[1]))
}

/// Sends a request to the host and prints what it said.
fn send(line: &str) -> ExitCode {
    let reply = match broker::request(std::path::Path::new(BROKER_REQUEST_IN), line) {
        Ok(reply) => reply,
        Err(reason) => {
            eprintln!("pumpkin-shell: {reason}");
            return ExitCode::from(EXIT_FAILED);
        }
    };
    let (status, detail) = reply.split_once('\t').unwrap_or((reply.as_str(), ""));
    if status == "ok" {
        eprintln!("pumpkin-shell: done");
        ExitCode::SUCCESS
    } else {
        eprintln!("pumpkin-shell: {detail}");
        ExitCode::from(EXIT_FAILED)
    }
}

/// Replaces this process with the real git, under the name `git`.
fn exec_real_git(args: &[String]) -> ExitCode {
    let error = Command::new(REAL_GIT_IN).arg0("git").args(args).exec();
    eprintln!("git: cannot run the real git: {error}");
    ExitCode::from(127)
}
