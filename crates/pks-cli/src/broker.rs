//! The host side of the brokers (Phase 12): asks the user, then performs the
//! action. The sandbox never runs these programs itself.
//!
//! Every request is answered on the terminal running `pumpkin-shell ide`.
//! Without a terminal the answer is no, so a background run cannot approve a
//! push or open a page.

use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use pks_sandbox::linux::broker::{Handler, Request};

/// Performs brokered actions for one repo.
pub struct Host {
    repo: PathBuf,
}

impl Host {
    #[must_use]
    pub fn new(repo: &Path) -> Self {
        Self {
            repo: repo.to_path_buf(),
        }
    }
}

/// Asks the user on the terminal. Anything but `y` or `yes` is a no, and so
/// is a missing terminal.
fn ask(question: &str) -> bool {
    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        eprintln!("broker: {question} There is no terminal to ask on, so it is denied.");
        return false;
    }
    eprint!("broker: {question} Allow? [y/N] ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    if stdin.lock().read_line(&mut line).unwrap_or(0) == 0 {
        return false;
    }
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

impl Handler for Host {
    fn approve(&self, request: &Request) -> bool {
        match request {
            Request::Open { url } => ask(&format!("the IDE asks to open {url} in your browser.")),
            Request::Push { remote, branch } => ask(&format!(
                "the IDE asks to push branch {branch} to remote {remote} of {}.",
                self.repo.display()
            )),
        }
    }

    fn open_url(&self, url: &str) -> Result<(), String> {
        // The URL was checked to start with http:// or https://, so it cannot
        // be read as an option. It is passed as one argument, not in a shell.
        let status = Command::new("xdg-open")
            .arg(url)
            .status()
            .map_err(|e| format!("cannot run xdg-open: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("xdg-open failed ({status})"))
        }
    }

    fn push(&self, remote: &str, branch: &str) -> Result<(), String> {
        // The names were checked: they cannot start with `-` or contain `..`.
        // No prompt for credentials: a missing login fails instead of hanging.
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.repo)
            .args(["push", remote, branch])
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()
            .map_err(|e| format!("cannot run git: {e}"))?;
        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let first = stderr.lines().next().unwrap_or("git push failed");
            Err(format!("git push failed: {first}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs git with a fixed identity, so commits work on any machine.
    fn git(dir: &Path, args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
        let status = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .env("GIT_AUTHOR_NAME", "test")
            .env("GIT_AUTHOR_EMAIL", "test@example.invalid")
            .env("GIT_COMMITTER_NAME", "test")
            .env("GIT_COMMITTER_EMAIL", "test@example.invalid")
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("git {args:?} failed").into())
        }
    }

    #[test]
    fn without_a_terminal_every_request_is_denied() {
        // The test runner's stdin is not a terminal.
        let host = Host::new(Path::new("/nonexistent"));
        assert!(!host.approve(&Request::Open {
            url: "https://a.example/".to_owned()
        }));
        assert!(!host.approve(&Request::Push {
            remote: "origin".to_owned(),
            branch: "main".to_owned()
        }));
    }

    /// The approved push really runs: a commit goes to a local bare remote.
    #[test]
    fn an_approved_push_sends_the_branch_to_the_remote() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let remote = root.path().join("remote.git");
        let repo = root.path().join("repo");
        std::fs::create_dir_all(&repo)?;
        git(
            root.path(),
            &["init", "--bare", "-q", remote.to_str().ok_or("path")?],
        )?;
        git(&repo, &["init", "-q", "-b", "main"])?;
        std::fs::write(repo.join("README.md"), "hello\n")?;
        git(&repo, &["add", "README.md"])?;
        git(&repo, &["commit", "-q", "-m", "first"])?;
        git(
            &repo,
            &["remote", "add", "origin", remote.to_str().ok_or("path")?],
        )?;

        let host = Host::new(&repo);
        host.push("origin", "main")
            .map_err(|e| format!("push failed: {e}"))?;

        let refs = Command::new("git")
            .arg("-C")
            .arg(&remote)
            .args(["show-ref", "refs/heads/main"])
            .output()?;
        assert!(refs.status.success(), "the remote has no main branch");
        Ok(())
    }

    #[test]
    fn a_push_to_a_remote_that_does_not_exist_reports_the_reason()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let repo = root.path().join("repo");
        std::fs::create_dir_all(&repo)?;
        git(&repo, &["init", "-q", "-b", "main"])?;
        std::fs::write(repo.join("README.md"), "hello\n")?;
        git(&repo, &["add", "README.md"])?;
        git(&repo, &["commit", "-q", "-m", "first"])?;
        let error = Host::new(&repo).push("nowhere", "main");
        assert!(error.is_err());
        assert!(error.is_err_and(|message| message.starts_with("git push failed")));
        Ok(())
    }
}
