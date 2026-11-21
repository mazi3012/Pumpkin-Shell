//! The host side of the brokers (Phase 12): asks the user, then performs the
//! action. The sandbox never runs these programs itself.
//!
//! Every request is answered on the terminal running `pumpkin-shell ide`.
//! Without a terminal the answer is no, so a background run cannot approve a
//! push or open a page.
//!
//! A link can be opened or copied to the host clipboard. The copy is host to
//! host and needs the user's answer, so the sandbox clipboard is never used.
//! The same request asked again within a minute is refused without a second
//! prompt, so a retrying IDE does not stack up prompts.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use pks_sandbox::linux::broker::{Decision, Handler, Request};

use crate::ask;

/// How long an answered request is remembered, so an identical one is refused
/// without asking again.
const REPEAT_WINDOW: Duration = Duration::from_secs(60);

/// Performs brokered actions for one repo.
/// Writes one log entry: rule, target and verdict. Never the page's full URL
/// or any text the sandbox sent beyond these fields.
pub type Record = std::sync::Arc<dyn Fn(&str, &str, &str) + Send + Sync>;

/// The scheme and host of a URL, without its path or query, which can carry
/// login state. `https://app.example/x?code=1` becomes `https://app.example`.
fn origin_of(url: &str) -> String {
    let (scheme, rest) = url.split_once("://").unwrap_or(("", url));
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    format!("{scheme}://{host}")
}

pub struct Host {
    repo: PathBuf,
    /// Writes decisions to the session log.
    record: Record,
    /// The host desktop the popups are shown on. `None` shows nothing and
    /// refuses every request.
    desktop: Option<std::ffi::OsString>,
    /// When each recent request was answered, by request text.
    answered: Mutex<HashMap<String, Instant>>,
    /// Whether `xclip` is installed, so copy is offered.
    clipboard: bool,
}

impl Host {
    #[must_use]
    pub fn new(repo: &Path, record: Record) -> Self {
        Self {
            repo: repo.to_path_buf(),
            record,
            desktop: std::env::var_os("DISPLAY"),
            answered: Mutex::new(HashMap::new()),
            clipboard: Command::new("xclip")
                .arg("-version")
                .output()
                .is_ok_and(|out| out.status.success()),
        }
    }

    /// A host with no desktop, for tests: nothing is shown, requests are refused.
    #[cfg(test)]
    fn without_desktop(repo: &Path) -> Self {
        Self {
            desktop: None,
            record: std::sync::Arc::new(|_, _, _| {}),
            ..Self::new(repo, std::sync::Arc::new(|_, _, _| {}))
        }
    }

    /// Whether this request was answered a moment ago.
    fn answered_recently(&self, key: &str) -> bool {
        let Ok(mut answered) = self.answered.lock() else {
            return false;
        };
        answered.retain(|_, when| when.elapsed() < REPEAT_WINDOW);
        answered.contains_key(key)
    }

    fn remember(&self, key: &str) {
        if let Ok(mut answered) = self.answered.lock() {
            answered.insert(key.to_owned(), Instant::now());
        }
    }
}

/// Copies `text` to the clipboard with `xclip`, as a separate program with the
/// text on its input.
fn copy_to_clipboard(text: &str) -> Result<(), String> {
    let mut child = Command::new("xclip")
        .args(["-selection", "clipboard"])
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot run xclip: {e}"))?;
    if let Some(mut input) = child.stdin.take() {
        input
            .write_all(text.as_bytes())
            .map_err(|e| format!("cannot write to xclip: {e}"))?;
    }
    let status = child.wait().map_err(|e| format!("xclip failed: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("xclip failed ({status})"))
    }
}

impl Handler for Host {
    fn approve(&self, request: &Request) -> Decision {
        if let Request::Refused { .. } = request {
            return Decision::Deny;
        }
        let key = match request {
            Request::Open { url } => format!("open {url}"),
            Request::Push { remote, branch } => format!("push {remote} {branch}"),
            Request::Refused { .. } => unreachable!("refusals are not approved"),
        };
        if self.answered_recently(&key) {
            eprintln!("broker: the same request was just answered; not asking again.");
            return Decision::Deny;
        }
        let decision = match request {
            Request::Open { url } => {
                let open = "Open in browser";
                let copy = "Copy link";
                let deny = "Deny";
                let options: Vec<&str> = if self.clipboard {
                    vec![open, copy, deny]
                } else {
                    vec![open, deny]
                };
                let text = format!("Kiro wants to open this link:\n\n{url}");
                match ask::choose(
                    self.desktop.clone(),
                    "Pumpkin-Shell: open a link?",
                    &text,
                    &options,
                )
                .as_deref()
                {
                    Some(choice) if choice == open => Decision::Allow,
                    Some(choice) if choice == copy => Decision::CopyOnly,
                    _ => Decision::Deny,
                }
            }
            Request::Refused { .. } => Decision::Deny,
            Request::Push { remote, branch } => {
                let text = format!(
                    "Kiro wants to push branch {branch} to remote {remote} of:\n{}",
                    self.repo.display()
                );
                if ask::confirm(
                    self.desktop.clone(),
                    "Pumpkin-Shell: push to git?",
                    &text,
                    "Push",
                    "Deny",
                ) {
                    Decision::Allow
                } else {
                    Decision::Deny
                }
            }
        };
        self.remember(&key);
        let verdict = match decision {
            Decision::Allow => "allow",
            Decision::CopyOnly => "copy",
            Decision::Deny => "deny",
        };
        match request {
            Request::Open { url } => (self.record)("BROKER-OPEN", &origin_of(url), verdict),
            Request::Push { remote, branch } => {
                (self.record)("BROKER-PUSH", &format!("{remote} {branch}"), verdict)
            }
            Request::Refused { .. } => {}
        }
        decision
    }

    fn copy_url(&self, url: &str) -> Result<(), String> {
        copy_to_clipboard(url)
    }

    fn warn(&self, message: &str) {
        (self.record)("BROKER-REFUSED", "git push", "blocked");
        eprintln!("broker: {message}");
        ask::notice(
            self.desktop.clone(),
            "Pumpkin-Shell: blocked",
            &format!("Kiro tried a command that is blocked:\n\n{message}"),
        );
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

    fn quiet() -> Record {
        std::sync::Arc::new(|_, _, _| {})
    }

    #[test]
    fn a_link_is_logged_by_its_origin_only() {
        assert_eq!(
            origin_of("https://app.kiro.dev/signin?state=abc&code=secret#frag"),
            "https://app.kiro.dev"
        );
        assert_eq!(
            origin_of("http://localhost:3128/callback?code=x"),
            "http://localhost:3128"
        );
    }

    #[test]
    fn a_refused_open_is_logged_as_deny_with_the_origin() {
        let entries = std::sync::Arc::new(Mutex::new(Vec::<String>::new()));
        let sink = std::sync::Arc::clone(&entries);
        let record: Record = std::sync::Arc::new(move |rule, target, verdict| {
            if let Ok(mut list) = sink.lock() {
                list.push(format!("{rule} {target} {verdict}"));
            }
        });
        let host = Host {
            record,
            ..Host::without_desktop(Path::new("/nonexistent"))
        };
        let url = "https://app.kiro.dev/signin?code=secret";
        assert_eq!(
            host.approve(&Request::Open {
                url: url.to_owned()
            }),
            Decision::Deny
        );
        let logged = entries.lock().map(|list| list.clone()).unwrap_or_default();
        assert_eq!(
            logged,
            vec!["BROKER-OPEN https://app.kiro.dev deny".to_owned()]
        );
        assert!(
            !logged.join("").contains("secret"),
            "the query leaked into the log"
        );
    }

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
    fn without_a_desktop_every_request_is_denied() {
        // The test runner's stdin is not a terminal.
        let host = Host::without_desktop(Path::new("/nonexistent"));
        let open = Request::Open {
            url: "https://a.example/".to_owned(),
        };
        let push = Request::Push {
            remote: "origin".to_owned(),
            branch: "main".to_owned(),
        };
        assert_eq!(host.approve(&open), Decision::Deny);
        assert_eq!(host.approve(&push), Decision::Deny);
    }

    #[test]
    fn a_request_answered_a_moment_ago_is_not_asked_again() {
        let host = Host::without_desktop(Path::new("/nonexistent"));
        let open = Request::Open {
            url: "https://a.example/".to_owned(),
        };
        // The first answer is "no" (no terminal); it is still remembered, so
        // the repeat is refused at once with no second question.
        assert_eq!(host.approve(&open), Decision::Deny);
        assert!(host.answered_recently("open https://a.example/"));
        assert_eq!(host.approve(&open), Decision::Deny);
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

        let host = Host::new(&repo, quiet());
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
        let error = Host::new(&repo, quiet()).push("nowhere", "main");
        assert!(error.is_err_and(|message| message.starts_with("git push failed")));
        Ok(())
    }
}
