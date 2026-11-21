//! The host side of the brokers (PRD §6.1, Phase 12). The sandbox asks for an
//! action, and the host decides whether to perform it.
//!
//! Wire format: one request line per connection, fields separated by tabs.
//! - `open<TAB><url>`
//! - `push<TAB><remote><TAB><branch>`
//!
//! The reply is one line: `ok<TAB><detail>`, `denied<TAB><detail>` or
//! `error<TAB><detail>`. Every field is checked here before anything is
//! shown to the user or passed to a program.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Longest request line accepted. A longer line is refused, not cut short.
const MAX_LINE: u64 = 4096;
/// Longest URL accepted.
const MAX_URL: usize = 2048;

/// A validated request from the sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Open this URL in the host's browser.
    Open { url: String },
    /// Push `branch` to `remote` from the repo, on the host.
    Push { remote: String, branch: String },
}

/// The user's answer to a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Perform the action (open the page, push the branch).
    Allow,
    /// Copy the link to the host's clipboard instead of opening it. Only
    /// offered for `open`.
    CopyOnly,
    /// Do nothing.
    Deny,
}

/// What the host does with a request. The CLI implements this with a real
/// prompt and real programs; tests implement it with fakes.
pub trait Handler {
    /// Asks the user.
    fn approve(&self, request: &Request) -> Decision;
    /// Copies the URL to the host's clipboard.
    fn copy_url(&self, url: &str) -> Result<(), String>;
    /// Opens the URL in the host's browser.
    fn open_url(&self, url: &str) -> Result<(), String>;
    /// Pushes the branch to the remote in the repo.
    fn push(&self, remote: &str, branch: &str) -> Result<(), String>;
}

/// Parses and checks one request line (without its newline).
///
/// # Errors
/// Returns the reason when the line is not a request or a field fails its
/// check.
pub fn parse(line: &str) -> Result<Request, String> {
    let mut fields = line.split('\t');
    match fields.next() {
        Some("open") => {
            let url = fields.next().ok_or("open needs a URL")?;
            if fields.next().is_some() {
                return Err("open takes one field".to_owned());
            }
            check_url(url)?;
            Ok(Request::Open {
                url: url.to_owned(),
            })
        }
        Some("push") => {
            let remote = fields.next().ok_or("push needs a remote")?;
            let branch = fields.next().ok_or("push needs a branch")?;
            if fields.next().is_some() {
                return Err("push takes two fields".to_owned());
            }
            check_name("remote", remote, 64, false)?;
            check_name("branch", branch, 200, true)?;
            Ok(Request::Push {
                remote: remote.to_owned(),
                branch: branch.to_owned(),
            })
        }
        Some(other) => Err(format!("unknown request {other:?}")),
        None => Err("empty request".to_owned()),
    }
}

/// Only web addresses. `file:`, `javascript:` and anything with a space,
/// tab or control character are refused.
fn check_url(url: &str) -> Result<(), String> {
    if url.len() > MAX_URL {
        return Err(format!("the URL is longer than {MAX_URL} bytes"));
    }
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err("only http and https URLs can be opened".to_owned());
    }
    if !url.bytes().all(|b| b.is_ascii_graphic()) {
        return Err("the URL contains a space or a control character".to_owned());
    }
    Ok(())
}

/// A remote or branch name: letters, digits and `-_./`, never starting with
/// `-` (which a program would read as an option) and never containing `..`.
fn check_name(what: &str, name: &str, max: usize, allow_slash: bool) -> Result<(), String> {
    if name.is_empty() || name.len() > max {
        return Err(format!("the {what} name must be 1 to {max} characters"));
    }
    if name.starts_with('-') || name.contains("..") {
        return Err(format!("the {what} name {name:?} is not allowed"));
    }
    let ok = name.bytes().all(|b| {
        b.is_ascii_alphanumeric()
            || b == b'-'
            || b == b'_'
            || b == b'.'
            || (allow_slash && b == b'/')
    });
    if !ok {
        return Err(format!(
            "the {what} name {name:?} has characters that are not allowed"
        ));
    }
    Ok(())
}

/// Handles one request line and returns the reply line (without newline).
#[must_use]
pub fn respond(line: &str, handler: &dyn Handler) -> String {
    let request = match parse(line) {
        Ok(request) => request,
        Err(reason) => return format!("error\t{reason}"),
    };
    let (result, done) = match (handler.approve(&request), &request) {
        (Decision::Deny, _) | (Decision::CopyOnly, Request::Push { .. }) => {
            return "denied\tthe user did not approve it".to_owned();
        }
        (Decision::CopyOnly, Request::Open { url }) => (handler.copy_url(url), "copied"),
        (Decision::Allow, Request::Open { url }) => (handler.open_url(url), "done"),
        (Decision::Allow, Request::Push { remote, branch }) => {
            (handler.push(remote, branch), "done")
        }
    };
    match result {
        Ok(()) => format!("ok\t{done}"),
        Err(reason) => format!("error\t{reason}"),
    }
}

/// Serves requests on `listener` until `stop` is set. Requests are handled one
/// at a time, because each may wait for the user.
///
/// # Errors
/// Fails when the listener cannot be set up.
pub fn serve(
    listener: UnixListener,
    handler: Arc<dyn Handler + Send + Sync>,
    stop: Arc<AtomicBool>,
) -> std::io::Result<()> {
    listener.set_nonblocking(true)?;
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => {
                let _ = stream.set_nonblocking(false);
                let _ = answer(stream, handler.as_ref());
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn answer(mut stream: UnixStream, handler: &dyn Handler) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut line = String::new();
    let read = BufReader::new(stream.try_clone()?.take(MAX_LINE + 1)).read_line(&mut line)?;
    let reply = if read as u64 > MAX_LINE {
        "error\tthe request is too long".to_owned()
    } else {
        respond(line.trim_end_matches(['\r', '\n']), handler)
    };
    stream.write_all(reply.as_bytes())?;
    stream.write_all(b"\n")
}

/// Sends one request line from inside the sandbox and returns the reply line.
/// The host may take a while to answer (the user is asked), so the wait is
/// long.
///
/// # Errors
/// Fails when the broker socket cannot be reached or no reply comes.
pub fn request(socket: &std::path::Path, line: &str) -> Result<String, String> {
    let mut stream =
        UnixStream::connect(socket).map_err(|e| format!("the broker is not reachable: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(300)))
        .map_err(|e| format!("cannot set a timeout: {e}"))?;
    stream
        .write_all(format!("{line}\n").as_bytes())
        .map_err(|e| format!("cannot send the request: {e}"))?;
    let mut reply = String::new();
    BufReader::new(stream)
        .read_line(&mut reply)
        .map_err(|e| format!("no reply from the broker: {e}"))?;
    Ok(reply.trim_end_matches(['\r', '\n']).to_owned())
}

/// Host side of the callback relay (Phase 12, OAuth sign-in). Each connection
/// to the host's loopback port is passed to the in-sandbox agent's socket, and
/// from there to the IDE's own listener on the same port.
///
/// # Errors
/// Fails when the listener cannot be set up.
pub fn callback_host(
    listener: std::net::TcpListener,
    agent_socket: std::path::PathBuf,
    stop: Arc<AtomicBool>,
) -> std::io::Result<()> {
    listener.set_nonblocking(true)?;
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((tcp, _)) => {
                let _ = tcp.set_nonblocking(false);
                // A connection the agent refuses is dropped; the sign-in then
                // fails visibly in the browser, not silently.
                if let Ok(unix) = UnixStream::connect(&agent_socket) {
                    std::thread::spawn(move || crate::linux::relay::pipe(tcp, unix));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// The in-sandbox side of the callback relay. Listens on `socket` (in the
/// shared broker directory) and passes each connection to `target`, the IDE's
/// listener inside the sandbox. Runs until the sandbox ends.
///
/// # Errors
/// Fails when the socket cannot be created.
pub fn sandbox_callback(
    socket: &std::path::Path,
    target: std::net::SocketAddr,
) -> std::io::Result<()> {
    // A socket left by an earlier run is replaced.
    let _ = std::fs::remove_file(socket);
    let listener = UnixListener::bind(socket)?;
    for stream in listener.incoming() {
        let Ok(unix) = stream else { continue };
        std::thread::spawn(move || {
            // The IDE may not be listening yet; the host then sees the
            // connection close.
            if let Ok(tcp) = std::net::TcpStream::connect(target) {
                crate::linux::relay::pipe(tcp, unix);
            }
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// Records what the host was asked to do.
    struct Fake {
        allow: bool,
        calls: RefCell<Vec<String>>,
    }

    impl Fake {
        fn new(allow: bool) -> Self {
            Self {
                allow,
                calls: RefCell::new(Vec::new()),
            }
        }
    }

    impl Handler for Fake {
        fn approve(&self, request: &Request) -> Decision {
            self.calls.borrow_mut().push(format!("approve {request:?}"));
            if self.allow {
                Decision::Allow
            } else {
                Decision::Deny
            }
        }
        fn copy_url(&self, url: &str) -> Result<(), String> {
            self.calls.borrow_mut().push(format!("copy {url}"));
            Ok(())
        }
        fn open_url(&self, url: &str) -> Result<(), String> {
            self.calls.borrow_mut().push(format!("open {url}"));
            Ok(())
        }
        fn push(&self, remote: &str, branch: &str) -> Result<(), String> {
            self.calls
                .borrow_mut()
                .push(format!("push {remote} {branch}"));
            Ok(())
        }
    }

    #[test]
    fn valid_open_and_push_requests_are_parsed() {
        assert_eq!(
            parse("open\thttps://accounts.example.com/oauth?x=1"),
            Ok(Request::Open {
                url: "https://accounts.example.com/oauth?x=1".to_owned()
            })
        );
        assert_eq!(
            parse("push\torigin\tfeature/login-1"),
            Ok(Request::Push {
                remote: "origin".to_owned(),
                branch: "feature/login-1".to_owned()
            })
        );
    }

    #[test]
    fn urls_that_are_not_web_addresses_or_contain_spaces_are_refused() {
        for bad in [
            "open\tfile:///etc/passwd",
            "open\tjavascript:alert(1)",
            "open\thttps://a.example/ with space",
            "open\thttps://a.example/\u{7}",
            "open\t",
            "open\thttps://a.example\textra",
        ] {
            assert!(parse(bad).is_err(), "accepted {bad:?}");
        }
        let long = format!("open\thttps://a.example/{}", "x".repeat(MAX_URL));
        assert!(parse(&long).is_err());
    }

    #[test]
    fn remote_and_branch_names_cannot_become_options_or_paths() {
        for bad in [
            "push\t-o\tmain",
            "push\torigin\t--force",
            "push\torigin\t../secret",
            "push\torigin\ta b",
            "push\t\tmain",
            "push\torigin\t",
            "push\torigin\tmain\textra",
            "pull\torigin\tmain",
            "",
        ] {
            assert!(parse(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn a_denied_request_performs_nothing() {
        let fake = Fake::new(false);
        let reply = respond("open\thttps://a.example/", &fake);
        assert!(reply.starts_with("denied"), "{reply}");
        assert_eq!(fake.calls.borrow().len(), 1, "only the question was asked");
    }

    #[test]
    fn an_approved_open_and_push_are_performed_once() {
        let fake = Fake::new(true);
        assert_eq!(
            respond("open\thttps://a.example/", &fake),
            "ok\tdone".to_owned()
        );
        assert_eq!(respond("push\torigin\tmain", &fake), "ok\tdone".to_owned());
        let calls = fake.calls.borrow();
        assert!(
            calls.contains(&"open https://a.example/".to_owned()),
            "{calls:?}"
        );
        assert!(calls.contains(&"push origin main".to_owned()), "{calls:?}");
    }

    #[test]
    fn a_refused_line_is_answered_without_asking_the_user() {
        let fake = Fake::new(true);
        assert!(respond("open\tfile:///x", &fake).starts_with("error"));
        assert!(fake.calls.borrow().is_empty());
    }

    #[test]
    fn requests_travel_over_a_unix_socket() -> std::io::Result<()> {
        use std::io::{BufRead, BufReader};
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("broker.sock");
        let listener = UnixListener::bind(&path)?;
        let stop = Arc::new(AtomicBool::new(false));
        let handler: Arc<dyn Handler + Send + Sync> = Arc::new(FakeSync);
        let flag = Arc::clone(&stop);
        let server = std::thread::spawn(move || serve(listener, handler, flag));

        let mut client = UnixStream::connect(&path)?;
        client.write_all(b"open\thttps://a.example/\n")?;
        let mut reply = String::new();
        BufReader::new(&client).read_line(&mut reply)?;
        assert_eq!(reply.trim_end(), "ok\tdone");

        stop.store(true, Ordering::Relaxed);
        let _ = server.join();
        Ok(())
    }

    /// `Fake` without interior mutability, so it can be shared across threads.
    struct FakeSync;
    impl Handler for FakeSync {
        fn approve(&self, _: &Request) -> Decision {
            Decision::Allow
        }
        fn copy_url(&self, _: &str) -> Result<(), String> {
            Ok(())
        }
        fn open_url(&self, _: &str) -> Result<(), String> {
            Ok(())
        }
        fn push(&self, _: &str, _: &str) -> Result<(), String> {
            Ok(())
        }
    }

    #[test]
    fn an_overlong_line_is_refused() -> std::io::Result<()> {
        use std::io::{BufRead, BufReader};
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("broker.sock");
        let listener = UnixListener::bind(&path)?;
        let stop = Arc::new(AtomicBool::new(false));
        let handler: Arc<dyn Handler + Send + Sync> = Arc::new(FakeSync);
        let flag = Arc::clone(&stop);
        let server = std::thread::spawn(move || serve(listener, handler, flag));

        let mut client = UnixStream::connect(&path)?;
        let long = format!("open\thttps://a.example/{}\n", "x".repeat(8000));
        // The server may close before the whole line is sent; the reply is
        // what matters.
        let _ = client.write_all(long.as_bytes());
        let mut reply = String::new();
        BufReader::new(&client).read_line(&mut reply)?;
        assert!(reply.starts_with("error"), "{reply}");

        stop.store(true, Ordering::Relaxed);
        let _ = server.join();
        Ok(())
    }
}
