//! `pumpkin-shell dashboard`: a live, read-only page on this machine (PRD
//! FR-DASH, Phase 19).
//!
//! The server listens on 127.0.0.1 only. It answers GET requests only. It
//! refuses any `Host` header other than the loopback names, which stops a
//! website from using a DNS name to reach it (DNS rebinding). It sends a
//! strict content security policy and loads nothing from outside.

mod summary;

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use summary::{Checker, snapshot};

/// The port used when none is given. It is not one of Pumpkin-Shell's own
/// ports (proxy 3129, mirror 3130, callback 3128).
pub const DEFAULT_PORT: u16 = 8765;

const INDEX: &str = include_str!("index.html");
const STYLE: &str = include_str!("style.css");
const SCRIPT: &str = include_str!("app.js");
const ICON: &str = include_str!("icon.svg");

/// Largest request head accepted, in bytes.
const MAX_HEAD: usize = 8192;
/// Longest time to wait for a client to send its request.
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// The policy sent with every page. Only this origin may load anything, and
/// no inline script or style runs.
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/// Runs the dashboard until the process is stopped.
pub fn run(port: u16) -> ExitCode {
    let Some(data) = pks_core::paths::data_dir(&pks_core::paths::process_env) else {
        eprintln!("dashboard: cannot find your data directory (is HOME set?)");
        return ExitCode::from(2);
    };
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let listener = match TcpListener::bind(address) {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!(
                "dashboard: cannot listen on {address}: {error}. Try --port with another number"
            );
            return ExitCode::from(2);
        }
    };
    let port = listener.local_addr().map_or(port, |a| a.port());
    println!("Pumpkin-Shell Watch: http://127.0.0.1:{port}/ (read-only; stop with Ctrl+C)");
    let state = Arc::new(Mutex::new(Checker::new(data)));
    let stop = Arc::new(AtomicBool::new(false));
    match serve(listener, state, port, stop) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("dashboard: {error}");
            ExitCode::from(2)
        }
    }
}

/// Starts the dashboard on a background thread and returns the port it
/// listens on. It runs until the process exits. Used by `kiro` and `ide`, so
/// the page is up while the IDE is open.
///
/// # Errors
/// Fails when the data directory is unknown or the port is in use.
pub fn start_in_background(port: u16) -> Result<u16, String> {
    let Some(data) = pks_core::paths::data_dir(&pks_core::paths::process_env) else {
        return Err("cannot find your data directory (is HOME set?)".to_owned());
    };
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let listener = TcpListener::bind(address)
        .map_err(|error| format!("cannot listen on {address}: {error}"))?;
    let port = listener.local_addr().map_or(port, |a| a.port());
    let state = Arc::new(Mutex::new(Checker::new(data)));
    let stop = Arc::new(AtomicBool::new(false));
    std::thread::spawn(move || {
        let _ = serve(listener, state, port, stop);
    });
    Ok(port)
}

/// Answers requests until `stop` is set. Each connection gets its own thread,
/// so one slow client does not hold up the page.
///
/// # Errors
/// Fails when the listener stops accepting.
pub fn serve(
    listener: TcpListener,
    state: Arc<Mutex<Checker>>,
    port: u16,
    stop: Arc<AtomicBool>,
) -> io::Result<()> {
    listener.set_nonblocking(true)?;
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => {
                let _ = stream.set_nonblocking(false);
                let state = Arc::clone(&state);
                std::thread::spawn(move || {
                    let _ = answer(stream, &state, port);
                });
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Reads one request head, up to the blank line. `None` when it is too large.
fn read_head(stream: &mut TcpStream) -> io::Result<Option<Vec<u8>>> {
    let mut head = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    loop {
        if stream.read(&mut byte)? == 0 {
            return Ok(Some(head));
        }
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            return Ok(Some(head));
        }
        if head.len() > MAX_HEAD {
            return Ok(None);
        }
    }
}

/// A reply: status, type, body and any extra header.
struct Reply {
    status: u16,
    reason: &'static str,
    content_type: &'static str,
    body: Vec<u8>,
    allow: Option<&'static str>,
}

impl Reply {
    fn text(status: u16, reason: &'static str, message: &str) -> Self {
        Self {
            status,
            reason,
            content_type: "text/plain; charset=utf-8",
            body: message.as_bytes().to_vec(),
            allow: None,
        }
    }

    fn asset(content_type: &'static str, body: &str) -> Self {
        Self {
            status: 200,
            reason: "OK",
            content_type,
            body: body.as_bytes().to_vec(),
            allow: None,
        }
    }
}

/// The loopback names a request may use. Anything else is refused.
fn host_allowed(host: &str, port: u16) -> bool {
    host == format!("127.0.0.1:{port}") || host == format!("localhost:{port}")
}

/// The header value of `name`, case-insensitively, from a request head.
fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim().eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

/// Decides what to answer for one request. Pure apart from reading the logs.
fn route(head: &str, port: u16, state: &Mutex<Checker>, now: u64) -> Reply {
    let mut parts = head.lines().next().unwrap_or("").split(' ');
    let (Some(method), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next())
    else {
        return Reply::text(400, "Bad Request", "the request line is malformed");
    };
    if !version.starts_with("HTTP/1.") {
        return Reply::text(400, "Bad Request", "only HTTP/1.x is accepted");
    }
    match header(head, "host") {
        Some(host) if host_allowed(host, port) => {}
        _ => return Reply::text(403, "Forbidden", "this dashboard answers only on 127.0.0.1"),
    }
    if method != "GET" {
        let mut reply = Reply::text(405, "Method Not Allowed", "the dashboard is read-only");
        reply.allow = Some("GET");
        return reply;
    }
    let path = target.split('?').next().unwrap_or("/");
    match path {
        "/" | "/index.html" => Reply::asset("text/html; charset=utf-8", INDEX),
        "/style.css" => Reply::asset("text/css; charset=utf-8", STYLE),
        "/app.js" => Reply::asset("text/javascript; charset=utf-8", SCRIPT),
        "/icon.svg" => Reply::asset("image/svg+xml", ICON),
        "/api/snapshot" => {
            let mut checker = state.lock().unwrap_or_else(PoisonError::into_inner);
            let data = snapshot(&mut checker, now);
            match serde_json::to_vec(&data) {
                Ok(body) => Reply {
                    status: 200,
                    reason: "OK",
                    content_type: "application/json",
                    body,
                    allow: None,
                },
                Err(_) => Reply::text(500, "Internal Server Error", "cannot encode the snapshot"),
            }
        }
        _ => Reply::text(404, "Not Found", "no such page"),
    }
}

/// Reads one request, answers it, and closes the connection.
fn answer(mut stream: TcpStream, state: &Mutex<Checker>, port: u16) -> io::Result<()> {
    stream.set_read_timeout(Some(READ_TIMEOUT))?;
    let Some(raw) = read_head(&mut stream)? else {
        return write_reply(
            &mut stream,
            &Reply::text(
                431,
                "Request Header Fields Too Large",
                "the request is too large",
            ),
        );
    };
    let head = String::from_utf8_lossy(&raw).into_owned();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    let reply = route(&head, port, state, now);
    write_reply(&mut stream, &reply)
}

fn write_reply(stream: &mut TcpStream, reply: &Reply) -> io::Result<()> {
    let mut head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: {CSP}\r\nConnection: close\r\n",
        reply.status,
        reply.reason,
        reply.content_type,
        reply.body.len(),
    );
    if let Some(allow) = reply.allow {
        head.push_str(&format!("Allow: {allow}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())?;
    stream.write_all(&reply.body)?;
    stream.flush()
}

#[cfg(test)]
mod tests;
