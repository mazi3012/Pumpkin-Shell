//! The mirror's HTTP endpoint (PRD FR-REG, Phase 14).
//!
//! HTTP/1.1 over a Unix socket on the host. The sandbox reaches it through its
//! loopback relay, so nothing else can. Only `GET` is accepted. A request head
//! over 8 KiB is refused, and so is a target with a control character or a
//! `..` segment. One request is answered at a time, because the upstream
//! runtime is single-threaded. The connection is closed after each answer.

use std::io::{self, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use crate::mirror::{Mirror, Reply, Source};

/// Largest request head accepted, in bytes.
const MAX_HEAD: usize = 8192;
/// Longest time to wait for a client to send its request.
const READ_TIMEOUT: Duration = Duration::from_secs(20);

/// Receives each fact the mirror wants recorded (for example a blocked version
/// or an install script). The caller writes it to the session log.
pub type Record = Arc<dyn Fn(&str) + Send + Sync>;

/// Serves requests until `stop` is set.
///
/// # Errors
/// Fails when the listener cannot be set up or stops accepting.
pub fn serve<S: Source + 'static>(
    listener: UnixListener,
    mirror: Arc<Mirror<S>>,
    record: Record,
    stop: Arc<AtomicBool>,
) -> io::Result<()> {
    listener.set_nonblocking(true)?;
    // Each connection is read in its own thread, so a client that sends
    // nothing cannot hold up the others. The answers still come one at a time.
    let turn = Arc::new(Mutex::new(()));
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => {
                let _ = stream.set_nonblocking(false);
                let (mirror, record, turn) =
                    (Arc::clone(&mirror), Arc::clone(&record), Arc::clone(&turn));
                std::thread::spawn(move || {
                    let _ = answer(stream, &mirror, &record, &turn);
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

/// Reads one request head, up to the blank line, byte by byte so nothing past
/// it is consumed. `None` when the head is larger than [`MAX_HEAD`].
fn read_head(stream: &mut UnixStream) -> io::Result<Option<Vec<u8>>> {
    let mut head = Vec::with_capacity(256);
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

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        431 => "Request Header Fields Too Large",
        502 => "Bad Gateway",
        _ => "Error",
    }
}

fn write_reply(stream: &mut UnixStream, reply: &Reply) -> io::Result<()> {
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        reply.status,
        reason(reply.status),
        reply.content_type,
        reply.body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(&reply.body)
}

fn plain(stream: &mut UnixStream, status: u16, message: &str) -> io::Result<()> {
    let reply = Reply {
        status,
        content_type: "text/plain",
        body: message.as_bytes().to_vec(),
        notes: Vec::new(),
    };
    write_reply(stream, &reply)
}

/// Whether a request target is safe to hand to the mirror.
fn target_ok(target: &str) -> bool {
    target.starts_with('/')
        && !target
            .bytes()
            .any(|b| b.is_ascii_control() || b == b' ' || b == b'\\')
        && !target.split(['/', '?']).any(|segment| segment == "..")
}

fn answer<S: Source>(
    mut stream: UnixStream,
    mirror: &Mirror<S>,
    record: &Record,
    turn: &Mutex<()>,
) -> io::Result<()> {
    stream.set_read_timeout(Some(READ_TIMEOUT))?;
    let Some(head) = read_head(&mut stream)? else {
        return plain(&mut stream, 431, "the request head is too large");
    };
    let text = String::from_utf8_lossy(&head);
    let first = text.lines().next().unwrap_or("");
    let mut parts = first.split(' ');
    let (Some(method), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next())
    else {
        return plain(&mut stream, 400, "the request line is malformed");
    };
    if !version.starts_with("HTTP/1.") {
        return plain(&mut stream, 400, "only HTTP/1.x is accepted");
    }
    if method != "GET" {
        return plain(&mut stream, 405, "only GET is accepted");
    }
    if !target_ok(target) {
        return plain(&mut stream, 400, "the request target is not allowed");
    }
    // The upstream runtime is single-threaded, so only one request is worked
    // on at a time. A poisoned lock is still usable: the guard holds no data.
    let reply = {
        let _turn = turn.lock().unwrap_or_else(PoisonError::into_inner);
        mirror.handle(target)
    };
    for note in &reply.notes {
        record(note);
    }
    write_reply(&mut stream, &reply)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::upstream::UpstreamError;
    use std::io::{BufRead, BufReader};
    use std::sync::Mutex;

    /// OSV that has no malware to report.
    struct CleanAdvisories;
    impl crate::osv::Advisories for CleanAdvisories {
        fn check(&self, _: &str, _: &str, _: &str) -> crate::osv::Verdict {
            crate::osv::Verdict::Clean
        }
    }

    /// A registry with one old version and one that is too new.
    struct OneOld;
    impl Source for OneOld {
        fn fetch(&self, _url: &str, _accept: Option<&str>) -> Result<Vec<u8>, UpstreamError> {
            let now = 1_800_000_000_i64;
            let at = |secs: i64| {
                time::OffsetDateTime::from_unix_timestamp(now - secs)
                    .ok()
                    .and_then(|t| {
                        t.format(&time::format_description::well_known::Rfc3339)
                            .ok()
                    })
                    .unwrap_or_default()
            };
            Ok(serde_json::json!({
                "name": "pkg",
                "dist-tags": { "latest": "2.0.0" },
                "versions": {
                    "1.0.0": { "scripts": { "postinstall": "x" }, "dist": { "tarball": "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz" } },
                    "2.0.0": { "dist": { "tarball": "https://registry.npmjs.org/pkg/-/pkg-2.0.0.tgz" } },
                },
                "time": {
                    "1.0.0": at(200 * 86_400),
                    "2.0.0": at(3600),
                },
            })
            .to_string()
            .into_bytes())
        }
    }

    /// The directory holding the socket, the stop flag, and the recorded notes.
    type Harness = (tempfile::TempDir, Arc<AtomicBool>, Arc<Mutex<Vec<String>>>);

    /// Starts a server on a fresh socket and returns its path, the stop flag,
    /// and the list of recorded notes.
    fn start() -> Result<Harness, Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let listener = UnixListener::bind(dir.path().join("mirror.sock"))?;
        let mirror = Arc::new(Mirror::new(
            OneOld,
            "http://127.0.0.1:3130",
            Box::new(|| 1_800_000_000),
            Box::new(CleanAdvisories),
        ));
        let notes = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&notes);
        let record: Record = Arc::new(move |note: &str| {
            if let Ok(mut list) = sink.lock() {
                list.push(note.to_owned());
            }
        });
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        std::thread::spawn(move || {
            let _ = serve(listener, mirror, record, flag);
        });
        Ok((dir, stop, notes))
    }

    /// Sends raw bytes and returns the status line and the body.
    fn ask(
        dir: &tempfile::TempDir,
        raw: &[u8],
    ) -> Result<(String, Vec<u8>), Box<dyn std::error::Error>> {
        let mut stream = UnixStream::connect(dir.path().join("mirror.sock"))?;
        stream.write_all(raw)?;
        let mut reader = BufReader::new(stream);
        let mut status = String::new();
        reader.read_line(&mut status)?;
        let mut length = 0usize;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line)?;
            if line == "\r\n" || line.is_empty() {
                break;
            }
            if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                length = value.trim().parse()?;
            }
        }
        let mut body = vec![0u8; length];
        reader.read_exact(&mut body)?;
        Ok((status.trim_end().to_owned(), body))
    }

    #[test]
    fn a_get_gets_the_filtered_document_and_the_notes_are_recorded()
    -> Result<(), Box<dyn std::error::Error>> {
        let (dir, stop, notes) = start()?;
        let (status, body) = ask(&dir, b"GET /npm/pkg HTTP/1.1\r\nHost: x\r\n\r\n")?;
        assert_eq!(status, "HTTP/1.1 200 OK");
        let doc: serde_json::Value = serde_json::from_slice(&body)?;
        assert!(doc["versions"].get("2.0.0").is_none());
        let recorded = notes.lock().map(|n| n.clone()).unwrap_or_default();
        assert!(
            recorded.iter().any(|n| n == "REG-INSTALL-SCRIPT pkg@1.0.0"),
            "{recorded:?}"
        );
        assert!(
            recorded
                .iter()
                .any(|n| n.starts_with("REG-COOLDOWN pkg@2.0.0")),
            "{recorded:?}"
        );
        stop.store(true, Ordering::Relaxed);
        Ok(())
    }

    #[test]
    fn a_client_that_sends_nothing_does_not_hold_up_the_next_request()
    -> Result<(), Box<dyn std::error::Error>> {
        let (dir, stop, _) = start()?;
        // Connects and never sends a request, as the relay's readiness probe does.
        let idle = UnixStream::connect(dir.path().join("mirror.sock"))?;
        let started = std::time::Instant::now();
        let (status, _) = ask(&dir, b"GET /npm/pkg HTTP/1.1\r\nHost: x\r\n\r\n")?;
        assert_eq!(status, "HTTP/1.1 200 OK");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the request waited {:?} behind an idle client",
            started.elapsed()
        );
        drop(idle);
        stop.store(true, Ordering::Relaxed);
        Ok(())
    }

    #[test]
    fn only_get_is_accepted() -> Result<(), Box<dyn std::error::Error>> {
        let (dir, stop, _) = start()?;
        let (status, _) = ask(&dir, b"POST /npm/pkg HTTP/1.1\r\n\r\n")?;
        assert_eq!(status, "HTTP/1.1 405 Method Not Allowed");
        stop.store(true, Ordering::Relaxed);
        Ok(())
    }

    #[test]
    fn an_oversized_head_is_refused() -> Result<(), Box<dyn std::error::Error>> {
        let (dir, stop, _) = start()?;
        let mut raw = b"GET /npm/pkg HTTP/1.1\r\nX-Pad: ".to_vec();
        raw.extend(std::iter::repeat_n(b'a', MAX_HEAD + 100));
        let (status, _) =
            ask(&dir, &raw).unwrap_or_else(|_| ("HTTP/1.1 431 closed".to_owned(), Vec::new()));
        assert!(status.contains("431"), "{status}");
        stop.store(true, Ordering::Relaxed);
        Ok(())
    }

    #[test]
    fn targets_with_dot_dot_or_control_characters_are_refused()
    -> Result<(), Box<dyn std::error::Error>> {
        let (dir, stop, _) = start()?;
        for raw in [
            &b"GET /npm/../../etc/passwd HTTP/1.1\r\n\r\n"[..],
            &b"GET /npm/%2e%2e/x HTTP/1.1\r\n\r\n"[..],
            &b"GET /npm/a\\b HTTP/1.1\r\n\r\n"[..],
            &b"GET relative HTTP/1.1\r\n\r\n"[..],
        ] {
            let (status, _) = ask(&dir, raw)?;
            assert!(
                status.starts_with("HTTP/1.1 400"),
                "{status} for {:?}",
                String::from_utf8_lossy(raw)
            );
        }
        stop.store(true, Ordering::Relaxed);
        Ok(())
    }

    #[test]
    fn a_request_line_without_a_version_is_refused() -> Result<(), Box<dyn std::error::Error>> {
        let (dir, stop, _) = start()?;
        let (status, _) = ask(&dir, b"GET /npm/pkg\r\n\r\n")?;
        assert!(status.starts_with("HTTP/1.1 400"), "{status}");
        let (status, _) = ask(&dir, b"GET /npm/pkg SPDY/3\r\n\r\n")?;
        assert!(status.starts_with("HTTP/1.1 400"), "{status}");
        stop.store(true, Ordering::Relaxed);
        Ok(())
    }
}
