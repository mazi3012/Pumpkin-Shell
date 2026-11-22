//! Tests for the dashboard server and its data. Each server runs on its own
//! port, on loopback, and stops when the test ends.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use pks_core::keys;
use pks_core::log::{Logger, Record};

use super::serve;
use super::summary::{Check, Checker, Severity, parse_events, severity_of, snapshot};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A running dashboard for a test, stopped on drop.
struct Server {
    port: u16,
    stop: Arc<AtomicBool>,
    _data: tempfile::TempDir,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Starts a dashboard over a fresh data directory.
fn start() -> Result<(Server, PathBuf), Box<dyn std::error::Error>> {
    let data = tempfile::tempdir()?;
    let path = data.path().to_path_buf();
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    let port = listener.local_addr()?.port();
    let state = Arc::new(Mutex::new(Checker::new(path.clone())));
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    std::thread::spawn(move || {
        let _ = serve(listener, state, port, flag);
    });
    Ok((
        Server {
            port,
            stop,
            _data: data,
        },
        path,
    ))
}

/// Sends one request and returns the status line, the head and the body.
fn request(
    port: u16,
    method: &str,
    path: &str,
    host: &str,
) -> Result<(String, String, Vec<u8>), Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))?;
    stream.write_all(
        format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
    )?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("no end of head")?;
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let status = head.lines().next().unwrap_or("").to_owned();
    Ok((status, head, raw[split + 4..].to_vec()))
}

/// Writes one signed session log under `data/sessions/<id>`. Each record is
/// `(layer, target, rule, verdict)`. The log is closed with a checkpoint.
fn session(
    data: &Path,
    id: &str,
    records: &[(&str, &str, &str, &str)],
) -> Result<(), Box<dyn std::error::Error>> {
    let key = keys::load_or_create_signing_key(&data.join("keys"))?;
    let dir = data.join("sessions").join(id);
    std::fs::create_dir_all(&dir)?;
    let mut logger = Logger::create(&dir.join("session.jsonl"), key, id)?;
    for (index, &(layer, target, rule, verdict)) in records.iter().enumerate() {
        logger.append(
            &Record {
                policy_hash: "policy",
                layer,
                target,
                rule,
                verdict,
            },
            1_000 + index as u64,
        )?;
    }
    logger.finish(9_000)?;
    Ok(())
}

#[test]
fn the_page_is_served_with_a_strict_policy() -> TestResult {
    let (server, _) = start()?;
    let (status, head, body) = request(
        server.port,
        "GET",
        "/",
        &format!("127.0.0.1:{}", server.port),
    )?;
    assert_eq!(status, "HTTP/1.1 200 OK");
    assert!(
        head.contains("Content-Security-Policy: default-src 'none'; script-src 'self'"),
        "{head}"
    );
    assert!(head.contains("X-Content-Type-Options: nosniff"), "{head}");
    let page = String::from_utf8(body)?;
    assert!(page.contains("Pumpkin-Shell"), "the page carries the brand");
    Ok(())
}

#[test]
fn the_page_loads_no_resource_from_outside() -> TestResult {
    let (server, _) = start()?;
    let host = format!("127.0.0.1:{}", server.port);
    for path in ["/", "/style.css", "/app.js"] {
        let (_, _, body) = request(server.port, "GET", path, &host)?;
        let text = String::from_utf8(body)?;
        for word in text.split(['"', '\'', ' ', '(', ')']) {
            if word.starts_with("http://") || word.starts_with("https://") {
                assert!(
                    word.starts_with(&format!("http://127.0.0.1:{}", server.port))
                        || word.starts_with("http://www.w3.org/"),
                    "{path} refers to {word}"
                );
            }
        }
    }
    Ok(())
}

#[test]
fn the_page_has_its_own_assets_and_a_404_for_anything_else() -> TestResult {
    let (server, _) = start()?;
    let host = format!("127.0.0.1:{}", server.port);
    for (path, kind) in [
        ("/style.css", "text/css"),
        ("/app.js", "text/javascript"),
        ("/icon.svg", "image/svg+xml"),
    ] {
        let (status, head, _) = request(server.port, "GET", path, &host)?;
        assert_eq!(status, "HTTP/1.1 200 OK", "{path}");
        assert!(head.contains(kind), "{path}: {head}");
    }
    let (status, _, _) = request(server.port, "GET", "/no-such-page", &host)?;
    assert_eq!(status, "HTTP/1.1 404 Not Found");
    Ok(())
}

#[test]
fn only_get_is_accepted() -> TestResult {
    let (server, _) = start()?;
    let host = format!("127.0.0.1:{}", server.port);
    for method in ["POST", "PUT", "DELETE"] {
        let (status, head, _) = request(server.port, method, "/api/snapshot", &host)?;
        assert_eq!(status, "HTTP/1.1 405 Method Not Allowed", "{method}");
        assert!(head.contains("Allow: GET"), "{head}");
    }
    Ok(())
}

#[test]
fn a_host_other_than_the_loopback_names_is_refused() -> TestResult {
    let (server, _) = start()?;
    for host in [
        "evil.example.org",
        "evil.example.org:8765",
        "127.0.0.1.nip.io",
        "example.com",
    ] {
        let (status, _, _) = request(server.port, "GET", "/", host)?;
        assert_eq!(status, "HTTP/1.1 403 Forbidden", "{host}");
    }
    let (status, _, _) = request(
        server.port,
        "GET",
        "/",
        &format!("localhost:{}", server.port),
    )?;
    assert_eq!(status, "HTTP/1.1 200 OK", "localhost is allowed");
    Ok(())
}

#[test]
fn a_request_without_a_host_header_is_refused() -> TestResult {
    let (server, _) = start()?;
    let mut stream = TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, server.port)))?;
    stream.write_all(b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n")?;
    let mut raw = String::new();
    stream.read_to_string(&mut raw)?;
    assert!(raw.starts_with("HTTP/1.1 403"), "{raw}");
    Ok(())
}

#[test]
fn the_snapshot_counts_the_findings_of_a_real_signed_log() -> TestResult {
    let (server, data) = start()?;
    session(
        &data,
        "aaaa1111",
        &[
            ("net", "example.org:443", "NET-UNKNOWN-DOMAIN", "block"),
            ("fs", ".aws/credentials", "FS-DECOY-READ", "alert"),
            (
                "net",
                "[2001:4860:4860::8888]:443",
                "NET-DIRECT-CONNECT",
                "alert",
            ),
            ("clip", "12 bytes", "CLIP-PASTE", "allow"),
        ],
    )?;
    let (status, _, body) = request(
        server.port,
        "GET",
        "/api/snapshot",
        &format!("127.0.0.1:{}", server.port),
    )?;
    assert_eq!(status, "HTTP/1.1 200 OK");
    let snap: serde_json::Value = serde_json::from_slice(&body)?;
    assert_eq!(snap["totals"]["sessions"], 1);
    assert_eq!(snap["totals"]["decoy_reads"], 1);
    assert_eq!(snap["totals"]["network_blocked"], 1);
    // NET-UNKNOWN-DOMAIN (WARN), FS-DECOY-READ (HIGH) and NET-DIRECT-CONNECT (WARN).
    assert_eq!(snap["totals"]["findings"], 3, "{snap}");
    assert_eq!(snap["totals"]["warn"], 2, "two WARN findings");
    assert_eq!(snap["totals"]["high"], 1, "the decoy read is HIGH");
    assert_eq!(snap["sessions"][0]["check"], "verified", "{snap}");
    assert_eq!(snap["sessions"][0]["entries"], 4);
    Ok(())
}

#[test]
fn a_tampered_log_is_shown_as_failed() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let data = tmp.path().to_path_buf();
    session(
        &data,
        "bbbb2222",
        &[
            ("fs", ".ssh/id_ed25519", "FS-DECOY-READ", "alert"),
            ("net", "127.0.0.1:5432", "NET-DIRECT-CONNECT", "alert"),
        ],
    )?;
    let log = data.join("sessions").join("bbbb2222").join("session.jsonl");
    let text = std::fs::read_to_string(&log)?;
    std::fs::write(&log, text.replace("FS-DECOY-READ", "NOTHING-HAPPENED"))?;
    let mut checker = Checker::new(data.clone());
    let snap = snapshot(&mut checker, 1);
    assert_eq!(
        snap.sessions[0].check,
        Check::Failed,
        "{:?}",
        snap.sessions[0]
    );
    assert_eq!(snap.totals.logs_failed, 1);
    Ok(())
}

#[test]
fn a_log_without_a_key_is_unavailable_not_verified() -> TestResult {
    let data = tempfile::tempdir()?;
    let dir = data.path().join("sessions").join("cccc3333");
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("session.jsonl"), "{\"v\":1}\n")?;
    let mut checker = Checker::new(data.path().to_path_buf());
    let snap = snapshot(&mut checker, 1);
    assert_eq!(snap.sessions[0].check, Check::Unavailable);
    Ok(())
}

#[test]
fn events_are_listed_newest_first_and_the_feed_is_capped() -> TestResult {
    let data = tempfile::tempdir()?;
    let records: Vec<(&str, &str, &str, &str)> = (0..250)
        .map(|_| ("net", "127.0.0.1:5432", "NET-DIRECT-CONNECT", "alert"))
        .collect();
    session(data.path(), "dddd4444", &records)?;
    let mut checker = Checker::new(data.path().to_path_buf());
    let snap = snapshot(&mut checker, 1);
    assert_eq!(snap.events.len(), super::summary::MAX_EVENTS);
    assert!(
        snap.events.windows(2).all(|w| w[0].ts >= w[1].ts),
        "newest first"
    );
    assert_eq!(
        snap.totals.findings, 250,
        "the totals count every record, not only the feed"
    );
    Ok(())
}

#[test]
fn rules_have_their_published_severity() {
    assert_eq!(severity_of("EXEC-AGENT-YOLO"), Severity::Critical);
    assert_eq!(severity_of("FS-DECOY-READ"), Severity::High);
    assert_eq!(severity_of("NET-DIRECT-CONNECT"), Severity::Warn);
    assert_eq!(severity_of("BROKER-OPEN"), Severity::Notice);
    assert_eq!(severity_of("SOMETHING-NEW"), Severity::Notice);
}

#[test]
fn lines_that_are_not_records_are_skipped() {
    let text = "garbage\n{\"seq\":0,\"ts\":5,\"layer\":\"fs\",\"target\":\"x\",\"rule\":\"FS-DECOY-READ\",\"verdict\":\"alert\"}\n{\"half\":";
    let events = parse_events("s", text);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].severity, Severity::High);
}

#[test]
fn a_session_that_is_not_running_is_shown_as_ended() -> TestResult {
    let data = tempfile::tempdir()?;
    session(
        data.path(),
        "eeee5555",
        &[("fs", "x", "FS-DECOY-READ", "alert")],
    )?;
    let mut checker = Checker::new(data.path().to_path_buf());
    let snap = snapshot(&mut checker, 1);
    assert_eq!(snap.sessions[0].status, "ended");
    assert_eq!(snap.totals.running, 0);
    Ok(())
}
