//! Handles one proxied connection: parses the CONNECT request, applies the
//! allowlist and the ask prompt, checks every resolved address, dials the
//! address it checked, and relays bytes (PRD FR-NET).
//!
//! Decisions are made per connection and reported as findings. A connection
//! that cannot be decided is refused (fail closed).

use std::collections::BTreeSet;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use pks_core::net::HostPort;
use pks_core::policy::Mode;
use pks_core::{Finding, RuleId, Severity};

use crate::addr;

/// Rule for a destination that is not on the allowlist (PRD FR-DET).
pub const NET_UNKNOWN_DOMAIN: RuleId = RuleId::new("NET-UNKNOWN-DOMAIN");
/// Rule for a destination that resolves to a private or reserved address.
pub const NET_PRIVATE_IP: RuleId = RuleId::new("NET-PRIVATE-IP");
/// Rule for more than 10 MB sent to one host.
pub const NET_LARGE_UPLOAD: RuleId = RuleId::new("NET-LARGE-UPLOAD");
/// Rule for a connection relayed to a host port the user listed (PRD FR-NET).
pub const NET_HOST_PORT: RuleId = RuleId::new("NET-HOST-PORT");

/// How long an unknown domain is held while the user is asked (PRD FR-NET).
pub const ASK_HOLD: Duration = Duration::from_secs(20);
/// Upload size that raises NET-LARGE-UPLOAD.
pub const LARGE_UPLOAD_BYTES: u64 = 10 * 1024 * 1024;
const MAX_HEAD_BYTES: usize = 8 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The answer to one ask prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// Allow this connection only.
    AllowOnce,
    /// Allow this endpoint for the rest of the session.
    AllowSession,
    /// Refuse.
    Deny,
}

/// Asks the user about an endpoint. Returns `None` when nobody can answer
/// (headless); the engine then denies.
pub trait Asker: Send + Sync {
    fn ask(&self, endpoint: &HostPort) -> Option<Answer>;
}

/// Resolves a host name. Injected so tests need no network.
pub trait Resolver: Send + Sync {
    fn resolve(&self, endpoint: &HostPort) -> io::Result<Vec<SocketAddr>>;
}

/// Opens a TCP connection to an address the engine has already checked.
pub trait Dialer: Send + Sync {
    fn dial(&self, addr: SocketAddr, timeout: Duration) -> io::Result<TcpStream>;
}

/// The system resolver.
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve(&self, endpoint: &HostPort) -> io::Result<Vec<SocketAddr>> {
        (endpoint.host(), endpoint.port())
            .to_socket_addrs()
            .map(Iterator::collect)
    }
}

/// Plain TCP.
pub struct TcpDialer;

impl Dialer for TcpDialer {
    fn dial(&self, addr: SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
        TcpStream::connect_timeout(&addr, timeout)
    }
}

/// Receives each finding the engine raises.
pub type EventSink = Arc<dyn Fn(Finding) + Send + Sync>;

/// Everything an engine needs.
pub struct Config {
    /// Endpoints allowed without asking.
    pub allow: BTreeSet<HostPort>,
    /// Host ports the sandbox may reach on `127.0.0.1` (PRD FR-NET).
    pub host_ports: BTreeSet<u16>,
    /// Enforce blocks; monitor allows and reports.
    pub mode: Mode,
    pub resolver: Arc<dyn Resolver>,
    pub dialer: Arc<dyn Dialer>,
    pub asker: Arc<dyn Asker>,
    pub events: EventSink,
    /// How long the ask is held before it counts as "deny".
    pub hold: Duration,
}

/// Connection handling. Shared by all connections of one proxy.
pub struct Engine {
    config: Config,
    /// Endpoints allowed for this session by an earlier answer.
    session: Mutex<BTreeSet<HostPort>>,
}

/// A client stream that can be split for the two relay directions.
pub trait Client: io::Read + io::Write + Send + Sized + 'static {
    fn duplicate(&self) -> io::Result<Self>;
}

#[cfg(unix)]
impl Client for std::os::unix::net::UnixStream {
    fn duplicate(&self) -> io::Result<Self> {
        self.try_clone()
    }
}

impl Client for TcpStream {
    fn duplicate(&self) -> io::Result<Self> {
        self.try_clone()
    }
}

/// The reply a client gets, with its status line.
fn reply(status: &str) -> Vec<u8> {
    format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").into_bytes()
}

/// Reads the request head up to the blank line. Stops at the first byte past
/// it, so nothing that follows (a TLS hello, for example) is consumed.
fn read_head<R: Read>(stream: &mut R) -> io::Result<Vec<u8>> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= MAX_HEAD_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request head too long",
            ));
        }
        if stream.read(&mut byte)? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "client closed early",
            ));
        }
        head.push(byte[0]);
    }
    Ok(head)
}

/// The CONNECT target of a request head, or the status to answer with.
fn connect_target(head: &[u8]) -> Result<HostPort, &'static str> {
    let text = std::str::from_utf8(head).map_err(|_| "400 Bad Request")?;
    let line = text.split("\r\n").next().unwrap_or_default();
    let mut parts = line.split(' ');
    let (method, target, version) = (parts.next(), parts.next(), parts.next());
    if method != Some("CONNECT") {
        return Err("405 Method Not Allowed");
    }
    if !matches!(version, Some("HTTP/1.0") | Some("HTTP/1.1")) || parts.next().is_some() {
        return Err("400 Bad Request");
    }
    let endpoint = HostPort::parse(target.unwrap_or_default()).map_err(|_| "400 Bad Request")?;
    Ok(endpoint)
}

impl Engine {
    #[must_use]
    pub fn new(config: Config) -> Self {
        Self {
            config,
            session: Mutex::new(BTreeSet::new()),
        }
    }

    fn emit(&self, rule: RuleId, severity: Severity, target: &str, message: String, fix: &str) {
        (self.config.events)(Finding {
            rule,
            severity,
            target: target.to_owned(),
            message,
            fix: fix.to_owned(),
        });
    }

    fn is_allowed(&self, endpoint: &HostPort) -> bool {
        self.config.allow.contains(endpoint)
            || self
                .session
                .lock()
                .is_ok_and(|session| session.contains(endpoint))
    }

    /// Asks the user, holding for `hold`. No answer in time counts as deny.
    fn ask(&self, endpoint: &HostPort) -> Answer {
        let (tx, rx) = mpsc::channel();
        let asker = Arc::clone(&self.config.asker);
        let asked = endpoint.clone();
        // The prompt runs on its own thread so the hold can end first. If it
        // never answers, that thread is left behind; it holds no resources.
        thread::spawn(move || {
            let _ = tx.send(asker.ask(&asked));
        });
        match rx.recv_timeout(self.config.hold) {
            Ok(Some(answer)) => answer,
            _ => Answer::Deny,
        }
    }

    /// Decides whether `endpoint` may be reached, asking if needed.
    /// Returns `false` when the connection must be refused.
    fn permitted(&self, endpoint: &HostPort) -> bool {
        if self.is_allowed(endpoint) {
            return true;
        }
        let monitor = self.config.mode == Mode::Monitor;
        if monitor {
            self.emit(
                NET_UNKNOWN_DOMAIN,
                Severity::Warn,
                &endpoint.to_string(),
                "not on the allowlist; monitor mode allows it and records it".to_owned(),
                "Add it to [network] allow in your policy.toml if you need it.",
            );
            return true;
        }
        match self.ask(endpoint) {
            Answer::AllowOnce => true,
            Answer::AllowSession => {
                if let Ok(mut session) = self.session.lock() {
                    session.insert(endpoint.clone());
                }
                true
            }
            Answer::Deny => {
                self.emit(
                    NET_UNKNOWN_DOMAIN,
                    Severity::Warn,
                    &endpoint.to_string(),
                    "not on the allowlist; refused (no answer, or denied)".to_owned(),
                    "Add it to [network] allow in your policy.toml to allow it every time.",
                );
                false
            }
        }
    }

    /// Handles one connection from start to end.
    pub fn handle<C: Client>(&self, mut client: C) {
        let head = match read_head(&mut client) {
            Ok(head) => head,
            Err(_) => return,
        };
        let endpoint = match connect_target(&head) {
            Ok(endpoint) => endpoint,
            Err(status) => {
                let _ = client.write_all(&reply(status));
                return;
            }
        };
        let upstream = if let Some(port) = self.listed_host_port(&endpoint) {
            self.emit(
                NET_HOST_PORT,
                Severity::Notice,
                &endpoint.to_string(),
                format!("relayed to the host's 127.0.0.1:{port}; listed in host_ports"),
                "Remove the port from [network] host_ports in your policy.toml to stop relaying it.",
            );
            self.connect_host_port(port)
        } else {
            if !self.permitted(&endpoint) {
                let _ = client.write_all(&reply("403 Forbidden"));
                return;
            }
            self.connect_checked(&endpoint)
        };
        let upstream = match upstream {
            Ok(upstream) => upstream,
            Err(status) => {
                let _ = client.write_all(&reply(status));
                return;
            }
        };
        if client
            .write_all(&reply("200 Connection Established"))
            .is_err()
        {
            return;
        }
        relay(client, upstream, &endpoint, &self.config.events);
    }

    /// The port of `endpoint` when it is `127.0.0.1:<port>` and `<port>` is
    /// listed. Only that exact address is a host port, so `localhost` and
    /// every other loopback address still follow the normal rules.
    fn listed_host_port(&self, endpoint: &HostPort) -> Option<u16> {
        let port = endpoint.port();
        (endpoint.host() == "127.0.0.1" && self.config.host_ports.contains(&port)).then_some(port)
    }
    /// Dials the host's own loopback at a listed port. Only called after
    /// `listed_host_port` said yes.
    fn connect_host_port(&self, port: u16) -> Result<TcpStream, &'static str> {
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        self.config
            .dialer
            .dial(addr, CONNECT_TIMEOUT)
            .map_err(|_| "502 Bad Gateway")
    }
    /// Resolves, refuses non-public addresses, and dials the first address
    /// that answers. The dialed address is the one that was checked, so a
    /// second resolution cannot change it (DNS rebinding).
    fn connect_checked(&self, endpoint: &HostPort) -> Result<TcpStream, &'static str> {
        let addrs = self
            .config
            .resolver
            .resolve(endpoint)
            .map_err(|_| "502 Bad Gateway")?;
        if addrs.is_empty() {
            return Err("502 Bad Gateway");
        }
        for addr in &addrs {
            if let Some(reason) = refusal_of(addr.ip()) {
                self.emit(
                    NET_PRIVATE_IP,
                    Severity::High,
                    &endpoint.to_string(),
                    format!("resolves to {} ({reason}); refused", addr.ip()),
                    "The destination is not public. Connect to a public address instead.",
                );
                return Err("403 Forbidden");
            }
        }
        for addr in &addrs {
            if let Ok(stream) = self.config.dialer.dial(*addr, CONNECT_TIMEOUT) {
                return Ok(stream);
            }
        }
        Err("502 Bad Gateway")
    }
}

fn refusal_of(ip: IpAddr) -> Option<&'static str> {
    addr::refusal(ip)
}

/// Copies both ways until either side closes. Counts bytes sent by the
/// client and raises NET-LARGE-UPLOAD once when the limit is crossed.
fn relay<C: Client>(client: C, upstream: TcpStream, endpoint: &HostPort, events: &EventSink) {
    let uploaded = Arc::new(AtomicU64::new(0));
    let (mut client_read, mut client_write) = match (client.duplicate(), client.duplicate()) {
        (Ok(read), Ok(write)) => (read, write),
        _ => return,
    };
    let (mut up_read, mut up_write) = match (upstream.try_clone(), upstream.try_clone()) {
        (Ok(read), Ok(write)) => (read, write),
        _ => return,
    };
    let counter = Arc::clone(&uploaded);
    let target = endpoint.to_string();
    let sink = Arc::clone(events);
    let up_thread = thread::spawn(move || {
        let mut last = 0u64;
        let mut warned = false;
        let mut buffer = [0u8; 16 * 1024];
        loop {
            match client_read.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if up_write.write_all(&buffer[..n]).is_err() {
                        break;
                    }
                    let total = counter.fetch_add(n as u64, Ordering::Relaxed) + n as u64;
                    if !warned && total > LARGE_UPLOAD_BYTES {
                        warned = true;
                        sink(Finding {
                            rule: NET_LARGE_UPLOAD,
                            severity: Severity::Warn,
                            target: target.clone(),
                            message: format!(
                                "more than 10 MB sent to this host ({} bytes so far)",
                                total
                            ),
                            fix:
                                "Check what the IDE is sending. Model API hosts are not yet exempt."
                                    .to_owned(),
                        });
                    }
                    last = total;
                }
            }
        }
        let _ = up_write.shutdown(std::net::Shutdown::Write);
        last
    });
    let down = thread::spawn(move || {
        let _ = io::copy(&mut up_read, &mut client_write);
        let _ = client_write.flush();
    });
    let _ = up_thread.join();
    let _ = down.join();
}

#[cfg(test)]
mod tests {

    /// A connected pair of loopback streams: the client end and the proxy end.
    /// TCP works on every platform, so the tests run on Windows too.
    fn stream_pair() -> io::Result<(TcpStream, TcpStream)> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let client = TcpStream::connect(listener.local_addr()?)?;
        let (server, _) = listener.accept()?;
        Ok((client, server))
    }
    use super::*;
    use std::net::{Ipv4Addr, TcpListener};
    use std::sync::Mutex as StdMutex;

    struct FixedResolver(Vec<SocketAddr>);
    impl Resolver for FixedResolver {
        fn resolve(&self, _: &HostPort) -> io::Result<Vec<SocketAddr>> {
            Ok(self.0.clone())
        }
    }

    /// Sends every connection to a local test server, whatever the address.
    struct RedirectDialer(SocketAddr);
    impl Dialer for RedirectDialer {
        fn dial(&self, _: SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
            TcpStream::connect_timeout(&self.0, timeout)
        }
    }

    struct Scripted(Option<Answer>);
    impl Asker for Scripted {
        fn ask(&self, _: &HostPort) -> Option<Answer> {
            self.0
        }
    }

    struct Silent;
    impl Asker for Silent {
        fn ask(&self, _: &HostPort) -> Option<Answer> {
            thread::sleep(Duration::from_secs(60));
            None
        }
    }

    type Log = Arc<StdMutex<Vec<Finding>>>;

    fn events() -> (EventSink, Log) {
        let log: Log = Arc::new(StdMutex::new(Vec::new()));
        let sink = Arc::clone(&log);
        (
            Arc::new(move |f| sink.lock().map(|mut v| v.push(f)).unwrap_or(())),
            log,
        )
    }

    /// A public-looking address; the redirect dialer decides where it goes.
    fn public() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443)
    }

    /// Runs one connection through an engine and returns the status line.
    fn run(engine: &Engine, request: &[u8]) -> io::Result<String> {
        let (mut client, server) = stream_pair()?;
        client.write_all(request)?;
        let _ = client.shutdown(std::net::Shutdown::Write);
        engine.handle(server);
        let mut reply = String::new();
        client.read_to_string(&mut reply).ok();
        Ok(reply.lines().next().unwrap_or_default().to_owned())
    }

    fn engine(
        allow: &[&str],
        mode: Mode,
        asker: Arc<dyn Asker>,
        hold: Duration,
        upstream: SocketAddr,
        resolved: Vec<SocketAddr>,
    ) -> (Engine, Log) {
        let (sink, log) = events();
        let allow = allow
            .iter()
            .map(|t| HostPort::parse(t).unwrap_or_else(|e| panic!("{e}")))
            .collect();
        let config = Config {
            allow,
            host_ports: BTreeSet::new(),
            mode,
            resolver: Arc::new(FixedResolver(resolved)),
            dialer: Arc::new(RedirectDialer(upstream)),
            asker,
            events: sink,
            hold,
        };
        (Engine::new(config), log)
    }

    /// A TCP server that answers one request with a fixed body.
    fn upstream_server() -> io::Result<SocketAddr> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                thread::spawn(move || {
                    let mut stream = stream;
                    let mut buffer = [0u8; 1024];
                    let _ = stream.read(&mut buffer);
                    let _ = stream.write_all(b"upstream says hi");
                });
            }
        });
        Ok(addr)
    }

    #[test]
    fn an_allowed_endpoint_is_connected_and_relayed() -> io::Result<()> {
        let upstream = upstream_server()?;
        let (engine, _) = engine(
            &["api.example.com:443"],
            Mode::Enforce,
            Arc::new(Scripted(None)),
            ASK_HOLD,
            upstream,
            vec![public()],
        );
        let (mut client, server) = stream_pair()?;
        client.write_all(
            b"CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n\r\n",
        )?;
        thread::spawn(move || engine.handle(server));
        let mut status = [0u8; 39];
        client.read_exact(&mut status)?;
        assert!(String::from_utf8_lossy(&status).starts_with("HTTP/1.1 200"));
        client.write_all(b"hello")?;
        let _ = client.shutdown(std::net::Shutdown::Write);
        let mut body = String::new();
        client.read_to_string(&mut body)?;
        assert!(body.contains("upstream says hi"), "{body}");
        Ok(())
    }

    #[test]
    fn an_unknown_endpoint_is_refused_when_nobody_answers() -> io::Result<()> {
        let upstream = upstream_server()?;
        let (engine, log) = engine(
            &[],
            Mode::Enforce,
            Arc::new(Scripted(None)),
            ASK_HOLD,
            upstream,
            vec![public()],
        );
        let status = run(&engine, b"CONNECT evil.example.org:443 HTTP/1.1\r\n\r\n")?;
        assert!(status.starts_with("HTTP/1.1 403"), "{status}");
        let findings = log.lock().map(|l| l.clone()).unwrap_or_default();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule.as_str(), "NET-UNKNOWN-DOMAIN");
        assert_eq!(findings[0].severity, Severity::Warn);
        Ok(())
    }

    #[test]
    fn an_answer_of_allow_once_connects_but_asks_again_next_time() -> io::Result<()> {
        let upstream = upstream_server()?;
        let (engine, _) = engine(
            &[],
            Mode::Enforce,
            Arc::new(Scripted(Some(Answer::AllowOnce))),
            ASK_HOLD,
            upstream,
            vec![public()],
        );
        assert!(
            run(&engine, b"CONNECT x.example.org:443 HTTP/1.1\r\n\r\n")?
                .starts_with("HTTP/1.1 200")
        );
        assert!(
            !engine.is_allowed(
                &HostPort::parse("x.example.org:443").unwrap_or_else(|e| panic!("{e}"))
            )
        );
        Ok(())
    }

    #[test]
    fn an_answer_of_allow_session_remembers_the_endpoint() -> io::Result<()> {
        let upstream = upstream_server()?;
        let (engine, _) = engine(
            &[],
            Mode::Enforce,
            Arc::new(Scripted(Some(Answer::AllowSession))),
            ASK_HOLD,
            upstream,
            vec![public()],
        );
        assert!(
            run(&engine, b"CONNECT x.example.org:443 HTTP/1.1\r\n\r\n")?
                .starts_with("HTTP/1.1 200")
        );
        assert!(
            engine.is_allowed(
                &HostPort::parse("x.example.org:443").unwrap_or_else(|e| panic!("{e}"))
            )
        );
        Ok(())
    }

    #[test]
    fn a_prompt_that_never_answers_is_denied_after_the_hold() -> io::Result<()> {
        let upstream = upstream_server()?;
        let (engine, _) = engine(
            &[],
            Mode::Enforce,
            Arc::new(Silent),
            Duration::from_millis(200),
            upstream,
            vec![public()],
        );
        let started = std::time::Instant::now();
        let status = run(&engine, b"CONNECT slow.example.org:443 HTTP/1.1\r\n\r\n")?;
        assert!(status.starts_with("HTTP/1.1 403"), "{status}");
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the hold did not end"
        );
        Ok(())
    }

    #[test]
    fn the_default_hold_is_twenty_seconds() {
        assert_eq!(ASK_HOLD, Duration::from_secs(20));
    }

    #[test]
    fn monitor_mode_allows_and_reports_an_unknown_endpoint() -> io::Result<()> {
        let upstream = upstream_server()?;
        let (engine, log) = engine(
            &[],
            Mode::Monitor,
            Arc::new(Scripted(None)),
            ASK_HOLD,
            upstream,
            vec![public()],
        );
        assert!(
            run(&engine, b"CONNECT new.example.org:443 HTTP/1.1\r\n\r\n")?
                .starts_with("HTTP/1.1 200")
        );
        let findings = log.lock().map(|l| l.clone()).unwrap_or_default();
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("monitor mode"));
        Ok(())
    }

    #[test]
    fn a_name_that_resolves_to_a_private_address_is_refused_and_reported() -> io::Result<()> {
        let upstream = upstream_server()?;
        let private = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), 443);
        let (engine, log) = engine(
            &["internal.example.com:443"],
            Mode::Enforce,
            Arc::new(Scripted(None)),
            ASK_HOLD,
            upstream,
            vec![public(), private],
        );
        let status = run(
            &engine,
            b"CONNECT internal.example.com:443 HTTP/1.1\r\n\r\n",
        )?;
        assert!(status.starts_with("HTTP/1.1 403"), "{status}");
        let findings = log.lock().map(|l| l.clone()).unwrap_or_default();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule.as_str(), "NET-PRIVATE-IP");
        assert_eq!(findings[0].severity, Severity::High);
        Ok(())
    }

    #[test]
    fn the_metadata_address_is_refused_even_when_allowed_by_name() -> io::Result<()> {
        let upstream = upstream_server()?;
        let metadata = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)), 80);
        let (engine, log) = engine(
            &["metadata.example.com:80"],
            Mode::Enforce,
            Arc::new(Scripted(None)),
            ASK_HOLD,
            upstream,
            vec![metadata],
        );
        assert!(
            run(&engine, b"CONNECT metadata.example.com:80 HTTP/1.1\r\n\r\n")?
                .starts_with("HTTP/1.1 403")
        );
        assert_eq!(log.lock().map(|l| l.len()).unwrap_or(0), 1);
        Ok(())
    }

    #[test]
    fn an_ip_literal_on_a_private_address_is_refused_without_a_lookup() -> io::Result<()> {
        let upstream = upstream_server()?;
        let private = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 22);
        let (engine, _) = engine(
            &["192.168.1.10:22"],
            Mode::Enforce,
            Arc::new(Scripted(None)),
            ASK_HOLD,
            upstream,
            vec![private],
        );
        assert!(
            run(&engine, b"CONNECT 192.168.1.10:22 HTTP/1.1\r\n\r\n")?.starts_with("HTTP/1.1 403")
        );
        Ok(())
    }

    #[test]
    fn wildcards_and_other_methods_are_refused_before_any_decision() -> io::Result<()> {
        let upstream = upstream_server()?;
        let (engine, log) = engine(
            &[],
            Mode::Enforce,
            Arc::new(Scripted(Some(Answer::AllowOnce))),
            ASK_HOLD,
            upstream,
            vec![public()],
        );
        assert!(
            run(&engine, b"CONNECT *.amazonaws.com:443 HTTP/1.1\r\n\r\n")?
                .starts_with("HTTP/1.1 400")
        );
        assert!(
            run(&engine, b"GET http://example.com/ HTTP/1.1\r\n\r\n")?.starts_with("HTTP/1.1 405")
        );
        assert!(run(&engine, b"CONNECT example.com HTTP/1.1\r\n\r\n")?.starts_with("HTTP/1.1 400"));
        assert!(
            run(&engine, b"CONNECT example.com:443 HTTP/2\r\n\r\n")?.starts_with("HTTP/1.1 400")
        );
        assert_eq!(
            log.lock().map(|l| l.len()).unwrap_or(1),
            0,
            "no finding for malformed requests"
        );
        Ok(())
    }

    #[test]
    fn an_oversized_head_is_refused() -> io::Result<()> {
        let upstream = upstream_server()?;
        let (engine, _) = engine(
            &[],
            Mode::Enforce,
            Arc::new(Scripted(None)),
            ASK_HOLD,
            upstream,
            vec![public()],
        );
        let mut request = b"CONNECT example.com:443 HTTP/1.1\r\nX: ".to_vec();
        request.extend(std::iter::repeat_n(b'a', MAX_HEAD_BYTES));
        // The engine stops reading at the limit and closes the client.
        let (mut client, server) = stream_pair()?;
        client.write_all(&request)?;
        engine.handle(server);
        let mut reply = String::new();
        client.read_to_string(&mut reply).ok();
        assert!(reply.is_empty(), "{reply}");
        Ok(())
    }

    #[test]
    fn the_head_reader_stops_at_the_blank_line() -> io::Result<()> {
        let mut input: &[u8] = b"CONNECT a:1 HTTP/1.1\r\n\r\n\x16\x03\x01";
        let head = read_head(&mut input)?;
        assert_eq!(head, b"CONNECT a:1 HTTP/1.1\r\n\r\n");
        assert_eq!(input, b"\x16\x03\x01", "bytes after the head were consumed");
        Ok(())
    }

    /// An upstream that reads everything the client sends, then answers.
    fn draining_upstream() -> io::Result<SocketAddr> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                thread::spawn(move || {
                    let mut stream = stream;
                    let _ = io::copy(&mut stream, &mut io::sink());
                    let _ = stream.write_all(b"got it");
                });
            }
        });
        Ok(addr)
    }

    #[test]
    fn a_large_upload_raises_one_warning() -> io::Result<()> {
        let upstream = draining_upstream()?;
        let (engine, log) = engine(
            &["api.example.com:443"],
            Mode::Enforce,
            Arc::new(Scripted(None)),
            ASK_HOLD,
            upstream,
            vec![public()],
        );
        let (mut client, server) = stream_pair()?;
        client.write_all(b"CONNECT api.example.com:443 HTTP/1.1\r\n\r\n")?;
        thread::spawn(move || engine.handle(server));
        let mut status = [0u8; 39];
        client.read_exact(&mut status)?;
        let chunk = vec![b'u'; 1024 * 1024];
        for _ in 0..11 {
            client.write_all(&chunk)?;
        }
        let _ = client.shutdown(std::net::Shutdown::Write);
        let mut sink = Vec::new();
        client.read_to_end(&mut sink).ok();
        thread::sleep(Duration::from_millis(200));
        let findings = log.lock().map(|l| l.clone()).unwrap_or_default();
        let uploads: Vec<_> = findings
            .iter()
            .filter(|f| f.rule.as_str() == "NET-LARGE-UPLOAD")
            .collect();
        assert_eq!(uploads.len(), 1, "{findings:?}");
        assert_eq!(uploads[0].severity, Severity::Warn);
        Ok(())
    }

    /// Records every address dialed, and connects each one to `upstream`.
    struct LoopbackRecorder {
        seen: Arc<StdMutex<Vec<SocketAddr>>>,
        upstream: SocketAddr,
    }
    impl Dialer for LoopbackRecorder {
        fn dial(&self, addr: SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
            if let Ok(mut seen) = self.seen.lock() {
                seen.push(addr);
            }
            TcpStream::connect_timeout(&self.upstream, timeout)
        }
    }

    fn host_port_engine(
        ports: &[u16],
        upstream: SocketAddr,
    ) -> (Engine, Log, Arc<StdMutex<Vec<SocketAddr>>>) {
        let (sink, log) = events();
        let seen = Arc::new(StdMutex::new(Vec::new()));
        let config = Config {
            allow: BTreeSet::new(),
            host_ports: ports.iter().copied().collect(),
            mode: Mode::Enforce,
            resolver: Arc::new(FixedResolver(vec![public()])),
            dialer: Arc::new(LoopbackRecorder {
                seen: Arc::clone(&seen),
                upstream,
            }),
            asker: Arc::new(Scripted(None)),
            events: sink,
            hold: ASK_HOLD,
        };
        (Engine::new(config), log, seen)
    }

    #[test]
    fn a_listed_host_port_is_dialed_on_loopback_and_reported_as_a_notice() -> io::Result<()> {
        let upstream = upstream_server()?;
        let (engine, log, seen) = host_port_engine(&[5432], upstream);
        let status = run(&engine, b"CONNECT 127.0.0.1:5432 HTTP/1.1\r\n\r\n")?;
        assert!(status.starts_with("HTTP/1.1 200"), "{status}");
        let dialed = seen.lock().map(|v| v.clone()).unwrap_or_default();
        assert_eq!(dialed, vec![SocketAddr::from(([127, 0, 0, 1], 5432))]);
        let log = log.lock().map(|v| v.clone()).unwrap_or_default();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].rule.as_str(), "NET-HOST-PORT");
        assert_eq!(log[0].severity, Severity::Notice);
        Ok(())
    }

    #[test]
    fn a_loopback_port_that_is_not_listed_is_refused() -> io::Result<()> {
        let upstream = upstream_server()?;
        let (engine, _, seen) = host_port_engine(&[5432], upstream);
        let status = run(&engine, b"CONNECT 127.0.0.1:6379 HTTP/1.1\r\n\r\n")?;
        assert!(status.starts_with("HTTP/1.1 403"), "{status}");
        assert!(seen.lock().map(|v| v.is_empty()).unwrap_or(false));
        Ok(())
    }

    #[test]
    fn localhost_with_a_listed_port_number_is_not_a_host_port() -> io::Result<()> {
        let upstream = upstream_server()?;
        let (engine, _, seen) = host_port_engine(&[5432], upstream);
        let status = run(&engine, b"CONNECT localhost:5432 HTTP/1.1\r\n\r\n")?;
        assert!(status.starts_with("HTTP/1.1 403"), "{status}");
        assert!(seen.lock().map(|v| v.is_empty()).unwrap_or(false));
        Ok(())
    }
}
