//! The relay inside the sandbox (Phase 9). It listens on loopback and forwards
//! each TCP connection to the host proxy's Unix socket. The sandbox has no
//! other network, so the proxy is the only way out.
//!
//! Two kinds of listener run here:
//! - the proxy listener on `127.0.0.1:3128`. The IDE speaks HTTP `CONNECT` to
//!   it, so bytes are copied as they are;
//! - one listener per host port the user listed. The IDE speaks the port's
//!   own protocol to `127.0.0.1:<port>` and has no idea about the proxy, so
//!   the relay sends `CONNECT 127.0.0.1:<port>` itself before copying bytes.
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::thread;

/// Where the proxy's socket appears inside the sandbox.
pub const PROXY_SOCKET_IN: &str = "/run/pks/proxy.sock";
/// The loopback address the IDE is told to use as its proxy.
pub const PROXY_LISTEN: &str = "127.0.0.1:3128";
/// Largest reply head the relay will read from the proxy.
const MAX_REPLY_BYTES: usize = 1024;

/// Serves forever: each connection is copied both ways to a new connection
/// on `socket`. Each port in `host_ports` also gets a listener on
/// `127.0.0.1:<port>`, forwarded to the host's `127.0.0.1:<port>` through the
/// proxy.
///
/// # Errors
/// Fails when `listen` is not a loopback address (the relay must never listen
/// on a reachable interface), or when any listener cannot be bound. Every
/// listener is bound before any starts serving, so a failure stops the relay
/// before the IDE can use it.
pub fn run(listen: SocketAddr, socket: &Path, host_ports: &[u16]) -> io::Result<()> {
    if !listen.ip().is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the relay may only listen on loopback",
        ));
    }
    let listener = TcpListener::bind(listen)?;
    let mut host_listeners = Vec::new();
    for port in host_ports {
        host_listeners.push((*port, TcpListener::bind(loopback(*port))?));
    }
    for (port, host_listener) in host_listeners {
        let socket: PathBuf = socket.to_path_buf();
        thread::spawn(move || {
            for stream in host_listener.incoming().flatten() {
                let socket = socket.clone();
                thread::spawn(move || {
                    let _ = forward_host_port(stream, &socket, port);
                });
            }
        });
    }
    let socket: PathBuf = socket.to_path_buf();
    for stream in listener.incoming().flatten() {
        let socket = socket.clone();
        thread::spawn(move || {
            if let Ok(upstream) = UnixStream::connect(&socket) {
                pipe(stream, upstream);
            }
        });
    }
    Ok(())
}

/// Sends `CONNECT 127.0.0.1:<port>` to the proxy and, when it answers 200,
/// copies bytes both ways. Any other answer closes the client's connection.
fn forward_host_port(tcp: TcpStream, socket: &Path, port: u16) -> io::Result<()> {
    let mut unix = UnixStream::connect(socket)?;
    write!(
        unix,
        "CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"
    )?;
    let head = read_reply_head(&mut unix)?;
    if !head.starts_with("HTTP/1.1 200") {
        return Ok(());
    }
    pipe(tcp, unix);
    Ok(())
}

/// Reads the reply head one byte at a time, so nothing after the blank line
/// is taken from the stream. The bytes after it belong to the tunnel.
fn read_reply_head(stream: &mut UnixStream) -> io::Result<String> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= MAX_REPLY_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the proxy's reply is too long",
            ));
        }
        if stream.read(&mut byte)? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the proxy closed before replying",
            ));
        }
        head.push(byte[0]);
    }
    Ok(String::from_utf8_lossy(&head).into_owned())
}

fn loopback(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

fn pipe(tcp: TcpStream, unix: UnixStream) {
    let (Ok(mut tcp_read), Ok(mut unix_write)) = (tcp.try_clone(), unix.try_clone()) else {
        return;
    };
    let (Ok(mut unix_read), mut tcp_write) = (unix.try_clone(), tcp) else {
        return;
    };
    let up = thread::spawn(move || {
        let _ = io::copy(&mut tcp_read, &mut unix_write);
    });
    let _ = io::copy(&mut unix_read, &mut tcp_write);
    let _ = up.join();
}

/// The address the relay listens on, as a parsed value.
#[must_use]
pub fn listen_address() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 3128))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_relay_refuses_a_non_loopback_address() {
        let result = run(
            "0.0.0.0:3128".parse().unwrap_or_else(|_| listen_address()),
            Path::new("/nonexistent"),
            &[],
        );
        assert_eq!(
            result.err().map(|e| e.kind()),
            Some(io::ErrorKind::InvalidInput)
        );
    }

    #[test]
    fn the_constant_and_the_default_address_agree() {
        assert_eq!(listen_address().to_string(), PROXY_LISTEN);
    }

    /// A free loopback port. It is released before use, so another process
    /// could take it; the tests are the only users of these ports.
    fn free_port() -> io::Result<u16> {
        Ok(TcpListener::bind(loopback(0))?.local_addr()?.port())
    }

    /// Starts the relay with one host port, and waits until it accepts.
    fn start_relay(socket: &Path, port: u16) -> io::Result<()> {
        let socket = socket.to_path_buf();
        thread::spawn(move || {
            let _ = run(loopback(0), &socket, &[port]);
        });
        for _ in 0..200 {
            if TcpStream::connect(loopback(port)).is_ok() {
                return Ok(());
            }
            thread::sleep(std::time::Duration::from_millis(10));
        }
        Err(io::Error::other("the relay did not start"))
    }

    /// A fake proxy on `socket`. Each connection is handled on its own
    /// thread: it sends the request head it read on the returned channel,
    /// answers with `status`, and, when the answer is 200, echoes "pong"
    /// after reading four bytes. Connections are handled concurrently
    /// because `start_relay` opens a probe connection of its own.
    fn fake_proxy(
        socket: &Path,
        status: &'static str,
    ) -> io::Result<std::sync::mpsc::Receiver<String>> {
        let listener = std::os::unix::net::UnixListener::bind(socket)?;
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let tx = tx.clone();
                thread::spawn(move || {
                    let mut stream = stream;
                    let mut head = Vec::new();
                    let mut byte = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") {
                        match stream.read(&mut byte) {
                            Ok(1) => head.push(byte[0]),
                            _ => return,
                        }
                    }
                    let _ = tx.send(String::from_utf8_lossy(&head).into_owned());
                    let _ = stream.write_all(status.as_bytes());
                    if status.starts_with("HTTP/1.1 200") {
                        let mut buffer = [0u8; 4];
                        if stream.read_exact(&mut buffer).is_ok() {
                            let _ = stream.write_all(b"pong");
                        }
                    }
                });
            }
        });
        Ok(rx)
    }

    #[test]
    fn a_listed_port_sends_connect_to_the_proxy_then_copies_bytes() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let socket = dir.path().join("proxy.sock");
        let port = free_port()?;
        let requests = fake_proxy(&socket, "HTTP/1.1 200 Connection Established\r\n\r\n")?;
        start_relay(&socket, port)?;
        let mut client = TcpStream::connect(loopback(port))?;
        client.write_all(b"ping")?;
        let mut answer = [0u8; 4];
        client.read_exact(&mut answer)?;
        assert_eq!(&answer, b"pong");
        let request = requests
            .recv_timeout(std::time::Duration::from_secs(10))
            .map_err(|_| io::Error::other("no request reached the proxy"))?;
        assert!(
            request.starts_with(&format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\n")),
            "{request}"
        );
        Ok(())
    }

    #[test]
    fn a_listed_port_the_proxy_refuses_is_closed_at_once() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let socket = dir.path().join("proxy.sock");
        let port = free_port()?;
        let requests = fake_proxy(&socket, "HTTP/1.1 403 Forbidden\r\n\r\n")?;
        start_relay(&socket, port)?;
        let mut client = TcpStream::connect(loopback(port))?;
        let mut rest = Vec::new();
        client.read_to_end(&mut rest)?;
        assert!(rest.is_empty(), "{rest:?}");
        let request = requests
            .recv_timeout(std::time::Duration::from_secs(10))
            .map_err(|_| io::Error::other("no request reached the proxy"))?;
        assert!(request.starts_with("CONNECT 127.0.0.1:"), "{request}");
        Ok(())
    }
}
