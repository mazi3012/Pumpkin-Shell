//! The relay inside the sandbox (Phase 9). It listens on loopback and forwards
//! each TCP connection to the host proxy's Unix socket. The sandbox has no
//! other network, so the proxy is the only way out.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::thread;

/// Where the proxy's socket appears inside the sandbox.
pub const PROXY_SOCKET_IN: &str = "/run/pks/proxy.sock";
/// The loopback address the IDE is told to use as its proxy.
pub const PROXY_LISTEN: &str = "127.0.0.1:3128";

/// Serves forever: each connection is copied both ways to a new connection
/// on `socket`.
///
/// # Errors
/// Fails when `listen` is not a loopback address (the relay must never listen
/// on a reachable interface), or when the listener cannot be bound.
pub fn run(listen: SocketAddr, socket: &Path) -> io::Result<()> {
    if !listen.ip().is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the relay may only listen on loopback",
        ));
    }
    let listener = TcpListener::bind(listen)?;
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
}
