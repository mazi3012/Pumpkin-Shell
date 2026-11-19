//! The accept loop: serves the proxy on a Unix socket until asked to stop.

use std::io;
use std::os::unix::net::UnixListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use crate::engine::Engine;

/// How long a client may take to send its request head.
const CLIENT_READ_TIMEOUT: Duration = Duration::from_secs(10);
const POLL: Duration = Duration::from_millis(50);

/// Accepts connections until `stop` is set. Each connection runs on its own
/// thread. Returns when the flag is seen.
///
/// # Errors
/// Fails if the listener cannot be switched to non-blocking mode.
pub fn serve(listener: UnixListener, engine: Arc<Engine>, stop: Arc<AtomicBool>) -> io::Result<()> {
    listener.set_nonblocking(true)?;
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => {
                // The accepted stream must block, with a timeout on the head.
                if stream.set_nonblocking(false).is_err()
                    || stream.set_read_timeout(Some(CLIENT_READ_TIMEOUT)).is_err()
                {
                    continue;
                }
                let engine = Arc::clone(&engine);
                thread::spawn(move || engine.handle(stream));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => thread::sleep(POLL),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
