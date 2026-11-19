//! The egress proxy (PRD FR-NET, Phase 9).
//!
//! The IDE reaches the internet only through this proxy. The proxy accepts
//! HTTP `CONNECT` requests on a Unix socket, and each request is decided:
//!
//! - an endpoint on the user's allowlist (exact `host:port`) is connected;
//! - anything else is asked about, and held for 20 seconds; no answer, or a
//!   "deny", refuses it; in monitor mode it is connected and reported;
//! - a name that resolves to any private, link-local, loopback or metadata
//!   address is refused, whatever the allowlist says;
//! - the address that was checked is the one dialed.
//!
//! Every decision is reported as a finding, and the caller records them.

pub mod addr;
pub mod engine;
#[cfg(unix)]
pub mod server;

pub use engine::{
    Answer, Asker, Config, Dialer, Engine, EventSink, Resolver, SystemResolver, TcpDialer,
};
#[cfg(unix)]
pub use server::serve;
