//! `pks-proxy`: egress proxy for the Pumpkin-Shell sandbox.
//!
//! The proxy runs inside the sandbox on loopback and forwards to a Unix socket
//! on the host. It implements HTTP CONNECT with allowlists, DNS resolution,
//! and bandwidth monitoring.

pub mod allowlist;
pub mod dns;
pub mod proxy;
pub mod relay;

pub use proxy::{Proxy, ProxyConfig};
