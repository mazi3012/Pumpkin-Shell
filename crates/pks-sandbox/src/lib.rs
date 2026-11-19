//! Sandbox backend for Pumpkin-Shell
//!
//! This crate provides the `SandboxBackend` trait and platform-specific
//! implementations. The Linux implementation is behind `#[cfg(target_os = "linux")]`.

pub mod backend;

pub use backend::{create_backend, SandboxBackend};
