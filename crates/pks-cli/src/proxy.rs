//! CLI commands for proxy management.

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Proxy management commands.
#[derive(Parser)]
pub struct ProxyArgs {
    #[command(subcommand)]
    pub cmd: ProxyCmd,
}

/// Available proxy commands.
#[derive(Subcommand)]
pub enum ProxyCmd {
    /// Start the proxy server.
    Start(StartArgs),
    /// Stop the proxy server.
    Stop,
    /// Show proxy status.
    Status,
}

/// Start proxy arguments.
#[derive(Parser)]
pub struct StartArgs {
    /// Path to the Unix socket.
    #[arg(long, default_value = "/tmp/pks-proxy.sock")]
    pub socket: PathBuf,

    /// Local relay address (loopback).
    #[arg(long, default_value = "127.0.0.1:1080")]
    pub relay: String,

    /// Allowlist file path (TOML).
    #[arg(long)]
    pub allowlist: Option<PathBuf>,

    /// Headless mode (deny unknown domains without prompting).
    #[arg(long, default_value = "false")]
    pub headless: bool,

    /// Timeout for unknown domain prompts (seconds).
    #[arg(long, default_value = "20")]
    pub timeout: u64,
}

/// Run the proxy command.
pub fn run(args: &ProxyArgs) -> Result<()> {
    match &args.cmd {
        ProxyCmd::Start(start_args) => start_proxy(start_args),
        ProxyCmd::Stop => stop_proxy(),
        ProxyCmd::Status => status_proxy(),
    }
}

fn start_proxy(args: &StartArgs) -> Result<()> {
    println!("Starting proxy...");
    println!("  Socket: {}", args.socket.display());
    println!("  Relay: {}", args.relay);
    println!("  Headless: {}", args.headless);
    println!("  Timeout: {}s", args.timeout);
    
    // TODO: Actually start the proxy server
    // This would spawn the proxy in the background
    Ok(())
}

fn stop_proxy() -> Result<()> {
    println!("Stopping proxy...");
    // TODO: Actually stop the proxy server
    Ok(())
}

fn status_proxy() -> Result<()> {
    println!("Proxy status:");
    // TODO: Actually check proxy status
    println!("  Not running");
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::proxy::{ProxyArgs, ProxyCmd, StartArgs};

    #[test]
    fn test_proxy_args_parse() {
        let args = ProxyArgs::parse_from(["proxy", "start", "--headless"]);
        match &args.cmd {
            ProxyCmd::Start(start) => {
                assert!(start.headless);
            }
            _ => panic!("Expected Start command"),
        }
    }
}
