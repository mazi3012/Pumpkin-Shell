//! HTTP CONNECT proxy server.

use anyhow::Result;
use futures::StreamExt;
use hyper::body::{Body, Incoming};
use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::{Method, Request, Response};
use std::net::SocketAddr;
use std::path::PathBuf;
use tokio::net::UnixListener;
use tokio::net::TcpStream;
use tracing::{info, warn, error};

use crate::allowlist::Allowlist;

/// Configuration for the proxy.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Path to the Unix socket for host communication.
    pub socket_path: PathBuf,
    /// Host relay address (loopback in sandbox).
    pub relay_address: SocketAddr,
    /// Allowlist of allowed host:port pairs.
    pub allowlist: Allowlist,
    /// Unknown domain timeout in seconds.
    pub unknown_timeout: u64,
    /// Enable headless mode (deny unknown domains without prompting).
    pub headless: bool,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            socket_path: PathBuf::from("/tmp/pks-proxy.sock"),
            relay_address: SocketAddr::new("127.0.0.1".parse().unwrap(), 1080),
            allowlist: Allowlist::new(),
            unknown_timeout: 20,
            headless: false,
        }
    }
}

/// HTTP CONNECT proxy.
pub struct Proxy {
    config: ProxyConfig,
}

impl Proxy {
    /// Create a new proxy with the given configuration.
    pub fn new(config: ProxyConfig) -> Self {
        Self { config }
    }

    /// Run the proxy server.
    pub async fn run(self) -> Result<()> {
        // Remove existing socket if it exists
        if self.config.socket_path.exists() {
            std::fs::remove_file(&self.config.socket_path)?;
        }

        let listener = UnixListener::bind(&self.config.socket_path)?;
        info!("Proxy listening on {}", self.config.socket_path.display());

        loop {
            let (stream, _addr) = listener.accept().await?;
            let config = self.config.clone();
            
            tokio::task::spawn(async move {
                if let Err(e) = Self::handle_connection(stream, config).await {
                    error!("Connection error: {}", e);
                }
            });
        }
    }

    /// Handle a single connection.
    async fn handle_connection(
        stream: tokio::net::UnixStream,
        config: ProxyConfig,
    ) -> Result<()> {
        let http = Http::new();
        let service = service_fn(move |req| {
            let config = config.clone();
            async move { Self::handle_request(req, config).await }
        });

        http.serve_connection(stream, service).await?;
        Ok(())
    }

    /// Handle an HTTP request.
    async fn handle_request(
        req: Request<Incoming>,
        config: ProxyConfig,
    ) -> Result<Response<hyper::body::Body>> {
        match req.method() {
            Method::CONNECT => {
                let target = req.uri().clone();
                let target_str = target.to_string();
                
                // Parse host:port from CONNECT target
                let (host, port) = Self::parse_host_port(&target_str)?;
                
                // Check allowlist
                if !config.allowlist.is_allowed(&host, port) {
                    return Ok(Response::builder()
                        .status(403)
                        .body("host not allowed".into())?);
                }

                // Try to connect to the relay
                match tokio::net::TcpStream::connect(config.relay_address).await {
                    Ok(relay) => {
                        // Forward the connection
                        let response = Response::builder()
                            .status(200)
                            .body("Connection established".into())?;
                        
                        // TODO: Tunnel data between client and relay
                        // This would require async read/write handling
                        Ok(response)
                    }
                    Err(e) => {
                        warn!("Failed to connect to relay: {}", e);
                        
                        // If headless, deny unknown domains
                        if config.headless {
                            return Ok(Response::builder()
                                .status(503)
                                .body("proxy unavailable".into())?);
                        }
                        
                        // In head mode, we'd prompt the user here
                        // For now, just log and continue
                        info!("CONNECT to {}:{} (unknown domain, would prompt)", host, port);
                        
                        Ok(Response::builder()
                            .status(200)
                            .body("Connection established".into())?)
                    }
                }
            }
            _ => {
                Ok(Response::builder()
                    .status(405)
                    .body("method not allowed".into())?)
            }
        }
    }

    /// Parse host:port from a CONNECT target.
    fn parse_host_port(target: &str) -> Result<(String, u16)> {
        // CONNECT target is typically "host:port"
        let parts: Vec<&str> = target.split(':').collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!("invalid CONNECT target: {}", target));
        }
        
        let host = parts[0].to_string();
        let port: u16 = parts[1].parse()?;
        Ok((host, port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_host_port() {
        let (host, port) = Proxy::parse_host_port("api.openai.com:443").unwrap();
        assert_eq!(host, "api.openai.com");
        assert_eq!(port, 443);
        
        let (host, port) = Proxy::parse_host_port("localhost:8080").unwrap();
        assert_eq!(host, "localhost");
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_parse_host_port_invalid() {
        assert!(Proxy::parse_host_port("api.openai.com").is_err());
        assert!(Proxy::parse_host_port("api.openai.com:443:extra").is_err());
        assert!(Proxy::parse_host_port("invalid:port").is_err());
    }
}
