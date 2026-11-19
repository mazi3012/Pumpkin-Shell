//! Sandbox-side relay for proxy connections.

use anyhow::Result;
use hyper::body::Incoming;
use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::{Method, Request, Response};
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, warn, error};

/// Relay configuration.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// Local loopback address for the relay.
    pub local_address: SocketAddr,
    /// Maximum buffer size for data transfer.
    pub max_buffer_size: usize,
    /// Per-host upload tracking.
    pub upload_tracker: UploadTracker,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            local_address: SocketAddr::new("127.0.0.1".parse().unwrap(), 1080),
            max_buffer_size: 65536,
            upload_tracker: UploadTracker::new(),
        }
    }
}

/// Upload tracker for monitoring data sent.
#[derive(Debug, Clone)]
pub struct UploadTracker {
    /// Bytes uploaded per host.
    pub bytes_per_host: std::collections::HashMap<String, u64>,
    /// Threshold for large upload alerts (10 MB).
    pub large_upload_threshold: u64,
}

impl UploadTracker {
    /// Create a new upload tracker.
    pub fn new() -> Self {
        Self {
            bytes_per_host: std::collections::HashMap::new(),
            large_upload_threshold: 10_000_000, // 10 MB
        }
    }

    /// Record uploaded bytes for a host.
    pub fn record_upload(&mut self, host: &str, bytes: u64) {
        *self.bytes_per_host.entry(host.to_string()).or_insert(0) += bytes;
    }

    /// Check if a host has exceeded the large upload threshold.
    pub fn is_large_upload(&self, host: &str) -> bool {
        self.bytes_per_host.get(host).map_or(false, |&bytes| bytes > self.large_upload_threshold)
    }

    /// Get uploaded bytes for a host.
    pub fn get_bytes(&self, host: &str) -> Option<u64> {
        self.bytes_per_host.get(host).copied()
    }

    /// Reset tracking for a host.
    pub fn reset(&mut self, host: &str) {
        self.bytes_per_host.remove(host);
    }
}

impl Default for UploadTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Sandbox-side relay that forwards HTTP CONNECT requests.
pub struct Relay {
    config: RelayConfig,
}

impl Relay {
    /// Create a new relay with the given configuration.
    pub fn new(config: RelayConfig) -> Self {
        Self { config }
    }

    /// Start the relay server.
    pub async fn run(self) -> Result<()> {
        let listener = tokio::net::TcpListener::bind(&self.config.local_address).await?;
        info!("Relay listening on {}", self.config.local_address);

        loop {
            let (stream, addr) = listener.accept().await?;
            info!("Relay connection from {}", addr);
            
            let config = self.config.clone();
            tokio::task::spawn(async move {
                if let Err(e) = Self::handle_relay(stream, config).await {
                    error!("Relay error: {}", e);
                }
            });
        }
    }

    /// Handle a relay connection.
    async fn handle_relay(stream: TcpStream, config: RelayConfig) -> Result<()> {
        let http = Http::new();
        let service = service_fn(move |req| {
            let config = config.clone();
            async move { Self::handle_relay_request(req, config).await }
        });

        http.serve_connection(stream, service).await?;
        Ok(())
    }

    /// Handle a relay request.
    async fn handle_relay_request(req: Request<Incoming>, config: RelayConfig) -> Result<Response<Incoming>> {
        match req.method() {
            Method::CONNECT => {
                let target = req.uri().clone();
                let target_str = target.to_string();
                
                // Parse host:port
                let (host, port) = Self::parse_host_port(&target_str)?;
                
                // Check for large upload
                if config.upload_tracker.is_large_upload(&host) {
                    warn!(
                        "NET-LARGE-UPLOAD: {} sent {} bytes",
                        host,
                        config.upload_tracker.get_bytes(&host).unwrap_or(0)
                    );
                }

                // Connect to the target
                match TcpStream::connect(format!("{}:{}", host, port)).await {
                    Ok(target_stream) => {
                        info!("Relay connected to {}:{}", host, port);
                        
                        // Create a response indicating connection established
                        let response = Response::builder()
                            .status(200)
                            .body(Incoming::empty())?;
                        
                        Ok(response)
                    }
                    Err(e) => {
                        error!("Failed to connect to {}:{}: {}", host, port, e);
                        
                        Ok(Response::builder()
                            .status(502)
                            .body(Incoming::empty())?)
                    }
                }
            }
            _ => {
                Ok(Response::builder()
                    .status(405)
                    .body(Incoming::empty())?)
            }
        }
    }

    /// Parse host:port from a CONNECT target.
    fn parse_host_port(target: &str) -> Result<(String, u16)> {
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
    fn test_upload_tracker() {
        let mut tracker = UploadTracker::new();
        
        tracker.record_upload("example.com", 5_000_000);
        assert!(!tracker.is_large_upload("example.com"));
        
        tracker.record_upload("example.com", 6_000_000);
        assert!(tracker.is_large_upload("example.com"));
        assert_eq!(tracker.get_bytes("example.com"), Some(11_000_000));
        
        tracker.reset("example.com");
        assert!(!tracker.is_large_upload("example.com"));
        assert_eq!(tracker.get_bytes("example.com"), None);
    }
}
