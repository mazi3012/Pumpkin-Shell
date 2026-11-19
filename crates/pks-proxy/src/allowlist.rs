//! HTTP CONNECT allowlist for known services.

use std::collections::HashSet;
use std::net::SocketAddr;

use anyhow::Result;

/// Known model API hosts that get automatic access.
const MODEL_API_HOSTS: &[&str] = &[
    "api.openai.com",
    "api.anthropic.com",
    "api.google.com",
    "api.github.com",
];

/// Shared cloud domains that must not use wildcards.
const SHARED_CLOUD_DOMAINS: &[&str] = &[
    "*.amazonaws.com",
    "*.googleapis.com",
    "*.blob.core.windows.net",
];

/// Allowed host:port pairs.
#[derive(Debug, Clone)]
pub struct Allowlist {
    /// Exact host:port entries.
    exact: HashSet<String>,
    /// Host patterns (may include wildcards for non-shared domains).
    patterns: Vec<String>,
    /// Per-host upload thresholds in bytes.
    upload_limits: std::collections::HashMap<String, u64>,
}

impl Allowlist {
    /// Create a new allowlist with default model API access.
    pub fn new() -> Self {
        let mut exact = HashSet::new();
        for host in MODEL_API_HOSTS {
            exact.insert(format!("{}:443", host));
        }

        Self {
            exact,
            patterns: Vec::new(),
            upload_limits: std::collections::HashMap::new(),
        }
    }

    /// Add an exact host:port entry.
    pub fn add_exact(&mut self, host: &str, port: u16) {
        self.exact.insert(format!("{}:{}", host, port));
    }

    /// Add a pattern entry (wildcards allowed for non-shared domains).
    pub fn add_pattern(&mut self, pattern: &str) -> Result<()> {
        // Reject wildcards for shared cloud domains
        for shared in SHARED_CLOUD_DOMAINS {
            if pattern.contains(shared.replace('*', "").as_str()) {
                anyhow::bail!("wildcard not allowed for shared domain: {}", shared);
            }
        }
        self.patterns.push(pattern.to_string());
        Ok(())
    }

    /// Set upload limit for a host.
    pub fn set_upload_limit(&mut self, host: &str, bytes: u64) {
        self.upload_limits.insert(host.to_string(), bytes);
    }

    /// Check if a host:port is allowed.
    pub fn is_allowed(&self, host: &str, port: u16) -> bool {
        let key = format!("{}:{}", host, port);
        
        // Check exact matches first
        if self.exact.contains(&key) {
            return true;
        }

        // Check patterns
        for pattern in &self.patterns {
            if Self::pattern_matches(pattern, host, port) {
                return true;
            }
        }

        false
    }

    /// Check if pattern matches host:port.
    fn pattern_matches(pattern: &str, host: &str, port: u16) -> bool {
        // Simple pattern matching: * matches any subdomain
        if pattern.contains('*') {
            let pattern_host = pattern.split(':').next().unwrap_or(pattern);
            let pattern_prefix = pattern_host.trim_end_matches('*');
            
            if pattern_prefix.is_empty() {
                return true; // * matches everything
            }
            
            // Check if host ends with pattern prefix or is a subdomain
            if host.ends_with(pattern_prefix) {
                // Ensure we're matching at a subdomain boundary
                if host.len() == pattern_prefix.len() {
                    return true;
                }
                if host[..host.len() - pattern_prefix.len()].ends_with('.') {
                    return true;
                }
            }
            false
        } else {
            // Exact match
            let pattern_host = pattern.split(':').next().unwrap_or(pattern);
            host == pattern_host
        }
    }

    /// Get upload limit for a host.
    pub fn upload_limit(&self, host: &str) -> Option<u64> {
        self.upload_limits.get(host).copied()
    }
}

impl Default for Allowlist {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allowlist_new() {
        let allowlist = Allowlist::new();
        // Model API hosts should be allowed
        assert!(allowlist.is_allowed("api.openai.com", 443));
        assert!(allowlist.is_allowed("api.anthropic.com", 443));
    }

    #[test]
    fn test_allowlist_exact() {
        let mut allowlist = Allowlist::new();
        allowlist.add_exact("example.com", 8080);
        
        assert!(allowlist.is_allowed("example.com", 8080));
        assert!(!allowlist.is_allowed("example.com", 443));
        assert!(!allowlist.is_allowed("other.com", 8080));
    }

    #[test]
    fn test_allowlist_pattern() {
        let mut allowlist = Allowlist::new();
        allowlist.add_pattern("*.example.com").unwrap();
        
        assert!(allowlist.is_allowed("api.example.com", 443));
        assert!(allowlist.is_allowed("www.example.com", 80));
        assert!(!allowlist.is_allowed("example.com", 443));
        assert!(!allowlist.is_allowed("other.com", 443));
    }

    #[test]
    fn test_allowlist_reject_shared_domain_wildcard() {
        let mut allowlist = Allowlist::new();
        
        // Should reject wildcard for shared cloud domains
        assert!(allowlist.add_pattern("*.amazonaws.com").is_err());
        assert!(allowlist.add_pattern("*.googleapis.com").is_err());
        assert!(allowlist.add_pattern("*.blob.core.windows.net").is_err());
    }

    #[test]
    fn test_upload_limit() {
        let mut allowlist = Allowlist::new();
        allowlist.set_upload_limit("example.com", 10_000_000);
        
        assert_eq!(allowlist.upload_limit("example.com"), Some(10_000_000));
        assert_eq!(allowlist.upload_limit("other.com"), None);
    }
}
