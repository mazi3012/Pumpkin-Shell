//! Exact network endpoints (PRD FR-NET: "CONNECT allowlist of exact
//! `host:port`. Wildcards over shared cloud domains are rejected").
//!
//! An endpoint has an explicit port and no wildcard. Anything else (a bare
//! host, `*.example.com`, a port 0, a space, uppercase-only oddities that do
//! not normalize) is refused, so an allowlist entry can name exactly one
//! destination.

use std::fmt;

/// A host and a port, both exact.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HostPort {
    host: String,
    port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HostPortError {
    #[error("{0:?} must be host:port with an explicit port")]
    MissingPort(String),
    #[error("{0:?} is not a valid port (1 to 65535)")]
    BadPort(String),
    #[error("{0:?} has a wildcard; an allowlist entry must name one exact host")]
    Wildcard(String),
    #[error("{0:?} is not a valid host name")]
    BadHost(String),
}

impl HostPort {
    /// Parses `host:port` or `[ipv6]:port`. The host is lowercased.
    ///
    /// # Errors
    /// Fails when the port is missing or out of range, or the host contains a
    /// wildcard or characters a host name cannot have.
    pub fn parse(text: &str) -> Result<Self, HostPortError> {
        if text.contains('*') {
            return Err(HostPortError::Wildcard(text.to_owned()));
        }
        let (host, port) = if let Some(rest) = text.strip_prefix('[') {
            let (addr, after) = rest
                .split_once(']')
                .ok_or_else(|| HostPortError::MissingPort(text.to_owned()))?;
            let port = after
                .strip_prefix(':')
                .ok_or_else(|| HostPortError::MissingPort(text.to_owned()))?;
            if addr.parse::<std::net::Ipv6Addr>().is_err() {
                return Err(HostPortError::BadHost(text.to_owned()));
            }
            (addr.to_owned(), port)
        } else {
            let (host, port) = text
                .rsplit_once(':')
                .ok_or_else(|| HostPortError::MissingPort(text.to_owned()))?;
            if host.contains(':') {
                // An unbracketed IPv6 address has ambiguous ports.
                return Err(HostPortError::BadHost(text.to_owned()));
            }
            (host.to_owned(), port)
        };
        let port: u16 = port
            .parse()
            .ok()
            .filter(|p| *p != 0)
            .ok_or_else(|| HostPortError::BadPort(text.to_owned()))?;
        let host = host.to_ascii_lowercase();
        if !valid_host(&host) {
            return Err(HostPortError::BadHost(text.to_owned()));
        }
        Ok(Self { host, port })
    }

    /// The host name or IP literal, lowercase.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl fmt::Display for HostPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

/// Accepts IP literals, and host names made of LDH labels (letters, digits,
/// hyphens) of 1 to 63 characters, at most 253 characters in total.
fn valid_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    if host.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(text: &str) -> HostPort {
        HostPort::parse(text).unwrap_or_else(|e| panic!("{text}: {e}"))
    }

    #[test]
    fn parses_exact_names_and_lowercases_the_host() {
        let endpoint = ok("API.Example.COM:443");
        assert_eq!(endpoint.host(), "api.example.com");
        assert_eq!(endpoint.port(), 443);
        assert_eq!(endpoint.to_string(), "api.example.com:443");
    }

    #[test]
    fn parses_bracketed_ipv6_and_ip_literals() {
        assert_eq!(ok("[2001:db8::1]:8443").to_string(), "[2001:db8::1]:8443");
        assert_eq!(ok("93.184.216.34:80").host(), "93.184.216.34");
    }

    #[test]
    fn refuses_wildcards_in_any_position() {
        for text in ["*.example.com:443", "example.*:443", "*:443", "a.*.com:80"] {
            assert!(
                matches!(HostPort::parse(text), Err(HostPortError::Wildcard(_))),
                "{text}"
            );
        }
    }

    #[test]
    fn refuses_a_missing_or_bad_port() {
        for text in [
            "example.com",
            "example.com:",
            "example.com:0",
            "example.com:65536",
            "example.com:http",
            "example.com:-1",
        ] {
            assert!(HostPort::parse(text).is_err(), "{text} was accepted");
        }
        assert!(matches!(
            HostPort::parse("example.com"),
            Err(HostPortError::MissingPort(_))
        ));
    }

    #[test]
    fn refuses_names_that_are_not_host_names() {
        for text in [
            "exa mple.com:443",
            "under_score.com:443",
            "-lead.com:443",
            "trail-.com:443",
            "a..b:443",
            "ex\u{e9}.com:443",
            ":443",
            "a/b:443",
            "example.com/:443",
            "[::1:443",
            "fe80::1:443",
        ] {
            assert!(HostPort::parse(text).is_err(), "{text:?} was accepted");
        }
        let long_label = format!("{}.com:443", "a".repeat(64));
        assert!(HostPort::parse(&long_label).is_err());
    }

    #[test]
    fn equal_endpoints_compare_equal_after_normalizing_case() {
        assert_eq!(ok("EXAMPLE.com:443"), ok("example.com:443"));
        assert_ne!(ok("example.com:443"), ok("example.com:444"));
    }
}
