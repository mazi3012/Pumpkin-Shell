//! DNS resolution with security checks.

use anyhow::{Result, anyhow};
use ipnet::IpNet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

/// Check if an IP address is private.
pub fn is_private(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            // 10.0.0.0/8
            if v4.octets()[0] == 10 {
                return true;
            }
            // 172.16.0.0/12
            if v4.octets()[0] == 172 && (16..=31).contains(&v4.octets()[1]) {
                return true;
            }
            // 192.168.0.0/16
            if v4.octets()[0] == 192 && v4.octets()[1] == 168 {
                return true;
            }
            // 127.0.0.0/8 (loopback)
            if v4.octets()[0] == 127 {
                return true;
            }
            // 169.254.0.0/16 (link-local)
            if v4.octets()[0] == 169 && v4.octets()[1] == 254 {
                return true;
            }
            // 0.0.0.0/8 (this network)
            if v4.octets()[0] == 0 {
                return true;
            }
        }
        IpAddr::V6(v6) => {
            // IPv6 loopback ::1
            if v6.segments() == [0, 0, 0, 0, 0, 0, 0, 1] {
                return true;
            }
            // IPv6 unique local (fc00::/7)
            if v6.segments()[0] & 0xfe00 == 0xfc00 {
                return true;
            }
            // IPv6 link-local (fe80::/10)
            if v6.segments()[0] & 0xffc0 == 0xfe80 {
                return true;
            }
            // IPv6 unspecified (::)
            if v6.segments() == [0, 0, 0, 0, 0, 0, 0, 0] {
                return true;
            }
        }
    }
    false
}

/// Check if an IP is a metadata address.
pub fn is_metadata(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            // AWS metadata: 169.254.169.254
            *v4 == Ipv4Addr::new(169, 254, 169, 254)
        }
        IpAddr::V6(_) => false,
    }
}

/// Check if an IP is link-local.
pub fn is_link_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            // 169.254.0.0/16
            v4.octets()[0] == 169 && v4.octets()[1] == 254
        }
        IpAddr::V6(v6) => {
            // fe80::/10
            v6.segments()[0] & 0xffc0 == 0xfe80
        }
    }
}

/// Validate a resolved address.
pub fn validate_address(addr: &SocketAddr) -> Result<()> {
    let ip = addr.ip();
    
    if is_private(&ip) {
        return Err(anyhow!(
            "NET-PRIVATE-IP: private IP address {} not allowed",
            ip
        ));
    }
    
    if is_metadata(&ip) {
        return Err(anyhow!(
            "NET-PRIVATE-IP: metadata address {} not allowed",
            ip
        ));
    }
    
    if is_link_local(&ip) {
        return Err(anyhow!(
            "NET-PRIVATE-IP: link-local address {} not allowed",
            ip
        ));
    }
    
    Ok(())
}

/// Parse a socket address from a string.
pub fn parse_socket_addr(s: &str) -> Result<SocketAddr> {
    SocketAddr::from_str(s).map_err(|e| anyhow!("invalid socket address: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_private_ipv4() {
        assert!(is_private(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_private(&IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(is_private(&IpAddr::V4(Ipv4Addr::new(172, 31, 255, 255))));
        assert!(is_private(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(is_private(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(is_private(&IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))));
        assert!(is_private(&IpAddr::V4(Ipv4Addr::new(0, 0, 0, 1))));
        assert!(!is_private(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!is_private(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
    }

    #[test]
    fn test_is_private_ipv6() {
        assert!(is_private(&IpAddr::V6("fc00::1".parse().unwrap())));
        assert!(is_private(&IpAddr::V6("fe80::1".parse().unwrap())));
        assert!(is_private(&IpAddr::V6("::1".parse().unwrap())));
        assert!(is_private(&IpAddr::V6("::".parse().unwrap())));
        assert!(!is_private(&IpAddr::V6("2001:4860:4860::8888".parse().unwrap())));
    }

    #[test]
    fn test_is_metadata() {
        assert!(is_metadata(&IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))));
        assert!(!is_metadata(&IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))));
        assert!(!is_metadata(&IpAddr::V6("::1".parse().unwrap())));
    }

    #[test]
    fn test_is_link_local() {
        assert!(is_link_local(&IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))));
        assert!(is_link_local(&IpAddr::V6("fe80::1".parse().unwrap())));
        assert!(!is_link_local(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn test_validate_address() {
        assert!(validate_address(&SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 443)).is_ok());
        assert!(validate_address(&SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443)).is_err());
        assert!(validate_address(&SocketAddr::new(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)), 443)).is_err());
        assert!(validate_address(&SocketAddr::new(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)), 443)).is_err());
    }

    #[test]
    fn test_parse_socket_addr() {
        let addr = parse_socket_addr("1.2.3.4:8080").unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(addr.port(), 8080);
        
        let addr = parse_socket_addr("[::1]:8080").unwrap();
        assert_eq!(addr.ip(), IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(addr.port(), 8080);
    }
}
