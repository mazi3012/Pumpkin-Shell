//! Which destination addresses the proxy refuses (PRD FR-NET: "refuses
//! private, link-local and metadata addresses").
//!
//! The lists are written out here rather than taken from `Ipv4Addr::is_global`,
//! which is nightly-only on the pinned toolchain. Every range is the IANA
//! special-purpose range it names. The list is conservative: an address that
//! is not clearly public is refused. Tests pin each range.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Why an address is refused, or `None` when it may be dialed.
#[must_use]
pub fn refusal(ip: IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => refuse_v4(v4),
        IpAddr::V6(v6) => refuse_v6(v6),
    }
}

fn refuse_v4(ip: Ipv4Addr) -> Option<&'static str> {
    let [a, b, c, _] = ip.octets();
    let reason = match (a, b, c) {
        // 0.0.0.0/8: "this network"; 0.0.0.0 reaches the local host on some systems.
        (0, _, _) => "unspecified or 'this network' (0.0.0.0/8)",
        // 10.0.0.0/8: private.
        (10, _, _) => "private network (10.0.0.0/8)",
        // 127.0.0.0/8: loopback.
        (127, _, _) => "loopback (127.0.0.0/8)",
        // 169.254.0.0/16: link-local. Includes the cloud metadata address 169.254.169.254.
        (169, 254, _) => "link-local or cloud metadata (169.254.0.0/16)",
        // 172.16.0.0/12: private.
        (172, 16..=31, _) => "private network (172.16.0.0/12)",
        // 192.0.0.0/24: IETF protocol assignments.
        (192, 0, 0) => "IETF protocol assignments (192.0.0.0/24)",
        // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24: documentation.
        (192, 0, 2) | (198, 51, 100) | (203, 0, 113) => "documentation (RFC 5737)",
        // 192.88.99.0/24: deprecated 6to4 relay anycast.
        (192, 88, 99) => "deprecated 6to4 relay (192.88.99.0/24)",
        // 192.168.0.0/16: private.
        (192, 168, _) => "private network (192.168.0.0/16)",
        // 198.18.0.0/15: benchmarking.
        (198, 18..=19, _) => "benchmarking (198.18.0.0/15)",
        // 100.64.0.0/10: shared address space (carrier-grade NAT).
        (100, 64..=127, _) => "shared address space (100.64.0.0/10)",
        // 224.0.0.0/4: multicast; 240.0.0.0/4: reserved, includes broadcast.
        (224..=255, _, _) => "multicast or reserved (224.0.0.0/4 and above)",
        _ => return None,
    };
    Some(reason)
}

fn refuse_v6(ip: Ipv6Addr) -> Option<&'static str> {
    // IPv4-mapped (::ffff:a.b.c.d): judged by the IPv4 address inside.
    if let Some(v4) = ip.to_ipv4_mapped() {
        return refuse_v4(v4);
    }
    let segments = ip.segments();
    let [s0, s1, _, _, _, _, _, _] = segments;
    let reason = if ip.is_unspecified() {
        "unspecified (::)"
    } else if ip.is_loopback() {
        "loopback (::1)"
    } else if s0 == 0x64 && s1 == 0xff9b {
        // 64:ff9b::/96: NAT64 embeds an IPv4 address that may be private.
        "NAT64 well-known prefix (64:ff9b::/96)"
    } else if s0 == 0x100 && s1 == 0 && segments[2] == 0 && segments[3] == 0 {
        "discard-only (100::/64)"
    } else if s0 == 0x2001 && s1 == 0 {
        "Teredo tunnel (2001::/32)"
    } else if s0 == 0x2001 && s1 == 0xdb8 {
        "documentation (2001:db8::/32)"
    } else if s0 == 0x2002 {
        // 2002::/16: 6to4 embeds an IPv4 address.
        "6to4 tunnel (2002::/16)"
    } else if s0 & 0xfe00 == 0xfc00 {
        "unique local (fc00::/7)"
    } else if s0 & 0xffc0 == 0xfe80 {
        "link-local (fe80::/10)"
    } else if s0 & 0xffc0 == 0xfec0 {
        "deprecated site-local (fec0::/10)"
    } else if s0 & 0xff00 == 0xff00 {
        "multicast (ff00::/8)"
    } else {
        return None;
    };
    Some(reason)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(text: &str) -> IpAddr {
        IpAddr::V4(text.parse().unwrap_or(Ipv4Addr::UNSPECIFIED))
    }

    fn v6(text: &str) -> IpAddr {
        IpAddr::V6(text.parse().unwrap_or(Ipv6Addr::UNSPECIFIED))
    }

    #[test]
    fn refuses_every_listed_ipv4_range() {
        for text in [
            "0.0.0.0",
            "0.255.255.255",
            "10.0.0.1",
            "10.255.255.255",
            "127.0.0.1",
            "127.255.255.255",
            "169.254.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.1",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.19.255.255",
            "198.51.100.7",
            "203.0.113.9",
            "100.64.0.1",
            "100.127.255.255",
            "224.0.0.1",
            "239.255.255.255",
            "240.0.0.1",
            "255.255.255.255",
        ] {
            assert!(refusal(v4(text)).is_some(), "{text} was allowed");
        }
    }

    #[test]
    fn allows_public_ipv4_including_the_edges_of_each_range() {
        for text in [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.216.34",
            "172.15.255.255",
            "172.32.0.0",
            "192.167.255.255",
            "192.169.0.0",
            "169.253.255.255",
            "169.255.0.0",
            "100.63.255.255",
            "100.128.0.0",
            "198.17.255.255",
            "198.20.0.0",
            "11.0.0.1",
            "126.255.255.255",
        ] {
            assert!(
                refusal(v4(text)).is_none(),
                "{text} was refused: {:?}",
                refusal(v4(text))
            );
        }
    }

    #[test]
    fn refuses_listed_ipv6_ranges_and_allows_public_ones() {
        for text in [
            "::",
            "::1",
            "64:ff9b::1",
            "100::1",
            "2001::1",
            "2001:db8::1",
            "2002::1",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "febf::1",
            "fec0::1",
            "ff02::1",
        ] {
            assert!(refusal(v6(text)).is_some(), "{text} was allowed");
        }
        for text in [
            "2606:4700:4700::1111",
            "2a00:1450::1",
            "2001:4860:4860::8888",
        ] {
            assert!(refusal(v6(text)).is_none(), "{text} was refused");
        }
    }

    #[test]
    fn ipv4_mapped_addresses_are_judged_by_the_ipv4_inside() {
        assert!(refusal(v6("::ffff:10.0.0.1")).is_some());
        assert!(refusal(v6("::ffff:169.254.169.254")).is_some());
        assert!(refusal(v6("::ffff:93.184.216.34")).is_none());
    }
}
