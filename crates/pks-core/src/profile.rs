//! Built-in IDE profiles. A profile lists the endpoints an IDE needs to run,
//! so a new user can sign in without writing a policy file (PRD FR-POL,
//! Phase 13.2). The profile files live in `profiles/` and are compiled in.

use std::collections::BTreeSet;

use crate::net::HostPort;
use crate::policy::{PolicyError, PolicyFile};

const KIRO: &str = include_str!("../../../profiles/kiro.toml");

/// The endpoints a Kiro IDE installation needs, from `profiles/kiro.toml`.
///
/// # Errors
/// Fails only if the built-in profile is malformed. That is a build bug.
pub fn kiro_allow() -> Result<BTreeSet<HostPort>, PolicyError> {
    Ok(PolicyFile::parse(KIRO)?.allow)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_kiro_profile_lists_the_eight_documented_endpoints() {
        let allow = kiro_allow().expect("the built-in profile parses");
        let mut names: Vec<String> = allow.iter().map(ToString::to_string).collect();
        names.sort();
        assert_eq!(
            names,
            [
                "app.kiro.dev:443",
                "assets.app.kiro.dev:443",
                "management.us-east-1.kiro.dev:443",
                "prod.download.desktop.kiro.dev:443",
                "prod.us-east-1.auth.desktop.kiro.dev:443",
                "q.us-east-1.amazonaws.com:443",
                "runtime.us-east-1.kiro.dev:443",
                "telemetry.us-east-1.kiro.dev:443",
            ]
        );
    }

    #[test]
    fn the_kiro_profile_has_no_wildcard_endpoint() {
        let allow = kiro_allow().expect("the built-in profile parses");
        assert!(
            allow
                .iter()
                .all(|endpoint| !endpoint.to_string().contains('*'))
        );
    }

    #[test]
    fn the_kiro_sign_in_host_is_allowed_exactly() {
        let allow = kiro_allow().expect("the built-in profile parses");
        let sign_in = HostPort::parse("prod.us-east-1.auth.desktop.kiro.dev:443").expect("valid");
        assert!(allow.contains(&sign_in));
        let other_port = HostPort::parse("prod.us-east-1.auth.desktop.kiro.dev:80").expect("valid");
        assert!(!allow.contains(&other_port));
    }
}
