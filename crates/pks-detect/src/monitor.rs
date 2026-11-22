//! Rules for what the sandbox monitor sees (PRD FR-DET, Phase 15):
//! EXEC-AGENT-YOLO, EXEC-DESTRUCTIVE, EXEC-RECON and NET-DIRECT-CONNECT.
//!
//! These rules only report. They never block a call. The PRD's real control
//! is that the sandbox holds no credentials, so an alert here is information
//! for the user (PRD section 11, "exec argument alerts can be evaluated").

use std::net::SocketAddr;

use pks_core::{Finding, RuleId, Severity};

/// The flags that switch an AI tool's permission checks off (PRD FR-DET,
/// EXEC-AGENT-YOLO; the Nx "s1ngularity" pattern in PRD section 1, row 6).
const PERMISSION_OFF_FLAGS: [&str; 3] = [
    "--dangerously-skip-permissions",
    "--yolo",
    "--trust-all-tools",
];

/// Tools that read or scan for credentials (PRD FR-DET, EXEC-RECON).
const SCANNERS: [&str; 2] = ["trufflehog", "gitleaks"];

/// Search tools that are reported when they search a credential location.
const SEARCHERS: [&str; 4] = ["grep", "rg", "ag", "find"];

/// Credential locations in a user's home or a repo (EXEC-RECON).
const CREDENTIAL_PLACES: [&str; 7] = [
    ".aws/",
    ".ssh/",
    "id_rsa",
    ".kube/config",
    ".docker/config.json",
    ".npmrc",
    ".git-credentials",
];

/// Classifies one program start. `path` is the program's path, `argv` its
/// arguments (argv[0] included), and `interactive` whether the process that
/// started it has a terminal on stdin.
#[must_use]
pub fn exec_findings(path: &str, argv: &[String], interactive: bool) -> Vec<Finding> {
    let name = basename(path);
    let words: Vec<String> = argv.iter().map(|a| a.to_ascii_lowercase()).collect();
    let has = |needle: &str| words.iter().any(|w| w == needle);
    let mut findings = Vec::new();

    if !interactive
        && argv
            .iter()
            .any(|a| PERMISSION_OFF_FLAGS.contains(&a.as_str()))
    {
        findings.push(finding(
            "EXEC-AGENT-YOLO",
            Severity::Critical,
            path,
            "an AI tool was started with its permission checks off, by a process with no terminal",
            "The session is paused. Run 'pumpkin-shell resume' to continue or 'pumpkin-shell kill' to stop.",
        ));
    }

    if destructive(name, &words, &has) {
        findings.push(finding(
            "EXEC-DESTRUCTIVE",
            Severity::High,
            path,
            "a command that deletes or overwrites infrastructure or data was started",
            "The sandbox holds no cloud or database credentials, so the command should fail. Check its output in the IDE terminal.",
        ));
    }

    let scanner = SCANNERS.contains(&name);
    let searches_credentials = SEARCHERS.contains(&name)
        && words
            .iter()
            .any(|w| CREDENTIAL_PLACES.iter().any(|place| w.contains(place)));
    if scanner || searches_credentials {
        findings.push(finding(
            "EXEC-RECON",
            Severity::High,
            path,
            "a program searched for credentials",
            "Remove the search, or review what the IDE or agent was asked to do.",
        ));
    }
    findings
}

/// Whether a program's arguments make it a destructive command.
fn destructive(name: &str, words: &[String], has: &impl Fn(&str) -> bool) -> bool {
    let sql_destroys = words.iter().any(|w| {
        w.contains("drop table")
            || w.contains("drop database")
            || w.contains("drop schema")
            || w.contains("truncate table")
    });
    let tool = match name {
        "terraform" => has("destroy") || (has("apply") && has("-auto-approve")),
        "kubectl" => has("delete"),
        "aws" => words.iter().any(|w| w.starts_with("delete-")),
        "git" => has("push") && (has("--force") || has("-f") || has("--force-with-lease")),
        _ => false,
    };
    tool || sql_destroys
}

/// Classifies one connection to an IP address (NET-DIRECT-CONNECT). `allowed`
/// are the loopback ports the sandbox relays (the proxy, the mirror, the
/// callback and the host ports); a connection to one of them on loopback is
/// expected and not reported. Every other IP connection bypasses the proxy.
#[must_use]
pub fn connect_finding(target: SocketAddr, allowed: &[u16]) -> Option<Finding> {
    if target.ip().is_loopback() && allowed.contains(&target.port()) {
        return None;
    }
    let fix = if target.ip().is_loopback() {
        format!(
            "If a service on this machine should be reachable, add 'host_ports = [{}]' to the policy. Otherwise the connection is refused.",
            target.port()
        )
    } else {
        "Direct connections bypass the proxy and are refused. Tools must use the proxy (HTTP(S)_PROXY).".to_owned()
    };
    Some(Finding {
        rule: RuleId::new("NET-DIRECT-CONNECT"),
        severity: Severity::Warn,
        target: target.to_string(),
        message: "a program connected directly, not through the proxy".to_owned(),
        fix,
    })
}

fn finding(
    rule: &'static str,
    severity: Severity,
    target: &str,
    message: &str,
    fix: &str,
) -> Finding {
    Finding {
        rule: RuleId::new(rule),
        severity,
        target: target.to_owned(),
        message: message.to_owned(),
        fix: fix.to_owned(),
    }
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| (*w).to_owned()).collect()
    }

    fn rules(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.rule.as_str()).collect()
    }

    #[test]
    fn a_permission_off_flag_from_a_non_terminal_parent_is_critical() {
        let found = exec_findings(
            "/usr/bin/claude",
            &args(&["claude", "--dangerously-skip-permissions"]),
            false,
        );
        assert_eq!(rules(&found), ["EXEC-AGENT-YOLO"]);
        assert_eq!(found[0].severity, Severity::Critical);
    }

    #[test]
    fn the_same_flag_from_a_terminal_is_not_reported() {
        let found = exec_findings("/usr/bin/claude", &args(&["claude", "--yolo"]), true);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn terraform_destroy_is_high() {
        let found = exec_findings("/usr/bin/terraform", &args(&["terraform", "destroy"]), true);
        assert_eq!(rules(&found), ["EXEC-DESTRUCTIVE"]);
        assert_eq!(found[0].severity, Severity::High);
    }

    #[test]
    fn terraform_apply_without_review_is_destructive_but_plain_apply_is_not() {
        let auto = exec_findings(
            "terraform",
            &args(&["terraform", "apply", "-auto-approve"]),
            true,
        );
        assert_eq!(rules(&auto), ["EXEC-DESTRUCTIVE"]);
        assert!(exec_findings("terraform", &args(&["terraform", "plan"]), true).is_empty());
    }

    #[test]
    fn force_push_and_cloud_deletes_are_destructive() {
        for words in [
            &["git", "push", "--force", "origin", "main"][..],
            &["git", "push", "-f"][..],
            &["aws", "s3api", "delete-bucket", "--bucket", "x"][..],
            &["kubectl", "delete", "pod", "x"][..],
        ] {
            let found = exec_findings(words[0], &args(words), true);
            assert_eq!(rules(&found), ["EXEC-DESTRUCTIVE"], "{words:?}");
        }
        assert!(exec_findings("git", &args(&["git", "push", "origin", "main"]), true).is_empty());
    }

    #[test]
    fn sql_drops_and_truncates_are_destructive() {
        let found = exec_findings(
            "/usr/bin/psql",
            &args(&["psql", "-c", "DROP TABLE users"]),
            true,
        );
        assert_eq!(rules(&found), ["EXEC-DESTRUCTIVE"]);
        let found = exec_findings(
            "/usr/bin/mysql",
            &args(&["mysql", "-e", "truncate table orders"]),
            true,
        );
        assert_eq!(rules(&found), ["EXEC-DESTRUCTIVE"]);
    }

    #[test]
    fn trufflehog_and_a_search_of_a_credential_location_are_recon() {
        let found = exec_findings(
            "/usr/bin/trufflehog",
            &args(&["trufflehog", "filesystem", "."]),
            true,
        );
        assert_eq!(rules(&found), ["EXEC-RECON"]);
        let found = exec_findings(
            "/usr/bin/grep",
            &args(&["grep", "-r", "AKIA", "/home/sandbox/.aws/"]),
            true,
        );
        assert_eq!(rules(&found), ["EXEC-RECON"]);
        assert!(
            exec_findings("/usr/bin/grep", &args(&["grep", "-r", "TODO", "src"]), true).is_empty()
        );
    }

    #[test]
    fn a_connection_to_a_loopback_port_nothing_relays_is_warned_with_the_host_ports_hint() {
        let target: SocketAddr = "127.0.0.1:5432".parse().unwrap_or_else(|e| panic!("{e}"));
        let found = connect_finding(target, &[3129, 3130]).unwrap_or_else(|| panic!("no finding"));
        assert_eq!(found.rule.as_str(), "NET-DIRECT-CONNECT");
        assert_eq!(found.severity, Severity::Warn);
        assert!(found.fix.contains("host_ports = [5432]"), "{}", found.fix);
    }

    #[test]
    fn the_proxy_and_the_mirror_ports_are_not_reported() {
        for text in ["127.0.0.1:3129", "127.0.0.1:3130", "127.0.0.1:5432"] {
            let target: SocketAddr = text.parse().unwrap_or_else(|e| panic!("{e}"));
            let found = connect_finding(target, &[3129, 3130, 5432]);
            assert!(found.is_none(), "{text}");
        }
    }

    #[test]
    fn an_internet_address_is_reported_as_a_bypass() {
        let target: SocketAddr = "93.184.216.34:443"
            .parse()
            .unwrap_or_else(|e| panic!("{e}"));
        let found = connect_finding(target, &[3129]).unwrap_or_else(|| panic!("no finding"));
        assert!(found.fix.contains("proxy"), "{}", found.fix);
    }
}
