//! Finds secrets in text the sandbox wrote (PRD FR-DET `WS-SECRET-WRITTEN`,
//! PHASES 10.7). It reports where a secret is and what kind it is, never the
//! secret itself.
//!
//! The formats come from vendor documentation:
//! - GitHub token prefixes `ghp_`, `github_pat_`, `gho_`, `ghu_`, `ghs_` and
//!   `ghr_` (docs.github.com, "GitHub's token formats");
//! - AWS access key ID prefixes `AKIA` (long-term) and `ASIA` (temporary)
//!   (docs.aws.amazon.com, IAM unique ID prefixes). AWS's own examples end in
//!   `EXAMPLE` and are skipped;
//! - PEM private keys: a `-----BEGIN ... PRIVATE KEY-----` line (RFC 7468
//!   labels `PRIVATE KEY` and `ENCRYPTED PRIVATE KEY`, and the older
//!   `RSA`, `EC` and `OPENSSH` labels, which end the same way);
//! - the marker of Pumpkin-Shell's own decoy credentials, which shows that a
//!   decoy was copied into the repo.
//!
//! The docs do not give token lengths, so the length rules are heuristics: a
//! GitHub token has at least 20 more letters, digits or underscores after its
//! prefix, and an AWS key ID has at least 16 more capital letters or digits.
//! This is not a full secret scanner; a dedicated one (ggshield) belongs in
//! the commit hook (tech.md).

/// What kind of secret a hit is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    PrivateKey,
    AwsAccessKeyId,
    GithubToken,
    DecoyCopy,
}

impl Kind {
    /// A phrase for messages, with its article.
    #[must_use]
    pub fn describe(self) -> &'static str {
        match self {
            Self::PrivateKey => "a private key",
            Self::AwsAccessKeyId => "an AWS access key ID",
            Self::GithubToken => "a GitHub token",
            Self::DecoyCopy => "a copy of a decoy credential",
        }
    }
}

/// One secret found: its line (counting from 1) and kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hit {
    pub line: usize,
    pub kind: Kind,
}

const GITHUB_PREFIXES: [&str; 6] = ["ghp_", "github_pat_", "gho_", "ghu_", "ghs_", "ghr_"];
const AWS_PREFIXES: [&str; 2] = ["AKIA", "ASIA"];
/// The first words of the text `pks_core::decoy` writes into every decoy.
const DECOY_MARKER: &str = "PKS DECOY, not a credential";
const GITHUB_MIN_BODY: usize = 20;
const AWS_MIN_BODY: usize = 16;

fn before_is_word(line: &str, at: usize) -> bool {
    line[..at]
        .chars()
        .next_back()
        .is_some_and(|c| c.is_ascii_alphanumeric())
}

/// The length of the run of characters from `rest` that satisfy `keep`.
fn run(rest: &str, keep: impl Fn(char) -> bool) -> usize {
    rest.chars()
        .take_while(|c| keep(*c))
        .map(char::len_utf8)
        .sum()
}

fn has_github_token(line: &str) -> bool {
    GITHUB_PREFIXES.iter().any(|prefix| {
        line.match_indices(prefix).any(|(at, _)| {
            !before_is_word(line, at)
                && run(&line[at + prefix.len()..], |c| {
                    c.is_ascii_alphanumeric() || c == '_'
                }) >= GITHUB_MIN_BODY
        })
    })
}

fn has_aws_key(line: &str) -> bool {
    AWS_PREFIXES.iter().any(|prefix| {
        line.match_indices(prefix).any(|(at, _)| {
            if before_is_word(line, at) {
                return false;
            }
            let rest = &line[at + prefix.len()..];
            let body_len = run(rest, |c| c.is_ascii_uppercase() || c.is_ascii_digit());
            // AWS's documentation examples end in EXAMPLE.
            body_len >= AWS_MIN_BODY && !rest[..body_len].ends_with("EXAMPLE")
        })
    })
}

fn has_private_key(line: &str) -> bool {
    line.contains("-----BEGIN ") && line.contains("PRIVATE KEY-----")
}

/// Finds secrets in `text`, at most one hit per kind per line.
#[must_use]
pub fn find(text: &str) -> Vec<Hit> {
    let mut hits = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line_number = index + 1;
        let checks: [(Kind, bool); 4] = [
            (Kind::PrivateKey, has_private_key(line)),
            (Kind::AwsAccessKeyId, has_aws_key(line)),
            (Kind::GithubToken, has_github_token(line)),
            (Kind::DecoyCopy, line.contains(DECOY_MARKER)),
        ];
        for (kind, found) in checks {
            if found {
                hits.push(Hit {
                    line: line_number,
                    kind,
                });
            }
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test values are built at run time, so this file holds nothing that
    // looks like a real token to a scanner.
    fn github(prefix: &str) -> String {
        format!("{prefix}{}", "A1b2".repeat(9))
    }
    fn aws(prefix: &str) -> String {
        format!("{prefix}{}", "Q7".repeat(8))
    }
    fn kinds(text: &str) -> Vec<(usize, Kind)> {
        find(text).into_iter().map(|h| (h.line, h.kind)).collect()
    }

    #[test]
    fn every_github_prefix_is_found() {
        for prefix in GITHUB_PREFIXES {
            let text = format!("token = \"{}\"\n", github(prefix));
            assert_eq!(kinds(&text), [(1, Kind::GithubToken)], "{prefix}");
        }
    }

    #[test]
    fn a_short_or_embedded_prefix_is_not_a_github_token() {
        assert!(find("ghp_short\n").is_empty());
        assert!(find("see the ghp_ prefix in the docs\n").is_empty());
        let embedded = format!("x{}\n", github("ghp_"));
        assert!(find(&embedded).is_empty());
    }

    #[test]
    fn both_aws_prefixes_are_found() {
        for prefix in AWS_PREFIXES {
            let text = format!("aws_access_key_id = {}\n", aws(prefix));
            assert_eq!(kinds(&text), [(1, Kind::AwsAccessKeyId)], "{prefix}");
        }
    }

    #[test]
    fn aws_documentation_examples_are_skipped() {
        // AWS documents keys that end in EXAMPLE. Built at run time, so no
        // key-shaped text is in this file.
        let documented = format!("AKIA{}EXAMPLE", "IOSFODNN7");
        let temporary = format!("ASIA{}EXAMPLE", "X".repeat(11));
        assert!(find(&format!("{documented}\n")).is_empty());
        assert!(find(&format!("key: {documented} and {temporary}\n")).is_empty());
    }

    #[test]
    fn a_short_or_lowercase_aws_look_alike_is_not_a_key() {
        assert!(find("AKIA1234\n").is_empty());
        assert!(find(&format!("akia{}\n", "q7".repeat(8))).is_empty());
        assert!(find(&format!("x{}\n", aws("AKIA"))).is_empty());
    }

    #[test]
    fn private_key_headers_of_every_label_are_found() {
        for label in [
            "PRIVATE KEY",
            "ENCRYPTED PRIVATE KEY",
            "RSA PRIVATE KEY",
            "EC PRIVATE KEY",
            "OPENSSH PRIVATE KEY",
        ] {
            let text = format!("-----BEGIN {label}-----\nAAAA\n-----END {label}-----\n");
            assert_eq!(kinds(&text), [(1, Kind::PrivateKey)], "{label}");
        }
        // A public key or certificate is not a secret.
        assert!(find("-----BEGIN PUBLIC KEY-----\n").is_empty());
        assert!(find("-----BEGIN CERTIFICATE-----\n").is_empty());
    }

    #[test]
    fn a_copy_of_a_decoy_is_found() {
        let text = "PKS DECOY, not a credential: this AWS credentials is a trap. Marker 00\n";
        assert_eq!(kinds(text), [(1, Kind::DecoyCopy)]);
    }

    #[test]
    fn lines_are_counted_from_one_and_each_kind_is_reported_once_per_line() {
        let text = format!(
            "ok\n{} {}\nok\n{}\n",
            github("ghp_"),
            github("gho_"),
            aws("AKIA")
        );
        assert_eq!(
            kinds(&text),
            [(2, Kind::GithubToken), (4, Kind::AwsAccessKeyId)]
        );
    }

    #[test]
    fn clean_text_has_no_hits() {
        assert!(find("fn main() { println!(\"hello\"); }\n").is_empty());
        assert!(find("").is_empty());
    }
}
