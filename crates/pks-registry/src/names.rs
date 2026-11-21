//! Package names: checks and normalization. Every name from the sandbox is
//! checked here before it goes into a URL, so a name cannot add a path, a
//! query or another host.

/// Longest package name accepted, as npm allows.
const MAX_NAME: usize = 214;

fn is_alnum(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

/// One part of an npm name (the scope without `@`, or the package): starts
/// with a letter or digit, then letters, digits, `.`, `_`, `~` or `-`.
fn npm_part_ok(part: &str) -> bool {
    let bytes = part.as_bytes();
    let Some((first, rest)) = bytes.split_first() else {
        return false;
    };
    is_alnum(*first)
        && rest
            .iter()
            .all(|b| is_alnum(*b) || matches!(b, b'.' | b'_' | b'~' | b'-'))
}

/// An npm package name, with an optional `@scope/`. Capital letters are
/// allowed, because older packages have them. `..` is refused.
#[must_use]
pub fn valid_npm_name(name: &str) -> bool {
    if name.len() > MAX_NAME || name.contains("..") {
        return false;
    }
    match name.strip_prefix('@') {
        Some(scoped) => match scoped.split_once('/') {
            Some((scope, package)) => npm_part_ok(scope) && npm_part_ok(package),
            None => false,
        },
        None => npm_part_ok(name),
    }
}

/// A PyPI project name as PEP 508 defines it: letters and digits at both
/// ends, and `.`, `_` or `-` between.
#[must_use]
pub fn valid_pypi_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    let (Some(first), Some(last)) = (bytes.first(), bytes.last()) else {
        return false;
    };
    bytes.len() <= MAX_NAME
        && is_alnum(*first)
        && is_alnum(*last)
        && bytes
            .iter()
            .all(|b| is_alnum(*b) || matches!(b, b'.' | b'_' | b'-'))
}

/// PEP 503 normalization: lowercase, and each run of `-`, `_` and `.` becomes
/// one `-`. Meant for names that passed [`valid_pypi_name`].
#[must_use]
pub fn normalize_pypi(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut after_separator = false;
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            if !after_separator {
                out.push('-');
            }
            after_separator = true;
        } else {
            out.push(c.to_ascii_lowercase());
            after_separator = false;
        }
    }
    out
}

/// Decodes `%XX` escapes. `None` for a bad escape (`%`, `%2`, `%zz`) or when
/// the result is not UTF-8. npm clients write the slash of a scoped name as
/// `%2f`.
#[must_use]
pub fn percent_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let pair = bytes.get(i + 1..i + 3)?;
            let hex = std::str::from_utf8(pair).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_and_scoped_npm_names_are_accepted() {
        for ok in [
            "left-pad",
            "lodash",
            "JSONStream",
            "@types/node",
            "@babel/core",
            "a",
            "react.dom",
            "x_y~z",
            "@a/b",
        ] {
            assert!(valid_npm_name(ok), "{ok:?}");
        }
    }

    #[test]
    fn npm_names_that_could_change_a_url_are_refused() {
        let long = "a".repeat(MAX_NAME + 1);
        for bad in [
            "",
            "@",
            "@scope",
            "@/pkg",
            "@scope/",
            "@scope/pkg/extra",
            "a/b",
            "../etc",
            "a..b",
            ".hidden",
            "_private",
            "-flag",
            "a b",
            "a?x=1",
            "a#frag",
            "a%2fb",
            "a\\b",
            "caf\u{e9}",
            "a\0b",
            "a:b",
            "a@1.0.0",
            long.as_str(),
        ] {
            assert!(!valid_npm_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn pypi_names_follow_pep_508() {
        for ok in [
            "requests",
            "Django",
            "a",
            "zope.interface",
            "my_pkg-2",
            "A1",
        ] {
            assert!(valid_pypi_name(ok), "{ok:?}");
        }
        for bad in [
            "",
            "-a",
            "a-",
            ".a",
            "a.",
            "a b",
            "a/b",
            "a..b/c",
            "a?b",
            "caf\u{e9}",
        ] {
            assert!(!valid_pypi_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn pep_503_normalization_matches_the_specification_examples() {
        assert_eq!(normalize_pypi("Friendly-Bard"), "friendly-bard");
        assert_eq!(normalize_pypi("FRIENDLY-BARD"), "friendly-bard");
        assert_eq!(normalize_pypi("friendly.bard"), "friendly-bard");
        assert_eq!(normalize_pypi("friendly_bard"), "friendly-bard");
        assert_eq!(normalize_pypi("Foo._-Bar"), "foo-bar");
        assert_eq!(normalize_pypi("a--b__c..d"), "a-b-c-d");
    }

    #[test]
    fn percent_escapes_decode_and_bad_ones_are_refused() {
        assert_eq!(
            percent_decode("@babel%2fcore").as_deref(),
            Some("@babel/core")
        );
        assert_eq!(
            percent_decode("@babel%2Fcore").as_deref(),
            Some("@babel/core")
        );
        assert_eq!(percent_decode("plain").as_deref(), Some("plain"));
        for bad in ["%", "a%", "a%2", "a%zz", "%ff", "a%c3"] {
            assert_eq!(percent_decode(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn an_escape_cannot_smuggle_a_forbidden_character_past_the_check() {
        // `%2e%2e` decodes to `..`, which the name check then refuses.
        let decoded = percent_decode("%2e%2e%2fetc").unwrap_or_default();
        assert_eq!(decoded, "../etc");
        assert!(!valid_npm_name(&decoded));
    }
}
