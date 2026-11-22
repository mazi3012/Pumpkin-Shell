//! Package age rules (PRD FR-REG): the version cooldown and the new-package
//! rule. Times are Unix seconds. The caller passes `now`.

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// A version published less than this long ago is hidden (72 hours).
pub const COOLDOWN_SECS: i64 = 72 * 3600;
/// A package whose first release is younger than this is blocked (30 days).
pub const YOUNG_PACKAGE_SECS: i64 = 30 * 24 * 3600;

/// Parses an RFC 3339 timestamp such as `2026-05-14T19:25:27.735762Z`, the
/// form npm's `time` and PyPI's `upload-time` use. `None` for anything else.
#[must_use]
pub fn parse_time(text: &str) -> Option<i64> {
    OffsetDateTime::parse(text, &Rfc3339)
        .ok()
        .map(OffsetDateTime::unix_timestamp)
}

/// Whether something published at `published` is younger than `window`.
/// A time in the future (a clock that is wrong) counts as young, so the safe
/// answer is the one given when the clock cannot be trusted.
#[must_use]
pub fn is_younger_than(published: i64, now: i64, window: i64) -> bool {
    now.saturating_sub(published) < window
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_registry_timestamps_parse() {
        // Shapes seen on registry.npmjs.org and pypi.org on 2026-11-21.
        assert_eq!(parse_time("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_time("2026-05-14T19:25:27.735762Z"),
            Some(1_778_786_727)
        );
        assert_eq!(parse_time("2014-03-14T09:09:20.762Z"), Some(1_394_788_160));
    }

    #[test]
    fn text_that_is_not_a_time_is_refused() {
        for bad in [
            "",
            "yesterday",
            "2026-05-14",
            "2026-13-40T00:00:00Z",
            "1778786727",
        ] {
            assert_eq!(parse_time(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn the_cooldown_edge_is_exactly_72_hours() {
        let now = 1_000_000_000;
        assert!(is_younger_than(now - COOLDOWN_SECS + 1, now, COOLDOWN_SECS));
        assert!(!is_younger_than(now - COOLDOWN_SECS, now, COOLDOWN_SECS));
        assert!(!is_younger_than(
            now - COOLDOWN_SECS - 1,
            now,
            COOLDOWN_SECS
        ));
    }

    #[test]
    fn the_young_package_edge_is_exactly_30_days() {
        let now = 1_000_000_000;
        assert!(is_younger_than(
            now - YOUNG_PACKAGE_SECS + 1,
            now,
            YOUNG_PACKAGE_SECS
        ));
        assert!(!is_younger_than(
            now - YOUNG_PACKAGE_SECS,
            now,
            YOUNG_PACKAGE_SECS
        ));
    }

    #[test]
    fn a_time_in_the_future_counts_as_young() {
        assert!(is_younger_than(2_000_000_000, 1_000_000_000, COOLDOWN_SECS));
    }

    #[test]
    fn extreme_values_do_not_overflow() {
        assert!(is_younger_than(i64::MAX, i64::MIN, COOLDOWN_SECS));
        assert!(!is_younger_than(i64::MIN, i64::MAX, COOLDOWN_SECS));
    }
}
