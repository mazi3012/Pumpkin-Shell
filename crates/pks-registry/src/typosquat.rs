//! Typosquat check (PRD FR-REG): a package name one or two edits away from a
//! popular package gets a warning.
//!
//! The reference list is the top 1,000 names of each ecosystem
//! (`data/*.txt`, sources in DECISIONS.md). A name that is itself in the
//! list is never flagged. The rule is the PRD's: distance 1 for names of at
//! least 5 characters, distance 2 for names of at least 10. Shorter names are
//! not checked. A swap of two letters costs two edits, so a short name with
//! a swap (`lodsah` for `lodash`) is not caught.

use std::sync::OnceLock;

use crate::names::normalize_pypi;

const NPM_TOP: &str = include_str!("../data/npm-top.txt");
const PYPI_TOP: &str = include_str!("../data/pypi-top.txt");

/// How many names of each list form the reference.
pub const REFERENCE_SIZE: usize = 1000;

/// The registries the guard covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ecosystem {
    Npm,
    PyPi,
}

fn lines(text: &'static str) -> Vec<&'static str> {
    text.lines().filter(|line| !line.is_empty()).collect()
}

/// All stored names of `ecosystem`, most downloaded first (2,000 of them).
#[must_use]
pub fn top_names(ecosystem: Ecosystem) -> &'static [&'static str] {
    static NPM: OnceLock<Vec<&'static str>> = OnceLock::new();
    static PYPI: OnceLock<Vec<&'static str>> = OnceLock::new();
    match ecosystem {
        Ecosystem::Npm => NPM.get_or_init(|| lines(NPM_TOP)),
        Ecosystem::PyPi => PYPI.get_or_init(|| lines(PYPI_TOP)),
    }
}

/// The names a package is compared with: the first [`REFERENCE_SIZE`].
#[must_use]
pub fn reference(ecosystem: Ecosystem) -> &'static [&'static str] {
    let all = top_names(ecosystem);
    &all[..REFERENCE_SIZE.min(all.len())]
}

/// How many edits apart a name may be from a popular one and still be flagged.
fn allowed_distance(length: usize) -> usize {
    if length >= 10 {
        2
    } else {
        usize::from(length >= 5)
    }
}

/// The popular name `name` looks like, or `None`. `name` must be normalized.
/// A name that is in `reference` is not flagged. When several names are
/// close, the nearest wins, and the more popular one on a tie.
#[must_use]
pub fn find_similar<'a>(reference: &[&'a str], name: &str) -> Option<&'a str> {
    let limit = allowed_distance(name.chars().count());
    if limit == 0 || reference.contains(&name) {
        return None;
    }
    let mut best: Option<(usize, &'a str)> = None;
    for popular in reference {
        if popular.len().abs_diff(name.len()) > limit {
            continue;
        }
        let distance = strsim::levenshtein(name, popular);
        if (1..=limit).contains(&distance) && best.is_none_or(|(d, _)| distance < d) {
            best = Some((distance, popular));
        }
    }
    best.map(|(_, popular)| popular)
}

/// Checks a package name of `ecosystem`. Returns the popular package it
/// resembles.
#[must_use]
pub fn check(ecosystem: Ecosystem, name: &str) -> Option<&'static str> {
    let name = match ecosystem {
        Ecosystem::Npm => name.to_ascii_lowercase(),
        Ecosystem::PyPi => normalize_pypi(name),
    };
    find_similar(reference(ecosystem), &name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lists_have_the_expected_size_and_no_blank_or_duplicate_names() {
        for ecosystem in [Ecosystem::Npm, Ecosystem::PyPi] {
            let all = top_names(ecosystem);
            assert_eq!(all.len(), 2000);
            assert_eq!(reference(ecosystem).len(), REFERENCE_SIZE);
            let unique: std::collections::HashSet<_> = all.iter().collect();
            assert_eq!(unique.len(), all.len(), "{ecosystem:?} has duplicates");
            assert!(all.iter().all(|n| !n.is_empty() && !n.contains(' ')));
        }
        assert_eq!(top_names(Ecosystem::Npm)[0], "semver");
        assert_eq!(top_names(Ecosystem::PyPi)[0], "boto3");
    }

    #[test]
    fn pypi_names_in_the_list_are_already_normalized() {
        for name in top_names(Ecosystem::PyPi) {
            assert_eq!(normalize_pypi(name), *name);
        }
    }

    #[test]
    fn near_misses_of_popular_packages_are_flagged() {
        // Each pair was confirmed against the stored lists on 2026-11-21.
        assert_eq!(check(Ecosystem::Npm, "expresss"), Some("express"));
        assert_eq!(check(Ecosystem::Npm, "reakt"), Some("react"));
        assert_eq!(check(Ecosystem::PyPi, "requets"), Some("requests"));
        assert_eq!(check(Ecosystem::PyPi, "reqests"), Some("requests"));
    }

    #[test]
    fn pypi_spelling_variants_are_normalized_before_the_check() {
        assert_eq!(check(Ecosystem::PyPi, "Reqests"), Some("requests"));
        // `re.qu_ests` becomes `re-qu-ests`, two edits from `requests`; a name of
        // 10 characters allows two.
        assert_eq!(check(Ecosystem::PyPi, "re.qu_ests"), Some("requests"));
        assert_eq!(
            check(Ecosystem::PyPi, "Requests"),
            None,
            "it is the popular name"
        );
    }

    #[test]
    fn a_popular_name_is_never_flagged_even_when_another_is_one_edit_away() {
        // `safe-buffer` and `safer-buffer` are both popular and one edit apart.
        let npm = reference(Ecosystem::Npm);
        assert!(npm.contains(&"safe-buffer") && npm.contains(&"safer-buffer"));
        assert_eq!(check(Ecosystem::Npm, "safe-buffer"), None);
        assert_eq!(check(Ecosystem::Npm, "safer-buffer"), None);
    }

    #[test]
    fn short_names_and_unrelated_names_are_not_flagged() {
        assert_eq!(
            check(Ecosystem::Npm, "reac"),
            None,
            "4 characters: not checked"
        );
        assert_eq!(check(Ecosystem::Npm, "a"), None);
        assert_eq!(check(Ecosystem::Npm, ""), None);
        assert_eq!(check(Ecosystem::Npm, "zzzzzz-unrelated-name"), None);
    }

    #[test]
    fn a_swap_of_two_letters_in_a_short_name_is_a_known_miss() {
        // `lodsah` is two edits from `lodash`; names under 10 characters allow one.
        assert!(reference(Ecosystem::Npm).contains(&"lodash"));
        assert_eq!(check(Ecosystem::Npm, "lodsah"), None);
    }

    #[test]
    fn the_distance_limit_depends_on_the_length_of_the_name() {
        assert_eq!(allowed_distance(4), 0);
        assert_eq!(allowed_distance(5), 1);
        assert_eq!(allowed_distance(9), 1);
        assert_eq!(allowed_distance(10), 2);
        let reference = ["abcdefghij"];
        // Length 10: two edits are allowed. Length 9: one edit only.
        assert_eq!(find_similar(&reference, "abcdefghxx"), Some("abcdefghij"));
        let reference = ["abcdefghi"];
        assert_eq!(find_similar(&reference, "abcdefgxx"), None);
        assert_eq!(find_similar(&reference, "abcdefgxi"), Some("abcdefghi"));
    }

    #[test]
    fn the_nearest_name_wins_and_a_tie_goes_to_the_more_popular() {
        let reference = ["abcdex", "abcdey", "abcdxy"];
        assert_eq!(find_similar(&reference, "abcdef"), Some("abcdex"));
        let reference = ["abcxyz", "abcdez"];
        assert_eq!(find_similar(&reference, "abcdez1"), Some("abcdez"));
    }

    /// Counts the names of `names` that [`find_similar`] flags against
    /// `reference`, skipping `skip_self` (the name under test) when asked.
    fn flagged(names: &[&'static str], reference: &[&'static str], skip_self: bool) -> usize {
        names
            .iter()
            .filter(|name| {
                let others: Vec<&str> = if skip_self {
                    reference.iter().copied().filter(|r| r != *name).collect()
                } else {
                    reference.to_vec()
                };
                find_similar(&others, name).is_some()
            })
            .count()
    }

    /// The false-positive benchmark of Phase 14, recorded in DECISIONS.md. If
    /// the lists in `data/` are refreshed these numbers change, and the
    /// recorded benchmark must be refreshed with them.
    #[test]
    fn warnings_on_popular_packages_match_the_recorded_benchmark() {
        for (ecosystem, inside, outside) in [(Ecosystem::Npm, 42, 19), (Ecosystem::PyPi, 47, 22)] {
            let all = top_names(ecosystem);
            let reference = reference(ecosystem);
            // Ranks 1-1000, each checked as if it were not in the list.
            assert_eq!(
                flagged(&all[..1000], reference, true),
                inside,
                "{ecosystem:?}"
            );
            // Ranks 1001-2000 against the reference list.
            assert_eq!(
                flagged(&all[1000..], reference, false),
                outside,
                "{ecosystem:?}"
            );
        }
    }
}
