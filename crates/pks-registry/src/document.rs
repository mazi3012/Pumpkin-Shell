//! Filters for the documents a package manager asks the mirror for (PRD FR-REG
//! checks 2, 3 and 4 of the evaluation order):
//!
//! - the npm packument (`GET /<name>`), which lists versions with publish
//!   times in `time` and install scripts in each version's `scripts`;
//! - the PyPI simple JSON index (`GET /simple/<name>/`, PEP 691/700), which
//!   lists files with `upload-time`.
//!
//! Each filter takes the document, the current time and the policy, changes
//! the document so that a too-new version is no longer offered, and reports
//! what it did. The caller decides what to block and what to log.
//!
//! Fail closed: a version or file whose publish time cannot be read is hidden.

use serde_json::{Map, Value};

use crate::age::{COOLDOWN_SECS, YOUNG_PACKAGE_SECS, is_younger_than, parse_time};

/// npm lifecycle scripts that run when a package is installed.
const INSTALL_SCRIPTS: [&str; 3] = ["preinstall", "install", "postinstall"];

/// What the npm filter found.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NpmReport {
    /// Versions removed from the document (published inside the cooldown, or
    /// with no readable publish time).
    pub hidden: Vec<String>,
    /// Visible versions that run an install script, as `name@version`.
    pub install_scripts: Vec<String>,
    /// The package's first release is inside the new-package window.
    pub too_new: bool,
}

/// What the PyPI filter found.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PypiReport {
    /// Files removed from the index (uploaded inside the cooldown, or with no
    /// readable upload time or version in the filename).
    pub hidden_files: Vec<String>,
    /// The package's first upload is inside the new-package window.
    pub too_new: bool,
}

/// Publish time of an npm version, from the document's `time` map.
fn npm_published(time: &Map<String, Value>, version: &str) -> Option<i64> {
    time.get(version)
        .and_then(Value::as_str)
        .and_then(parse_time)
}

/// Filters an npm packument in place.
///
/// Versions published inside [`COOLDOWN_SECS`] are removed from `versions` and
/// `time`. A dist-tag that pointed at a removed version is moved to the newest
/// visible version, or removed when no version is visible. A package whose
/// earliest release is inside [`YOUNG_PACKAGE_SECS`] is marked `too_new`.
///
/// # Errors
/// Returns `None` when the document has no `versions` or `time` object, which
/// means it is not a packument and must not be served.
#[must_use]
pub fn filter_npm(doc: &mut Value, now: i64) -> Option<NpmReport> {
    let name = doc
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let time = doc.get("time")?.as_object()?.clone();
    let versions = doc.get_mut("versions")?.as_object_mut()?;

    let mut report = NpmReport::default();
    let earliest = versions
        .keys()
        .filter_map(|v| npm_published(&time, v))
        .min();
    if let Some(first) = earliest {
        report.too_new = is_younger_than(first, now, YOUNG_PACKAGE_SECS);
    }

    let mut hidden = Vec::new();
    for version in versions.keys() {
        let visible = npm_published(&time, version)
            .is_some_and(|published| !is_younger_than(published, now, COOLDOWN_SECS));
        if !visible {
            hidden.push(version.clone());
        }
    }
    for version in &hidden {
        versions.remove(version);
    }
    report.hidden = hidden.clone();

    if let Some(time_map) = doc.get_mut("time").and_then(Value::as_object_mut) {
        for version in &hidden {
            time_map.remove(version);
        }
    }

    let visible_newest = newest_visible(doc);
    if let Some(tags) = doc.get_mut("dist-tags").and_then(Value::as_object_mut) {
        let names: Vec<String> = tags.keys().cloned().collect();
        for tag in names {
            let points_to = tags.get(&tag).and_then(Value::as_str).map(str::to_owned);
            let gone = points_to
                .as_deref()
                .is_none_or(|v| hidden.iter().any(|h| h == v));
            if gone {
                match &visible_newest {
                    Some(newest) => {
                        tags.insert(tag, Value::String(newest.clone()));
                    }
                    None => {
                        tags.remove(&tag);
                    }
                }
            }
        }
    }

    if let Some(all) = doc.get("versions").and_then(Value::as_object) {
        for (version, meta) in all {
            let scripts = meta.get("scripts").and_then(Value::as_object);
            let runs = scripts.is_some_and(|s| INSTALL_SCRIPTS.iter().any(|k| s.contains_key(*k)));
            if runs {
                report.install_scripts.push(format!("{name}@{version}"));
            }
        }
    }
    report.install_scripts.sort();
    Some(report)
}

/// The visible version published most recently. A pre-release is used only
/// when no stable version is visible.
fn newest_visible(doc: &Value) -> Option<String> {
    let versions = doc.get("versions")?.as_object()?;
    let time = doc.get("time")?.as_object()?;
    let mut best: Option<(bool, i64, String)> = None;
    for version in versions.keys() {
        let Some(published) = npm_published(time, version) else {
            continue;
        };
        let stable = !version.contains('-');
        let candidate = (stable, published, version.clone());
        if best
            .as_ref()
            .is_none_or(|b| (candidate.0, candidate.1) > (b.0, b.1))
        {
            best = Some(candidate);
        }
    }
    best.map(|(_, _, version)| version)
}

/// The version a PyPI file belongs to, from its filename. Wheels are
/// `{name}-{version}(-{build})?-{py}-{abi}-{platform}.whl`. Source
/// distributions end in `-{version}.tar.gz` (or `.zip`, `.tar.bz2`, `.tar.xz`).
#[must_use]
pub fn pypi_version_of(filename: &str) -> Option<String> {
    if let Some(stem) = filename.strip_suffix(".whl") {
        let parts: Vec<&str> = stem.split('-').collect();
        return (parts.len() >= 5 && !parts[1].is_empty()).then(|| parts[1].to_owned());
    }
    let stem = [".tar.gz", ".tar.bz2", ".tar.xz", ".zip"]
        .iter()
        .find_map(|ext| filename.strip_suffix(ext))?;
    let (_, version) = stem.rsplit_once('-')?;
    (!version.is_empty()).then(|| version.to_owned())
}

/// Filters a PyPI simple JSON index in place.
///
/// A file uploaded inside [`COOLDOWN_SECS`] is removed. A file with no
/// readable upload time, or whose version cannot be read from its name, is
/// removed too. A version with no files left is removed from `versions`. The
/// package is `too_new` when its earliest upload is inside
/// [`YOUNG_PACKAGE_SECS`].
///
/// # Errors
/// Returns `None` when the document has no `files` array.
#[must_use]
pub fn filter_pypi(doc: &mut Value, now: i64) -> Option<PypiReport> {
    let files = doc.get_mut("files")?.as_array_mut()?;

    let earliest = files
        .iter()
        .filter_map(|f| {
            f.get("upload-time")
                .and_then(Value::as_str)
                .and_then(parse_time)
        })
        .min();
    let mut report = PypiReport {
        too_new: earliest.is_some_and(|first| is_younger_than(first, now, YOUNG_PACKAGE_SECS)),
        ..PypiReport::default()
    };

    let mut kept_versions: Vec<String> = Vec::new();
    files.retain(|file| {
        let filename = file
            .get("filename")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let published = file
            .get("upload-time")
            .and_then(Value::as_str)
            .and_then(parse_time);
        let version = pypi_version_of(&filename);
        let keep = match (published, &version) {
            (Some(at), Some(v)) if !is_younger_than(at, now, COOLDOWN_SECS) => {
                kept_versions.push(v.clone());
                true
            }
            _ => false,
        };
        if !keep {
            report.hidden_files.push(filename);
        }
        keep
    });

    if let Some(listed) = doc.get_mut("versions").and_then(Value::as_array_mut) {
        listed.retain(|v| {
            v.as_str()
                .is_some_and(|v| kept_versions.iter().any(|k| k == v))
        });
    }
    Some(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const NOW: i64 = 1_800_000_000;
    const DAY: i64 = 86_400;

    /// An RFC 3339 time `secs` seconds before NOW (UTC), formatted by hand.
    fn ago(secs: i64) -> String {
        let t = NOW - secs;
        time::OffsetDateTime::from_unix_timestamp(t)
            .map(|d| {
                d.format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default()
            })
            .unwrap_or_default()
    }

    #[test]
    fn a_version_inside_the_cooldown_is_hidden_and_the_previous_one_resolves() {
        let mut doc = json!({
            "name": "pkg",
            "dist-tags": { "latest": "2.0.0" },
            "versions": { "1.0.0": {}, "2.0.0": {} },
            "time": {
                "created": ago(200 * DAY),
                "1.0.0": ago(200 * DAY),
                "2.0.0": ago(2 * 3600),
            },
        });
        let report = filter_npm(&mut doc, NOW).unwrap();
        assert_eq!(report.hidden, vec!["2.0.0".to_owned()]);
        assert!(doc["versions"].get("2.0.0").is_none());
        assert!(doc["time"].get("2.0.0").is_none());
        assert_eq!(
            doc["dist-tags"]["latest"], "1.0.0",
            "the tag moves to the visible version"
        );
        assert!(!report.too_new);
    }

    #[test]
    fn a_version_published_exactly_72_hours_ago_is_offered_again() {
        let mut doc = json!({
            "name": "pkg",
            "dist-tags": { "latest": "1.0.0" },
            "versions": { "1.0.0": {} },
            "time": { "1.0.0": ago(COOLDOWN_SECS) },
        });
        assert!(filter_npm(&mut doc, NOW).unwrap().hidden.is_empty());
    }

    #[test]
    fn a_version_without_a_readable_time_is_hidden() {
        let mut doc = json!({
            "name": "pkg",
            "dist-tags": { "latest": "1.0.0" },
            "versions": { "1.0.0": {} },
            "time": { "1.0.0": "not a time" },
        });
        assert_eq!(
            filter_npm(&mut doc, NOW).unwrap().hidden,
            vec!["1.0.0".to_owned()]
        );
    }

    #[test]
    fn when_nothing_is_visible_the_tags_are_removed() {
        let mut doc = json!({
            "name": "pkg",
            "dist-tags": { "latest": "1.0.0" },
            "versions": { "1.0.0": {} },
            "time": { "created": ago(400 * DAY), "1.0.0": ago(60) },
        });
        filter_npm(&mut doc, NOW).unwrap();
        assert!(doc["dist-tags"].get("latest").is_none());
        assert_eq!(doc["versions"].as_object().map(Map::len), Some(0));
    }

    #[test]
    fn a_package_whose_first_release_is_young_is_too_new() {
        let mut doc = json!({
            "name": "newpkg",
            "dist-tags": { "latest": "1.0.0" },
            "versions": { "1.0.0": {} },
            "time": { "created": ago(5 * DAY), "1.0.0": ago(5 * DAY) },
        });
        let report = filter_npm(&mut doc, NOW).unwrap();
        assert!(report.too_new);
    }

    #[test]
    fn an_older_package_with_a_young_release_is_not_too_new() {
        let mut doc = json!({
            "name": "pkg",
            "dist-tags": { "latest": "2.0.0" },
            "versions": { "1.0.0": {}, "2.0.0": {} },
            "time": { "1.0.0": ago(200 * DAY), "2.0.0": ago(3 * DAY) },
        });
        assert!(!filter_npm(&mut doc, NOW).unwrap().too_new);
    }

    #[test]
    fn install_scripts_of_visible_versions_are_listed_and_hidden_ones_are_not() {
        let mut doc = json!({
            "name": "tool",
            "dist-tags": { "latest": "2.0.0" },
            "versions": {
                "1.0.0": { "scripts": { "postinstall": "node install.js" } },
                "1.1.0": { "scripts": { "test": "jest" } },
                "2.0.0": { "scripts": { "preinstall": "echo hi" } },
            },
            "time": {
                "1.0.0": ago(100 * DAY),
                "1.1.0": ago(50 * DAY),
                "2.0.0": ago(60),
            },
        });
        let report = filter_npm(&mut doc, NOW).unwrap();
        assert_eq!(report.install_scripts, vec!["tool@1.0.0".to_owned()]);
        assert_eq!(report.hidden, vec!["2.0.0".to_owned()]);
    }

    #[test]
    fn scripts_named_install_and_preinstall_count_too() {
        let mut doc = json!({
            "name": "x",
            "dist-tags": { "latest": "1.0.0" },
            "versions": { "1.0.0": { "scripts": { "install": "a", "preinstall": "b" } } },
            "time": { "1.0.0": ago(100 * DAY) },
        });
        assert_eq!(filter_npm(&mut doc, NOW).unwrap().install_scripts.len(), 1);
    }

    #[test]
    fn a_document_without_versions_or_time_is_refused() {
        assert!(filter_npm(&mut json!({ "name": "x" }), NOW).is_none());
        assert!(filter_npm(&mut json!({ "name": "x", "versions": {} }), NOW).is_none());
    }

    #[test]
    fn the_newest_visible_version_is_chosen_by_publish_time_and_stable_wins() {
        let doc = json!({
            "versions": { "1.0.0": {}, "1.1.0-beta": {}, "1.0.5": {} },
            "time": {
                "1.0.0": ago(100 * DAY),
                "1.1.0-beta": ago(5 * DAY),
                "1.0.5": ago(20 * DAY),
            },
        });
        assert_eq!(newest_visible(&doc).as_deref(), Some("1.0.5"));
    }

    #[test]
    fn wheel_filenames_give_their_version_with_and_without_a_build_tag() {
        assert_eq!(
            pypi_version_of("requests-2.34.2-py3-none-any.whl").as_deref(),
            Some("2.34.2")
        );
        assert_eq!(
            pypi_version_of("pkg-1.0-1-py3-none-any.whl").as_deref(),
            Some("1.0")
        );
        assert_eq!(pypi_version_of("bad.whl"), None);
    }

    #[test]
    fn source_distribution_filenames_give_their_version() {
        assert_eq!(
            pypi_version_of("requests-2.34.2.tar.gz").as_deref(),
            Some("2.34.2")
        );
        assert_eq!(pypi_version_of("my-pkg-1.0.zip").as_deref(), Some("1.0"));
        assert_eq!(pypi_version_of("noversion.tar.gz"), None);
        assert_eq!(pypi_version_of("file.exe"), None);
    }

    #[test]
    fn a_young_pypi_file_is_removed_and_its_version_only_when_no_file_is_left() {
        let mut doc = json!({
            "name": "requests",
            "versions": ["2.34.1", "2.34.2"],
            "files": [
                { "filename": "requests-2.34.1.tar.gz", "upload-time": ago(100 * DAY) },
                { "filename": "requests-2.34.1-py3-none-any.whl", "upload-time": ago(100 * DAY) },
                { "filename": "requests-2.34.2.tar.gz", "upload-time": ago(60) },
                { "filename": "requests-2.34.2-py3-none-any.whl", "upload-time": ago(60) },
            ],
        });
        let report = filter_pypi(&mut doc, NOW).unwrap();
        assert_eq!(report.hidden_files.len(), 2);
        assert_eq!(doc["versions"], json!(["2.34.1"]));
        assert_eq!(doc["files"].as_array().map(Vec::len), Some(2));
        assert!(!report.too_new);
    }

    #[test]
    fn a_pypi_file_with_no_upload_time_or_no_version_is_hidden() {
        let mut doc = json!({
            "name": "x",
            "versions": ["1.0"],
            "files": [
                { "filename": "x-1.0.tar.gz" },
                { "filename": "README.txt", "upload-time": ago(100 * DAY) },
                { "filename": "x-1.0-py3-none-any.whl", "upload-time": ago(100 * DAY) },
            ],
        });
        let report = filter_pypi(&mut doc, NOW).unwrap();
        assert_eq!(report.hidden_files.len(), 2);
        assert_eq!(doc["files"].as_array().map(Vec::len), Some(1));
    }

    #[test]
    fn a_pypi_project_whose_first_upload_is_young_is_too_new() {
        let mut doc = json!({
            "name": "fresh",
            "versions": ["1.0"],
            "files": [{ "filename": "fresh-1.0.tar.gz", "upload-time": ago(3 * DAY) }],
        });
        assert!(filter_pypi(&mut doc, NOW).unwrap().too_new);
    }

    #[test]
    fn a_pypi_document_without_files_is_refused() {
        assert!(filter_pypi(&mut json!({ "name": "x" }), NOW).is_none());
    }
}
