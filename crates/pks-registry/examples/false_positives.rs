//! False-positive benchmark for the registry guard (PRD FR-REG, Phase 14).
//!
//! Runs the same document filters the mirror uses over the 1,000 most
//! downloaded npm and PyPI packages, live from the registries, and counts what
//! the guard would do to them. A popular package should not be refused; a
//! version hidden by the cooldown is expected (the install resolves an older
//! version); a warning is only an alert.
//!
//! Run: `cargo run --release -p pks-registry --example false_positives`.
//! It makes about 2,000 HTTPS requests, so it takes a few minutes.

use pks_registry::document::{filter_npm, filter_pypi};
use pks_registry::typosquat::{self, Ecosystem};
use pks_registry::upstream::Upstream;

const NPM_NAMES: &str = include_str!("../data/npm-top.txt");
const PYPI_NAMES: &str = include_str!("../data/pypi-top.txt");
const SAMPLE: usize = 1000;

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

fn main() {
    let upstream = match Upstream::new() {
        Ok(upstream) => upstream,
        Err(error) => {
            eprintln!("cannot start the HTTPS client: {error}");
            std::process::exit(2);
        }
    };
    let clock = now();

    let mut npm = Tally::default();
    for name in NPM_NAMES.lines().take(SAMPLE) {
        let url = format!("https://registry.npmjs.org/{}", name.replace('/', "%2f"));
        match upstream.get(&url) {
            Ok(body) => match serde_json::from_slice::<serde_json::Value>(&body) {
                Ok(mut doc) => match filter_npm(&mut doc, clock) {
                    Some(report) => npm.record(
                        report.too_new,
                        !report.hidden.is_empty(),
                        !report.install_scripts.is_empty(),
                    ),
                    None => npm.failed(name, "not a packument"),
                },
                Err(_) => npm.failed(name, "not JSON"),
            },
            Err(error) => npm.failed(name, &error.to_string()),
        }
    }

    let mut pypi = Tally::default();
    for name in PYPI_NAMES.lines().take(SAMPLE) {
        let url = format!("https://pypi.org/simple/{name}/");
        match upstream.get_accept(&url, Some("application/vnd.pypi.simple.v1+json")) {
            Ok(body) => match serde_json::from_slice::<serde_json::Value>(&body) {
                Ok(mut doc) => match filter_pypi(&mut doc, clock) {
                    Some(report) => {
                        pypi.record(report.too_new, !report.hidden_files.is_empty(), false)
                    }
                    None => pypi.failed(name, "not an index"),
                },
                Err(_) => pypi.failed(name, "not JSON"),
            },
            Err(error) => pypi.failed(name, &error.to_string()),
        }
    }

    let npm_warn = NPM_NAMES
        .lines()
        .take(SAMPLE)
        .filter(|n| typosquat::check(Ecosystem::Npm, n).is_some())
        .count();
    let pypi_warn = PYPI_NAMES
        .lines()
        .take(SAMPLE)
        .filter(|n| typosquat::check(Ecosystem::PyPi, n).is_some())
        .count();

    println!("checked on {clock} (unix seconds), sample of {SAMPLE} per registry");
    npm.print("npm");
    println!("  typosquat warnings against the other popular names: {npm_warn}");
    pypi.print("PyPI");
    println!("  typosquat warnings against the other popular names: {pypi_warn}");
}

#[derive(Default)]
struct Tally {
    checked: usize,
    refused_too_new: usize,
    with_hidden_version: usize,
    with_install_script: usize,
    failed: usize,
    failures: Vec<String>,
}

impl Tally {
    fn record(&mut self, too_new: bool, hidden: bool, scripts: bool) {
        self.checked += 1;
        self.refused_too_new += usize::from(too_new);
        self.with_hidden_version += usize::from(hidden);
        self.with_install_script += usize::from(scripts);
    }

    fn failed(&mut self, name: &str, why: &str) {
        self.failed += 1;
        if self.failures.len() < 10 {
            self.failures.push(format!("{name}: {why}"));
        }
    }

    fn print(&self, label: &str) {
        println!(
            "{label}: {} checked, {} could not be read",
            self.checked, self.failed
        );
        println!(
            "  refused as too new (false positive if it appears): {}",
            self.refused_too_new
        );
        println!(
            "  with a version hidden by the 72-hour cooldown: {}",
            self.with_hidden_version
        );
        println!(
            "  with an install script in a visible version: {}",
            self.with_install_script
        );
        for failure in &self.failures {
            println!("  unreadable: {failure}");
        }
    }
}
