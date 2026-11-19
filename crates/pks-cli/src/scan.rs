//! `pumpkin-shell scan`: finds agent-escape setups in a repository.

use std::path::Path;
use std::process::ExitCode;

use pks_core::Severity;
use pks_scan::{Report, ScanOptions};

/// Findings shown per skip reason before the rest are only counted.
const MAX_SKIPPED_LISTED: usize = 10;

/// Exit code for an incomplete scan or a scan that could not start.
const EXIT_ERROR: u8 = 2;

pub fn run(path: &Path, json: bool, ci: bool, fail_on: Severity, no_ignore: bool) -> ExitCode {
    let options = ScanOptions {
        respect_gitignore: !no_ignore,
    };
    let report = match pks_scan::scan(path, &options) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("scan: {error}");
            return ExitCode::from(EXIT_ERROR);
        }
    };

    if json {
        match serde_json::to_string_pretty(&report) {
            Ok(text) => println!("{text}"),
            Err(error) => {
                eprintln!("scan: could not encode the report as JSON: {error}");
                return ExitCode::from(EXIT_ERROR);
            }
        }
    } else {
        print_human(&report);
    }

    if !report.is_complete() {
        ExitCode::from(EXIT_ERROR)
    } else if ci && report.has_findings_at_least(fail_on) {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn print_human(report: &Report) {
    for finding in &report.findings {
        println!(
            "[{:?}] {} {}\n    {}\n    fix: {}",
            finding.severity,
            finding.rule.as_str(),
            finding.target,
            finding.message,
            finding.fix
        );
    }
    for issue in &report.errors {
        if issue.path.is_empty() {
            println!("[ERROR] {}", issue.message);
        } else {
            println!("[ERROR] {}: {}", issue.path, issue.message);
        }
    }
    for skipped in report.skipped.iter().take(MAX_SKIPPED_LISTED) {
        println!("[SKIPPED] {} ({:?})", skipped.path, skipped.reason);
    }
    if report.skipped.len() > MAX_SKIPPED_LISTED {
        println!(
            "[SKIPPED] {} more (use --json for the full list)",
            report.skipped.len() - MAX_SKIPPED_LISTED
        );
    }
    println!(
        "{} file(s) scanned, {} finding(s), {} skipped, {} error(s).",
        report.files_scanned,
        report.findings.len(),
        report.skipped.len(),
        report.errors.len()
    );
}
