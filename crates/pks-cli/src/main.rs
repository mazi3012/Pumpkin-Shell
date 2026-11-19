//! `pumpkin-shell`: sandbox and tripwire system for AI-powered IDEs.

mod doctor;
mod log;
mod policy;
mod scan;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use pks_core::Severity;

/// Sandbox and tripwire system for AI-powered IDEs on Linux and Windows.
#[derive(Parser)]
#[command(name = "pumpkin-shell", version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Check whether this machine can run the sandbox, and how to fix each problem.
    Doctor {
        /// Print the report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Scan a repository for setups that let an agent escape its workspace.
    Scan {
        /// Repository to scan.
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Print the report as JSON.
        #[arg(long)]
        json: bool,
        /// Exit 1 when a finding reaches --fail-on. Exit 2 when the scan is incomplete.
        #[arg(long)]
        ci: bool,
        /// Lowest severity that fails a --ci run.
        #[arg(long, value_enum, default_value_t = FailOn::High)]
        fail_on: FailOn,
        /// Also scan files that .gitignore lists. Use this in CI: a committed
        /// .gitignore can otherwise hide tracked files from the scan.
        #[arg(long)]
        no_ignore: bool,
    },
    /// Pin the repo's pumpkin-shell.toml so it is applied. Run it again after any edit.
    Trust {
        /// Repository whose pumpkin-shell.toml to pin.
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    /// Show and check the policy that applies to a repository.
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    /// Work with session logs.
    Log {
        #[command(subcommand)]
        command: LogCommand,
    },
}

#[derive(Subcommand)]
enum PolicyCommand {
    /// Print the effective policy. Exit 1 when the repo policy is not applied or tries to loosen a rule.
    Check {
        /// Repository to check.
        #[arg(default_value = ".")]
        path: PathBuf,
    },
}

#[derive(Subcommand)]
enum LogCommand {
    /// Check a session log's chain, signatures and checkpoint. Exit 1 when it fails, 2 when it cannot be checked.
    Verify {
        /// The session log (.jsonl). Its checkpoint is read from `<file>.checkpoint`.
        file: PathBuf,
        /// Accept a log with no checkpoint (a session that may still be running).
        #[arg(long)]
        allow_open: bool,
        /// Directory holding log-signing.pub (default: the pumpkin-shell data dir, under keys).
        #[arg(long)]
        key_dir: Option<PathBuf>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum FailOn {
    Notice,
    Warn,
    High,
    Critical,
}

impl From<FailOn> for Severity {
    fn from(value: FailOn) -> Self {
        match value {
            FailOn::Notice => Severity::Notice,
            FailOn::Warn => Severity::Warn,
            FailOn::High => Severity::High,
            FailOn::Critical => Severity::Critical,
        }
    }
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Some(Command::Doctor { json }) => doctor::run(json),
        Some(Command::Scan {
            path,
            json,
            ci,
            fail_on,
            no_ignore,
        }) => scan::run(&path, json, ci, fail_on.into(), no_ignore),
        Some(Command::Trust { path }) => policy::trust(&path),
        Some(Command::Policy {
            command: PolicyCommand::Check { path },
        }) => policy::check(&path),
        Some(Command::Log {
            command:
                LogCommand::Verify {
                    file,
                    allow_open,
                    key_dir,
                },
        }) => log::verify(&file, allow_open, key_dir.as_deref()),
        None => ExitCode::SUCCESS,
    }
}

#[cfg(test)]
mod tests {
    use super::{Cli, FailOn};
    use clap::CommandFactory;
    use pks_core::Severity;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn fail_on_maps_to_the_matching_severity() {
        assert_eq!(Severity::from(FailOn::Notice), Severity::Notice);
        assert_eq!(Severity::from(FailOn::Warn), Severity::Warn);
        assert_eq!(Severity::from(FailOn::High), Severity::High);
        assert_eq!(Severity::from(FailOn::Critical), Severity::Critical);
    }
}
