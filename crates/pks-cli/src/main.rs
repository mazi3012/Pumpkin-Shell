//! `pumpkin-shell`: sandbox and tripwire system for AI-powered IDEs.

mod doctor;

mod scan;

use std::process::ExitCode;

use clap::{Parser, Subcommand};

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

    /// Scan a repository for agent-escape setups.
    Scan {
        /// Path to the repository root (default: current directory).
        #[arg(short, long, default_value = ".")]
        path: String,

        /// Print the report as JSON.
        #[arg(long)]
        json: bool,

        /// CI mode: exit 0 if clean, 1 if findings, 2 on error.
        #[arg(long)]
        ci: bool,
    },
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Some(Command::Doctor { json }) => doctor::run(json),
        Some(Command::Scan { path, json, ci }) => scan::run(&path, json, ci),
        None => ExitCode::SUCCESS,
    }
}

#[cfg(test)]
mod tests {
    use super::Cli;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }
}
