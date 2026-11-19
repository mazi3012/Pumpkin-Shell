//! `pumpkin-shell`: sandbox and tripwire system for AI-powered IDEs.

mod doctor;

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
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Some(Command::Doctor { json }) => doctor::run(json),
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
