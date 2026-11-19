//! `pumpkin-shell`: sandbox and tripwire system for AI-powered IDEs.

mod doctor;
mod ide;
mod log;
mod policy;
mod proxy;
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

    /// Launch an IDE in the sandbox.
    Ide(IdeArgs),

    /// Policy management commands.
    Policy {
        #[command(subcommand)]
        cmd: policy::PolicyCmd,
    },

    /// Log management commands.
    Log {
        #[command(subcommand)]
        cmd: log::LogCmd,
    },

    /// Proxy management commands.
    Proxy {
        #[command(subcommand)]
        cmd: proxy::ProxyArgs,
    },
}

#[derive(Parser)]
pub struct IdeArgs {
    /// IDE to launch (e.g., kiro)
    pub ide: String,

    /// Path to the repository (default: current directory)
    #[arg(short, long, default_value = ".")]
    pub repo: String,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Some(Command::Doctor { json }) => doctor::run(json),
        Some(Command::Scan { path, json, ci }) => scan::run(&path, json, ci),
        Some(Command::Ide(args)) => ide::run(&args.ide, &args.repo),
        Some(Command::Policy { cmd }) => match policy::handle_policy_cmd(&cmd) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("Error: {}", e);
                ExitCode::from(2)
            }
        },
        Some(Command::Log { cmd }) => match log::handle_log_cmd(&cmd) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("Error: {}", e);
                ExitCode::from(2)
            }
        },
        Some(Command::Proxy { cmd }) => match proxy::run(&cmd) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("Error: {}", e);
                ExitCode::from(2)
            }
        },
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
