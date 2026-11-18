//! `pumpkin-shell`: sandbox and tripwire system for AI-powered IDEs.

use clap::Parser;

/// Sandbox and tripwire system for AI-powered IDEs on Linux and Windows.
#[derive(Parser)]
#[command(name = "pumpkin-shell", version)]
struct Cli {}

fn main() {
    Cli::parse();
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
