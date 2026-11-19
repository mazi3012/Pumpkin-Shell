//! Policy management commands

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

/// Policy management commands
#[derive(Parser)]
pub enum PolicyCmd {
    /// Trust a repository policy (pin the hash)
    Trust(PolicyTrustArgs),
    /// Verify a repository policy against pinned hash
    Verify(PolicyVerifyArgs),
}

#[derive(Parser)]
pub struct PolicyTrustArgs {
    /// Path to repository policy file
    #[arg(short = 'p', long)]
    pub policy: PathBuf,
    /// Path to policy hash file (where to store pinned hash)
    #[arg(short = 'f', long)]
    pub hash_file: PathBuf,
}

#[derive(Parser)]
pub struct PolicyVerifyArgs {
    /// Path to repository policy file
    #[arg(short = 'p', long)]
    pub policy: PathBuf,
    /// Path to pinned hash file
    #[arg(short = 'f', long)]
    pub hash_file: PathBuf,
}

pub fn handle_policy_cmd(cmd: &PolicyCmd) -> Result<()> {
    match cmd {
        PolicyCmd::Trust(args) => policy_trust(args),
        PolicyCmd::Verify(args) => policy_verify(args),
    }
}

fn policy_trust(args: &PolicyTrustArgs) -> Result<()> {
    let policy = pks_policy::Policy::load(&args.policy)?;
    let hash = policy.hash();

    // Save pinned hash
    #[allow(deprecated)]
    std::fs::write(&args.hash_file, base64::encode(&hash))?;
    eprintln!("Trusted policy '{}': hash pinned", args.policy.display());
    Ok(())
}

fn policy_verify(args: &PolicyVerifyArgs) -> Result<()> {
    let policy = pks_policy::Policy::load(&args.policy)?;
    let current_hash = policy.hash();

    let pinned_hash = std::fs::read_to_string(&args.hash_file)?;
    #[allow(deprecated)]
    let pinned_hash = base64::decode(pinned_hash.trim())?;

    if current_hash == pinned_hash {
        eprintln!("Policy '{}' verified: hash matches", args.policy.display());
        Ok(())
    } else {
        anyhow::bail!(
            "Policy '{}' modified: hash mismatch (POL-UNTRUSTED)",
            args.policy.display()
        );
    }
}
