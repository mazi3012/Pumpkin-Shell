//! Log management commands

use anyhow::Result;
use clap::Parser;
use pks_policy::log::{LogChain, LogEntry};
use std::path::PathBuf;

/// Log management commands
#[derive(Parser)]
pub enum LogCmd {
    /// Create a new log entry
    Append(LogAppendArgs),
    /// Verify log chain integrity
    Verify(LogVerifyArgs),
    /// Create a checkpoint
    Checkpoint(LogCheckpointArgs),
}

#[derive(Parser)]
pub struct LogAppendArgs {
    /// Path to log file
    #[arg(short = 'l', long)]
    pub log: PathBuf,
    /// Session ID
    #[arg(short = 's', long)]
    pub session: String,
    /// Layer name
    #[arg(short = 'r', long)]
    pub layer: String,
    /// Target path
    #[arg(short = 't', long)]
    pub target: String,
    /// Rule name
    #[arg(short = 'u', long)]
    pub rule: String,
    /// Verdict (block/allow/warn)
    #[arg(short = 'v', long)]
    pub verdict: String,
    /// Policy hash
    #[arg(short = 'c', long)]
    pub policy_hash: String,
}

#[derive(Parser)]
pub struct LogVerifyArgs {
    /// Path to log file
    #[arg(short = 'l', long)]
    pub log: PathBuf,
}

#[derive(Parser)]
pub struct LogCheckpointArgs {
    /// Path to log file
    #[arg(short = 'l', long)]
    pub log: PathBuf,
    /// Output checkpoint file
    #[arg(short = 'o', long)]
    pub output: PathBuf,
}

pub fn handle_log_cmd(cmd: &LogCmd) -> Result<()> {
    match cmd {
        LogCmd::Append(args) => log_append(args),
        LogCmd::Verify(args) => log_verify(args),
        LogCmd::Checkpoint(args) => log_checkpoint(args),
    }
}

fn log_append(args: &LogAppendArgs) -> Result<()> {
    let mut chain = if args.log.exists() {
        LogChain::load(&args.log)?
    } else {
        LogChain::new()
    };

    // Calculate sequence number
    let seq = chain.len() as u64;

    // Calculate previous hash
    let prev_hash = if chain.is_empty() {
        LogChain::empty_hash()
    } else {
        chain.entries()[(seq - 1) as usize].hash()
    };

    // Create entry
    let entry = LogEntry::new(
        &args.session,
        seq,
        &prev_hash,
        &args.policy_hash,
        &args.layer,
        &args.target,
        &args.rule,
        &args.verdict,
    );

    chain.append(entry)?;

    chain.save(&args.log)?;

    eprintln!(
        "Log entry appended: seq={}, layer={}, rule={}",
        seq, args.layer, args.rule
    );
    Ok(())
}

fn log_verify(args: &LogVerifyArgs) -> Result<()> {
    let chain = LogChain::load(&args.log)?;

    match chain.verify() {
        Ok(()) => {
            eprintln!("Log chain verified successfully");
            Ok(())
        }
        Err(e) => {
            eprintln!("Log chain verification failed: {}", e);
            Err(anyhow::anyhow!(e))
        }
    }
}

fn log_checkpoint(args: &LogCheckpointArgs) -> Result<()> {
    let chain = LogChain::load(&args.log)?;
    let checkpoint = chain.checkpoint();

    let checkpoint_data = serde_json::json!({
        "checkpoint": checkpoint,
        "timestamp": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::ZERO),
        "entry_count": chain.len()
    });

    std::fs::write(
        &args.output,
        serde_json::to_string_pretty(&checkpoint_data)?,
    )?;

    eprintln!("Checkpoint created: {}", args.output.display());
    Ok(())
}
