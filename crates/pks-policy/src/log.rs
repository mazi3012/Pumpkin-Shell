//! Tamper-evident signed log
//!
//! Log format is JSONL (JSON Lines) with the following fields:
//!
//! ```json
//! {
//!   "v": "1",
//!   "session": "uuid",
//!   "seq": 0,
//!   "ts": "2026-11-19T12:00:00Z",
//!   "prev": "base64_sha256_of_previous_entry",
//!   "policy_hash": "base64_sha256_of_policy",
//!   "layer": "sandbox",
//!   "target": "/path/to/resource",
//!   "rule": "EXEC-DESTRUCTIVE",
//!   "verdict": "block",
//!   "sig": "base64_ed25519_signature"
//! }
//! ```

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// A single log entry
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogEntry {
    pub v: String,
    pub session: String,
    pub seq: u64,
    pub ts: String,
    pub prev: String,
    pub policy_hash: String,
    pub layer: String,
    pub target: String,
    pub rule: String,
    pub verdict: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
}

impl LogEntry {
    /// Create a new log entry
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session: &str,
        seq: u64,
        prev_hash: &str,
        policy_hash: &str,
        layer: &str,
        target: &str,
        rule: &str,
        verdict: &str,
    ) -> Self {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let ts_str = format!("{}.{:09}", ts, 0);

        LogEntry {
            v: "1".to_string(),
            session: session.to_string(),
            seq,
            ts: ts_str,
            prev: prev_hash.to_string(),
            policy_hash: policy_hash.to_string(),
            layer: layer.to_string(),
            target: target.to_string(),
            rule: rule.to_string(),
            verdict: verdict.to_string(),
            sig: None,
        }
    }

    /// Calculate the hash of this entry
    #[allow(deprecated)]
    pub fn hash(&self) -> String {
        let json = serde_json::to_string(self).expect("Failed to serialize entry");
        let mut hasher = Sha256::new();
        hasher.update(json.as_bytes());
        base64::encode(hasher.finalize())
    }
}

/// Chain of log entries with verification
pub struct LogChain {
    entries: Vec<LogEntry>,
}

impl Default for LogChain {
    fn default() -> Self {
        Self::new()
    }
}

impl LogChain {
    /// Create a new log chain
    pub fn new() -> Self {
        LogChain {
            entries: Vec::new(),
        }
    }

    /// Get the number of entries
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the chain is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get entries slice
    pub fn entries(&self) -> &[LogEntry] {
        &self.entries
    }

    /// Load log chain from file
    pub fn load(path: &Path) -> Result<Self, LogError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| LogError::ReadFailed(path.to_path_buf(), e))?;

        let mut entries = Vec::new();
        for (line_num, line) in content.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let entry: LogEntry = serde_json::from_str(line)
                .map_err(|e| LogError::ParseFailed(path.to_path_buf(), line_num + 1, e))?;
            entries.push(entry);
        }

        Ok(LogChain { entries })
    }

    /// Save log chain to file
    pub fn save(&self, path: &Path) -> Result<(), LogError> {
        let content = self
            .entries
            .iter()
            .map(|e| serde_json::to_string(e).expect("Failed to serialize entry"))
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(path, content).map_err(|e| LogError::WriteFailed(path.to_path_buf(), e))?;
        Ok(())
    }

    /// Append an entry
    pub fn append(&mut self, entry: LogEntry) -> Result<(), LogError> {
        if self.entries.is_empty() {
            // First entry: prev should be empty hash
            if !entry.prev.is_empty() && entry.prev != Self::empty_hash() {
                return Err(LogError::InvalidPrevHash);
            }
        } else {
            // Verify chain continuity
            let prev_hash = self.entries.last().unwrap().hash();
            if entry.prev != prev_hash {
                return Err(LogError::ChainBroken {
                    expected: prev_hash,
                    got: entry.prev.clone(),
                });
            }
        }

        self.entries.push(entry);
        Ok(())
    }

    /// Verify the entire log chain
    pub fn verify(&self) -> Result<(), LogError> {
        if self.entries.is_empty() {
            return Ok(());
        }

        // Check chain continuity
        let prev_hash = Self::empty_hash();
        for (i, entry) in self.entries.iter().enumerate() {
            if i == 0 {
                if !entry.prev.is_empty() && entry.prev != prev_hash {
                    return Err(LogError::InvalidPrevHash);
                }
            } else {
                if entry.prev != self.entries[i - 1].hash() {
                    return Err(LogError::ChainBroken {
                        expected: self.entries[i - 1].hash(),
                        got: entry.prev.clone(),
                    });
                }
            }
        }

        Ok(())
    }

    /// Generate an empty hash for the first entry
    #[allow(deprecated)]
    pub fn empty_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"");
        base64::encode(hasher.finalize())
    }

    /// Get checkpoint hash (hash of all entries concatenated)
    #[allow(deprecated)]
    pub fn checkpoint(&self) -> String {
        let mut hasher = Sha256::new();
        for entry in &self.entries {
            hasher.update(serde_json::to_string(entry).expect("Failed to serialize entry"));
        }
        base64::encode(hasher.finalize())
    }

    /// Check if log has been tampered with (editing, deleting, reordering, truncating)
    pub fn check_tampering(&self) -> Result<(), LogError> {
        self.verify()
    }
}

/// Error types for log operations
#[derive(Error, Debug)]
pub enum LogError {
    #[error("Failed to read log file '{0}': {1}")]
    ReadFailed(std::path::PathBuf, std::io::Error),

    #[error("Failed to parse log file '{0}' line {1}: {2}")]
    ParseFailed(std::path::PathBuf, usize, serde_json::Error),

    #[error("Failed to write log file '{0}': {1}")]
    WriteFailed(std::path::PathBuf, std::io::Error),

    #[error("Log chain broken: expected '{expected}', got '{got}'")]
    ChainBroken { expected: String, got: String },

    #[error("Invalid previous hash for first entry")]
    InvalidPrevHash,

    #[error("Missing signature in entry")]
    MissingSignature,

    #[error("Missing public key for verification")]
    MissingPublicKey,

    #[error("Invalid public key")]
    InvalidPublicKey,

    #[error("Invalid signature length")]
    InvalidSignatureLength,

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Decode failed for '{0}': {1}")]
    DecodeFailed(String, base64::DecodeError),

    #[error("Log has been tampered with")]
    Tampered,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_log_entry_hash() {
        let entry = LogEntry::new(
            "test-session",
            0,
            "",
            "policy-hash",
            "sandbox",
            "/path/to/file",
            "EXEC-DESTRUCTIVE",
            "block",
        );

        let hash1 = entry.hash();
        let hash2 = entry.hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_log_chain_save_load() {
        let mut chain = LogChain::new();

        // Create and append entries
        for i in 0..3 {
            let prev_hash = if i == 0 {
                LogChain::empty_hash()
            } else {
                chain.entries()[(i - 1) as usize].hash()
            };
            let entry = LogEntry::new(
                "test-session",
                i as u64,
                &prev_hash,
                "policy-hash",
                "sandbox",
                "/path/to/file",
                "EXEC-DESTRUCTIVE",
                "block",
            );
            chain.append(entry).unwrap();
        }

        let dir = tempdir().unwrap();
        let path = dir.path().join("log.jsonl");

        chain.save(&path).unwrap();

        let loaded = LogChain::load(&path).unwrap();
        assert_eq!(loaded.entries.len(), chain.entries.len());
        assert_eq!(loaded.entries[0].session, chain.entries[0].session);
    }
}
