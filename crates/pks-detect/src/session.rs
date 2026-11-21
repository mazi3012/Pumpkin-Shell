//! Session information for notifications and review.

use std::path::PathBuf;

/// Information about a running or completed session.
#[derive(Debug, Clone)]
pub struct SessionInfo {
    /// Session ID.
    pub id: String,
    /// Path to the session directory.
    pub dir: PathBuf,
    /// Path to the session log.
    pub log: PathBuf,
    /// Path to the watch file.
    pub watch: PathBuf,
    /// Path to the snapshot directory.
    pub snapshot: PathBuf,
    /// Path to the file holding the sandbox's process ID, while it runs.
    pub pid: PathBuf,
    /// Path to the marker that exists while the session is paused.
    pub paused: PathBuf,
}

/// File in a session directory with the sandbox's process ID, written while
/// the IDE runs.
pub const PID_FILE: &str = "ide.pid";
/// File in a session directory that exists while the session is paused.
pub const PAUSED_FILE: &str = "paused";

/// The sandbox's process ID from the PID file in `dir`. `None` when the file
/// is missing or does not hold a number (the IDE is not running).
#[must_use]
pub fn read_pid(dir: &std::path::Path) -> Option<i32> {
    std::fs::read_to_string(dir.join(PID_FILE))
        .ok()?
        .trim()
        .parse()
        .ok()
        .filter(|pid| *pid > 0)
}

impl SessionInfo {
    /// Creates session info for the given session directory.
    pub fn new(session_dir: PathBuf) -> Self {
        let id = session_dir
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        Self {
            id,
            log: session_dir.join("session.jsonl"),
            watch: session_dir.join("watch.jsonl"),
            snapshot: session_dir.join("snapshot.git"),
            pid: session_dir.join(PID_FILE),
            paused: session_dir.join(PAUSED_FILE),
            dir: session_dir,
        }
    }

    /// Lists all sessions in the data directory.
    pub fn list(data_dir: &std::path::Path) -> Vec<Self> {
        let sessions_dir = data_dir.join("sessions");
        let mut sessions = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&sessions_dir) {
            for entry in entries.flatten() {
                if entry.path().is_dir() {
                    sessions.push(Self::new(entry.path()));
                }
            }
        }
        // Sort by modification time, newest first.
        sessions.sort_by(|a, b| {
            let a_time = std::fs::metadata(&a.dir)
                .and_then(|m| m.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            let b_time = std::fs::metadata(&b.dir)
                .and_then(|m| m.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            b_time.cmp(&a_time)
        });
        sessions
    }

    /// Finds a session by ID.
    pub fn find(data_dir: &std::path::Path, id: &str) -> Option<Self> {
        let sessions_dir = data_dir.join("sessions");
        let session_dir = sessions_dir.join(id);
        if session_dir.is_dir() {
            Some(Self::new(session_dir))
        } else {
            None
        }
    }
}
