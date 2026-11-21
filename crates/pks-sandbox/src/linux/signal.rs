//! Pausing, resuming and killing a sandboxed session (PRD FR-NOTIFY).
//!
//! bubblewrap runs the IDE in a new session and process group that its own
//! group does not contain (checked on bubblewrap 0.9.0: the sandboxed `sleep`
//! had a different group from bwrap). A signal to bwrap's group would miss the
//! IDE, so signals go to every process below bwrap in the process tree. Every
//! process in the sandbox is such a descendant, including orphans, because
//! they are re-parented inside the sandbox and that parent is in the tree.

use std::collections::{BTreeSet, HashMap};
use std::io;

/// Rounds of the tree walk. Each round signals the processes it has not seen
/// yet, so a process forked during the walk is caught by the next round.
const MAX_ROUNDS: usize = 8;

/// The signals this module sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    /// Pause the session (SIGSTOP). It cannot be caught or ignored.
    Stop,
    /// Resume a paused session (SIGCONT).
    Continue,
    /// Kill the session (SIGKILL).
    Kill,
}

/// Sends `signal` to the process `root` and to every process below it.
/// Returns the number of processes signalled.
///
/// # Errors
/// Fails when `root` is not a positive process ID, when `root` does not exist,
/// or when `/proc` cannot be read. A process that exits during the walk is not
/// an error.
pub fn signal_tree(root: i32, signal: Signal) -> io::Result<usize> {
    if root <= 0 {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    let mut signalled: BTreeSet<i32> = BTreeSet::new();
    for _ in 0..MAX_ROUNDS {
        let children = children_map()?;
        let mut fresh = false;
        for pid in descendants(root, &children) {
            if !signalled.insert(pid) {
                continue;
            }
            fresh = true;
            match send(pid, signal) {
                Ok(()) => {}
                // The process exited after the walk listed it.
                Err(error) if error.raw_os_error() == Some(libc::ESRCH) => {}
                Err(error) => return Err(error),
            }
        }
        if !fresh {
            break;
        }
    }
    if signalled.is_empty() {
        return Err(io::Error::from_raw_os_error(libc::ESRCH));
    }
    Ok(signalled.len())
}

/// Parent of every process listed in `/proc`, as a map from parent to children.
fn children_map() -> io::Result<HashMap<i32, Vec<i32>>> {
    let mut children: HashMap<i32, Vec<i32>> = HashMap::new();
    for entry in std::fs::read_dir("/proc")? {
        let Ok(entry) = entry else { continue };
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<i32>().ok())
        else {
            continue;
        };
        // A process that exits while it is read has no stat file any more.
        let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        if let Some(parent) = parent_of(&stat) {
            children.entry(parent).or_default().push(pid);
        }
    }
    Ok(children)
}

/// The parent process ID from the text of `/proc/<pid>/stat`. The command name
/// is in parentheses and may contain spaces or `)`, so the fields are read
/// after the last `)`: state, then parent.
fn parent_of(stat: &str) -> Option<i32> {
    let (_, after_name) = stat.rsplit_once(')')?;
    after_name.split_whitespace().nth(1)?.parse().ok()
}

/// `root` and every process below it, found by walking the children map.
fn descendants(root: i32, children: &HashMap<i32, Vec<i32>>) -> Vec<i32> {
    let mut found = vec![root];
    let mut next = 0;
    while next < found.len() {
        if let Some(kids) = children.get(&found[next]) {
            found.extend(kids.iter().copied());
        }
        next += 1;
    }
    found
}

/// Sends one signal to one process.
#[allow(unsafe_code)]
fn send(pid: i32, signal: Signal) -> io::Result<()> {
    let number = match signal {
        Signal::Stop => libc::SIGSTOP,
        Signal::Continue => libc::SIGCONT,
        Signal::Kill => libc::SIGKILL,
    };
    // SAFETY: kill(2) reads two integers and nothing else. `pid` is positive,
    // so only that one process is addressed.
    let rc = unsafe { libc::kill(pid, number) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_non_positive_pid_is_refused_before_any_signal_is_sent() {
        assert!(signal_tree(0, Signal::Stop).is_err());
        assert!(signal_tree(-5, Signal::Kill).is_err());
    }

    #[test]
    fn the_parent_is_read_after_a_command_name_with_spaces_and_brackets() {
        let stat = "123 (my (odd) name) S 45 1 1 0 -1";
        assert_eq!(parent_of(stat), Some(45));
        assert_eq!(parent_of("garbage"), None);
    }

    #[test]
    fn descendants_include_the_root_and_every_level_below_it() {
        let children = HashMap::from([(1, vec![2, 3]), (2, vec![4]), (4, vec![5])]);
        let mut found = descendants(1, &children);
        found.sort_unstable();
        assert_eq!(found, vec![1, 2, 3, 4, 5]);
        assert_eq!(descendants(3, &children), vec![3]);
    }
}
