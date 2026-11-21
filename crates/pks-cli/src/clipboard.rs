//! Copy out of the sandbox and paste into it (Phase 12).
//!
//! The sandbox has its own clipboard, on its own display. While the IDE runs,
//! the host reads both clipboards once a second:
//! - text Kiro copied is offered to the user, in a desktop popup, before it
//!   goes to the host clipboard (copy out);
//! - text the user copied on the desktop is offered, the same way, before it
//!   goes into Kiro's clipboard (paste in).
//!
//! Nothing moves without a yes. Text the host wrote itself is never offered
//! back. Only the length and a hash go to the session log, never the text.

use std::collections::HashSet;
use std::collections::hash_map::DefaultHasher;
use std::ffi::OsString;
use std::hash::{Hash, Hasher};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::ask;

/// File in the session directory that holds the nested display's details.
pub const DISPLAY_FILE: &str = "display";
/// Largest text moved in either direction.
const MAX_BYTES: usize = 64 * 1024;
/// How often the two clipboards are read.
const POLL: Duration = Duration::from_secs(1);
/// How long to wait for the sandbox display to be set up.
const WAIT_FOR_DISPLAY: Duration = Duration::from_secs(60);
/// Characters of the text shown in a popup.
const PREVIEW: usize = 200;
/// How long a clipboard read may take before it is abandoned.
const READ_TIMEOUT: Duration = Duration::from_secs(3);

/// The sandbox's display: its `DISPLAY` and access file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nested {
    pub display: OsString,
    pub xauthority: PathBuf,
}

/// Reads `DISPLAY=` and `XAUTHORITY=` lines from the display file.
#[must_use]
pub fn parse_display_file(text: &str) -> Option<Nested> {
    let mut display = None;
    let mut xauthority = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("DISPLAY=") {
            display = Some(OsString::from(value));
        } else if let Some(value) = line.strip_prefix("XAUTHORITY=") {
            xauthority = Some(PathBuf::from(value));
        }
    }
    Some(Nested {
        display: display?,
        xauthority: xauthority?,
    })
}

/// Reads the clipboard of `on` (or the host's own clipboard when `None`).
/// `None` when it is empty, not text, too large, or xclip fails or does not
/// answer in time. A sandbox that stops answering must not stall the watcher.
fn read(on: Option<&Nested>) -> Option<String> {
    let mut command = Command::new("xclip");
    command
        .args(["-o", "-selection", "clipboard"])
        .stdin(Stdio::null())
        .stderr(Stdio::null());
    if let Some(nested) = on {
        command
            .env("DISPLAY", &nested.display)
            .env("XAUTHORITY", &nested.xauthority);
    }
    let bytes = capture(&mut command)?;
    if bytes.is_empty() || bytes.len() > MAX_BYTES {
        return None;
    }
    String::from_utf8(bytes).ok()
}

/// Runs `command` and returns its output, or `None` when it fails or does not
/// finish within `READ_TIMEOUT`. The output is read up to one byte past the
/// limit, so a huge clipboard cannot exhaust memory.
fn capture(command: &mut Command) -> Option<Vec<u8>> {
    let mut child = command.stdout(Stdio::piped()).spawn().ok()?;
    let stdout = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stdout.take(MAX_BYTES as u64 + 1).read_to_end(&mut bytes);
        bytes
    });
    let deadline = Instant::now() + READ_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let bytes = reader.join().ok()?;
                return status.success().then_some(bytes);
            }
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.join();
                return None;
            }
        }
    }
}

/// Sets the clipboard of `on` (or the host's own clipboard when `None`).
/// xclip keeps the text itself after it returns.
fn write(on: Option<&Nested>, text: &str) -> Result<(), String> {
    let mut command = Command::new("xclip");
    command
        .args(["-i", "-selection", "clipboard"])
        .stdin(Stdio::piped())
        .stderr(Stdio::null());
    if let Some(nested) = on {
        command
            .env("DISPLAY", &nested.display)
            .env("XAUTHORITY", &nested.xauthority);
    }
    let mut child = command
        .spawn()
        .map_err(|e| format!("cannot run xclip: {e}"))?;
    if let Some(mut input) = child.stdin.take() {
        input
            .write_all(text.as_bytes())
            .map_err(|e| format!("cannot write to xclip: {e}"))?;
    }
    let status = child.wait().map_err(|e| format!("xclip failed: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("xclip failed ({status})"))
    }
}

fn hash_of(text: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    text.hash(&mut hasher);
    hasher.finish()
}

/// Waits for the sandbox's display file to appear, then returns its contents.
fn wait_for_nested(dir: &Path, stop: &AtomicBool) -> Option<Nested> {
    let path = dir.join(DISPLAY_FILE);
    let deadline = Instant::now() + WAIT_FOR_DISPLAY;
    while Instant::now() < deadline && !stop.load(Ordering::Relaxed) {
        if let Ok(text) = std::fs::read_to_string(&path)
            && let Some(nested) = parse_display_file(&text)
        {
            return Some(nested);
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    None
}

/// Watches both clipboards until `stop` is set. `record(rule, bytes, allowed)`
/// writes one line to the session log.
pub fn watch(stop: Arc<AtomicBool>, session_dir: PathBuf, record: impl Fn(&str, usize, bool)) {
    let Some(nested) = wait_for_nested(&session_dir, &stop) else {
        return;
    };
    let desktop = std::env::var_os("DISPLAY");
    // What is already on each clipboard is not offered; only new copies are.
    let mut seen_nested = read(Some(&nested)).map(|text| hash_of(&text));
    let mut seen_host = read(None).map(|text| hash_of(&text));
    // Hashes of text this watcher wrote, so it is never offered back.
    let mut ours: HashSet<u64> = HashSet::new();

    while !stop.load(Ordering::Relaxed) {
        std::thread::sleep(POLL);

        if let Some(text) = read(Some(&nested)) {
            let hash = hash_of(&text);
            if seen_nested != Some(hash) {
                seen_nested = Some(hash);
                if !ours.contains(&hash) {
                    let title = "Pumpkin-Shell: copy from Kiro?";
                    let body = format!(
                        "Kiro copied {} characters. Copy them to your clipboard?\n\n{}",
                        text.chars().count(),
                        ask::clean(&text, PREVIEW)
                    );
                    let yes = "Copy to my clipboard";
                    let allowed = ask::confirm(desktop.clone(), title, &body, yes, "Don't copy");
                    record("CLIP-COPY", text.len(), allowed);
                    if allowed {
                        match write(None, &text) {
                            Ok(()) => {
                                ours.insert(hash);
                            }
                            Err(error) => eprintln!("broker: copy failed: {error}"),
                        }
                    }
                }
            }
        }

        if let Some(text) = read(None) {
            let hash = hash_of(&text);
            if seen_host != Some(hash) {
                seen_host = Some(hash);
                if !ours.contains(&hash) {
                    let title = "Pumpkin-Shell: paste into Kiro?";
                    let body = format!(
                        "You copied {} characters on your desktop. Send them to Kiro?\n\
                         After you allow, press Ctrl+V in the Kiro window.\n\n{}",
                        text.chars().count(),
                        ask::clean(&text, PREVIEW)
                    );
                    let yes = "Send to Kiro";
                    let allowed = ask::confirm(desktop.clone(), title, &body, yes, "Don't send");
                    record("CLIP-PASTE", text.len(), allowed);
                    if allowed {
                        match write(Some(&nested), &text) {
                            Ok(()) => {
                                ours.insert(hash);
                            }
                            Err(error) => eprintln!("broker: paste failed: {error}"),
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_display_file_gives_the_display_and_its_access_file() {
        let nested = parse_display_file("DISPLAY=:62\nXAUTHORITY=/tmp/x/Xauthority-62\n");
        assert_eq!(
            nested,
            Some(Nested {
                display: OsString::from(":62"),
                xauthority: PathBuf::from("/tmp/x/Xauthority-62"),
            })
        );
        assert_eq!(parse_display_file("DISPLAY=:62\n"), None);
    }

    #[test]
    fn a_command_that_answers_is_read_and_one_that_never_does_is_abandoned() {
        assert_eq!(
            capture(Command::new("printf").arg("hi")),
            Some(b"hi".to_vec())
        );
        let started = Instant::now();
        assert_eq!(capture(Command::new("sleep").arg("30")), None);
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "waited too long"
        );
    }

    #[test]
    fn the_same_text_has_the_same_hash_and_other_text_does_not() {
        assert_eq!(hash_of("hello"), hash_of("hello"));
        assert_ne!(hash_of("hello"), hash_of("hello!"));
    }
}
