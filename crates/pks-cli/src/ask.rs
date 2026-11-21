//! Approval popups on the host desktop (Phase 12).
//!
//! The popup is drawn by the host's own display, outside the sandbox display.
//! The sandboxed IDE cannot read the text in it or click its buttons, so an
//! agent inside the sandbox cannot approve its own request. Without a desktop
//! (no DISPLAY) nothing can be shown, and the request is refused.

use std::ffi::OsString;
use std::process::{Command, Stdio};

/// Longest text shown in a popup. Longer text is cut and marked.
const MAX_TEXT: usize = 1000;
/// Seconds before an unanswered popup closes, which counts as "no".
const TIMEOUT_SECONDS: &str = "120";

/// Shows a popup with one choice per row on `display` and returns the chosen
/// row, or `None` when the user closed it, let it time out, or there is no
/// desktop (`display` is `None` or empty).
pub(crate) fn choose(
    display: Option<OsString>,
    title: &str,
    text: &str,
    options: &[&str],
) -> Option<String> {
    let display = display.filter(|value| !value.is_empty())?;
    let mut command = Command::new("zenity");
    command
        .args(["--list", "--title"])
        .arg(clean(title, 120))
        .arg("--text")
        .arg(clean(text, MAX_TEXT))
        .args([
            "--no-markup",
            "--hide-header",
            "--column",
            "Choice",
            "--width",
            "560",
            "--height",
            "300",
            "--timeout",
            TIMEOUT_SECONDS,
        ])
        .env("DISPLAY", display.clone())
        .stdin(Stdio::null())
        .stderr(Stdio::null());
    for option in options {
        command.arg(option);
    }
    notify(&display, title);
    let output = command.output().ok()?;
    if !output.status.success() {
        return None;
    }
    let chosen = String::from_utf8_lossy(&output.stdout)
        .trim_end()
        .to_owned();
    options
        .iter()
        .find(|option| **option == chosen)
        .map(|option| (*option).to_owned())
}

/// Shows a yes/no popup with two buttons. `true` only for the yes button.
/// Closing the window, timing out, or no desktop all count as no.
#[must_use]
pub(crate) fn confirm(
    display: Option<OsString>,
    title: &str,
    text: &str,
    yes: &str,
    no: &str,
) -> bool {
    let Some(display) = display.filter(|value| !value.is_empty()) else {
        return false;
    };
    notify(&display, title);
    let status = Command::new("zenity")
        .args(["--question", "--title"])
        .arg(clean(title, 120))
        .arg("--text")
        .arg(clean(text, MAX_TEXT))
        .args([
            "--no-markup",
            "--width",
            "520",
            "--timeout",
            TIMEOUT_SECONDS,
            "--ok-label",
        ])
        .arg(clean(yes, 40))
        .arg("--cancel-label")
        .arg(clean(no, 40))
        .env("DISPLAY", display)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .status();
    matches!(status, Ok(status) if status.success())
}

/// Shows a notice with one OK button, for a refused request. Returns when the
/// user closes it, or after the timeout.
pub(crate) fn notice(display: Option<OsString>, title: &str, text: &str) {
    let Some(display) = display.filter(|value| !value.is_empty()) else {
        return;
    };
    notify(&display, title);
    let _ = Command::new("zenity")
        .args(["--warning", "--title"])
        .arg(clean(title, 120))
        .arg("--text")
        .arg(clean(text, MAX_TEXT))
        .args([
            "--no-markup",
            "--width",
            "520",
            "--timeout",
            TIMEOUT_SECONDS,
        ])
        .env("DISPLAY", display)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// A short desktop notice saying where to answer. Best effort.
fn notify(display: &OsString, title: &str) {
    let _ = Command::new("notify-send")
        .arg("--app-name=Pumpkin-Shell")
        .arg(clean(title, 120))
        .arg("Answer the window that just opened on your desktop.")
        .env("DISPLAY", display)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// Removes control characters (except newlines) and cuts the text to `max`
/// characters. Popups show what the sandbox sent, so control characters
/// cannot hide or rewrite what the user reads.
#[must_use]
pub fn clean(text: &str, max: usize) -> String {
    let mut out: String = text
        .chars()
        .filter(|c| *c == '\n' || !c.is_control())
        .take(max)
        .collect();
    if text.chars().filter(|c| *c != '\n').count() > max {
        out.push_str(" ...");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_no_desktop_nothing_is_chosen() {
        assert_eq!(choose(None, "t", "x", &["Allow", "Deny"]), None);
        assert_eq!(
            choose(Some(OsString::new()), "t", "x", &["Allow", "Deny"]),
            None
        );
    }

    #[test]
    fn control_characters_are_removed_and_long_text_is_cut() {
        assert_eq!(clean("a\u{1b}[31mred\tb\nc", 100), "a[31mredb\nc");
        let long = "x".repeat(10);
        assert_eq!(clean(&long, 4), "xxxx ...");
        assert_eq!(clean("short", 10), "short");
    }
}
