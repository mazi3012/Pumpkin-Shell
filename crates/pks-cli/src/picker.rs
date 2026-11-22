//! Host-side folder picker for `pumpkin-shell kiro` and `pumpkin-shell ide`
//! when no folder is given. The window runs on the host, outside the sandbox,
//! through zenity. zenity is a recommended package of pumpkin-shell.

use std::io;
use std::path::PathBuf;
use std::process::Command;

/// Asks for a folder with a zenity window.
///
/// `usage` is the command to show when the window cannot give a folder, for
/// example `pumpkin-shell kiro /yourfolderhere`.
///
/// # Errors
/// Returns a message for the user when zenity is missing, the window is
/// closed without a choice, or the choice is empty.
pub fn choose_folder(usage: &str) -> Result<PathBuf, String> {
    let output = match Command::new("zenity")
        .args([
            "--file-selection",
            "--directory",
            "--title=Choose your project folder",
        ])
        .output()
    {
        Ok(output) => output,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(format!(
                "zenity is not installed, so no folder window can open.\nGive the folder instead:\n  {usage}"
            ));
        }
        Err(error) => {
            return Err(format!(
                "cannot open the folder window: {error}\nGive the folder instead:\n  {usage}"
            ));
        }
    };
    parse_choice(output.status.success(), &output.stdout, usage)
}

/// Reads zenity's result. zenity exits non-zero when the user cancels, and
/// prints the chosen path on stdout, followed by a newline.
fn parse_choice(success: bool, stdout: &[u8], usage: &str) -> Result<PathBuf, String> {
    let text = String::from_utf8_lossy(stdout);
    let chosen = text.strip_suffix('\n').unwrap_or(&text);
    if !success || chosen.is_empty() {
        return Err(format!(
            "no folder was chosen.\nGive the folder instead:\n  {usage}"
        ));
    }
    Ok(PathBuf::from(chosen))
}

#[cfg(test)]
mod tests {
    use super::*;

    const USAGE: &str = "pumpkin-shell kiro /yourfolderhere";

    #[test]
    fn a_chosen_folder_is_returned_without_the_newline() {
        assert_eq!(
            parse_choice(true, b"/home/me/project\n", USAGE),
            Ok(PathBuf::from("/home/me/project"))
        );
    }

    #[test]
    fn a_cancelled_window_names_the_command_to_run() {
        let error = parse_choice(false, b"", USAGE).expect_err("cancel is not a folder");
        assert!(error.contains(USAGE), "{error}");
    }

    #[test]
    fn an_empty_choice_is_refused() {
        let error = parse_choice(true, b"\n", USAGE).expect_err("empty is not a folder");
        assert!(error.contains(USAGE), "{error}");
    }
}
