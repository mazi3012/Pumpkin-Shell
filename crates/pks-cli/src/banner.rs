//! The start banner for `pumpkin-shell kiro` and `pumpkin-shell ide`. It shows
//! the version, the project and the dashboard link in orange. It is printed to
//! the terminal only, never into a pipe, and it has no color when NO_COLOR is set.

use std::io::{IsTerminal, Write};

/// Orange in the 256-color palette (208). Most terminals show it.
const ORANGE: &str = "\x1b[38;5;208m";
const DIM: &str = "\x1b[2m";
const RESET: &str = "\x1b[0m";

/// One line of the status list.
pub struct Row {
    /// A symbol that marks the state, such as "●" (on) or "○" (off).
    pub mark: &'static str,
    pub label: &'static str,
    pub value: String,
}

/// Returns the banner text. With `color` false the text has no escape codes.
#[must_use]
pub fn render(version: &str, rows: &[Row], color: bool) -> String {
    let (on, dim) = if color { (ORANGE, DIM) } else { ("", "") };
    let reset = if color { RESET } else { "" };
    let rule = "─".repeat(46);
    let mut out = String::new();
    out.push_str(&format!(
        "{on}  ▲ PUMPKIN-SHELL {version}{reset}  {dim}sandbox for AI IDEs{reset}\n"
    ));
    out.push_str(&format!("{dim}  {rule}{reset}\n"));
    for row in rows {
        out.push_str(&format!(
            "  {on}{}{reset} {:<10} {}\n",
            row.mark, row.label, row.value
        ));
    }
    out
}

/// Prints the banner to stderr when it is a terminal. Scripts and pipes get
/// nothing extra.
pub fn show(version: &str, rows: &[Row]) {
    let stderr = std::io::stderr();
    if !stderr.is_terminal() {
        return;
    }
    let color = std::env::var_os("NO_COLOR").is_none();
    let mut handle = stderr.lock();
    let _ = write!(handle, "{}", render(version, rows, color));
    let _ = writeln!(handle);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows() -> Vec<Row> {
        vec![
            Row {
                mark: "●",
                label: "Dashboard",
                value: "http://127.0.0.1:8765/".to_owned(),
            },
            Row {
                mark: "○",
                label: "Sandbox",
                value: "off".to_owned(),
            },
        ]
    }

    #[test]
    fn the_banner_names_the_version_and_each_row() {
        let text = render("1.0.3", &rows(), false);
        assert!(text.contains("PUMPKIN-SHELL 1.0.3"), "{text}");
        assert!(text.contains("● Dashboard"), "{text}");
        assert!(text.contains("http://127.0.0.1:8765/"), "{text}");
        assert!(text.contains("○ Sandbox"), "{text}");
    }

    #[test]
    fn without_color_there_are_no_escape_codes() {
        assert!(!render("1.0.3", &rows(), false).contains('\x1b'));
    }

    #[test]
    fn with_color_the_banner_is_orange() {
        let text = render("1.0.3", &rows(), true);
        assert!(text.contains("\x1b[38;5;208m"), "{text:?}");
        assert!(text.contains(RESET));
    }
}
