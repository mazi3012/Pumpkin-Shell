//! Rule WS-HIDDEN-UNICODE: characters that are invisible or change how text
//! is displayed. They can hide instructions in rules files ("Rules File
//! Backdoor", PRD §1 row 8).

use pks_core::{Finding, Severity};

use crate::{finding, rule};

/// Findings listed per file before the rest are only counted.
const MAX_LISTED_PER_FILE: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Class {
    /// U+E0000 to U+E007F. Invisible, and some models read them as text.
    Tag,
    /// Bidirectional formatting characters.
    Bidi,
    /// Zero-width characters.
    ZeroWidth,
}

impl Class {
    fn label(self) -> &'static str {
        match self {
            Class::Tag => "tag character",
            Class::Bidi => "bidirectional control character",
            Class::ZeroWidth => "zero-width character",
        }
    }
}

/// Returns the class of a hidden character, or `None` for a normal one.
pub(crate) fn classify(c: char) -> Option<Class> {
    match u32::from(c) {
        0xE0000..=0xE007F => Some(Class::Tag),
        // ALM, LRM, RLM, embeddings and overrides, isolates.
        0x061C | 0x200E | 0x200F | 0x202A..=0x202E | 0x2066..=0x2069 => Some(Class::Bidi),
        // ZWSP, ZWNJ, ZWJ, word joiner, zero-width no-break space.
        0x200B | 0x200C | 0x200D | 0x2060 | 0xFEFF => Some(Class::ZeroWidth),
        _ => None,
    }
}

struct Hit {
    line: usize,
    ch: char,
    class: Class,
}

fn find_hidden(text: &str) -> Vec<Hit> {
    let mut hits = Vec::new();
    let mut line = 1;
    for (index, c) in text.chars().enumerate() {
        if c == '\n' {
            line += 1;
            continue;
        }
        // A byte order mark at the very start of a file is normal.
        if index == 0 && c == '\u{feff}' {
            continue;
        }
        if let Some(class) = classify(c) {
            hits.push(Hit { line, ch: c, class });
        }
    }
    hits
}

/// Findings for one file. `path` is already cleaned for display.
pub(crate) fn findings(path: &str, text: &str) -> Vec<Finding> {
    let hits = find_hidden(text);
    let mut out: Vec<Finding> = hits
        .iter()
        .take(MAX_LISTED_PER_FILE)
        .map(|hit| {
            finding(
                rule::HIDDEN_UNICODE,
                Severity::High,
                format!("{path}:{}", hit.line),
                format!("{} U+{:04X}", hit.class.label(), u32::from(hit.ch)),
                "Remove the invisible character, or find out why it is there.",
            )
        })
        .collect();
    if hits.len() > MAX_LISTED_PER_FILE {
        out.push(finding(
            rule::HIDDEN_UNICODE,
            Severity::High,
            path.to_owned(),
            format!(
                "{} more hidden characters in this file are not listed",
                hits.len() - MAX_LISTED_PER_FILE
            ),
            "Remove the invisible characters, or find out why they are there.",
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_each_documented_range() {
        assert_eq!(classify('\u{e0000}'), Some(Class::Tag));
        assert_eq!(classify('\u{e0041}'), Some(Class::Tag));
        assert_eq!(classify('\u{e007f}'), Some(Class::Tag));
        assert_eq!(classify('\u{e0080}'), None);
        for cp in [
            0x061C, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068,
            0x2069,
        ] {
            assert_eq!(
                classify(char::from_u32(cp).unwrap_or('a')),
                Some(Class::Bidi),
                "{cp:#x}"
            );
        }
        for cp in [0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF] {
            assert_eq!(
                classify(char::from_u32(cp).unwrap_or('a')),
                Some(Class::ZeroWidth),
                "{cp:#x}"
            );
        }
        assert_eq!(classify('a'), None);
        assert_eq!(classify('é'), None);
        assert_eq!(classify(' '), None);
    }

    #[test]
    fn reports_line_and_code_point() {
        let text = "line one\nline two\u{200b}\nline three\n";
        let out = findings("a.md", text);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].target, "a.md:2");
        assert!(out[0].message.contains("U+200B"));
        assert_eq!(out[0].severity, Severity::High);
        assert_eq!(out[0].rule.as_str(), "WS-HIDDEN-UNICODE");
    }

    #[test]
    fn counts_lines_across_crlf() {
        let out = findings("a.md", "a\r\nb\r\nc\u{202e}\r\n");
        assert_eq!(out[0].target, "a.md:3");
    }

    #[test]
    fn ignores_a_leading_byte_order_mark_only() {
        assert!(findings("a.md", "\u{feff}hello").is_empty());
        assert_eq!(findings("a.md", "he\u{feff}llo").len(), 1);
        assert_eq!(findings("a.md", "\u{feff}\u{feff}x").len(), 1);
    }

    #[test]
    fn clean_text_has_no_findings() {
        assert!(findings("a.md", "just ascii and café ☕ and 日本語\n").is_empty());
    }

    #[test]
    fn caps_listed_findings_and_counts_the_rest() {
        let text = "\u{200b}".repeat(MAX_LISTED_PER_FILE + 5);
        let out = findings("a.md", &text);
        assert_eq!(out.len(), MAX_LISTED_PER_FILE + 1);
        assert!(out[MAX_LISTED_PER_FILE].message.starts_with("5 more"));
        assert_eq!(out[MAX_LISTED_PER_FILE].target, "a.md");
    }
}
