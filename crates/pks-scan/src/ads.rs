//! Rule WS-ADS (Windows only): NTFS alternate data streams can hold code or
//! text that normal file listings and editors do not show.
//!
//! API (windows-sys 0.61.2 docs): `FindFirstStreamW(lpfilename, infolevel,
//! lpfindstreamdata, dwflags) -> HANDLE`, `FindNextStreamW(hfindstream,
//! lpfindstreamdata) -> BOOL`, `FindClose(hfindfile)`. A name like
//! `::$DATA` is the normal content of the file. `Zone.Identifier` is the
//! "downloaded from the internet" mark that Windows adds; it is ignored
//! because every unzipped download carries it.
//!
//! This is the only module in the crate that needs `unsafe`: thin wrappers
//! around the Win32 calls above.
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use pks_core::Severity;
use windows_sys::Win32::Foundation::{ERROR_HANDLE_EOF, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    FindClose, FindFirstStreamW, FindNextStreamW, FindStreamInfoStandard, WIN32_FIND_STREAM_DATA,
};

use crate::{Report, ScanIssue, clean, finding, rule};

/// Closes the search handle when dropped.
struct FindHandle(HANDLE);

impl Drop for FindHandle {
    fn drop(&mut self) {
        // SAFETY: the handle came from a successful `FindFirstStreamW` call
        // and is closed exactly once, here.
        unsafe {
            FindClose(self.0);
        }
    }
}

fn stream_name(data: &WIN32_FIND_STREAM_DATA) -> String {
    let end = data
        .cStreamName
        .iter()
        .position(|&unit| unit == 0)
        .unwrap_or(data.cStreamName.len());
    String::from_utf16_lossy(&data.cStreamName[..end])
}

fn is_end_of_streams(error: &io::Error) -> bool {
    error.raw_os_error() == Some(ERROR_HANDLE_EOF.cast_signed())
}

/// Names of all streams of `path`, including the default `::$DATA`.
fn stream_names(path: &Path) -> io::Result<Vec<String>> {
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut data = WIN32_FIND_STREAM_DATA::default();
    // SAFETY: `wide` is a NUL-terminated UTF-16 string that outlives the
    // call, and `data` is a valid `WIN32_FIND_STREAM_DATA`, which is what
    // `FindStreamInfoStandard` makes the function write.
    let handle = unsafe {
        FindFirstStreamW(
            wide.as_ptr(),
            FindStreamInfoStandard,
            (&raw mut data).cast::<c_void>(),
            0,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        let error = io::Error::last_os_error();
        return if is_end_of_streams(&error) {
            Ok(Vec::new())
        } else {
            Err(error)
        };
    }
    let handle = FindHandle(handle);
    let mut names = vec![stream_name(&data)];
    loop {
        // SAFETY: `handle.0` is an open search handle and `data` is valid.
        let found = unsafe { FindNextStreamW(handle.0, (&raw mut data).cast::<c_void>()) };
        if found == 0 {
            let error = io::Error::last_os_error();
            return if is_end_of_streams(&error) {
                Ok(names)
            } else {
                Err(error)
            };
        }
        names.push(stream_name(&data));
    }
}

fn is_expected(name: &str) -> bool {
    name == "::$DATA" || name.eq_ignore_ascii_case(":Zone.Identifier:$DATA")
}

/// Reports every unexpected stream on `root/rel`. `shown` is the cleaned path.
pub(crate) fn check(root: &Path, rel: &Path, shown: &str, report: &mut Report) {
    // `canonicalize` gives an absolute `\\?\` path, which also works for
    // paths longer than MAX_PATH.
    let full = match std::fs::canonicalize(root.join(rel)) {
        Ok(full) => full,
        Err(error) => {
            report.errors.push(ScanIssue {
                path: shown.to_owned(),
                message: clean(&error.to_string()),
            });
            return;
        }
    };
    match stream_names(&full) {
        Ok(names) => {
            for name in names.iter().filter(|name| !is_expected(name)) {
                report.findings.push(finding(
                    rule::ADS,
                    Severity::High,
                    shown.to_owned(),
                    format!("alternate data stream `{}`", clean(name)),
                    "Delete the stream (`Remove-Item -Stream`), or find out who added it.",
                ));
            }
        }
        Err(error) => report.errors.push(ScanIssue {
            path: shown.to_owned(),
            message: clean(&error.to_string()),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ScanOptions, scan};
    use std::fs;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const OPTIONS: ScanOptions = ScanOptions {
        respect_gitignore: false,
    };

    #[test]
    fn expected_stream_names() {
        assert!(is_expected("::$DATA"));
        assert!(is_expected(":Zone.Identifier:$DATA"));
        assert!(is_expected(":zone.identifier:$DATA"));
        assert!(!is_expected(":payload:$DATA"));
    }

    #[test]
    fn a_plain_file_has_only_the_default_stream() -> TestResult {
        let dir = tempfile::tempdir()?;
        let file = dir.path().join("a.txt");
        fs::write(&file, "x")?;
        assert_eq!(stream_names(&fs::canonicalize(&file)?)?, ["::$DATA"]);
        Ok(())
    }

    #[test]
    fn a_hidden_stream_is_found_by_the_scan() -> TestResult {
        let dir = tempfile::tempdir()?;
        let file = dir.path().join("a.txt");
        fs::write(&file, "visible")?;
        fs::write(format!("{}:payload", file.display()), "hidden")?;
        let report = scan(dir.path(), &OPTIONS)?;
        let ads: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.rule.as_str() == "WS-ADS")
            .collect();
        assert_eq!(ads.len(), 1, "{:?}", report.findings);
        assert_eq!(ads[0].target, "a.txt");
        assert!(ads[0].message.contains(":payload:$DATA"));
        assert!(report.errors.is_empty(), "{:?}", report.errors);
        Ok(())
    }

    #[test]
    fn zone_identifier_alone_is_not_a_finding() -> TestResult {
        let dir = tempfile::tempdir()?;
        let file = dir.path().join("a.txt");
        fs::write(&file, "x")?;
        fs::write(
            format!("{}:Zone.Identifier", file.display()),
            "[ZoneTransfer]\r\nZoneId=3\r\n",
        )?;
        let report = scan(dir.path(), &OPTIONS)?;
        assert!(
            report.findings.iter().all(|f| f.rule.as_str() != "WS-ADS"),
            "{:?}",
            report.findings
        );
        Ok(())
    }
}
