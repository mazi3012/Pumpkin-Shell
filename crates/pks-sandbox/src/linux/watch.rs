//! Access watch on files the host gives the sandbox (PRD FR-WS "Decoys").
//!
//! Linux inotify reports `IN_OPEN` and `IN_ACCESS` for a file no matter which
//! mount namespace the opening process is in, because the sandbox binds the
//! same inode. So a read inside the sandbox is seen on the host.
//!
//! This module is a thin wrapper over `inotify_init1`, `inotify_add_watch`,
//! `poll` and `read`. Each `unsafe` block calls one of them, and the buffers
//! are checked before use. Events are parsed from bytes, not by casting, so
//! alignment is never assumed.
#![allow(unsafe_code)]

use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

/// Bytes in the header of one `inotify_event`: wd, mask, cookie, len.
const EVENT_HEADER: usize = 16;

/// Watches a set of files for opens and reads.
#[derive(Debug)]
pub struct AccessWatch {
    fd: libc::c_int,
    watches: Vec<(libc::c_int, PathBuf)>,
}

impl AccessWatch {
    /// Starts watching `paths`. Each must exist.
    ///
    /// # Errors
    /// Fails when inotify cannot be set up, or a path cannot be watched.
    pub fn new(paths: &[PathBuf]) -> io::Result<Self> {
        // SAFETY: inotify_init1 takes no pointers; the result is checked.
        let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // `watch` owns the descriptor, so an error below closes it.
        let mut watch = Self {
            fd,
            watches: Vec::new(),
        };
        for path in paths {
            let text = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "a path has a NUL byte")
            })?;
            // SAFETY: `text` is a NUL-terminated string that lives for this call.
            let wd = unsafe {
                libc::inotify_add_watch(watch.fd, text.as_ptr(), libc::IN_OPEN | libc::IN_ACCESS)
            };
            if wd < 0 {
                return Err(io::Error::last_os_error());
            }
            watch.watches.push((wd, path.clone()));
        }
        Ok(watch)
    }

    /// Waits up to `timeout_ms` for accesses, and returns the watched paths
    /// that were accessed. Empty when nothing happened in time.
    ///
    /// # Errors
    /// Fails when `poll` or `read` fails.
    pub fn wait(&self, timeout_ms: i32) -> io::Result<Vec<PathBuf>> {
        let mut pending = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `pending` is one valid pollfd, and the count is 1.
        let ready = unsafe { libc::poll(&raw mut pending, 1, timeout_ms) };
        if ready < 0 {
            return Err(io::Error::last_os_error());
        }
        if ready == 0 {
            return Ok(Vec::new());
        }
        let mut buffer = vec![0u8; 4096];
        // SAFETY: the pointer and length describe `buffer`, which is valid for
        // writes of that many bytes.
        let read = unsafe { libc::read(self.fd, buffer.as_mut_ptr().cast(), buffer.len()) };
        if read < 0 {
            return Err(io::Error::last_os_error());
        }
        let bytes = usize::try_from(read).unwrap_or(0);
        let mut accessed: Vec<PathBuf> = Vec::new();
        let mut at = 0usize;
        while at + EVENT_HEADER <= bytes {
            let wd = i32::from_ne_bytes(buffer[at..at + 4].try_into().unwrap_or([0; 4]));
            let len = usize::try_from(u32::from_ne_bytes(
                buffer[at + 12..at + 16].try_into().unwrap_or([0; 4]),
            ))
            .unwrap_or(0);
            if let Some((_, path)) = self.watches.iter().find(|(id, _)| *id == wd)
                && !accessed.contains(path)
            {
                accessed.push(path.clone());
            }
            at += EVENT_HEADER + len;
        }
        Ok(accessed)
    }
}

impl Drop for AccessWatch {
    fn drop(&mut self) {
        // SAFETY: `fd` is the descriptor from inotify_init1, closed once here.
        unsafe {
            libc::close(self.fd);
        }
    }
}
