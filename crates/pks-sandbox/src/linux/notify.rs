//! Seccomp user notification for `execve`, `execveat` and `connect` (PRD
//! FR-DET, Phase 15).
//!
//! The sandbox installs a filter that sends those three system calls to a
//! listener. The listener's file descriptor goes to the host over a Unix
//! socket, and the sandbox then closes its own copy, so only the host can
//! answer. The host reads each call's arguments, reports them, and answers
//! "continue". The call then runs unchanged. This module is detection only:
//! it never changes what a call does (PRD design principle 1).
//!
//! The raw BPF program is written here because `seccompiler` has no
//! user-notification action. The constants come from `linux/seccomp.h`,
//! `linux/bpf_common.h` and `linux/audit.h`; the `libc` crate defines the
//! seccomp ones.
//!
//! Every `unsafe` block here is a thin FFI call: `prctl`, `seccomp`, the
//! notification ioctls, `sendmsg`/`recvmsg`, and the `CMSG_*` size helpers.
//! Each one has a `SAFETY` note.
#![allow(unsafe_code)]

use std::fs::File;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::FileExt;
use std::os::unix::net::UnixStream;

// Classic BPF opcodes (linux/bpf_common.h).
const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JEQ_K: u16 = 0x15;
const BPF_RET_K: u16 = 0x06;
/// `seccomp_data` offsets: `nr` is at 0, `arch` at 4.
const OFFSET_NR: u32 = 0;
const OFFSET_ARCH: u32 = 4;

/// `AUDIT_ARCH_X86_64` and `AUDIT_ARCH_AARCH64` (linux/audit.h): the machine
/// number, plus the 64-bit and little-endian flags.
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: Option<u32> = Some(0xC000_003E);
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: Option<u32> = Some(0xC000_00B7);
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const AUDIT_ARCH: Option<u32> = None;

/// Address families (linux/socket.h).
const AF_UNIX: u16 = 1;
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

/// The system calls the filter reports. Anything else is allowed unseen.
const WATCHED: [libc::c_long; 3] = [libc::SYS_execve, libc::SYS_execveat, libc::SYS_connect];

/// Longest argument read from the sandbox (a path, a sockaddr, one argv word).
const MAX_STRING: usize = 4096;
/// Most argv entries read from the sandbox.
const MAX_ARGV: usize = 256;

/// Errors from installing or running the notification listener.
#[derive(Debug, thiserror::Error)]
pub enum NotifyError {
    #[error("this CPU architecture is not supported by the monitor")]
    Architecture,
    #[error("{context}: {source}")]
    Io {
        context: &'static str,
        #[source]
        source: io::Error,
    },
}

fn io_error(context: &'static str) -> impl FnOnce(io::Error) -> NotifyError {
    move |source| NotifyError::Io { context, source }
}

/// The BPF program: kill the process on any architecture other than the
/// native one (so a 32-bit syscall ABI cannot skip the check), send the
/// watched calls to the listener, allow everything else.
fn program(arch: u32) -> Vec<libc::sock_filter> {
    let stmt = |code: u16, k: u32| libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    };
    let watched = WATCHED.len();
    let mut filter = vec![
        stmt(BPF_LD_W_ABS, OFFSET_ARCH),
        libc::sock_filter {
            code: BPF_JEQ_K,
            jt: 1,
            jf: 0,
            k: arch,
        },
        stmt(BPF_RET_K, libc::SECCOMP_RET_KILL_PROCESS),
        stmt(BPF_LD_W_ABS, OFFSET_NR),
    ];
    // The notify return sits after the allow return. Each comparison jumps
    // forward to it when it matches, and falls through otherwise.
    let notify_at = 4 + watched + 1;
    for (index, nr) in WATCHED.iter().enumerate() {
        let here = 4 + index;
        let jump = u8::try_from(notify_at - (here + 1)).unwrap_or(u8::MAX);
        filter.push(libc::sock_filter {
            code: BPF_JEQ_K,
            jt: jump,
            jf: 0,
            // The syscall numbers are small; `as` cannot truncate them here.
            k: u32::try_from(*nr).unwrap_or(u32::MAX),
        });
    }
    filter.push(stmt(BPF_RET_K, libc::SECCOMP_RET_ALLOW));
    filter.push(stmt(BPF_RET_K, libc::SECCOMP_RET_USER_NOTIF));
    filter
}

/// Installs the filter in this process and returns the listener.
///
/// # Errors
/// Fails on an unsupported architecture, or when the kernel refuses the
/// filter (no user notification support, or no `no_new_privs`).
pub fn install() -> Result<OwnedFd, NotifyError> {
    let arch = AUDIT_ARCH.ok_or(NotifyError::Architecture)?;
    let filter = program(arch);
    let len = u16::try_from(filter.len()).map_err(|_| NotifyError::Architecture)?;
    let prog = libc::sock_fprog {
        len,
        filter: filter.as_ptr().cast_mut(),
    };
    // SAFETY: prctl takes plain integers; no pointers are passed.
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        return Err(io_error("no_new_privs")(io::Error::last_os_error()));
    }
    // SAFETY: `prog` points at `filter`, which lives until this call returns.
    // The kernel copies the program before it returns.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER as libc::c_long,
            libc::SECCOMP_FILTER_FLAG_NEW_LISTENER as libc::c_long,
            std::ptr::from_ref(&prog),
        )
    };
    if fd < 0 {
        return Err(io_error("seccomp listener")(io::Error::last_os_error()));
    }
    let raw = RawFd::try_from(fd).map_err(|_| NotifyError::Architecture)?;
    // SAFETY: the kernel just returned `raw` as a new descriptor owned by no
    // one else.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// Sends one file descriptor over `stream` (SCM_RIGHTS).
///
/// # Errors
/// Fails when the socket write fails.
pub fn send_fd(stream: &UnixStream, fd: BorrowedFd<'_>) -> io::Result<()> {
    let payload = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr().cast_mut().cast(),
        iov_len: payload.len(),
    };
    let fd_size = FD_BYTES;
    // SAFETY: CMSG_SPACE and CMSG_LEN are pure size arithmetic.
    let space = unsafe { libc::CMSG_SPACE(fd_size as _) } as usize;
    let mut control = aligned_control(space);
    // SAFETY: `msg` is plain C data; every pointer below refers to a live local
    // (`iov`, `control`) that outlives the sendmsg call.
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &raw mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = space;
        let header = libc::CMSG_FIRSTHDR(&raw const msg);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(fd_size) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<RawFd>(), fd.as_raw_fd());
        if libc::sendmsg(stream.as_raw_fd(), &raw const msg, libc::MSG_NOSIGNAL) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Receives one file descriptor from `stream`. Any other descriptors that
/// arrive with it are closed.
///
/// # Errors
/// Fails when the read fails, the peer closed the socket, or no single
/// descriptor arrived.
pub fn recv_fd(stream: &UnixStream) -> io::Result<OwnedFd> {
    let mut payload = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    let fd_size = FD_BYTES;
    // SAFETY: size arithmetic only.
    let space = unsafe { libc::CMSG_SPACE(fd_size as _) } as usize;
    let mut control = aligned_control(space);
    let mut received: Vec<OwnedFd> = Vec::new();
    // SAFETY: as in send_fd. The received descriptors are wrapped as soon as
    // they are read, so each one is closed exactly once.
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &raw mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = space;
        let n = libc::recvmsg(stream.as_raw_fd(), &raw mut msg, libc::MSG_CMSG_CLOEXEC);
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the sandbox closed the monitor socket before it sent the listener",
            ));
        }
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut header = libc::CMSG_FIRSTHDR(&raw const msg);
        while !header.is_null() {
            if (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS {
                let data_len = (*header).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                for index in 0..data_len / std::mem::size_of::<RawFd>() {
                    let raw = std::ptr::read_unaligned(
                        libc::CMSG_DATA(header).cast::<RawFd>().add(index),
                    );
                    received.push(OwnedFd::from_raw_fd(raw));
                }
            }
            header = libc::CMSG_NXTHDR(&raw const msg, header);
        }
    }
    if received.len() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expected one listener descriptor, got {}", received.len()),
        ));
    }
    Ok(received.remove(0))
}

/// Size of one passed descriptor, as the `CMSG_*` helpers take it.
const FD_BYTES: libc::c_uint = std::mem::size_of::<RawFd>() as libc::c_uint;

/// A zeroed buffer of `bytes`, as `usize` words, so cmsg headers are aligned.
fn aligned_control(bytes: usize) -> Vec<usize> {
    vec![0usize; bytes.div_ceil(std::mem::size_of::<usize>())]
}

/// Serves the monitor for one sandbox (Phase 15). It waits for the sandbox to
/// connect to `listener`, takes the listener the sandbox sends, and reports
/// every event until the sandbox has ended. If the monitor fails while `stop`
/// is not set, `on_lost` runs once with the reason. A panic in `on_event`
/// counts as a failure. Returns when the sandbox ends, when `stop` is set
/// before anyone connects, or after `on_lost`.
pub fn serve_monitor(
    listener: &std::os::unix::net::UnixListener,
    stop: &std::sync::atomic::AtomicBool,
    mut on_event: impl FnMut(Event),
    on_lost: impl FnOnce(&str),
) {
    use std::sync::atomic::Ordering;
    let Some(stream) = accept_until(listener, stop) else {
        return;
    };
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let fd = recv_fd(&stream).map_err(|e| format!("cannot receive the listener: {e}"))?;
        supervise(&fd, &mut on_event).map_err(|e| e.to_string())
    }));
    let reason = match outcome {
        Ok(Ok(())) => return,
        Ok(Err(reason)) => reason,
        Err(_) => "the monitor panicked".to_owned(),
    };
    // A failure while the session is ending is not a monitor fault.
    if stop.load(Ordering::Relaxed) {
        return;
    }
    on_lost(&reason);
}

/// Waits for the sandbox to connect. `None` when `stop` is set first or the
/// socket fails.
fn accept_until(
    listener: &std::os::unix::net::UnixListener,
    stop: &std::sync::atomic::AtomicBool,
) -> Option<UnixStream> {
    use std::sync::atomic::Ordering;
    listener.set_nonblocking(true).ok()?;
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).ok()?;
                return Some(stream);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(_) => return None,
        }
    }
    None
}

/// What a monitored call did, as the host sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A program was started. `argv` is what the program was given. `interactive`
    /// is true when the process that started it has a terminal on stdin.
    Exec {
        pid: i32,
        path: String,
        argv: Vec<String>,
        interactive: bool,
    },
    /// A socket connected to `target` (IPv4 or IPv6). Unix sockets are not reported.
    Connect { pid: i32, target: SocketAddr },
    /// A connection to an address family this module does not decode.
    OtherConnect { pid: i32, family: u16 },
}

/// Runs the monitor loop until every process under the filter has exited.
/// For each notification, `on_event` is called and the call then continues.
/// Calls whose arguments cannot be read from the sandbox are skipped.
///
/// # Errors
/// Fails when the listener stops working for any reason other than the end
/// of the sandbox's processes. The caller must then end the session (fail
/// closed, PRD design principle 3).
pub fn supervise(listener: &OwnedFd, mut on_event: impl FnMut(Event)) -> Result<(), NotifyError> {
    let fd = listener.as_raw_fd();
    loop {
        // SAFETY: the buffer is a zeroed `seccomp_notif`, the type the ioctl
        // writes to.
        let mut request: libc::seccomp_notif = unsafe { std::mem::zeroed() };
        // SAFETY: fd is the open listener; the ioctl writes into `request`.
        let rc = unsafe { libc::ioctl(fd, libc::SECCOMP_IOCTL_NOTIF_RECV, &raw mut request) };
        if rc < 0 {
            let error = io::Error::last_os_error();
            match error.raw_os_error() {
                // No process is left under the filter: the sandbox has ended.
                Some(libc::ENOENT) => return Ok(()),
                Some(libc::EINTR) => continue,
                _ => return Err(io_error("reading a notification")(error)),
            }
        }
        if let Some(event) = decode(&request) {
            // The call has to still be pending for its arguments to mean
            // anything. A process that exited is skipped.
            if id_still_valid(fd, request.id) {
                on_event(event);
            }
        }
        respond_continue(fd, request.id)?;
    }
}

fn id_still_valid(fd: RawFd, id: u64) -> bool {
    // SAFETY: the ioctl reads one u64 from a live local.
    unsafe { libc::ioctl(fd, libc::SECCOMP_IOCTL_NOTIF_ID_VALID, &raw const id) == 0 }
}

fn respond_continue(fd: RawFd, id: u64) -> Result<(), NotifyError> {
    // SAFETY: a zeroed `seccomp_notif_resp` is a valid value of that type.
    let mut response: libc::seccomp_notif_resp = unsafe { std::mem::zeroed() };
    response.id = id;
    response.flags = libc::SECCOMP_USER_NOTIF_FLAG_CONTINUE as u32;
    // SAFETY: fd is the open listener; the ioctl reads `response`.
    let rc = unsafe { libc::ioctl(fd, libc::SECCOMP_IOCTL_NOTIF_SEND, &raw mut response) };
    if rc < 0 {
        let error = io::Error::last_os_error();
        // The process went away while the call was pending. Nothing to answer.
        if error.raw_os_error() == Some(libc::ENOENT) {
            return Ok(());
        }
        return Err(io_error("answering a notification")(error));
    }
    Ok(())
}

/// Reads the arguments of a notification. `None` when the call is not one
/// the host reports, or its arguments cannot be read.
fn decode(request: &libc::seccomp_notif) -> Option<Event> {
    let pid = i32::try_from(request.pid).ok()?;
    let args = request.data.args;
    match i64::from(request.data.nr) {
        nr if nr == libc::SYS_execve || nr == libc::SYS_execveat => {
            let (path_arg, argv_arg) = if nr == libc::SYS_execve {
                (args[0], args[1])
            } else {
                (args[1], args[2])
            };
            let path = read_string(pid, path_arg).ok()?;
            let argv = read_argv(pid, argv_arg).ok()?;
            Some(Event::Exec {
                pid,
                path,
                argv,
                interactive: is_interactive(pid),
            })
        }
        nr if nr == libc::SYS_connect => {
            let len = usize::try_from(args[2]).ok()?.min(128);
            let bytes = read_bytes(pid, args[1], len).ok()?;
            match decode_sockaddr(&bytes) {
                Some(SockAddr::Inet(target)) => Some(Event::Connect { pid, target }),
                Some(SockAddr::Unix) => None,
                Some(SockAddr::Other(family)) => Some(Event::OtherConnect { pid, family }),
                None => None,
            }
        }
        _ => None,
    }
}

/// A decoded socket address.
#[derive(Debug, PartialEq, Eq)]
enum SockAddr {
    Inet(SocketAddr),
    Unix,
    Other(u16),
}

/// Decodes a `sockaddr` (linux/socket.h, linux/in.h, linux/in6.h).
fn decode_sockaddr(bytes: &[u8]) -> Option<SockAddr> {
    let family = u16::from_ne_bytes([*bytes.first()?, *bytes.get(1)?]);
    match family {
        AF_UNIX => Some(SockAddr::Unix),
        AF_INET => {
            let port = u16::from_be_bytes([*bytes.get(2)?, *bytes.get(3)?]);
            let ip: [u8; 4] = bytes.get(4..8)?.try_into().ok()?;
            Some(SockAddr::Inet(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(ip),
                port,
            ))))
        }
        AF_INET6 => {
            let port = u16::from_be_bytes([*bytes.get(2)?, *bytes.get(3)?]);
            let ip: [u8; 16] = bytes.get(8..24)?.try_into().ok()?;
            Some(SockAddr::Inet(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(ip),
                port,
                0,
                0,
            ))))
        }
        other => Some(SockAddr::Other(other)),
    }
}

/// Reads `len` bytes of the sandbox process's memory at `addr`.
fn read_bytes(pid: i32, addr: u64, len: usize) -> io::Result<Vec<u8>> {
    let memory = File::open(format!("/proc/{pid}/mem"))?;
    let mut buffer = vec![0u8; len];
    memory.read_exact_at(&mut buffer, addr)?;
    Ok(buffer)
}

/// Reads a NUL-terminated string of the sandbox process at `addr`.
fn read_string(pid: i32, addr: u64) -> io::Result<String> {
    let memory = File::open(format!("/proc/{pid}/mem"))?;
    let mut bytes = Vec::new();
    let mut at = addr;
    while bytes.len() < MAX_STRING {
        let mut byte = [0u8; 1];
        memory.read_exact_at(&mut byte, at)?;
        if byte[0] == 0 {
            return Ok(String::from_utf8_lossy(&bytes).into_owned());
        }
        bytes.push(byte[0]);
        at += 1;
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "string longer than the monitor reads",
    ))
}

/// Reads the NUL-terminated argv array at `addr` (a list of pointers).
fn read_argv(pid: i32, addr: u64) -> io::Result<Vec<String>> {
    let memory = File::open(format!("/proc/{pid}/mem"))?;
    let mut argv = Vec::new();
    for index in 0..MAX_ARGV {
        let mut pointer = [0u8; 8];
        let at = addr + (index as u64) * 8;
        memory.read_exact_at(&mut pointer, at)?;
        let word = u64::from_ne_bytes(pointer);
        if word == 0 {
            return Ok(argv);
        }
        argv.push(read_string(pid, word)?);
    }
    Ok(argv)
}

/// Whether the process has a terminal on stdin (a pseudo-terminal or a
/// console). A process whose parent is not interactive, such as an install
/// script, is not.
fn is_interactive(pid: i32) -> bool {
    std::fs::read_link(format!("/proc/{pid}/fd/0"))
        .map(|target| {
            let text = target.to_string_lossy().into_owned();
            text.starts_with("/dev/pts/") || text.starts_with("/dev/tty")
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs the filter the way the kernel does, for one system call and
    /// architecture: returns the action value.
    fn run(filter: &[libc::sock_filter], arch: u32, nr: u32) -> u32 {
        let mut accumulator = 0u32;
        let mut pc = 0usize;
        loop {
            let insn = filter[pc];
            pc += 1;
            match insn.code {
                BPF_LD_W_ABS => {
                    accumulator = match insn.k {
                        OFFSET_ARCH => arch,
                        OFFSET_NR => nr,
                        other => panic!("unexpected load at {other}"),
                    };
                }
                BPF_JEQ_K => {
                    pc += if accumulator == insn.k {
                        usize::from(insn.jt)
                    } else {
                        usize::from(insn.jf)
                    };
                }
                BPF_RET_K => return insn.k,
                other => panic!("unexpected opcode {other:#x}"),
            }
        }
    }

    const NATIVE: u32 = 0xC000_003E;

    #[test]
    fn the_watched_calls_go_to_the_listener_and_the_rest_are_allowed() {
        let filter = program(NATIVE);
        for nr in [libc::SYS_execve, libc::SYS_execveat, libc::SYS_connect] {
            let nr = u32::try_from(nr).unwrap_or(u32::MAX);
            assert_eq!(
                run(&filter, NATIVE, nr),
                libc::SECCOMP_RET_USER_NOTIF,
                "nr {nr}"
            );
        }
        for nr in [libc::SYS_getpid, libc::SYS_read, libc::SYS_openat] {
            let nr = u32::try_from(nr).unwrap_or(u32::MAX);
            assert_eq!(run(&filter, NATIVE, nr), libc::SECCOMP_RET_ALLOW, "nr {nr}");
        }
    }

    #[test]
    fn a_call_from_another_architecture_kills_the_process() {
        let filter = program(NATIVE);
        let connect = u32::try_from(libc::SYS_connect).unwrap_or(u32::MAX);
        assert_eq!(
            run(&filter, 0x4000_0003, connect),
            libc::SECCOMP_RET_KILL_PROCESS
        );
    }

    #[test]
    fn a_connect_to_an_ipv4_address_is_decoded_with_its_port() {
        let bytes = [2, 0, 0x15, 0x38, 127, 0, 0, 1];
        assert_eq!(
            decode_sockaddr(&bytes),
            Some(SockAddr::Inet(
                "127.0.0.1:5432".parse().unwrap_or_else(|e| panic!("{e}"))
            ))
        );
    }

    #[test]
    fn a_connect_to_an_ipv6_address_is_decoded() {
        let mut bytes = vec![10, 0, 0x01, 0xbb, 0, 0, 0, 0];
        bytes.extend([0u8; 15]);
        bytes.push(1);
        bytes.extend([0u8; 4]);
        assert_eq!(
            decode_sockaddr(&bytes),
            Some(SockAddr::Inet(
                "[::1]:443".parse().unwrap_or_else(|e| panic!("{e}"))
            ))
        );
    }

    #[test]
    fn a_unix_socket_and_an_unknown_family_are_not_network_targets() {
        assert_eq!(decode_sockaddr(&[1, 0, b'/', 0]), Some(SockAddr::Unix));
        assert_eq!(decode_sockaddr(&[16, 0, 0, 0]), Some(SockAddr::Other(16)));
        assert_eq!(decode_sockaddr(&[2]), None);
    }

    #[test]
    fn a_descriptor_that_is_not_a_listener_makes_the_monitor_fail() {
        let file = File::open("/dev/null").unwrap_or_else(|e| panic!("{e}"));
        let result = supervise(&OwnedFd::from(file), |_| panic!("no event expected"));
        assert!(result.is_err(), "{result:?}");
    }

    #[test]
    fn a_descriptor_passed_over_a_socket_refers_to_the_same_file()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sender, receiver) = UnixStream::pair()?;
        let pipe = File::open("/dev/null")?;
        send_fd(&sender, std::os::fd::AsFd::as_fd(&pipe))?;
        let received = recv_fd(&receiver)?;
        // The received descriptor refers to the same open file.
        let stat = std::fs::metadata(format!("/proc/self/fd/{}", received.as_raw_fd()))?;
        assert!(std::os::unix::fs::FileTypeExt::is_char_device(
            &stat.file_type()
        ));
        Ok(())
    }
}
