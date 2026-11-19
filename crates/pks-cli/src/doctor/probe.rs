//! Linux system probes for `doctor`. Each function reads one fact from the
//! running system and returns it as plain data for `checks`.

use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::Command;

use landlock::{ABI, Access, AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr};

use super::checks::IdeScan;

const OSRELEASE: &str = "/proc/sys/kernel/osrelease";
const APPARMOR_USERNS_SYSCTL: &str = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns";

/// Landlock ABI versions in increasing order, so the index plus one is the
/// version number.
const LANDLOCK_ABIS: [ABI; 9] = [
    ABI::V1,
    ABI::V2,
    ABI::V3,
    ABI::V4,
    ABI::V5,
    ABI::V6,
    ABI::V7,
    ABI::V8,
    ABI::V9,
];

/// Kernel release string, such as `7.0.0-43-generic`.
pub fn kernel_release() -> io::Result<String> {
    Ok(fs::read_to_string(OSRELEASE)?.trim().to_owned())
}

/// Stdout of `bwrap --version`, or `None` if bwrap is missing or fails.
pub fn bwrap_version() -> Option<String> {
    let output = Command::new("bwrap").arg("--version").output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// True when bwrap can create a user namespace. Runs a real bwrap command,
/// so AppArmor and kernel policy are tested the same way the sandbox uses
/// them.
pub fn bwrap_userns_ok() -> bool {
    Command::new("bwrap")
        .args(["--unshare-user", "--ro-bind", "/", "/", "true"])
        .status()
        .is_ok_and(|status| status.success())
}

/// `Some(true)` when `kernel.apparmor_restrict_unprivileged_userns` is 1,
/// `Some(false)` when it is 0, and `None` when the sysctl is absent.
pub fn apparmor_restrict_userns() -> Option<bool> {
    let value = fs::read_to_string(APPARMOR_USERNS_SYSCTL).ok()?;
    match value.trim() {
        "1" => Some(true),
        "0" => Some(false),
        _ => None,
    }
}

/// Highest Landlock ABI version (1 to 9) the running kernel accepts.
///
/// Creating a ruleset does not restrict this process. With
/// `CompatLevel::HardRequirement`, `handle_access` fails when the kernel does
/// not support every right of the requested ABI (landlock 0.4.7 docs, the
/// `Compatible` trait example "with HardRequirement").
pub fn landlock_abi() -> Option<usize> {
    LANDLOCK_ABIS
        .iter()
        .enumerate()
        .filter(|(_, abi)| landlock_abi_accepted(**abi))
        .map(|(index, _)| index + 1)
        .max()
}

fn landlock_abi_accepted(abi: ABI) -> bool {
    Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(abi))
        .and_then(|ruleset| ruleset.create())
        .is_ok()
}

/// Whether the kernel supports seccomp user notification, probed with
/// `seccomp(SECCOMP_GET_NOTIF_SIZES, 0, &sizes)`. The call only reads sizes
/// and installs no filter.
#[allow(unsafe_code)]
// Thin FFI wrapper: the only call that needs `unsafe` in this crate. The
// kernel writes three u16 values (`struct seccomp_notif_sizes`) into `sizes`.
// The buffer is valid for that write for the whole call.
pub fn seccomp_notify_supported() -> bool {
    let mut sizes = [0u16; 3];
    // SAFETY: `sizes` is a live, writable buffer of exactly the struct size,
    // and SECCOMP_GET_NOTIF_SIZES with flags 0 only writes that struct.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_GET_NOTIF_SIZES,
            0,
            sizes.as_mut_ptr(),
        )
    };
    ret == 0
}

/// Display session from the environment: `(wayland, x11)`.
pub fn display_session() -> (bool, bool) {
    let wayland = std::env::var_os("WAYLAND_DISPLAY").is_some_and(|value| !value.is_empty());
    let x11 = std::env::var_os("DISPLAY").is_some_and(|value| !value.is_empty());
    (wayland, x11)
}

/// Scans the regular files under `root`. Symlinks are not followed.
/// Returns `Ok(None)` when `root` does not exist.
pub fn scan_ide_install(root: &Path) -> io::Result<Option<IdeScan>> {
    if !root.exists() {
        return Ok(None);
    }
    let mut scan = IdeScan {
        files: 0,
        tamperable: 0,
    };
    scan_dir(root, &mut scan)?;
    Ok(Some(scan))
}

fn scan_dir(dir: &Path, scan: &mut IdeScan) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        let meta = fs::symlink_metadata(&path)?;
        if meta.is_dir() {
            scan_dir(&path, scan)?;
        } else if meta.is_file() {
            scan.files += 1;
            if is_tamperable(&meta) {
                scan.tamperable += 1;
            }
        }
    }
    Ok(())
}

/// A file is tamperable when a non-root user can change it: world-writable,
/// group-writable by a non-root group, or owned by a non-root user.
fn is_tamperable(meta: &fs::Metadata) -> bool {
    let mode = meta.mode();
    let world_writable = mode & 0o002 != 0;
    let group_writable_non_root = mode & 0o020 != 0 && meta.gid() != 0;
    let owned_by_non_root = meta.uid() != 0;
    world_writable || group_writable_non_root || owned_by_non_root
}
