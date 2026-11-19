//! Pure check logic for `doctor`. Inputs come from `probe` (on Linux) or from
//! tests. Nothing here touches the system, so every pass/fail mapping can be
//! unit-tested.

use pks_core::{Finding, RuleId, Severity};
use serde::Serialize;

/// Minimum kernel for Landlock and seccomp user notification (PRD §9).
pub const MIN_KERNEL: (u32, u32) = (5, 13);
/// Kernel recommended by the PRD (§9).
pub const RECOMMENDED_KERNEL: (u32, u32) = (6, 7);
/// Minimum bubblewrap version (PRD §9).
pub const MIN_BWRAP: (u32, u32) = (0, 8);

/// Rule raised when files of the IDE install can be changed by non-root users.
pub const SYS_IDE_TAMPERABLE: RuleId = RuleId::new("SYS-IDE-TAMPERABLE");

/// Outcome of one check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Pass,
    Warn,
    Fail,
}

/// Result of one check, with a one-line fix when the check does not pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Check {
    pub name: &'static str,
    pub status: Status,
    pub detail: String,
    pub fix: Option<String>,
    pub finding: Option<Finding>,
}

impl Check {
    fn pass(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            status: Status::Pass,
            detail: detail.into(),
            fix: None,
            finding: None,
        }
    }

    fn warn(name: &'static str, detail: impl Into<String>, fix: impl Into<String>) -> Self {
        Self {
            name,
            status: Status::Warn,
            detail: detail.into(),
            fix: Some(fix.into()),
            finding: None,
        }
    }

    fn fail(name: &'static str, detail: impl Into<String>, fix: impl Into<String>) -> Self {
        Self {
            name,
            status: Status::Fail,
            detail: detail.into(),
            fix: Some(fix.into()),
            finding: None,
        }
    }
}

/// Reads `major.minor` from the start of a version-like string such as
/// `7.0.0-43-generic` or `bubblewrap 0.9.0`. Returns `None` when no two
/// numbers are found.
#[must_use]
pub fn parse_major_minor(text: &str) -> Option<(u32, u32)> {
    let mut numbers = text
        .split(|c: char| !c.is_ascii_digit())
        .filter(|part| !part.is_empty());
    let major = numbers.next()?.parse().ok()?;
    let minor = numbers.next()?.parse().ok()?;
    Some((major, minor))
}

/// Kernel version check (PRD §9, Phase 3 step 3.2).
#[must_use]
pub fn kernel_check(release: &str) -> Check {
    let name = "kernel";
    let Some(version) = parse_major_minor(release) else {
        return Check::fail(
            name,
            format!("could not read a version from kernel release {release:?}"),
            "Check /proc/sys/kernel/osrelease.",
        );
    };
    if version < MIN_KERNEL {
        Check::fail(
            name,
            format!("kernel {release} is older than 5.13"),
            "Install a kernel 5.13 or newer (6.7+ recommended).",
        )
    } else if version < RECOMMENDED_KERNEL {
        Check::warn(
            name,
            format!("kernel {release} works, 6.7+ recommended"),
            "Upgrade to kernel 6.7 or newer.",
        )
    } else {
        Check::pass(name, format!("kernel {release}"))
    }
}

/// bubblewrap presence and version check (Phase 3 step 3.3).
/// `version_output` is the stdout of `bwrap --version`, or `None` when the
/// binary could not be run.
#[must_use]
pub fn bwrap_check(version_output: Option<&str>) -> Check {
    let name = "bwrap";
    let Some(output) = version_output else {
        return Check::fail(
            name,
            "bwrap is not installed or not runnable",
            "Install bubblewrap 0.8 or newer with your package manager.",
        );
    };
    let last_word = output.split_whitespace().last().unwrap_or_default();
    let Some(version) = parse_major_minor(last_word) else {
        return Check::fail(
            name,
            format!("could not read the bwrap version from {output:?}"),
            "Check that `bwrap --version` prints a version number.",
        );
    };
    if version < MIN_BWRAP {
        Check::fail(
            name,
            format!("bwrap {last_word} is older than 0.8"),
            "Install bubblewrap 0.8 or newer.",
        )
    } else {
        Check::pass(name, format!("bwrap {last_word}"))
    }
}

/// Unprivileged user namespace check (Phase 3 step 3.4).
/// `bwrap_userns_ok` is the result of a real `bwrap --unshare-user` run.
/// `apparmor_restrict` is the value of
/// `kernel.apparmor_restrict_unprivileged_userns`, or `None` when the sysctl
/// does not exist.
#[must_use]
pub fn userns_check(bwrap_userns_ok: bool, apparmor_restrict: Option<bool>) -> Check {
    let name = "user namespaces";
    if bwrap_userns_ok {
        let note = match apparmor_restrict {
            Some(true) => "AppArmor restricts unprivileged user namespaces, but the probe passed",
            Some(false) => "AppArmor restriction is off",
            None => "no AppArmor restriction sysctl",
        };
        return Check::pass(name, format!("bwrap can create a user namespace; {note}"));
    }
    let fix = if apparmor_restrict == Some(true) {
        "Set kernel.apparmor_restrict_unprivileged_userns=0, or add an AppArmor profile for bwrap."
    } else {
        "Run `bwrap --unshare-user --ro-bind / / true` by hand and read its error."
    };
    Check::fail(name, "bwrap could not create a user namespace", fix)
}

/// Landlock ABI check (Phase 3 step 3.5). `abi` is the highest ABI version
/// the running kernel accepts, or `None` when Landlock is unavailable.
#[must_use]
pub fn landlock_check(abi: Option<usize>) -> Check {
    let name = "landlock";
    match abi {
        Some(version) => Check::pass(name, format!("Landlock ABI v{version}")),
        None => Check::fail(
            name,
            "Landlock is not available on this kernel",
            "Use a kernel with Landlock enabled (5.13 or newer, and in the boot LSM list).",
        ),
    }
}

/// seccomp user notification check (Phase 3 step 3.6).
/// `notify_supported` is the result of a `SECCOMP_GET_NOTIF_SIZES` probe.
#[must_use]
pub fn seccomp_check(notify_supported: bool) -> Check {
    let name = "seccomp user notification";
    if notify_supported {
        Check::pass(name, "supported")
    } else {
        Check::fail(
            name,
            "seccomp user notification is not supported",
            "Use a kernel 5.0 or newer with seccomp enabled.",
        )
    }
}

/// Display session check (Phase 3 step 3.7). A plain X11 session warns
/// because any app on the display can read keystrokes (PRD §6.1, Q4).
#[must_use]
pub fn display_check(wayland: bool, x11: bool) -> Check {
    let name = "display";
    if wayland {
        Check::pass(name, "Wayland session")
    } else if x11 {
        Check::warn(
            name,
            "X11 session: apps on the display can read keystrokes and inject input",
            "Use a nested X server (Xpra or Xephyr) or accept the risk (DECISIONS Q4).",
        )
    } else {
        Check::pass(name, "no display (headless)")
    }
}

/// Counts from scanning the IDE install directory (Phase 3 step 3.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdeScan {
    /// Regular files scanned.
    pub files: usize,
    /// Files a non-root user could change.
    pub tamperable: usize,
}

/// IDE install permission check (rule SYS-IDE-TAMPERABLE). `scan` is `None`
/// when the install directory does not exist.
#[must_use]
pub fn ide_check(path: &str, scan: Option<IdeScan>) -> Check {
    let name = "IDE install permissions";
    let Some(scan) = scan else {
        return Check::warn(
            name,
            format!("no IDE install found at {path}"),
            "Pass the IDE install path when Kiro is installed elsewhere.",
        );
    };
    if scan.tamperable == 0 {
        return Check::pass(
            name,
            format!("{} files checked, none writable by non-root", scan.files),
        );
    }
    let message = format!(
        "{} of {} files under {path} can be changed by non-root users",
        scan.tamperable, scan.files
    );
    let fix = format!("sudo chmod -R go-w {path}");
    Check {
        name,
        status: Status::Fail,
        detail: message.clone(),
        fix: Some(fix.clone()),
        finding: Some(Finding {
            rule: SYS_IDE_TAMPERABLE,
            severity: Severity::High,
            target: path.to_owned(),
            message,
            fix,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_kernel_release() {
        assert_eq!(parse_major_minor("7.0.0-43-generic"), Some((7, 0)));
        assert_eq!(parse_major_minor("5.13.0"), Some((5, 13)));
        assert_eq!(parse_major_minor("6.7"), Some((6, 7)));
        assert_eq!(parse_major_minor("unknown"), None);
        assert_eq!(parse_major_minor("5"), None);
    }

    #[test]
    fn kernel_maps_to_pass_warn_fail() {
        assert_eq!(kernel_check("5.12.9").status, Status::Fail);
        assert_eq!(kernel_check("5.13.0").status, Status::Warn);
        assert_eq!(kernel_check("6.6.1").status, Status::Warn);
        assert_eq!(kernel_check("6.7.0").status, Status::Pass);
        assert_eq!(kernel_check("7.0.0-43-generic").status, Status::Pass);
        assert_eq!(kernel_check("garbage").status, Status::Fail);
    }

    #[test]
    fn bwrap_maps_to_pass_fail() {
        assert_eq!(bwrap_check(None).status, Status::Fail);
        assert_eq!(bwrap_check(Some("bubblewrap 0.9.0")).status, Status::Pass);
        assert_eq!(bwrap_check(Some("bubblewrap 0.8.0")).status, Status::Pass);
        assert_eq!(bwrap_check(Some("bubblewrap 0.7.0")).status, Status::Fail);
        assert_eq!(bwrap_check(Some("no version here")).status, Status::Fail);
    }

    #[test]
    fn userns_maps_probe_and_apparmor() {
        assert_eq!(userns_check(true, None).status, Status::Pass);
        assert_eq!(userns_check(true, Some(true)).status, Status::Pass);
        assert_eq!(userns_check(false, Some(true)).status, Status::Fail);
        let fail = userns_check(false, Some(true));
        assert!(
            fail.fix
                .is_some_and(|fix| fix.contains("apparmor_restrict"))
        );
    }

    #[test]
    fn landlock_maps_abi_presence() {
        assert_eq!(landlock_check(Some(8)).status, Status::Pass);
        assert_eq!(landlock_check(None).status, Status::Fail);
    }

    #[test]
    fn seccomp_maps_probe() {
        assert_eq!(seccomp_check(true).status, Status::Pass);
        assert_eq!(seccomp_check(false).status, Status::Fail);
    }

    #[test]
    fn display_warns_only_on_plain_x11() {
        assert_eq!(display_check(true, false).status, Status::Pass);
        assert_eq!(display_check(true, true).status, Status::Pass);
        assert_eq!(display_check(false, true).status, Status::Warn);
        assert_eq!(display_check(false, false).status, Status::Pass);
    }

    #[test]
    fn ide_flags_tamperable_files_as_high_finding() {
        let clean = ide_check(
            "/usr/share/kiro",
            Some(IdeScan {
                files: 10,
                tamperable: 0,
            }),
        );
        assert_eq!(clean.status, Status::Pass);
        assert!(clean.finding.is_none());

        let bad = ide_check(
            "/usr/share/kiro",
            Some(IdeScan {
                files: 10,
                tamperable: 3,
            }),
        );
        assert_eq!(bad.status, Status::Fail);
        let finding = bad.finding.expect("tamperable files produce a finding");
        assert_eq!(finding.rule.as_str(), "SYS-IDE-TAMPERABLE");
        assert_eq!(finding.severity, Severity::High);
    }

    #[test]
    fn ide_missing_is_a_warning() {
        assert_eq!(ide_check("/nowhere", None).status, Status::Warn);
    }
}
