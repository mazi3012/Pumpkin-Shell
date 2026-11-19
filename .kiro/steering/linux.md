---
inclusion: auto
name: linux
description: "Linux sandbox backend (PRD §6.1): bubblewrap, Landlock, seccomp, AppArmor, display. Activates when working on doctor, the Linux backend, or Linux-specific behavior."
---

Source of truth: PRD §6.1 (#[[file:docs/PRD.md]]). If this file and the PRD disagree, the PRD wins.

## Isolation

- bubblewrap with `--unshare-all --die-with-parent --new-session` and a fresh `/proc`.
  - `--new-session` calls `setsid()` so the sandbox can't inject keystrokes into the host terminal. The seccomp filter that blocks the `TIOCSTI` ioctl backs it up.
  - bwrap always sets `PR_SET_NO_NEW_PRIVS`. So the setuid `chrome-sandbox` helper cannot work; Chromium falls back to its user-namespace sandbox.
- Nested user namespaces stay allowed so Chromium's own sandbox works. Never pass `--no-sandbox`.
- Landlock is a second filesystem layer, applied in addition to the bwrap mounts.
- Build the bwrap command as an argument vector, never a shell string.
- No root at runtime. Kernel ≥ 5.13 required, ≥ 6.7 recommended; bwrap ≥ 0.8.

## Filesystem

| Mount | Mode |
|---|---|
| Root, including the IDE install | Read-only |
| Repo | Read-write |
| Per-IDE home | Read-write, persistent |
| Existing protected paths | Bind-mounted from a staging copy |

New protected paths that don't exist yet are caught by the host inotify watcher and quarantined.

Not passed in: `$SSH_AUTH_SOCK`, the D-Bus session bus, `docker.sock`, `/run/user/$UID`.

## Display

- Default: Wayland socket only.
- X11: direct `$DISPLAY` access lets any client log keystrokes and inject input into other windows. X11 needs either a nested X server (Xpra / Xephyr, evaluated in Phase 5) or an explicit opt-in that prints this warning. Open question Q4.
- Wayland isolates clients from each other better than X11, but the shared clipboard is still a known risk (PRD §11).
- This dev machine runs X11 only (no Wayland).

## Network

Loopback only inside the sandbox, plus a relay to the host proxy's Unix socket.

## Auditing (Phase 15)

- A host-side seccomp user-notification supervisor traps only `execve` and `connect`. Everything else runs unaudited.
- If the supervisor dies, the session is killed (`SBX-MONITOR-LOST`).

## AppArmor on Ubuntu 24.04+

- Ubuntu can restrict unprivileged user namespaces with `kernel.apparmor_restrict_unprivileged_userns = 1`, which breaks bwrap.
- `doctor` detects this and explains or installs an AppArmor profile that allows userns for the Pumpkin-Shell launcher only.
- Do not tell users to set the sysctl to 0 as the fix. That turns the protection off for every program on the machine.
- Linux Mint 22.3 (this dev machine) ships with the restriction off. Test the restricted case in a VM or by toggling the sysctl temporarily.

## `doctor` probes

Probe the real capability; don't infer it from files that may not exist.

| Check | How |
|---|---|
| Kernel | `uname` release, compare against 5.13 / 6.7 |
| bwrap | `bwrap --version`, ≥ 0.8 |
| AppArmor userns restriction | Read `/proc/sys/kernel/apparmor_restrict_unprivileged_userns` if it exists (absent = no restriction) |
| Unprivileged userns works | Actually create one: run `bwrap --unshare-user --ro-bind / / true` and check the exit code. `/proc/sys/kernel/unprivileged_userns_clone` exists only on some Debian kernels; treat it as a hint only |
| Landlock | Call `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)` (via the `landlock` crate) to get the ABI version. `/sys/kernel/security/lsm` shows whether Landlock is enabled |
| seccomp user notification | Call `seccomp(SECCOMP_GET_ACTION_AVAIL, 0, SECCOMP_RET_USER_NOTIF)`; success means supported |
| Display | `WAYLAND_DISPLAY` / `DISPLAY` / `XDG_SESSION_TYPE` |
| IDE install | Walk the install dir (Kiro: `/usr/share/kiro`) for files writable by group/other or not owned by root → `SYS-IDE-TAMPERABLE` |

## Phase 8 implementation (verified 2026-11-19)
- Backend: `crates/pks-sandbox/src/linux/` (bwrap argument list, Xephyr display, in-sandbox step). CLI: `pumpkin-shell ide kiro|code [PATH]`.
- The in-sandbox step is `pumpkin-shell sandbox-init --rw ... --ro ... -- <ide> <args>`. It applies Landlock, then a seccomp filter that returns EPERM for TIOCSTI, then execs the IDE.
- Landlock write paths: the repo, the IDE home, `/tmp`, `/dev`, `/run`, `/proc`, and the nested display socket. `/proc` is writable because Chromium writes `uid_map` for the namespaces it creates; it is the sandbox's own procfs.
- Read paths: `/usr`, `/etc`, `/sys`, the init binary and the Xauthority file.
- Chromium keeps its own sandbox: `--no-sandbox` is never passed, and nested user namespaces stay enabled.

