# Changelog

## 1.0.3 - 2026-11-23

### Added
- `pumpkin-shell kiro` and `pumpkin-shell ide` without a folder open a zenity
  window to choose one. The command to type next time is printed first. If
  zenity is not installed, the command prints the usage line and exits with 2.

- A start banner in orange when `kiro` or `ide` starts in a terminal. It lists
  the IDE, the project, the sandbox and the dashboard link. It is not printed into
  pipes, and it has no color when NO_COLOR is set.
- `kiro` and `ide` start the dashboard in the background and print its link.
  `--no-dashboard` turns this off. If the port is busy, the banner says so.

### Changed
- The folder argument is optional. It no longer defaults to the current folder,
  so `pumpkin-shell kiro` with no argument opens the window. Use
  `pumpkin-shell kiro .` for the current folder.

## 1.0.2 - 2026-11-23

### Added
- Built-in Kiro profile (`profiles/kiro.toml`): the eight exact endpoints a Kiro
  installation needs are allowed by default. Kiro sign-in works with no policy
  file. Your own policy can still add or tighten hosts.

## 1.0.1 - 2026-11-23

### Added
- `pumpkin-shell dashboard`: Pumpkin-Shell Watch, a read-only page on 127.0.0.1
  (default port 8765). It checks each session log with the `log verify` code and
  shows findings by severity, network blocks, decoy reads and refused packages.
  It refreshes every 2 seconds. Checked against 25 real sessions.
- `pumpkin-shell kiro [PATH]`: same as `pumpkin-shell ide kiro [PATH]`.
- `packaging/install.sh`: downloads a release package, checks its cosign
  signature, and installs it only when the check passes.
- Each release also has a stable file name, `pumpkin-shell_amd64.deb`, with its
  own signature bundle, so the README link never needs a version number.
- The Debian package loads the AppArmor profile on Ubuntu 24.04 when unprivileged
  user namespaces are restricted, and removes it on uninstall.

### Changed
- README install: two steps. Download the `.deb` and install it with `apt`, then
  open a project in Kiro. Build from source moved to Advanced. The other install
  options are removed.
- The `kiro` help check no longer depends on the program name, which Windows
  prints as `pumpkin-shell.exe`.

### Fixed
- CLI tests no longer fail on Windows when the runner forces colored output.

## 1.0.0 - 2026-11-22

First release. Linux, with Kiro as the supported IDE.

- Sandbox: bubblewrap, Landlock and seccomp. No root at runtime.
- Egress proxy: exact host allowlist, private and metadata addresses blocked,
  an ask prompt for unknown hosts.
- npm and PyPI mirror: 72-hour version cooldown, packages under 30 days old
  blocked, OSV malware lookup, typosquat warnings, integrity check, install
  scripts off by default.
- Workspace integrity: protected files staged for review, snapshot and restore,
  decoy credentials.
- Detection rules with severity levels, alerts, pause on CRITICAL, and review.
- Signed, hash-chained session log with `log verify`.
- `scan` for agent-escape setups, `doctor`, `policy check`, `trust`.
- Escape corpus v1: 32 of 32 attacks pass on Linux.
- Not in 1.0.0: Windows, VS Code, Cursor, Windsurf.
