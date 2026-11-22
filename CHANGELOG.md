# Changelog

## 1.0.1 - 2026-11-23

### Added
- `pumpkin-shell dashboard`: Pumpkin-Shell Watch, a read-only page on 127.0.0.1
  (default port 8765). It checks each session log with the `log verify` code and
  shows findings by severity, network blocks, decoy reads and refused packages.
  It refreshes every 2 seconds. Checked against 25 real sessions.
- `pumpkin-shell kiro [PATH]`: same as `pumpkin-shell ide kiro [PATH]`.
- `packaging/install.sh`: downloads a release package, checks its cosign
  signature, and installs it only when the check passes.

### Changed
- README install section: two copy-paste cells. Cell 1 installs Pumpkin-Shell and
  its dependencies. Cell 2 launches Kiro. The other install options are removed.
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
- Escape corpus v1: 32 of 32 attacks blocked on Linux.
- Not in 1.0.0: Windows, VS Code, Cursor, Windsurf.
