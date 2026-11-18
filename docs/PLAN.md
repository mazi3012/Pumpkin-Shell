# Start plan (first 2 weeks)

Source of truth for scope: [PRD.md](PRD.md). Decisions: [DECISIONS.md](DECISIONS.md). Full numbered roadmap: [PHASES.md](PHASES.md).

## Dev machine baseline (probed 2026-11-19)

| Item | Value | Impact |
|---|---|---|
| OS | Linux Mint 22.3 (Ubuntu 24.04 base), kernel 7.0.0, x86_64, 4 cores, 7 GB RAM | Kernel supports Landlock, seccomp notify CONTINUE |
| bubblewrap | 0.9.0 | OK (needs 0.8+) |
| Unprivileged userns | allowed; `apparmor_restrict_unprivileged_userns = 0` | Mint differs from stock Ubuntu; test the restricted case in a VM or by toggling the sysctl |
| LSMs | landlock, apparmor, yama, bpf, ... | Landlock available |
| Display | **X11** (`DISPLAY=:0`), no Wayland | Task 2 must handle X11 (nested server or opt-in) |
| Kiro | 1.4.178 at `/usr/share/kiro` (not from a package) | Primary test target |
| VS Code | installed (`/usr/bin/code`) | Second test target |
| Cursor, Windsurf | not installed | Needed by Task 11 |
| Rust | 1.100.0 via rustup (clippy, rustfmt), installed 2026-11-19 | OK |
| cargo-deny, cargo-audit | 0.21.0, 0.23.0, installed 2026-11-19 | OK |
| gh | not installed | Optional |
| notify-send, xdg-open, docker, git 2.43 | installed | — |

**Security finding on this machine:** 67 files in `/usr/share/kiro`, including the `kiro` binary, are world-writable. Any local process can replace them. Fix: `sudo chmod -R go-w /usr/share/kiro`. Added to the PRD as rule SYS-IDE-TAMPERABLE.

## Step 0: environment (needs user approval)

1. Install Rust via rustup (stable, with `clippy`, `rustfmt`).
2. `cargo install --locked cargo-deny cargo-audit`.
3. Optional: `gh` CLI for CI and releases.
4. Fix Kiro install permissions (above).

## Week 1

| Order | Work | Done when |
|---|---|---|
| 1 | **Task 1 skeleton:** Cargo workspace, crates `pks-cli` (binary `pumpkin-shell`), `pks-core` (policy, events, receipts types), `pks-scan`, `pks-sandbox` (trait + `linux` / `windows` modules behind `cfg`). `.gitignore`, `rust-toolchain.toml`, `deny.toml`, GitHub Actions (fmt, clippy `-D warnings`, test, deny, audit) on ubuntu + windows runners | CI green on both runners |
| 2 | **`doctor` (Linux part):** kernel, bwrap version, userns + AppArmor sysctl, Landlock ABI, seccomp notify, display type, IDE install permission check | `pumpkin-shell doctor` prints pass/fail + fix lines on this machine, flags Kiro's world-writable files |
| 3 | **Task 4 `scan` → v0.1:** rules for hidden Unicode, `chat.tools.autoApprove`, MCP `autoApprove`, Kiro command hooks, `tasks.json` `folderOpen`, `yarnPath`, git `core.fsmonitor`/`hooksPath`; JSON + human output; `--ci` exit code | Fixture repos under `tests/fixtures/scan/` each produce the expected finding; clean repo produces none |

`scan` goes early because it is pure Rust, cross-platform, useful on day one, and builds the rule/finding types every later layer reuses.

## Week 2

| Order | Work | Done when |
|---|---|---|
| 4 | **Task 2 Linux PoC** (script first, Rust later): launch Kiro under bwrap with a test HOME, `--unshare-net`, ro root, rw repo. Iterate on display (X11 direct vs Xpra/Xephyr), GPU (`/dev/dri`), `/dev/shm`, fonts, nested userns for Chromium. Log each failure and the minimal fix in `docs/poc/linux-kiro.md` | Kiro opens the repo, edits a file; `cat ~/.ssh/*` from its terminal fails; no network except a stub |
| 5 | **Task 5 signed log:** hash chain, ed25519, checkpoint, `log verify`; tamper/delete/reorder/truncate tests | `log verify` fails on any edit |

Task 3 (Windows PoC) starts as soon as a Windows machine/VM is available (Q5).

## Working conventions

- Every task: tests first where practical, then code; each task ends with a runnable demo.
- Security rules are data-driven (rule ID, severity, action, fix hint) so `scan`, the watcher and the proxy share one engine.
- Unverified claims (`*` in the PRD) are verified before they appear in public docs or rule descriptions.
- Update `docs/DECISIONS.md` whenever a decision is made or changed.
