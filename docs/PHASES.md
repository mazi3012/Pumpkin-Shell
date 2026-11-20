# Pumpkin-Shell: implementation phases

Ordered roadmap for building v1.0. Work one phase at a time, in number order. A phase is done only when every line in its **Done when** list passes.

- Scope and requirements: [PRD.md](PRD.md). PRD task numbers (§12) are shown as `T1`–`T16`.
- Decisions and open questions (`Q1`–`Q6`): [DECISIONS.md](DECISIONS.md).
- Dev machine baseline and conventions: [PLAN.md](PLAN.md).

## Overview

| Phase | Name | PRD | Platform | Milestone | Status |
|---|---|---|---|---|---|
| 1 | Dev environment | PLAN Step 0 | Linux | | done (1.3 optional, not installed; 1.4 applied 2026-11-20) |
| 2 | Workspace skeleton and CI | T1 | Both | | done (PR #1 merged) |
| 3 | `doctor` (Linux) | T1 | Linux | | done (PR #2 merged) |
| 4 | `scan` | T4 | Both | **v0.1** | done (PR #5 merged, CI green on both runners; step 4.12 tag v0.1 pending) |
| 5 | Linux PoC: Kiro in bwrap | T2 | Linux | | done (PR #6 merged, CI green; accepted with a VS Code stand-in, real Kiro test is PRD scenario 2) |
| 6 | Windows PoC: Kiro as `pks-sandbox` | T3 | Windows | | blocked: Q5 (Windows machine) |
| 7 | Policy and signed log | T5 | Both | | done (PR #7 merged, CI green on both runners) |
| 8 | Linux `ide` backend | T6 | Linux | | done (PR #8 merged at e9daf3f, CI green on both runners; Kiro reaches its sign-in screen) |
| 9 | Egress proxy | T7 | Both | | done (PR #9 merged at f8ce48c) |
| 10 | Workspace integrity (Linux) | T8 | Linux | | in-progress (branch `phase-10-workspace-integrity`) |
| 11 | Notifications and review | T9 | Linux | | todo |
| 12 | Brokers | T10 | Linux | | todo |
| 13 | Code-OSS adapter, four IDEs | T11 | Linux | **Linux v0.5** | todo |
| 14 | npm and PyPI mirror | T12 | Both | | todo |
| 15 | Linux exec/connect auditing | T13 | Linux | | todo |
| 16 | Windows enforcement | T14 | Windows | | todo |
| 17 | Windows parity | T15 | Windows | | todo |
| 18 | v1.0 release | T16 | Both | **v1.0** | todo |

Phase 6 is out of number order on purpose. The PRD runs both proofs of concept early so the design can change before anything depends on it. If no Windows machine is available, skip Phase 6 and continue with Phase 7. It must be done before Phase 16.

Status values: `todo`, `in-progress`, `in-review (PR #<n>)`, `done`, `blocked: <reason>`. Update this table when a phase changes state.

---

## Phase 1: Dev environment

**Goal:** a machine that can build, lint and audit Rust code.

1.1. Install Rust with rustup (stable toolchain plus `clippy` and `rustfmt`). Use rustup, not apt: apt ships Rust 1.75, which is too old for current crates.
1.2. `cargo install --locked cargo-deny cargo-audit`.
1.3. Optional: install the `gh` CLI for CI and releases.
1.4. Optional, recommended: `sudo chmod -R go-w /usr/share/kiro` (67 world-writable files found, see PLAN.md).
1.5. Make the first git commit of the existing docs and steering, so later phases have a clean diff baseline.

**Done when:**
- `cargo --version`, `cargo clippy --version`, `cargo deny --version`, `cargo audit --version` all succeed.
- `git log` shows at least one commit.

**Needs from you:** approval to install the tools in 1.1 and 1.2. 1.4 needs sudo.

---

## Phase 2: Workspace skeleton and CI

**Goal:** an empty but buildable workspace with CI on Linux and Windows.

2.1. Root `Cargo.toml` workspace, `rust-toolchain.toml` (pinned stable), `deny.toml`, and a committed `Cargo.lock`.
2.2. Crate `pks-cli` only (binary `pumpkin-shell`, clap derive). Other crates are created in the phase that first uses them, per the no-dead-code rule in `tech.md`: `pks-core` in Phase 3, `pks-scan` in Phase 4, `pks-sandbox` in Phase 8.
2.3. `pumpkin-shell --version` and `--help` work, with integration tests.
2.4. GitHub Actions workflow on `ubuntu-latest` and `windows-latest`: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`, `cargo deny check`, `cargo audit`.
2.5. Add `target/` to `.gitignore`.

**Done when:**
- [x] All CI jobs pass locally on Linux (fmt, clippy, test, cargo-deny, cargo-audit; checked 2026-11-19).
- [x] CI is green on both runners: `check (ubuntu-latest)` and `check (windows-latest)` passed on PR #1 (merged into `mazi3012/pumpkin-shell` main at e6c5c25).
- [x] PR opened and merged: PR #1, `mazi3012/pumpkin-shell`.

Steps: 2.1 [x], 2.2 [x], 2.3 [x] (5 tests pass), 2.4 [x] CI runs on both runners, 2.5 [x].

**Blocked by:** Q1 (final binary name) only if you want a different name than `pumpkin-shell`. Q6 (license) for crate metadata; `license` can stay unset until decided.

---

## Phase 3: `doctor` (Linux)

**Goal:** `pumpkin-shell doctor` tells the user whether this machine can run the sandbox, and how to fix it if not.

3.0. Create crate `pks-core` with the shared types `doctor` needs: `Severity` (INFO, NOTICE, WARN, HIGH, CRITICAL), `RuleId`, `Finding` (rule, severity, target, message, fix hint). Rules are data, so `doctor`, `scan`, the watcher and the proxy share one type. Add only the types this phase uses.
3.1. Check framework: each check returns pass / warn / fail plus a one-line fix.
3.2. Kernel version (≥ 5.13 required, ≥ 6.7 recommended).
3.3. `bwrap` present and ≥ 0.8.
3.4. Unprivileged user namespaces allowed. Read `kernel.apparmor_restrict_unprivileged_userns` where it exists, and prove it by trying to create a user namespace.
3.5. Landlock ABI version (probe with the `landlock` crate, not a `/proc` file).
3.6. seccomp user notification support (probe the syscall; there is no `/proc` flag for it).
3.7. Display type: Wayland, X11, or none. X11 prints the risk warning (Q4).
3.8. IDE install permissions: report world-writable or non-root-owned files under the Kiro install (rule `SYS-IDE-TAMPERABLE`).
3.9. Human output and `--json` output.

**Done when:**
- [x] On this machine `doctor` passes the kernel, bwrap, userns and Landlock checks, warns about X11, and reports `SYS-IDE-TAMPERABLE` for `/usr/share/kiro` (67 of 4916 files, checked 2026-11-20).
- [x] Unit tests cover version parsing and each check's pass/fail mapping (10 unit tests in `doctor/checks.rs`).
- [ ] Windows CI runs the new code (not yet pushed).

Steps: 3.0 [x] `pks-core` (RuleId, Severity, Finding), 3.1 [x], 3.2 [x], 3.3 [x], 3.4 [x] (AppArmor sysctl read; fail path covered by unit test only), 3.5 [x] Landlock ABI v8, 3.6 [x] seccomp notify probe, 3.7 [x] X11 warning, 3.8 [x] `SYS-IDE-TAMPERABLE`, 3.9 [x] human and `--json`.

---

## Phase 4: `scan` → v0.1

**Goal:** a static scanner that finds agent-escape setups in a repo and works in CI. Pure Rust, no sandbox needed.

4.0. Create crate `pks-scan`.
4.1. Workspace walker: respects `.gitignore`, never follows symlinks out of the repo, compares paths by component (CVE-2025-54794).
4.2. `WS-HIDDEN-UNICODE`: tag chars U+E0000–U+E007F, bidi controls, zero-width characters. Report file, line and code point.
4.3. `WS-AUTOAPPROVE`: `chat.tools.autoApprove` in `.vscode/settings.json` (and Cursor/Windsurf equivalents); MCP `autoApprove` in `.kiro/settings/mcp.json`, `.mcp.json`, `.cursor/mcp.json`.
4.4. MCP server inventory: list every configured MCP server and its command.
4.5. Kiro command hooks in `.kiro/hooks/` (any hook with a `command` action).
4.6. `.vscode/tasks.json` tasks with `runOptions.runOn: "folderOpen"`.
4.7. `.yarnrc.yml` `yarnPath`.
4.8. `.git/config` `core.fsmonitor` and `core.hooksPath`; executable files in `.git/hooks`.
4.9. NTFS alternate data streams (Windows build only).
4.10. Output: human text and `--json`. `--ci` exits 0 when clean, 1 when findings at or above a threshold, 2 on error.
4.11. One fixture repo per rule under `tests/fixtures/scan/`, plus one clean repo.
4.12. Tag release **v0.1** with binaries for Linux and Windows.

**Done when:**
- [x] Every fixture produces exactly its expected finding; the clean repo produces none (`crates/pks-scan/tests/fixtures.rs`, 23 tests; run 2026-11-19).
- [x] `pumpkin-shell scan --ci` exits 1 on the hidden-Unicode fixture (`crates/pks-cli/tests/scan.rs`, 10 tests) and the CI workflow has a step that fails unless that exit code is 1 (PRD scenario 11).
- [x] CI is green on both runners: `check (ubuntu-latest)` and `check (windows-latest)` passed on PR #5 and again on `main` at 34e12c6. The Windows ADS tests ran there for the first time.

Steps: 4.0 [x], 4.1 [x] (`ignore` crate; `--no-ignore` for CI), 4.2 [x], 4.3 [x] (`settings.json` in `.vscode`, `.cursor`, `.windsurf`; MCP in `.kiro/settings`, `.mcp.json`, `.cursor`, `.vscode`), 4.4 [x] (rule `WS-MCP-SERVER`), 4.5 [x] (rule `WS-KIRO-HOOK`), 4.6 [x], 4.7 [x], 4.8 [x], 4.9 [x] (ran green on the Windows runner), 4.10 [x], 4.11 [x] (`ws-ads` has no fixture directory: an alternate stream cannot be stored in git, so its test creates one at run time), 4.12 [ ] not done: tagging **v0.1** needs your OK after the merge, and Linux and Windows binaries need a release workflow that does not exist yet.

Tests: 95 in the workspace (pks-core 2, pks-scan 45 unit + 23 fixture, pks-cli 11 unit + 4 + 10). Two protections were broken on purpose to confirm the tests fail (reading `.ignore` files, matching `.kiro/hooks` by string prefix).

**Note:** JSON config files such as `settings.json` allow comments (JSONC). Parse them with a JSONC-tolerant parser. Done: `jsonc-parser`.

---

## Phase 5: Linux PoC: Kiro in bwrap

**Goal:** prove Kiro runs inside bubblewrap before building the real backend. Shell script first, Rust later.

5.1. Script `scripts/poc/linux-kiro.sh`: bwrap with a test HOME, `--unshare-all`, `--die-with-parent`, `--new-session`, read-only root, read-write repo, fresh `/proc`.
5.2. Make the GUI work: X11 (direct with opt-in warning, or Xpra/Xephyr per Q4), GPU (`/dev/dri`), `/dev/shm`, fonts.
5.3. Keep Chromium's own sandbox working through nested user namespaces. Never pass `--no-sandbox`.
5.4. No network, or a stub proxy only.
5.5. Record every breakage and the minimum permission that fixed it in `docs/poc/linux-kiro.md`.

**Done when:**
- [x] Kiro opens the repo and edits a file. **Accepted by the user on 2026-11-19 as met with a stand-in.** Not fully met: Kiro starts in the sandbox but stops at its Sign in screen (needs the Phase 12 broker). A file edit through the GUI was shown with VS Code, which has the same Code-OSS base, not with Kiro.
- [x] `cat ~/.ssh/*` from the IDE's terminal fails (VS Code terminal; `--check` gives the same 23 passing probes for Kiro).
- [x] No network except the stub: no network at all, no stub yet (Phase 9).

Steps: 5.1 [x], 5.2 [x] (Xephyr; GPU and `/dev/shm` not needed, fonts from `/usr`), 5.3 [x] (nested userns; `--disable-userns` makes Chromium abort), 5.4 [x] (no network), 5.5 [x] (`docs/poc/linux-kiro.md`).

**Decision (user, 2026-11-19):** Phase 5 is accepted with VS Code as the stand-in. The real Kiro test is PRD scenario 2 (Kiro sign-in), after the Phase 9 proxy and the Phase 12 callback relay.

**Blocked by:** none. Q4 was decided on 2026-11-19: Xephyr.

---

## Phase 6: Windows PoC: Kiro as `pks-sandbox`

**Goal:** prove the Windows design (separate user, WFP, Job Object) before building on it.

6.1. Create local non-admin user `pks-sandbox` manually.
6.2. Run Kiro as that user inside a Job Object with kill-on-close.
6.3. WFP filters by the user's SID: only loopback to a stub proxy port allowed.
6.4. Test escapes: processes started through WMI `Win32_Process.Create` and `schtasks` must stay network-blocked, and cleanup must remove them.
6.5. Record findings in `docs/poc/windows-kiro.md`.

**Done when:**
- Kiro runs; `C:\Users\<you>\.ssh` is denied; a direct `curl` fails.

**Blocked by:** Q5 (Windows machine or VM), Q2 (admin install acceptable).

---

## Phase 7: Policy and signed log

**Goal:** the trusted host-side policy and tamper-evident log every later layer writes to.

7.1. Policy schema in TOML: user policy at `~/.config/pumpkin-shell/policy.toml` (`%APPDATA%\Pumpkin-Shell\` on Windows).
7.2. Repo `pumpkin-shell.toml` merge that can only tighten; loosening attempts raise `POL-UNTRUSTED` and are ignored.
7.3. `pumpkin-shell trust` pins the repo policy hash.
7.4. Signed log, JSONL fields: `v`, `session`, `seq`, `ts`, `prev`, `policy_hash`, `layer`, `target`, `rule`, `verdict`, `sig` (ed25519 via `ed25519-dalek`, hashes via `sha2`).
7.5. Key stored outside any sandbox-visible path. Signed checkpoint at session end.
7.6. `pumpkin-shell log verify`: checks chain, signatures and checkpoint.

**Done when:**
- [x] Tests show `log verify` fails after editing, deleting, reordering or truncating any line: every field of every line, every line deleted, every pair swapped, every tail cut, a cut in the middle of a line, and a cut with the checkpoint also deleted (`pks-core` `log::tests`, and `pks-cli/tests/policy_log.rs` through the real binary).
- [x] A repo policy that loosens a rule is rejected with `POL-UNTRUSTED`: every rule and every lower action, the mode, and a user policy as the baseline (`policy::tests`, `policy_log.rs`).
- [x] CI is green on both runners: PR #7 merged at `354478e`, `check (ubuntu-latest)` and `check (windows-latest)` passed.

Steps: 7.1 [x] (`policy.rs`, version 1 schema), 7.2 [x] (`merge`, `resolve`; CLI `policy check`), 7.3 [x] (`trust`, pins in the host data dir, not in the repo), 7.4 [x] (ed25519 via `ed25519-dalek` 3.0.0, SHA-256 via `sha2` 0.11.1), 7.5 [x] (key in `<data dir>/keys`, mode 0700/0600, refused if looser or a symlink; "never visible to the sandbox" is enforced by the Phase 8 mounts, which must not include the data dir), 7.6 [x] (`log verify`).

Tests: 224 in the workspace (pks-core 114, pks-scan 68, pks-cli 42). All mutation checks pass: 13 mutants of the log verifier, 13 of the policy and trust code, each caught by at least one test. Two gaps found that way (chain check, last-hash check) got their own tests, and a plain-`verify` mutant is caught by a weak-key forgery test.

Demo: `cargo run -p pks-core --example sample_log -- /tmp/pks-demo`, then `cargo run -p pks-cli -- log verify /tmp/pks-demo/session.jsonl --key-dir /tmp/pks-demo/keys`. Edit, delete, reorder or cut the file and verify fails with the reason.

Not done on purpose: a writer that reopens a closed or crashed session (`Logger` is create-only; a log with no checkpoint is checked with `--allow-open`), and plain `pumpkin-shell log` (a viewer). Nothing in the product writes logs yet; the proxy (Phase 9) is the first user.

---

## Phase 8: Linux `ide` backend

**Goal:** `pumpkin-shell ide kiro .` launches Kiro in the sandbox from Rust, using what Phase 5 learned.

8.0 [x]. Create crate `pks-sandbox` with the `SandboxBackend` trait and its Linux implementation behind `#[cfg(target_os = "linux")]`. The Windows implementation is added in Phase 16.
8.1 [x] (`linux/bwrap.rs`, tested) Implement `SandboxBackend` for Linux: build the bwrap argument vector (never a shell string).
8.2 [x] (read-only `/usr`, read-write repo and IDE home, tested) Read-only root including the IDE install, read-write repo, persistent per-IDE home.
8.3 [x] (`--clearenv` plus an exact allowlist, tested) Filtered environment. Not passed in: `SSH_AUTH_SOCK`, D-Bus session bus, `docker.sock`, `/run/user/$UID`.
8.4 [x] (Landlock ABI 1 required, newer rights best-effort; seccomp blocks TIOCSTI with EPERM; tested) Landlock as a second layer; seccomp filter blocking `TIOCSTI`.
8.5 [x] (`--unshare-all`, loopback only, no proxy yet) No network yet (Phase 9 adds the proxy).

**Done when:**
- [~] `pumpkin-shell ide kiro .` opens Kiro on this repo. **Partly met:** `pumpkin-shell ide kiro` starts Kiro in the sandbox on a nested display and Kiro shows its Sign in screen (screenshot). It stops there, as in Phase 5, because sign-in needs Phases 9 and 12. The repo is mounted at `/workspace`; the repo open itself is not visible until sign-in.
- [~] `~/.ssh`, `SSH_AUTH_SOCK` and the D-Bus session bus are unreachable from Kiro's terminal. **Verified with the same sandbox and IDE binary, not Kiro's terminal:** the 26 isolation probes in `tests/sandbox.rs` run inside the real sandbox and pass. Kiro's own terminal was not driven.


Tests: pks-sandbox 23 unit tests (spec refusals, bwrap argument list, display lookup); pks-cli `tests/sandbox.rs`, 8 tests that run real sandboxes: 26 isolation probes, a failing probe reported, Landlock write allow and deny, TIOCSTI EPERM and other ioctls unaffected, two refusal paths. Mutation checks: skipping seccomp, skipping Landlock, dropping `--unshare-all` and sharing the network each fail at least one test.

Found and fixed while testing: Chromium's setuid check failed under Landlock until `/proc` was writable (it writes `uid_map` for the namespaces it creates). The sandbox's `/proc` lists only its own processes, so the write reaches no host process (see DECISIONS).

Not done in Phase 8: VS Code (`ide code`) was not run; it is the same code path but untested. No GPU device (`/dev/dri`), no Wayland.
---

## Phase 9: Egress proxy

**Status: done.** Merged as PR #9 (f8ce48c). Open note carried forward: Kiro Extensions need `open-vsx.org` and `openvsx.eclipsecontent.org`, which are not in the allowlist (see DECISIONS.md).

**Goal:** the only network path out of the sandbox. Adds crate `pks-proxy`.

9.1. [x] Host proxy on a Unix socket, with a relay inside the sandbox on loopback (`pumpkin-shell sandbox-relay` on `127.0.0.1:3128`, started by `sandbox-init` before the seccomp filter).
9.2. [x] HTTP CONNECT allowlist of exact `host:port`. Wildcards are refused by `HostPort::parse` (tests in `pks-core`) and in the user policy `[network]` (test `a_wildcard_endpoint_in_the_user_policy_is_an_error`). A repo policy cannot add endpoints (`parse_repo` refuses `[network]`).
9.3. [x] Proxy resolves DNS itself, checks every resolved address, and dials the checked address. Refused: private, loopback, link-local, unspecified, multicast, documentation, CGNAT and metadata addresses (`addr.rs`, tests in `pks-proxy`).
9.4. [x] Unknown hosts are held for `ASK_HOLD` (20 s) and asked through the `Asker`; no answer or "deny" is refused; monitor mode allows and reports `NET-UNKNOWN-DOMAIN`. The terminal prompt in `ide` is not yet tested on a live terminal.
9.5. [x] Optional `host_ports` relays. Set in the user policy only: `[network] host_ports = [5432]`. The sandbox listens on `127.0.0.1:<port>` for each listed port and sends `CONNECT 127.0.0.1:<port>` to the proxy. The proxy dials only that exact loopback address and only for listed ports, and logs `NET-HOST-PORT` as NOTICE. Port 0 and 3128 are refused. Tests: engine (listed port dialed on loopback and reported; unlisted loopback port and `localhost` refused), relay unit tests (CONNECT sent, bytes copied, refusal closes), policy tests, and one real sandbox test (a host service on a listed port answers inside the sandbox, an unlisted port does not).
9.6. [~] `NET-LARGE-UPLOAD` (WARN above 10 MB per connection, test `a_large_upload_raises_one_warning`). Limit: the count is per connection, not per host, and there is no exemption for model-API hosts yet.
9.7. [x] Kiro IDE allowlist. Source: kiro.dev/docs/privacy-and-security/firewalls ("required by all Kiro products" and "every Kiro IDE installation" lists). Confirmed on 2026-11-19 with a monitor session (`a718a3b9`, 171 entries, checkpoint verified) and an enforce session (`b440c9f8`): sign-in persisted, two chat messages answered, zero blocked or monitored hosts. Eight entries: `app.kiro.dev`, `assets.app.kiro.dev`, `prod.us-east-1.auth.desktop.kiro.dev`, `prod.download.desktop.kiro.dev`, `runtime.us-east-1.kiro.dev`, `management.us-east-1.kiro.dev`, `telemetry.us-east-1.kiro.dev`, `q.us-east-1.amazonaws.com`. The last one is required by the vendor but was not seen in our sessions. Not on the profile: Chromium and Firefox background hosts, `kiro-prod-us-east-1.auth.us-east-1.amazoncognito.com` and `*.shortbread.aws.dev` (not in the IDE list).

**Done when:**
- [x] Kiro chat works through the proxy: enforce-mode session `b440c9f8`, signed in with the sandbox home, two chat replies, no blocked entries.
- [~] An unknown domain triggers the ask prompt. The engine asks through the `Asker` (engine tests with a fake asker), and the terminal prompt parses its answers (`ide::tests`: once/session allow, deny, empty line and end of input deny). A live prompt was not triggered: with the Kiro allowlist in enforce mode, Kiro did not contact an unlisted host in a 240 s run. Left open until a live run shows the prompt.
- [x] A request to `169.254.169.254` is blocked: the sandbox probe `proxy refuses cloud metadata` gets `CONNECT tunnel failed, response 403` through the relay, and the direct probes show no route to it. A LAN address is refused by the engine test `an_ip_literal_on_a_private_address_is_refused_without_a_lookup`.

Steps: 9.1 to 9.4 and 9.6 are in the branch. Test results are in the Phase 9 pull request.

---

## Phase 10: Workspace integrity (Linux)

**Goal:** protected files are staged, not written; the user can always recover.

10.1. [x] Protected paths bind-mounted from a staging copy (`WS-PROTECTED-WRITE`). The 12 PRD paths plus an in-repo `core.hooksPath` target. Existing paths are copied to `<session>/staging/`; missing ones get an empty staged file or directory and an empty mount point in the repo, removed at exit. Parent directories (`.git`, `.kiro`) are bound over themselves so they cannot be renamed. Symlinks, wrong types, special files and trees over 10,000 files or 64 MiB are refused before the session starts. At exit each staged copy is compared with its start state (content and mode) and each change is a HIGH finding, printed and logged with verdict `staged`. Tests: 17 in `pks-core::workspace`, bind checks in `pks-sandbox`, and two real-sandbox tests. Not done here: the "host inotify watcher" of the PRD is not needed, because every protected path is covered by a mount, including ones that do not exist yet.
10.2. [x] `WS-AUTOAPPROVE` on staged config changes: CRITICAL, staged. The config rules of `scan` (`pks-scan::staged::review`) run on each staged file the sandbox added or changed. Auto-approve turned on, or an MCP server or command hook added, is CRITICAL. An unparseable config is HIGH, never a pass. Pausing is Phase 11. Tests: 6 unit tests in `pks-scan::staged`, PRD scenarios 3 and 4 in the real sandbox.
10.3. [x] Watched paths held for review (`WS-WATCHED-CHANGE`, HIGH). Decided 2026-11-21 (option C): the sandbox works on a staged copy of each watched path, as protected paths do (10.1), so only the sandbox's writes are in the copy and nothing is applied to the repo. An overlayfs was rejected for watched paths: overlayfs cannot mount on a single file, and most watched paths are files (checked on this kernel). The earlier exit-time comparison with the snapshot (first version of 10.3) was removed on the user's confirmation (2026-11-21), with its helpers in `snapshot.rs` and five unit tests. Test: `an_edit_to_a_watched_file_is_held_and_the_repo_is_unchanged` in the real sandbox, and 2 unit tests in `pks-core::workspace`. The 11 watched paths (`.github/workflows`, `package.json`, `Makefile`, `Dockerfile`, `.devcontainer`, `conftest.py`, `setup.py`, `.pre-commit-config.yaml`, `.kiro/steering`, `AGENTS.md`, `.cursorrules`) are staged like protected paths, so symbolic links are refused and a missing one gets a mount point removed at exit.
10.4. [x] Snapshot before launch: working tree including untracked non-ignored files, via a temporary index in a bare git directory in the session dir (`snapshot.git`). `ide` refuses to start if the snapshot fails. `pumpkin-shell restore <sid> [--into DIR]` writes it into a new directory (default `<data>/restores/<sid>`). Tests: `pks-core` snapshot (7) and `pks-cli` restore (5, Linux). Not yet: a live `ide` run that shows the snapshot line (needs a GUI session).
10.5. [x] `WS-MASS-DELETE` (> 50 files or > 20% of the snapshot files) with a restore hint. Checked when the IDE exits, against the snapshot; it is HIGH, printed, and logged as layer `ws`. Tests: thresholds, a whole-directory delete, a few files in a large repo, and PRD scenario 8 in the real sandbox (`rm -rf src` inside, detected outside, restored). Limit: it is found at exit, not while the IDE runs; a live check comes with the watcher in Phase 11.
10.6. [x] Decoy `.ssh/id_ed25519`, `.aws/credentials` and `.config/gh/hosts.yml` in the IDE home, each with a random marker, written fresh for every session (`pks-core::decoy`). An access is `FS-DECOY-READ` (HIGH), reported while the IDE runs through an inotify watch (`pks-sandbox::linux::watch`, `IN_OPEN` and `IN_ACCESS`), once per decoy. The finding names the decoy, never its marker. Tests: 5 unit tests in `pks-core::decoy`, and 2 real-sandbox tests (a read inside the sandbox is seen on the host; a session that reads no decoy reports none). Limit: the watch covers files the sandbox opens; a decoy the IDE copies elsewhere is not tracked, and the decoys hold no real secret (a copy is worth nothing to an attacker).
10.7. [x] `WS-SECRET-WRITTEN` (HIGH) for secrets the sandbox wrote. Two places are scanned at exit: files added or changed in the repo since the snapshot (found with a temporary git index, ignored files excluded), and the staged copies of protected and watched paths. Kinds: private key headers, AWS access key IDs (`AKIA`, `ASIA`), GitHub tokens (six documented prefixes), and a copy of one of our decoys. The finding names the file, the first line and the kind; the value is never printed or logged. Tests: 10 unit tests in `pks-scan::secrets`, 6 in `pks-scan::staged`, 1 in `pks-core::snapshot`, and a real-sandbox test (a token written to a repo file and to a staged `.npmrc` is reported, value not shown).

**Done when:** PRD scenarios 3, 4 and 8 pass.

Status of that line (2026-11-21):
- Scenario 8 (`rm -rf src/`: `WS-MASS-DELETE`, `restore` recovers): [x] in the real sandbox (`a_mass_delete_inside_the_sandbox_is_found_and_restored`).
- Scenario 3 (a README injection enables auto-approve: write staged, CRITICAL alert, IDE paused): [~] the write is staged and the CRITICAL finding is raised (`scenario_3_enabling_auto_approve_is_staged_and_critical`). **"IDE paused" is not done: pausing is Phase 11 (11.5).** The finding is raised when the IDE exits, not live.
- Scenario 4 (the agent creates a test-on-save hook: works in-session; user approves it in review): [~] the hook works in-session, is staged, and is CRITICAL (`scenario_4_a_new_command_hook_is_staged_and_critical`). **"User approves it in review" is not done: `pumpkin-shell review` is Phase 11 (11.6).**
- Not yet run: the whole `pumpkin-shell ide` flow with a real IDE (snapshot line, decoys, staged mounts, exit report). The pieces are tested in the real sandbox; the glue in `ide.rs` is only compiled and linted. A run with the user is planned.

---

## Phase 11: Notifications and review

**Goal:** the user sees what happened and can approve, resume or kill. Adds crate `pks-detect`.

11.1. Severity engine routing: INFO/NOTICE → log and summary; WARN → `watch`; HIGH → `notify-send`; CRITICAL → webhook plus configured action.
11.2. Deduplication by rule + target; at most one desktop notification per 10 s.
11.3. `pumpkin-shell watch`.
11.4. Webhook output (Slack, Discord, plain JSON).
11.5. Pause with SIGSTOP; `resume` and `kill`.
11.6. `pumpkin-shell review`: blocks, staged writes to approve/reject, watched-file diff, quarantined files, restore command.
11.7. `allow` and `allow-write` commands. Every block message names the policy line that would allow it.

**Done when:**
- Reading a decoy file shows a desktop alert.
- A CRITICAL finding pauses Kiro until `resume`.

---

## Phase 12: Brokers

**Goal:** the host-side actions the sandbox may request but not perform.

12.1. URL-open broker: the sandbox's `xdg-open` forwards to the host browser.
12.2. OAuth callback relay back to the sandboxed IDE on loopback. Observed in Phase 5: Kiro IDE signs in with `redirect_uri=http://localhost:3128` and listens on `127.0.0.1:3128` inside the sandbox, so the host browser cannot reach it without a relay (`docs/poc/linux-kiro.md`).
12.3. `git push` approval: prompt shows remote and branch.

**Done when:** PRD scenarios 2 (Kiro sign-in) and 12 (`git push` prompt) pass.

---

## Phase 13: Code-OSS adapter and four IDEs → Linux v0.5

**Goal:** one adapter that covers Kiro, VS Code, Cursor and Windsurf. Adds crate `pks-ide` and `profiles/`.

13.1. Code-OSS adapter: shared layout of settings, extensions and user data.
13.2. Profiles in `profiles/*.toml`: paths, exact domains, env keys per IDE.
13.3. `pumpkin-shell ide import <ide>`: settings and extensions, never tokens.
13.4. `ide code`, `ide cursor`, `ide windsurf`.
13.5. Tag release **Linux v0.5**.

**Done when:** all four IDEs run under Pumpkin-Shell. Cursor and Windsurf must be installed first (not on this machine yet).

---

## Phase 14: npm and PyPI mirror

**Goal:** safe package installs without breaking them. Adds crate `pks-registry`.

14.1. Local mirror over plain HTTP inside the sandbox; rustls upstream. Direct registry connections blocked (`REG-DIRECT-BYPASS`).
14.2. 72-hour version cooldown: hide newer versions from npm packuments and the PyPI simple index (`REG-COOLDOWN`). Lockfile pinned to a too-new version is blocked with an explanation (`REG-TOO-NEW`).
14.3. Packages whose first release is under 30 days old are blocked; a 404 logs `REG-HALLUCINATED`.
14.4. OSV.dev `MAL-` lookups with a cache (`REG-MALWARE`). If OSV is unreachable, allow only packages ≥ 30 days old.
14.5. Typosquat check on normalized names (PEP 503, npm scopes): distance 1 for names ≥ 5 chars, 2 for ≥ 10 (`REG-TYPOSQUAT`).
14.6. Verify tarballs and wheels against `dist.integrity` / sha256 (`REG-INTEGRITY`).
14.7. `npm_config_ignore_scripts=true` by default; list packages with `hasInstallScript` in the session summary.
14.8. Clients: npm, pnpm, yarn, bun, pip, uv, poetry.

**Done when:**
- PRD scenario 5 passes (2-hour-old version with postinstall is skipped, previous version installs, no script runs).
- False-positive benchmark on the top 1,000 packages is recorded.

---

## Phase 15: Linux exec/connect auditing

**Goal:** see every process and connection the sandbox makes.

15.1. Host-side seccomp user-notification supervisor for `execve` and `connect`.
15.2. Rules `EXEC-AGENT-YOLO`, `EXEC-DESTRUCTIVE`, `EXEC-RECON`, `NET-DIRECT-CONNECT` (with fix hint).
15.3. Fail closed: if the supervisor dies, kill the session and raise `SBX-MONITOR-LOST`.

**Done when:** PRD scenarios 7 and 9 pass, and killing the supervisor kills the session.

---

## Phase 16: Windows enforcement

**Goal:** `pumpkin-shell ide kiro .` on Windows, using what Phase 6 learned.

16.1. Signed `Pumpkin-Shell Service` (LocalSystem) and MSI installer that creates `pks-sandbox`.
16.2. Repo ACL grant at session start, revoke at end, ownership reset, `safe.directory` in the sandbox user's gitconfig.
16.3. Deny-write ACEs on protected paths; changes via `allow-write` or review.
16.4. WFP filters by SID; everything except the proxy port blocked, including DNS.
16.5. Job Object with kill-on-close; at session end kill all `pks-sandbox` processes and remove scheduled tasks, Run keys and startup items (`WIN-PERSIST`).
16.6. Windows part of `doctor`: service, sandbox user, WFP.

**Done when:** `pumpkin-shell ide kiro .` works on Windows and PRD scenario 10 passes.

**Blocked by:** Phase 6, Q2, Q5.

---

## Phase 17: Windows parity

**Goal:** every Linux feature also works on Windows.

17.1. Proxy settings for the sandbox user (system proxy and `HTTP(S)_PROXY`).
17.2. Named-pipe brokers restricted to the service and sandbox user.
17.3. Toast notifications.
17.4. ETW process auditing and WFP audit events.
17.5. `ReadDirectoryChangesW` watcher.
17.6. Pause by suspending the job's processes.

**Done when:** all 12 PRD acceptance scenarios pass on Windows.

---

## Phase 18: v1.0 release

**Goal:** a signed, installable product with honest public claims.

18.1. Signed deb and rpm (cosign + SLSA provenance); signed MSI and service (Authenticode).
18.2. AppArmor profile and guidance for Ubuntu 24.04+.
18.3. Public threat model and known-risks page (PRD §11).
18.4. Published escape corpus with "N/N pass on corpus vX" results.
18.5. `cargo vet` added to CI.

**Done when:**
- Install to a protected Kiro session takes under 5 minutes on Ubuntu 24.04 and Windows 11.
- 100% of the escape corpus passes on both OSes.

---

## Rules for working through phases

- Each phase is built on its own branch, fully tested, and delivered as exactly one PR. The user reviews it. **Never merge a PR without the user's explicit permission for that PR.** Full rules: "One phase, one PR" in `.kiro/steering/organization.md`.
- A phase becomes `done` only after the user merges its PR. While waiting, its status is `in-review (PR #<n>)`.
- Start a phase only when the previous phase (in number order) is `done`, except Phase 6 as noted above.
- Before a phase starts, check its **Blocked by** line and resolve or ask about each open question.
- Every phase ends with tests and a runnable demo (`tech.md`).
- When a phase finishes: set its status to `done`, record decisions in `DECISIONS.md`, and save an LTM checkpoint: `python3 ltm/bin/ltm.py checkpoint --summary "Phase N done: <name>"`.
- If scope changes, edit the PRD first, then this file.
