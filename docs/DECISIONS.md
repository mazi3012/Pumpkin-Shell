# Decisions log

Record every product or architecture decision here with a date. Never delete entries; mark superseded ones.

## Decided

| Date | Decision | Why |
|---|---|---|
| 2026-11-19 | Product name **Pumpkin-Shell**, binary `pumpkin-shell` (spelling to be confirmed, see Q1) | User decision |
| 2026-11-19 | v1 targets **desktop IDEs only** on **Linux and Windows**. No standalone CLI-agent commands. macOS out of scope | User decision |
| 2026-11-19 | Kiro first, then VS Code, Cursor, Windsurf via one Code-OSS adapter | All four share Code-OSS layout |
| 2026-11-19 | **Full-IDE sandbox**, not split mode | Extension host runs file writes and MCP servers; split mode can only detect those |
| 2026-11-19 | Core language Rust; policy format TOML (not YAML) | `serde_yaml` is unmaintained; TOML is the Rust default |
| 2026-11-19 | Linux backend: bubblewrap + Landlock + seccomp, no root | Unprivileged, mount-level enforcement |
| 2026-11-19 | Windows backend: separate local user `pks-sandbox` + WFP filters + signed service; admin once at install | Job Objects and same-user ACLs are bypassable |
| 2026-11-19 | Registry guard as a local mirror, not TLS interception | Proxy only sees `CONNECT host:443`; MITM adds attack surface |
| 2026-11-19 | Defaults: 72 h version cooldown, typosquat WARN, npm install scripts off | Balance safety and friction |
| 2026-11-19 | Ship order: v0.1 `scan` → Linux v0.5 → Windows v1.0 | Linux is unprivileged and faster to validate |
| 2026-11-19 | Never claim "0% bypass"; report N/N on a published corpus | Credibility |
| 2026-11-19 | Toolchain: Rust **1.100.0** via rustup 1.29.3 (clippy, rustfmt); cargo-deny **0.21.0**, cargo-audit **0.23.0** | Latest stable, checked at doc.rust-lang.org/releases.html and the crates.io API on 2026-11-19 |
| 2026-11-19 | Always use the latest stable version of tools and dependencies, verified online before installing; pin exact versions | User decision |
| 2026-11-19 | Workflow: one phase at a time on branch `phase-<N>-<name>`, fully tested, one PR per phase. The agent never merges or pushes to `main`; merge only with the user's explicit permission for that specific PR | User decision |
| 2026-11-19 | **Never hallucinate or fabricate.** Every claim about code, libraries, documentation or behavior must be sourced: official docs, live source code, tests on this machine, or verified search. If unsure, ask or search; never guess. Hallucination is a blocker | User decision, critical |
| 2026-11-19 | **Never commit sensitive data.** No real credentials, API keys, tokens, cloud keys, passwords, .env files with real values, or personal information. Check every PR for accidental secrets before pushing. Workspace must stay 100% secure and clean | User decision, critical |
| 2026-11-20 | Phase 3 crates, checked on crates.io 2026-11-19 (all MIT and/or Apache-2.0, none yanked, updated within 6 months): `serde` 1.0.229, `serde_json` 1.0.154 (JSON output), `landlock` 0.4.7 (ABI probe), `libc` 0.2.191 (seccomp notify probe). `cargo deny` and `cargo audit` pass. Only one `unsafe` call: `SECCOMP_GET_NOTIF_SIZES` probe, documented in `doctor/probe.rs` | Phase 3 steps 3.5 and 3.6 need kernel probes; the libc constant is 3 and SYS_seccomp is 317 on x86_64 (docs.rs libc 0.2.191) |
| 2026-11-20 | Landlock ABI is probed by creating rulesets with `CompatLevel::HardRequirement` (no `restrict_self`, so the probe does not restrict the process). Highest accepted ABI is reported | landlock 0.4.7 docs, `Compatible` trait example "with HardRequirement" |
| 2026-11-20 | `doctor` exit code: 0 when no check fails, 1 when any check fails, 2 on report or Windows errors. Warnings do not fail | Phase 3 design; the user can change this if they want warnings to fail too |
| 2026-11-20 | `Severity` has only `High` for now. Other levels are added in the phase that first uses them | tech.md no-dead-code rule |
| 2026-11-19 | **Secure package installation.** Every dependency (crate, tool, GitHub Action) must be vetted: latest stable version, checked for CVEs via nvd.nist.gov and cargo audit, verified as maintained (last commit <6 months), and justified in docs/DECISIONS.md. No old versions without justification. Automated checks: `cargo deny` and `cargo audit` must pass | User decision, critical |

| 2026-11-19 | **Phase 6 (Windows PoC) skipped on purpose** by the user; work continues with later Linux phases. It must be done before Phase 16, and it needs a Windows machine (Q5) | User decision. `scripts/poc/windows-kiro.ps1` exists but was never run |
| 2026-11-19 | **PR #4 review.** PR #4 (`phase-4-scan`, head b80f393) bundles Phases 4, 5, 7 and 8, which breaks the one-phase-one-PR rule. Phase 3 had been merged first as PR #2. It is not merged. CI is red on both runners. Findings are recorded under each phase in `docs/PHASES.md` | Checked by running the binary and bwrap on this machine, not by reading the PR text. The PR text says "clippy passes" and "28 tests"; clippy exits 101 and `pks-sandbox` has 2 tests, not 5 |
| 2026-11-19 | **Security finding: sandbox exposes the real home.** The Phase 5 script and the Phase 8 backend use `--ro-bind / /`, so `~/.ssh` is visible and host `/tmp` is writable. A canary file in `$HOME` was readable; with `--tmpfs $HOME` it was not. Both also use `--env` and `--unset-env`, which bwrap 0.9.0 rejects (`--setenv`, `--unsetenv` are the real names) | Tested here on 2026-11-19. Must be fixed before any phase claims the sandbox hides credentials |
| 2026-11-19 | **PR #4 dependencies are not vetted.** Added without DECISIONS entries: `tokio`, `tempfile`, `anyhow`, `thiserror`, `globset`, `walkdir`, `base64`, `rand`, `sha2`. crates.io on 2026-11-19: `thiserror` pinned 1.0.56, latest 2.0.21 (both are in `Cargo.lock`); `base64` 0.21.7 vs 0.23.1; `rand` 0.8.5 vs 0.10.4; `sha2` 0.10.8 vs 0.11.1; `tokio` is unused in `pks-sandbox`. `cargo audit` is clean (101 crates). `cargo deny` fails: `pks-policy` and `pks-sandbox` have no license field. Each needs a decision (update or justify) in the phase PR that uses it | tech.md rule: latest stable, vetted, recorded. Versions checked at the crates.io API |
| 2026-11-19 | Rule IDs `FOLDEROPEN-TASK`, `YARNPATH` and `KIRO-COMMAND-HOOK` are not in the PRD rule table. They need PRD entries or renames to PRD names (`WS-AUTOAPPROVE`, `WS-*`) before v0.1 | PRD FR-DET is the source of truth for rule IDs (organization.md) |
| 2026-11-19 | Q4 (X11) is still open. The Phase 5 doc picks "direct X11 socket, opt-in with warning" but the script has no opt-in switch and exposes `:0` by default. `Xephyr` is installed here at `/usr/bin/Xephyr`; `xpra` is not | Checked on this machine; `doctor` still warns on X11 |

## Assumed defaults (not yet confirmed by user)

| Topic | Default |
|---|---|
| Unknown domain | `ask` (hold 20 s, desktop prompt); `deny` when headless |
| CRITICAL action | `pause` the whole sandbox |
| github.com | Reachable for read (clone/fetch); pushes need broker approval |

## Open questions

| # | Question | Blocks |
|---|---|---|
| Q1 | Spelling: "Pumpkin-Shell" or "PumpkinShell"? | Crate names, binary name |
| Q2 | One-time admin install on Windows acceptable? | Windows backend design (Task 3, 14) |
| Q3 | Linux first then Windows, or ship together? | Release plan |
| Q4 | Dev machine is an **X11** session (no Wayland). Use a nested X server (Xpra/Xephyr) for isolation, or X11 opt-in with warning, for the Linux PoC? | Task 2 |
| Q5 | Is a Windows machine or VM available for Tasks 3, 14, 15? | Windows work |
| Q6 | License (Apache-2.0, MIT, dual, or AGPL)? | Public repo, crate metadata |
