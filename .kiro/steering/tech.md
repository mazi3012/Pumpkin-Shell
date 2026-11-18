# Pumpkin-Shell: tech and engineering rules

## Stack
- Rust stable, Cargo workspace. Async: `tokio`. HTTP: `hyper` + `rustls` (no OpenSSL, no `reqwest`). CLI: `clap` (derive).
- Config: `serde` + `toml` (policy files are TOML, never YAML). Logs/receipts: `serde_json` JSONL.
- Crypto: `ed25519-dalek` + `sha2`. Never hand-roll crypto.
- File watching: `notify`. Typosquat distance: `strsim`.
- Linux sandbox: `bwrap` binary + `landlock` crate + seccomp (`seccompiler` or libseccomp bindings). No root at runtime.
- Windows sandbox: `windows` crate (windows-rs): separate local user, WFP, Job Objects, ETW, signed service.
- Platform code lives behind the `SandboxBackend` trait with `#[cfg(target_os = ...)]` modules. Shared logic must stay platform-neutral.

## Versions: always latest stable, verified online (user rule, critical)
- **Before installing or adding any toolchain, crate, tool, GitHub Action or other dependency:**
  1. Search the internet for its **latest stable** release (official release notes, crates.io, docs.rs, GitHub releases, vendor security advisories).
  2. Verify it is secure: check for known CVEs (cve.mitre.org, nvd.nist.gov), recent security issues on GitHub, maintenance status (last commit date), and license compatibility.
  3. Never rely on remembered version numbers; they go stale. Never use older versions without explicit justification.
- Use stable releases only: no beta, nightly, `-rc`, `-alpha` or yanked versions.
- Pin what you chose: Rust in `rust-toolchain.toml` (exact version, e.g. `1.100.0`), crates in `Cargo.toml` (exact minor) and `Cargo.lock` (committed), Actions by version tag or SHA.
- Record every install decision in `docs/DECISIONS.md` with the date, the source checked, and security findings.
- Current toolchain: **Rust 1.100.0** (stable, released 2026-11-12, per https://doc.rust-lang.org/releases.html, checked 2026-11-19, no CVEs).
- Install Rust with rustup, never with apt (apt ships 1.75, too old).

## Code rules
- `cargo fmt` and `cargo clippy --all-targets -- -D warnings` must pass.
- No `unwrap()`/`expect()` in non-test code paths that handle untrusted input; return typed errors (`thiserror` in libraries, `anyhow` only in the binary).
- No `unsafe` except in thin, documented FFI wrappers.
- Treat everything from inside the sandbox (files, paths, requests, process args) as untrusted input. Canonicalize paths by component, never by string prefix (see CVE-2025-54794).
- Never shell out with interpolated strings; pass argument vectors.
- Secrets never go into logs, receipts, or error messages.
- Dependencies: justify each new crate; prefer well-maintained ones; `cargo-deny` and `cargo-audit` must pass. Commit `Cargo.lock`.

## No hallucination or fabrication (user rule, critical)

- **Never invent code, documentation, or facts.** If I don't know something, I ask you or search for it. I do not guess, estimate or "fill in blanks" with made-up answers.
- **Every claim must be sourced.** Before writing code that depends on a library's behavior, API signature, version requirement, or best practice, I verify it by one of these methods (in order):
  1. Read the official documentation (crates.io, docs.rs, release notes, GitHub README).
  2. Check the live codebase (read the source file).
  3. Run a test or demo on this machine.
  4. Search the internet (with a note on what was found and where).
- **If I can't verify:** I say so explicitly. I don't write code that assumes the behavior is correct. I either ask you or search for the answer.
- **Examples of hallucination I will never do:**
  - Writing `use some_crate::function` without checking if that function exists.
  - Claiming a crate is maintained without looking at its last commit date.
  - Using a syntax or feature without confirming it's available in the Rust version we're targeting.
  - Adding a dependency without checking crates.io for its latest stable version and license.
  - Claiming a test passed when I haven't run it.
  - Suggesting a fix without understanding the root cause.
- **If you catch me hallucinating:** point it out, and I'll find the source and fix it immediately. Hallucination is a blocker for this project.

## No dead code (user rule)
- Never leave dead code: no unused functions, types, modules, crates, dependencies, feature flags, commented-out code, or placeholder stubs "for later".
- Add code only in the phase that uses it. Don't scaffold empty crates, traits or modules ahead of time; create them in the phase whose code calls them.
- `#[allow(dead_code)]`, `#[allow(unused)]` and `_`-prefixed names that hide unused code are not allowed. Fix the cause instead.
- `TODO` comments are allowed only with a phase number (`// TODO(phase 9): ...`) and only when that phase is in `docs/PHASES.md`.
- **Removing code:** when code becomes unused (a feature was abandoned, or the user asks to remove something), ask the user **once** to confirm, listing exactly what will be removed. After the user confirms, remove all of it in one change, including tests, fixtures, docs and steering references. Don't ask again for the same removal.
- Before every PR: `cargo clippy --all-targets -- -D warnings` (which fails on unused code), and a manual check that each new dependency is used.

## No sensitive data (user rule, critical)
- **Never commit secrets:** no private keys, API tokens, credentials, cloud keys, passwords, .env files with real values, or personal information to any branch or PR.
- **Workspace cleanup:** before every commit and PR, verify no secrets exist in:
  - `.env` files (use `.env.example` with placeholder values only)
  - `config/` or settings files with real credentials
  - Git history (never commit then delete; use `git rm --cached` if accidentally staged)
  - Documentation examples (use fake/example values with comments)
  - Code comments or error messages
  - Test fixtures (use synthetic/throwaway data only)
- **Git hooks:** use pre-commit checks to catch secrets before they reach the repo. Tools: `ggshield` (GitGuardian), `git-secrets`, `gitleaks`.
- **If a secret leaks:** immediately rotate it (revoke the token/key), then use `git filter-branch` or `git reset` to remove it from history. Report the incident.
- **Decoys in sandbox:** synthetic credentials in the sandboxed home are intentional (rule `FS-DECOY-READ`); they stay in the codebase as test fixtures, not real secrets.

## Secure package installation (user rule, critical)
- **Every dependency must be vetted before install.** Before adding a crate to `Cargo.toml`, a tool to CI, or a GitHub Action:
  1. **Search for the latest stable release:** official source (crates.io for Rust, docs.rs for documentation, GitHub releases for tools).
  2. **Verify security:**
     - Check CVE databases: [cve.mitre.org](https://cve.mitre.org), [nvd.nist.gov](https://nvd.nist.gov), `cargo audit` for known vulnerabilities.
     - Review recent GitHub security advisories and closed issues mentioning "security" or "vulnerability".
     - Verify maintenance: last commit date must be within the last 6 months (exception: stable, widely-used libraries like `serde`, `tokio` that update infrequently).
     - License check: compatible with Apache-2.0 or MIT (Pumpkin-Shell standard).
  3. **Justify the dependency** in the commit message or `docs/DECISIONS.md` if it's new. State why it's needed and what security checks were performed.
  4. **Never use older versions** without explicit justification. If a newer version exists and is secure, use it.
  5. **Record the decision:** `docs/DECISIONS.md` entry with date, version, source checked, and security summary (e.g., "no CVEs, actively maintained, 22 deps resolved").
- **Automated checks:**
  - `cargo deny check` must pass: validates licenses, checks for known-bad crates and source restrictions.
  - `cargo audit` must pass: detects advisory vulnerabilities.
- **CI/GitHub Actions:** pin by commit SHA or release tag, never `latest`. Verify the action is from the official organization (e.g. `actions/checkout@3d3c42e5` is official; forks require review).
- **Supply chain red flags:** if a package is:
  - Newly published (<30 days old) and doesn't come from a known maintainer → HIGH suspicion (typosquat, malware test).
  - Abandoned (no commits >12 months, open security issues) → switch to an alternative.
  - Has high download volume but low GitHub stars → potential malware farming.
  - → Investigate further or skip it.

## Testing
- Each task ends with tests plus a runnable demo.
- Detection rules get one fixture per rule under `tests/fixtures/`.
- Escape tests (FS-, NET-, IPC-, PROC-, ENV-, REG-, WIN-) form the published corpus; a rule is not "done" until its escape test exists.
- Run tests with `cargo test` (no watch mode).

## Dev machine notes
- Linux Mint 22.3, kernel 7.0, X11 session (no Wayland), bwrap 0.9.0, Kiro at `/usr/share/kiro`.
- Rust is installed with rustup in `~/.cargo`. If `cargo` is not found in a new shell, run `. "$HOME/.cargo/env"`.
