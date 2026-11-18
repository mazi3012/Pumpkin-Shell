# Pumpkin-Shell: tech and engineering rules

## Stack
- Rust stable, Cargo workspace. Async: `tokio`. HTTP: `hyper` + `rustls` (no OpenSSL, no `reqwest`). CLI: `clap` (derive).
- Config: `serde` + `toml` (policy files are TOML, never YAML). Logs/receipts: `serde_json` JSONL.
- Crypto: `ed25519-dalek` + `sha2`. Never hand-roll crypto.
- File watching: `notify`. Typosquat distance: `strsim`.
- Linux sandbox: `bwrap` binary + `landlock` crate + seccomp (`seccompiler` or libseccomp bindings). No root at runtime.
- Windows sandbox: `windows` crate (windows-rs): separate local user, WFP, Job Objects, ETW, signed service.
- Platform code lives behind the `SandboxBackend` trait with `#[cfg(target_os = ...)]` modules. Shared logic must stay platform-neutral.

## Versions: always latest stable, verified online
- Before installing or adding any toolchain, crate, tool, GitHub Action or other dependency, search the internet for its **latest stable** release (official release notes, crates.io, docs.rs, GitHub releases). Never rely on remembered version numbers; they go stale.
- Use stable releases only: no beta, nightly, `-rc`, `-alpha` or yanked versions.
- Pin what you chose: Rust in `rust-toolchain.toml` (exact version, e.g. `1.100.0`), crates in `Cargo.toml` (exact minor) and `Cargo.lock` (committed), Actions by version tag or SHA.
- Record toolchain changes in `docs/DECISIONS.md` with the date and the source you checked.
- Current toolchain: **Rust 1.100.0** (stable, released 2026-11-12, per https://doc.rust-lang.org/releases.html, checked 2026-11-19).
- Install Rust with rustup, never with apt (apt ships 1.75).

## Code rules
- `cargo fmt` and `cargo clippy --all-targets -- -D warnings` must pass.
- No `unwrap()`/`expect()` in non-test code paths that handle untrusted input; return typed errors (`thiserror` in libraries, `anyhow` only in the binary).
- No `unsafe` except in thin, documented FFI wrappers.
- Treat everything from inside the sandbox (files, paths, requests, process args) as untrusted input. Canonicalize paths by component, never by string prefix (see CVE-2025-54794).
- Never shell out with interpolated strings; pass argument vectors.
- Secrets never go into logs, receipts, or error messages.
- Dependencies: justify each new crate; prefer well-maintained ones; `cargo-deny` and `cargo-audit` must pass. Commit `Cargo.lock`.

## Testing
- Each task ends with tests plus a runnable demo.
- Detection rules get one fixture per rule under `tests/fixtures/`.
- Escape tests (FS-, NET-, IPC-, PROC-, ENV-, REG-, WIN-) form the published corpus; a rule is not "done" until its escape test exists.
- Run tests with `cargo test` (no watch mode).

## Dev machine notes
- Linux Mint 22.3, kernel 7.0, X11 session (no Wayland), bwrap 0.9.0, Kiro at `/usr/share/kiro`.
- Rust is installed with rustup in `~/.cargo`. If `cargo` is not found in a new shell, run `. "$HOME/.cargo/env"`.
