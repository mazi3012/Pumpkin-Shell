# Threat model and known risks (v1.0.0)

This document says what Pumpkin-Shell protects, from whom, and what it does not
protect. It follows PRD sections 1, 3 and 11. The measured results are in
[ESCAPE-CORPUS.md](ESCAPE-CORPUS.md). The design choices and their reasons are in
[DECISIONS.md](DECISIONS.md).

## What is protected

- **Your credentials.** SSH keys, cloud logins, the SSH agent, the Docker
  socket and the D-Bus session bus are not reachable from inside the sandbox.
  The sandbox does not mount your real home directory.
- **Your files outside the project.** The sandbox can write only to the
  project and to its own IDE home. System files are read-only.
- **Your network.** Direct connections are refused. Traffic goes through a proxy
  with an allowlist. Package installs go through a mirror.
- **Files that run later on your machine.** Protected files, such as `.envrc`,
  `.vscode/`, `.git/hooks` and `.kiro/settings`, are staged for your review
  instead of being written into the project.
- **The record.** Each decision goes into a log that is hash-chained and signed.
  The signing key is kept outside the sandbox.

## Who it defends against

| Attacker | Example | Defence |
|---|---|---|
| A prompt-injected agent (A1) | A README tells the agent to read `~/.ssh` | No keys in reach; decoy keys report any read; the sandbox has no direct network |
| A malicious dependency or extension (A2) | A package whose install script steals tokens | Install scripts are off; 72-hour cooldown; malware lookup (OSV `MAL-`); hash check |
| A well-meaning agent that makes a mistake (A3) | `rm -rf src/`, `terraform destroy` | Mass-delete detection and restore; destructive command alerts; no cloud credentials |
| Malware that drives AI tools (A4) | A postinstall script that starts an AI CLI with its permission checks off | The AI-tool flags are detected (EXEC-AGENT-YOLO, CRITICAL) |

## Out of scope

These are not claimed. The PRD lists them as out of scope (section 3).

- Kernel, bubblewrap and Landlock bugs, and privilege-escalation bugs in them.
- Malware that already runs on your machine as your user.
- Data sent to a domain you allowed, such as the AI model's own API or GitHub.
- The quality of the code the AI writes.
- macOS and Windows (Windows is after the first release).

## Known risks and gaps

These are the things we know do not work fully yet. Each one is also in the
corpus document or the decisions log.

1. **Detection rules are not blocks.** The EXEC-* and NET-DIRECT-CONNECT rules
   report. They do not stop a command. Argument matching can be evaded; the real
   control is that credentials are absent (PRD section 11).
2. **Monitor blind spots.** When the monitor cannot read a call's arguments (the
   process exited, or its memory is not readable), the call is skipped and not
   logged. Unix-socket connections and other address families are not reported.
3. **Decoy reads at startup.** Kiro reads the `.aws/credentials` decoy when it
   starts. This raises one HIGH alert per session. It is kept as a deliberate
   rule (DECISIONS, 2026-11-22).
4. **Data sent to allowed domains.** Anything sent to an allowed domain leaves
   the machine (PRD section 11).
5. **Shared desktop (X11).** The IDE runs on a nested X server (Xephyr), so it
   should not reach the windows of your desktop. Clipboard copy and paste go
   through a broker that you approve. Nobody has tried to break this from
   inside the sandbox, and it is not in the corpus. The PRD notes the same
   risk for a shared desktop (section 11), and a separate desktop or VM is a
   later version (DECISIONS Q4).
6. **The `PATH` in the sandbox excludes `/usr/local/bin`.** Tools installed there
   are not found by name inside the IDE. This is a usability limit, not a leak.
   It is recorded as a decision for the first release.
7. **Package checks are the user's step.** Releases are signed by the release
   workflow. `apt install` does not check that signature by itself, so run the
   check in the README before you install.
8. **Not yet verified on a clean Ubuntu 24.04 install.** The AppArmor profile is
   written and syntax-checked, but was not tested on a host where unprivileged
   user namespaces are restricted (see `packaging/apparmor/`).
9. **Dependencies not yet audited.** `cargo vet` (0.10.3) passes. 15 crates are
   audited through the imported Mozilla, Google and Bytecode Alliance audit sets.
   137 crates are exempted: they are accepted without an audit of ours. Each one
   is listed in `supply-chain/config.toml`. Auditing them is open work. `cargo
   deny` and `cargo audit` still run in CI.
10. **Escape corpus scope.** 32 attacks are listed. Known gaps in the corpus are
   listed in ESCAPE-CORPUS.md. A pass on the corpus does not mean no bypass
   exists.

## How to report a problem

Report a security problem privately to the maintainer. Do not open a public
issue for a bypass.

## Versions

- This document: v1.0.0.
- Corpus: v1, 32 attacks, Linux only.
