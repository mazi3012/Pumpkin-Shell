# Pumpkin-Shell: product context

Pumpkin-Shell is a Rust tool that launches AI-powered IDEs (Kiro first, then VS Code, Cursor, Windsurf) inside an OS-level sandbox on **Linux and Windows**. It removes capabilities (no host credentials, filtered network, staged writes to files that run later), guards npm/PyPI installs through a local mirror, detects and notifies on suspicious behavior, and writes a signed, hash-chained log.

- Canonical PRD: #[[file:docs/PRD.md]]
- Decisions and open questions: #[[file:docs/DECISIONS.md]]
- Current plan and machine baseline: #[[file:docs/PLAN.md]]
- Numbered implementation phases (work them in order, keep the status table current): #[[file:docs/PHASES.md]]
- `prd v1.md` is raw chat history with superseded versions (SlopSeal, CLI-first, macOS). Do not treat it as the spec.

## Non-negotiables

- Scope v1: desktop IDEs on Linux and Windows only. No standalone CLI-agent wrapping, no macOS.
- The whole IDE runs inside the sandbox (not split mode).
- Remove capabilities instead of guessing intent. Command/argument matching is detection only, never the security boundary.
- All authority (policy, signing key, log, proxy, brokers, auditing) lives on the host side, never inside the sandbox.
- Fail closed and alert. Never silently degrade security.
- Never claim "0% bypass". Report N/N on a published escape corpus.
- Low friction: every block message names the policy line that would allow it.
- Record new decisions in `docs/DECISIONS.md`.
- One phase at a time, fully tested, one PR per phase. **Never merge a PR or push to `main` without the user's explicit permission for that specific PR** (see `organization.md`).
- **Never hallucinate or fabricate.** Every claim about code, libraries or behavior must be sourced: official docs, live code, tests, or verified search. Hallucination is a blocker (see `tech.md`).
