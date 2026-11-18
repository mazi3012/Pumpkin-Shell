---
inclusion: auto
name: registry-guard
description: "npm and PyPI registry guard (PRD FR-REG, Phase 14). Activates when working on the package mirror, cooldown, typosquat, OSV or integrity checks."
---

Source of truth: PRD §7 FR-REG (#[[file:docs/PRD.md]]). Built in Phase 14 (crate `pks-registry`). If this file and the PRD disagree, the PRD wins.

## Architecture

- Local mirror over plain HTTP inside the sandbox; `rustls` for upstream. No TLS interception (DECISIONS: "Registry guard as a local mirror").
- Direct connections to real registry hosts are blocked: `REG-DIRECT-BYPASS` (HIGH, block).
- Clients covered: npm, pnpm, yarn, bun (npm registry); pip, uv, poetry (PyPI).

## Checks, in evaluation order

| # | Check | Result |
|---|---|---|
| 1 | Package name returns 404 upstream | `REG-HALLUCINATED` WARN (likely an AI-hallucinated name) |
| 2 | Package's **first** release < 30 days ago | `REG-TOO-NEW` HIGH, block |
| 3 | OSV.dev `MAL-` advisory for the version (cached) | `REG-MALWARE` CRITICAL, block |
| 4 | Versions < 72 h old | Removed from the npm packument / PyPI simple index (`REG-COOLDOWN` INFO). The install resolves the previous version and does not break |
| 5 | Lockfile pins a version that the cooldown hides | `REG-TOO-NEW` HIGH, block with an explanation |
| 6 | Typosquat (see below) | `REG-TYPOSQUAT` WARN |
| 7 | Tarball / wheel hash vs `dist.integrity` (npm) or sha256 (PyPI), before serving | Mismatch: `REG-INTEGRITY` CRITICAL, block |

If OSV is unreachable: allow only packages whose first release is ≥ 30 days old.

## Typosquat

- Normalize names first: PEP 503 for PyPI (lowercase, runs of `-_.` → `-`); keep the npm scope.
- Edit distance (`strsim`) to a list of popular packages: distance ≤ 1 for names ≥ 5 chars, ≤ 2 for names ≥ 10 chars. Shorter names are not checked.
- Default: **WARN**. Escalate to block only when the package is also young (< 30 days) or low-download.

## Install scripts

- `npm_config_ignore_scripts=true` is set in the sandbox by default.
- Packages with `hasInstallScript` are listed in the session summary so the user can decide.

## Not in scope

- `pumpkin-shell scan` is a static repo scanner (Phase 4). It does not query registries, OSV or package ages.
- cargo and Go registries are not in v1.

## Acceptance

- PRD scenario 5: a version published 2 h ago with a postinstall script is hidden, the previous version installs, no script runs.
- False-positive benchmark on the top 1,000 packages is recorded before Phase 14 is `done`.
