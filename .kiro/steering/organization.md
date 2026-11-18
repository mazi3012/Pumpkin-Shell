---
inclusion: always
---

# Pumpkin-Shell: organization and workflow

## Where things go

- Code layout: see `structure.md`. Don't create a second layout description here.
- Specs and plans live in `docs/`: `PRD.md` (scope), `PHASES.md` (numbered roadmap and status), `PLAN.md` (machine baseline), `DECISIONS.md` (decisions and open questions), `poc/` (proof-of-concept findings).
- Agent context lives in `.kiro/steering/`. Hooks live in `.kiro/hooks/` and are created with the `createHook` tool, never written by hand.

## What is committed

| Path | Committed? |
|---|---|
| `.kiro/steering/`, `.kiro/hooks/` | Yes. They are project rules and must be versioned with the code |
| `.kiro/settings/` | Only if it holds no secrets or machine-specific paths. Check before committing |
| `docs/`, source, tests, fixtures, `Cargo.lock` | Yes |
| `ltm/bin/ltm.py`, `ltm/config.json`, `ltm/manifest.json`, `ltm/README.md` | Yes |
| `ltm/store/`, `ltm/runtime/`, `ltm/reports/`, `ltm/snapshots/` | No (local memory; already in `.gitignore`) |
| `target/`, `.pumpkin-shell/` | No |

## Naming

| Kind | Convention | Example |
|---|---|---|
| Steering files | `kebab-case.md` | `detection-rules.md` |
| Top-level docs in `docs/` | `UPPERCASE.md` | `PRD.md`, `PHASES.md` |
| Rust crates | `pks-<name>` | `pks-core` |
| Rust modules and files | `snake_case.rs` | `policy_merge.rs` |
| Rule IDs | `AREA-NAME`, uppercase, from the PRD | `WS-AUTOAPPROVE` |
| Test fixtures | `tests/fixtures/<area>/<rule-id-lowercase>/` | `tests/fixtures/scan/ws-hidden-unicode/` |

## Working through phases

1. Start of a session: run `python3 ltm/bin/ltm.py files --limit 10` and read the status table in `docs/PHASES.md`.
2. Work on the lowest-numbered phase that isn't `done`. Do its numbered steps in order.
3. Before fixing an error, follow `troubleshooting.md` (search LTM first).
4. When a phase step finishes, make sure its tests pass before starting the next step.
5. When a phase finishes: update its status in `PHASES.md`, record decisions in `DECISIONS.md`, save an LTM checkpoint.
6. If scope changes: edit `PRD.md` first, then `PHASES.md`, then the affected steering file.

## Steering files

- One topic per file. Before adding a new file, check whether an existing one covers the topic and extend that instead.
- Domain files (detection rules, registry, Linux, Windows, policy, proxy, CLI, workspace integrity) summarize the PRD. They start with a "Source of truth" line. When they disagree with the PRD, the PRD wins and the steering file gets fixed.
- Only write facts that have been verified (docs, code, or a command run on this machine). Mark anything unverified with `*`, as the PRD does.
- Front-matter: `inclusion: always` for project-wide rules; `inclusion: auto` with `name` and `description` for topic files; `inclusion: fileMatch` with `fileMatchPattern` for file-type rules.

## Git

- Small commits, one logical change each. Run the checks in `tech.md` before committing Rust code.
- Branch strategy and commit-message format are not decided yet. Use plain imperative commit messages ("Add doctor kernel check") until a convention is recorded in `DECISIONS.md`.
- Never commit secrets. The LTM store is local-only for that reason.
