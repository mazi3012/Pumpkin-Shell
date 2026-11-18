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

## One phase, one PR (user rule, non-negotiable)

1. **One phase at a time.** Build only the current phase from `docs/PHASES.md`. Don't start the next phase until the user has reviewed and merged the current phase's PR.
2. **One branch per phase**, created from an up-to-date `main`: `phase-<N>-<short-name>` (e.g. `phase-2-workspace-skeleton`). Never commit or push directly to `main`.
3. **Test everything before opening the PR.** All of these must pass, with no skipped or ignored tests:
   - every item in the phase's **Done when** list, checked by actually running it;
   - every numbered step of the phase has tests that cover it;
   - `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`, `cargo deny check`, `cargo audit`;
   - CI is green on every runner, once CI exists;
   - **No sensitive data in any file or commit history:** no real credentials, API keys, tokens, .env files with real values, private keys, or personal information;
   - **Every new dependency has been vetted:** checked for latest stable, scanned for CVEs, verified as maintained and secure, and justified in the commit or `docs/DECISIONS.md`.
   If anything fails, fix it before opening the PR. If something truly can't be tested on this machine (e.g. Windows-only code), say so in the PR description; don't claim it passed.
4. **One PR per phase.** Push the branch and open exactly one PR. PR description: phase number and name, what changed, the Done-when checklist with the result of each item, the test and check output, and anything not verified.
5. **Stop and wait.** After opening the PR, tell the user it's ready for review and stop. Don't start the next phase and don't open another PR.
6. **Never merge without explicit permission.** Do not merge, squash, rebase-merge, approve, enable auto-merge, or push to `main`, even if CI is green and the review looks done. Merge only when the user explicitly says to merge **that specific PR** in the current conversation. Permission for one PR does not carry over to any other PR. If unsure, ask.
7. Review feedback goes into new commits on the same branch. Never force-push a branch that is under review unless the user asks.
8. After the user merges: update `main`, set the phase to `done` in `PHASES.md` (in the next phase's branch), save an LTM checkpoint, then start the next phase.

## Existing rules are binding (user rule)
- Never override, weaken or bypass rules from `.kiro/steering/` or `.kiro/hooks/`.
- If a request conflicts with a steering or hook rule, stop and ask the user before acting.
- Hooks are created only with the `createHook` tool. Don't edit hook files by hand.

## Phase status (user rule)
- When a phase's Done-when checks pass, update its row in `docs/PHASES.md` in the same commit.
- Mark `done` only with a green signal: local checks passing, and CI green for phases that need CI. Otherwise use `in-review (PR #n)` or `in-progress`.
- Check earlier phases against their Done-when list too, and fix any status that is out of date.

## Git

- Small commits, one logical change each, inside the phase branch. Run the checks in `tech.md` before committing Rust code.
- Commit messages: plain imperative ("Add doctor kernel check").
- Never commit secrets. The LTM store is local-only for that reason.
