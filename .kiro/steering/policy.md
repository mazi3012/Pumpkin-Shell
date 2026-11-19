---
inclusion: auto
name: policy
description: "Policy configuration and enforcement for Pumpkin-Shell. Activates when policy is referenced or edited."
---

## Policy Files

| File | Location | Visible in Sandbox? | Purpose |
|------|----------|---------------------|---------|
| User policy | `~/.config/pumpkin-shell/policy.toml` | No | Global user settings |
| Repo policy | `pumpkin-shell.toml` (in repo) | Yes | Repo-specific overrides |

## File format (version 1)
Source of truth: PRD FR-POL. The code is `crates/pks-core/src/policy.rs`.
```toml
version = 1                          # required
mode = "enforce"                     # or "monitor": log instead of block
[rules."NET-UNKNOWN-DOMAIN"]
action = "block"                     # "alert" < "ask" < "block"
```
- Only the rules in `CONFIGURABLE_RULES` can be set (the NET-* and REG-* rules). Others, including every `EXEC-*` rule, are rejected. Unknown keys are rejected.
- The user policy may set anything. The repo policy may only raise `mode` toward `enforce` and rule actions toward `block`.
- More fields (domains, paths, upload limits, secrets) are added in the phase whose code reads them.

## IDE Profiles

Paths, exact domains, and env keys for each IDE:

| IDE | Settings Paths | Env Keys | Domains |
|-----|----------------|----------|---------|
| Kiro | `~/.kiro/settings`, `.kiro/settings` | `KIRO_*` | From Kiro docs |
| VS Code | `~/.vscode/settings`, `.vscode/settings` | `VSCODE_*` | From VS Code docs |
| Cursor | `~/.cursor/settings`, `.cursor/settings` | `CURSOR_*` | From Cursor docs |
| Windsurf | `~/.windsurf/settings`, `.windsurf/settings` | `WINDSURF_*` | From Windsurf docs |

## Monitor Mode vs Enforce Mode

| Mode | Behavior | Use Case |
|------|----------|----------|
| **Monitor** | Log violations, no blocking | First deployment, learning phase |
| **Enforce** | Block and notify | Production |

## Policy Commands
| Command | Purpose |
|---------|---------|
| `pumpkin-shell trust [PATH]` | Pin the SHA-256 of the repo's `pumpkin-shell.toml` |
| `pumpkin-shell policy check [PATH]` | Print the effective policy and its hash; exit 1 when the repo policy is not applied or loosens something |
| `pumpkin-shell policy suggest` | Turn monitor logs into allow rules (later phase) |
| `pumpkin-shell review` | View policy violations (later phase) |

## Policy Merge Rules
1. The user policy loads first, on top of built-in defaults (the PRD FR-DET table).
2. The repo policy is applied only when its exact SHA-256 is pinned. Unpinned or changed: ignored, `POL-UNTRUSTED`.
3. A repo entry that would loosen a setting is ignored and reported as `POL-UNTRUSTED` (WARN). The rest of the file still applies.
4. An untrusted repo policy is never parsed.

## Trust pins
Pins are stored in the host data dir (`trusted-policies.toml`, mode 0600), keyed by the repo's canonical path. They are never stored in the repo: whoever can edit the policy could edit its pin. Moving the repo, or changing one byte of the policy, means running `trust` again.

## Policy Changes Workflow
1. User edits `pumpkin-shell.toml`.
2. `pumpkin-shell policy check` shows what would apply and what would be ignored.
3. `pumpkin-shell trust` pins the hash.
4. During a session the policy is read-only; the next session loads the new one.
5. Policy changes are recorded in the signed log with the policy hash.
