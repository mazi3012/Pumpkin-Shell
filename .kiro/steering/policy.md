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

## User Policy (`~/.config/pumpkin-shell/policy.toml`)

Never visible inside the sandbox. Defines global behavior:

```toml
# Example user policy
[secrets]
block_on_write = true

[network]
default_action = "ask"  # or "deny", "allow"

[domains]
"api.openai.com" = { action = "allow", upload_limit_mb = 100 }
"github.com" = { action = "allow" }

[paths]
allowed = [
  "~/.local/bin",
  "/usr/local/bin",
]

[monitor]
enabled = false  # Set to true for logging-only mode
```

## Repo Policy (`pumpkin-shell.toml`)

Can only **tighten** rules (never loosen). Hash-pinned to prevent tampering.

```toml
# Example repo policy
[secrets]
block_on_write = true  # Must be true or omitted

[network]
default_action = "deny"  # Stricter than user policy

[domains]
"api.openai.com" = { action = "allow", upload_limit_mb = 50 }  # Stricter limit

[paths]
allowed = [
  "~/.local/bin",
]  # Stricter than user policy

# Hash of this file (auto-generated, never edit manually)
trust = "sha256:abc123..."
```

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
| `pumpkin-shell policy suggest` | Turn monitor logs into allow rules |
| `pumpkin-shell trust` | Pin repo policy hash |
| `pumpkin-shell review` | View policy violations |

## Policy Merge Rules

1. User policy loads first (global defaults)
2. Repo policy merges on top (tighten-only)
3. If repo policy loosens a rule, the merge is rejected
4. Each merge is logged and signed

## Policy Changes Workflow

1. User edits `pumpkin-shell.toml`
2. `pumpkin-shell trust` calculates hash and pins
3. During session, policy is read-only
4. On next session, new policy loads
5. Changes are tracked in signed log
