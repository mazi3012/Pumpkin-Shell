---
inclusion: auto
name: cli
description: "Pumpkin-Shell CLI reference. Activates when CLI commands are discussed."
---

## Commands

| Command | Purpose |
|---------|---------|
| `doctor` | Check system prerequisites (bwrap, AppArmor, Landlock, seccomp, service, WFP) |
| `init` | Initialize repo with `pumpkin-shell.toml` |
| `ide <kiro\|code\|cursor\|windsurf> [path]` | Launch IDE in sandbox |
| `ide import <ide>` | Import settings + extensions (never tokens) |
| `watch` | Monitor alerts in real-time |
| `allow <rule-id>` | Add rule to user policy |
| `allow-write <path>` | Allow protected path write |
| `resume` | Resume after CRITICAL pause |
| `kill` | Terminate session |
| `review` | Review blocks, staged writes, watched-file diff |
| `restore <sid>` | Restore snapshot from session |
| `scan [--ci]` | Scan workspace for issues |
| `trust` | Pin repo policy hash |
| `policy suggest` | Turn monitor logs into allow rules |
| `log [verify]` | View or verify signed log |

## Common Workflows

### First Run

```bash
pumpkin-shell doctor
pumpkin-shell init
pumpkin-shell ide kiro .
```

### Monitoring

```bash
# Terminal 1: Watch alerts
pumpkin-shell watch

# Terminal 2: Review
pumpkin-shell review
```

### Handling Blocks

```bash
# Review blocks
pumpkin-shell review

# Allow a blocked rule
pumpkin-shell allow NET-UNKNOWN-DOMAIN

# Allow a blocked write
pumpkin-shell allow-write .kiro/settings/mcp.json

# Resume after pause
pumpkin-shell resume
```

### Recovery

```bash
# List sessions
ls ~/.config/pumpkin-shell/sessions/

# Restore from session
pumpkin-shell restore sess_2024_11_19_01
```

### CI Integration

```bash
# Scan with exit code
pumpkin-shell scan --ci

# Exit codes:
# 0 = clean
# 1 = issues found
# 2 = error
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Issues found (scan only) |
| 2 | Error |

## Configuration Files

| File | Location |
|------|----------|
| User policy | `~/.config/pumpkin-shell/policy.toml` |
| Repo policy | `pumpkin-shell.toml` (repo root) |
| Session data | `~/.config/pumpkin-shell/sessions/` |
| Log | `~/.config/pumpkin-shell/log.jsonl` |

## Auto-Complete

Shell completions available for:
- Bash
- Zsh
- Fish

Run `pumpkin-shell completion <shell>` to install.
