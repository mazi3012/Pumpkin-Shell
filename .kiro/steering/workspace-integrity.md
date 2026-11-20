---
inclusion: auto
name: workspace-integrity
description: "Workspace integrity protection for sandboxed IDE sessions. Activates when file writes occur or when reviewing protected paths."
---

## Protected Paths (Staged for Review)

These paths are bind-mounted from a staging copy on Linux or have deny-write ACLs on Windows. Changes go through review.

| Path | Description |
|------|-------------|
| `.git/hooks` | Git hooks (can execute arbitrary code) |
| `.git/config` | Git configuration |
| `core.hooksPath` target | Custom hooks directory |
| `.envrc` | Direnv environment loader |
| `.yarnrc.yml` | Yarn configuration |
| `.npmrc` | npm configuration |
| `.vscode/` | VS Code settings (auto-approve risk) |
| `.cursor/` | Cursor settings |
| `.windsurf/` | Windsurf settings |
| `.kiro/settings` | Kiro settings |
| `.kiro/hooks` | Kiro hooks (command execution risk) |
| `.mcp.json` | MCP configuration (auto-approve risk) |
| `pumpkin-shell.toml` | Policy configuration |
| IDE user-level `settings.json` | IDE settings in sandboxed home |
| IDE user-level `mcp.json` | MCP config in sandboxed home |

## Watched Paths (Editable, Always Shown in Review)

Changes are logged and shown in review but not blocked.

| Path | Description |
|------|-------------|
| `.github/workflows` | CI/CD workflows |
| `package.json` scripts and git/URL deps | Package scripts |
| `Makefile` | Build scripts |
| `Dockerfile` | Container definitions |
| `.devcontainer` | Dev container config |
| `conftest.py` | Policy tests |
| `setup.py` | Python setup |
| `.pre-commit-config.yaml` | Pre-commit hooks |
| `.kiro/steering` | Steering files |
| `AGENTS.md` | Agent instructions |
| `.cursorrules` | Cursor rules |
| Windows `*.lnk` | Shortcuts |
| Windows `desktop.ini` | Folder settings |
| Windows NTFS alternate data streams | ADS |

## Snapshot/Restore Workflow

1. **Snapshot before launch**: Working tree (including untracked non-ignored files) committed via temporary index
2. **Bundle to data dir**: Stored for recovery
3. **Recovery**: `pumpkin-shell restore <sid>`

## Decoy Files

Fake credentials placed in sandboxed home to detect exfiltration:

| File | Marker | Detects |
|------|--------|---------|
| `~/.ssh/id_ed25519` | Unique marker | SSH credential theft |
| `~/.aws/credentials` | Unique marker | AWS credential theft |
| `~/.config/gh/hosts.yml` | Unique marker | GitHub token theft |

## Decision: Protected vs Watched

- **Protected**: Files that execute later on host or contain secrets
- **Watched**: Files that influence behavior but don't execute directly

## Review Flow
1. Write to a protected path -> goes to the staged copy, `WS-PROTECTED-WRITE` is raised at session end
2. The staged copy is kept in `<data>/sessions/<sid>/staging/`
3. `pumpkin-shell review` (Phase 11) will show staged writes and let the user approve or reject; until then the user copies what they accept by hand
4. The repo itself is never written by the sandbox for these paths
