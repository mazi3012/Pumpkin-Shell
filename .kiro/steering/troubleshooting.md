---
inclusion: auto
name: troubleshooting
description: "Troubleshooting and bug patterns. Activates when the user reports an error, bug, or failure, or when about to implement a fix."
---

## Before implementing a fix

1. Check `troubleshooting.md` for this error pattern
2. Search `ltm/store/events.jsonl` for recent failures (last session)
3. Search `ltm/store/checkpoints.jsonl` for previous attempts
4. Run `python3 ltm/bin/ltm.py search "<error-message-or-keyword>"`

If a prior attempt or similar issue exists, reference it before proceeding.

## Common patterns to check

| Error type | Search term | Related files |
|------------|-------------|---------------|
| Build error | "build", "compile", "npm run build", "cargo build" | `build/`, `target/`, `node_modules/.cache/` |
| Runtime error | "RuntimeError", "TypeError", "KeyError", "NoneType" | `ltm/store/events.jsonl` |
| Git error | "dubious ownership", "Permission denied", "refusing to merge" | `.git/config`, `safe.directory` |
| Hook failure | "hook", "pre-commit", "pre-push" | `.kiro/hooks/` |
| MCP server error | "MCP", "connection refused", "uvx" | `.mcp.json`, `~/.kiro/settings/mcp.json` |
| Path error | "No such file", "ENOENT", "path not found" | Workspace root, relative paths |

## Known issues on this project

Add a row whenever a problem took more than one attempt to solve. Newest first.

| Date | Symptom | Cause | Fix |
|---|---|---|---|
| 2026-11-19 | `cargo install cargo-audit` looks stuck; a wait loop times out; then `error: no such command: audit` | Not stuck. cargo-audit compiles ~400 crates (the `gix` git library), which takes 10+ minutes on this 4-core machine. The foreground command was killed by the tool timeout before it finished | Run long `cargo install` / `cargo build` as a background process (`control_bash_process`) writing to a log file with an `EXIT $?` marker, then poll the log. Cargo reuses finished crates, so re-running is cheap |
| 2026-11-19 | `cargo: command not found` in a new shell | rustup puts tools in `~/.cargo/bin`, which isn't on PATH until the shell profile is reloaded | `. "$HOME/.cargo/env"` before cargo commands |
| 2026-11-19 | `sed`/`xargs` fails on `prd v1.md` | File name contains a space | Use `grep -lZ … \| xargs -0` |

## Fix checklist

When implementing a fix, ensure:

1. **Root cause identified** — not just symptoms
2. **Test or verification step added** — to catch recurrence
3. **Log or checkpoint updated** — "python3 ltm/bin/ltm.py checkpoint --summary 'Fix: <description>'"
4. **Troubleshooting.md updated** — if the issue is novel

## Example: Duplicate fix prevention

**User reports:** "The build is failing with 'No module named xyz'"

**Search history:**
```bash
python3 ltm/bin/ltm.py search "No module named"
```

**If found in recent session:**
- Reference the checkpoint or fix that was attempted
- Check if dependencies were added to `requirements.txt`/`Cargo.toml`
- Verify the environment matches the fix (virtualenv, virtualenv, etc.)

**If not found:**
- Proceed with the fix
- After successful fix, record: "python3 ltm/bin/ltm.py checkpoint --summary 'Fix: No module named xyz — added xyz to requirements.txt'"
