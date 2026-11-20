---
inclusion: auto
name: detection-rules
description: "Detection rule IDs, severities and actions from PRD FR-DET. Activates when implementing or reviewing detection rules, alerts, findings or severities."
---

Source of truth: PRD §7 FR-DET (#[[file:docs/PRD.md]]). If this file and the PRD disagree, the PRD wins; fix this file.

## Enforcement vs detection

- **Enforcement** comes from removed capabilities: no credentials in the sandbox, no network except the proxy, protected paths staged, read-only IDE install. These are what actually stop an attack.
- **Detection** rules raise alerts. Argument and command matching (all `EXEC-*` rules) is detection only and is never the security boundary (PRD §4 principle 1). Those rules can be evaded, so the real control is that credentials and network are absent (PRD §11).
- Never implement an `EXEC-*` rule as "block the command". It alerts at its severity; CRITICAL triggers the configured CRITICAL action (default: pause the sandbox).

## Rules

"Action" is the rule-specific action from the PRD. "Alert only" means the rule raises an alert at its severity and has no extra action. CRITICAL rules additionally trigger the configured CRITICAL action (default pause).

| Rule ID | Trigger | Severity | Action |
|---|---|---|---|
| REG-MALWARE | Package version has an OSV `MAL-` advisory | CRITICAL | Block |
| REG-INTEGRITY | Tarball/wheel hash differs from `dist.integrity` / sha256 | CRITICAL | Block |
| REG-TOO-NEW | Package first released < 30 days ago, or lockfile pins a version inside the cooldown | HIGH | Block, with explanation |
| REG-COOLDOWN | Version < 72 h old | INFO | Version hidden; previous version resolves |
| REG-HALLUCINATED | Package name returns 404 | WARN | Alert only |
| REG-TYPOSQUAT | Normalized name within edit distance 1 (≥ 5 chars) or 2 (≥ 10 chars) of a popular package | WARN | Alert only. Block only when also young or low-download |
| REG-DIRECT-BYPASS | Direct connection to a real registry host | HIGH | Block |
| NET-UNKNOWN-DOMAIN | Domain not in allowlist | WARN | Ask (hold 20 s); deny when headless |
| NET-PRIVATE-IP | Destination resolves to private, link-local or metadata address | HIGH | Block |
| NET-DIRECT-CONNECT | Connection that bypasses the proxy | WARN | Alert with fix hint (e.g. `host_ports = [5432]`) |
| NET-LARGE-UPLOAD | > 10 MB uploaded to a non-model-API host | WARN | Alert only |
| NET-HOST-PORT | Connection relayed to a host port listed in `[network] host_ports` | NOTICE | Logged |
| NET-DECOY-EGRESS | A decoy marker leaves the sandbox | CRITICAL | Alert (CRITICAL action applies) |
| FS-DECOY-READ | A decoy file is read | HIGH | Alert only |
| WS-PROTECTED-WRITE | Write to a protected path | HIGH | Staged for review |
| WS-AUTOAPPROVE | `chat.tools.autoApprove`, MCP `autoApprove: ["*"]`, new MCP server, new Kiro command hook | CRITICAL | Staged, pause |
| WS-HIDDEN-UNICODE | Tag chars U+E0000–U+E007F, bidi controls, zero-width chars | HIGH | Alert only (`scan --ci` fails) |
| WS-WATCHED-CHANGE | Change to a watched path, held in staging | HIGH | Held for review |
| WS-MCP-SERVER | Static `scan`: an MCP server is configured (inventory) | NOTICE | Listed; never fails `--ci` by default |
| WS-KIRO-HOOK | Static `scan`: a Kiro hook runs a shell command | WARN | Alert only |
| WS-FOLDER-OPEN-TASK | `.vscode/tasks.json` task with `runOn: folderOpen` | HIGH | Alert only (`scan --ci` fails) |
| WS-YARNPATH | `.yarnrc.yml` sets `yarnPath` | HIGH | Alert only (`scan --ci` fails) |
| WS-GIT-HOOK | `core.hooksPath`, `core.fsmonitor` program, config `include`, or an executable file in `.git/hooks` | HIGH | Alert only (`scan --ci` fails) |
| WS-ADS | Windows: NTFS alternate data stream (not `Zone.Identifier`) | HIGH | Alert only (`scan --ci` fails) |
| WS-SECRET-WRITTEN | Secret written into the repo | HIGH | Alert only |
| WS-MASS-DELETE | > 50 files or > 20% of tracked files deleted | HIGH | Alert with restore hint |
| EXEC-AGENT-YOLO | AI CLI with skip-permission flags from a non-interactive parent | CRITICAL | Alert (CRITICAL action applies). Detection only |
| EXEC-DESTRUCTIVE | `terraform apply -auto-approve` / `destroy`, `kubectl delete`, `aws … delete-*`, `git push --force`, `DROP` / `TRUNCATE` | HIGH | Alert only. Detection only |
| EXEC-RECON | Credential searches, trufflehog | HIGH | Alert only. Detection only |
| WIN-PERSIST | schtasks, Run keys, startup folder, WMI process create | HIGH | Alert; cleaned at session end |
| SYS-IDE-TAMPERABLE | IDE install files writable by non-root / non-admin | HIGH | Reported by `doctor` and at launch |
| SBX-MONITOR-LOST | Auditing supervisor died | CRITICAL | Session killed (fail closed) |
| POL-UNTRUSTED | Repo policy tries to loosen a rule | WARN | Loosening ignored |

## Severity routing (PRD FR-NOTIFY)

| Severity | Where it goes |
|---|---|
| INFO, NOTICE | Log and session summary |
| WARN | `pumpkin-shell watch` (tray or terminal panel) |
| HIGH | Desktop notification (`notify-send` / Windows toast) |
| CRITICAL | Also webhook (Slack, Discord, JSON) plus the configured action; default **pause** (SIGSTOP on Linux, suspend job processes on Windows) until `resume` or `kill` |

- Deduplicate by rule + target; at most one desktop notification per 10 s.
- Every block message names the policy line that would allow it (PRD §2 adoption rule).

## Implementation rules

- Rules are data: rule ID, severity, action, fix hint. `scan`, the watcher and the proxy share one engine (`pks-core`).
- Rule IDs are stable once published. Never rename one; add a new ID instead.
- Each rule gets one fixture under `tests/fixtures/` and, for runtime rules, an escape test in the published corpus.
