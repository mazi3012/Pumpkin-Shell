---
inclusion: auto
name: windows
description: "Windows sandbox backend for Pumpkin-Shell. Activates when Windows-specific configurations are referenced."
---

## Architecture

| Component | Setting |
|-----------|---------|
| Sandbox user | `pks-sandbox` (local non-admin) |
| Service | `Pumpkin-Shell Service` (LocalSystem, signed) |
| Installation | Admin once (MSI), none per session |

## Repo Access

| Step | Action |
|------|--------|
| Session start | Service grants `pks-sandbox` modify rights on repo |
| Session end | Service revokes rights, resets ownership |
| Git config | Service sets `safe.directory` (prevents "dubious ownership" error) |

## Protected Paths

Deny-write ACE for `pks-sandbox` on:
- `.git/hooks`
- `.kiro/hooks`
- `.kiro/settings`
- Similar paths

`pks-sandbox` cannot remove these (doesn't own them).

## Network

- WFP filters keyed to `pks-sandbox` SID
- Allow outbound only to loopback proxy port
- Everything else (including DNS) blocked
- Log as NET-DIRECT-CONNECT

## Process Lifetime

| Component | Enforcement |
|-----------|-------------|
| Normal tree | Job Object with kill-on-close |
| Session end | Service kills `pks-sandbox` processes |
| Persistence | Scheduled tasks, Run keys, startup items removed |

### WMI/COM/Task Scheduler Escapes

- Flagged when detected
- Removed at session end

## Auditing

| Event | Source |
|-------|--------|
| Process creation | ETW `Microsoft-Windows-Kernel-Process` |
| Network | WFP audit events |

## Brokers

| Type | Mechanism |
|------|-----------|
| HTTP(S) proxy | Named pipe (service + sandbox user only) |
| OAuth callback | Loopback (inbound only) |
| URL open | Named pipe |

## Known Risk: Shared Desktop

| Issue | Description |
|-------|-------------|
| Clipboard | Sandbox can read |
| Screen capture | Sandbox can capture |
| Keyboard hooks | Low-level hooks possible |

**Mitigation:** Documented publicly. Separate desktop or VM mode is v2.

## Persistence Cleanup

| Path | Action |
|------|--------|
| `schtasks` | Removed at session end |
| Run keys (HKCU) | Removed at session end |
| Startup folder | Removed at session end |

## Doctor Checks

| Check | Tool/Method |
|-------|-------------|
| Service | `sc query PumpkinShellService` |
| Sandbox user | `net user pks-sandbox` |
| WFP filters | `netsh wfp show filters` |
| Job Object | Verify processes stay within |

## Filesystem ACLs

```powershell
# Example: Deny write to .kiro/hooks
$acl = Get-Acl "$repo\.kiro\hooks"
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "pks-sandbox", "Write", "ContainerInherit,ObjectInherit", "None",
    "Deny"
)
$acl.AddAccessRule($accessRule)
Set-Acl "$repo\.kiro\hooks" $acl
```

## Windows Version Support

| Version | Architecture | Notes |
|---------|--------------|-------|
| Windows 10 | x64, ARM64 | |
| Windows 11 | x64, ARM64 | |
