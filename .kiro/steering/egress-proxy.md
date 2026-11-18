---
inclusion: auto
name: egress-proxy
description: "Egress proxy configuration for sandboxed IDE sessions. Activates when network connections are attempted."
---

## Allowlist Rules

| Type | Format | Example | Allowed? |
|------|--------|---------|----------|
| Exact host:port | `host:port` | `api.openai.com:443` | ✓ |
| Wildcard over shared cloud | `*.amazonaws.com:443` | ✗ (rejected) |

**Rule:** Wildcards over shared cloud domains are rejected (too permissive).

## DNS Handling

- Proxy resolves DNS itself (not sandboxed IDE)
- Private IPs blocked
- Link-local IPs blocked
- Metadata IPs blocked (e.g., `169.254.169.254`)

## Unknown Domain Behavior

| Mode | Action |
|------|--------|
| **Ask** | Connection held 20s, notification prompts allow/deny/always |
| **Headless** | Default to deny |

## Network Rules

| Rule | Severity | Action |
|------|----------|--------|
| NET-UNKNOWN-DOMAIN | WARN | Ask (20s hold) |
| NET-PRIVATE-IP | HIGH | Block |
| NET-DIRECT-CONNECT | WARN | Logged with fix hint |
| NET-LARGE-UPLOAD (>10MB to non-API) | WARN | Logged |

## Host Ports

Optional relays to host services:

```toml
[host_ports]
5432 = { description = "PostgreSQL", logged = "NOTICE" }
3306 = { description = "MySQL", logged = "NOTICE" }
```

- Logged as NOTICE (not WARN)
- User must configure in policy
- Not enabled by default

## Upload Byte Counters

Per-host tracking:
- Log at INFO level
- Alert if exceeds threshold (e.g., >10MB to non-API host)

## Proxy Architecture

```
Sandboxed IDE → Proxy Unix Socket → Proxy Process → Host Network
```

- Proxy process runs on host (trusted)
- IDE cannot bypass proxy
- All DNS resolution inside proxy

## Fix Hints

When NET-DIRECT-CONNECT is detected:
```
ERROR: Direct network connection blocked
HINT: Configure proxy in .kiro/settings/mcp.json:
  "mcpServers": {
    "example": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-xyz"],
      "env": {
        "HTTPS_PROXY": "http://127.0.0.1:PORT"
      }
    }
  }
```

## Domain Configuration

IDE profiles contain exact allowed domains:
- Kiro: From Kiro docs, confirmed in monitor mode
- VS Code: From VS Code docs, confirmed in monitor mode
- Cursor: From Cursor docs, confirmed in monitor mode
- Windsurf: From Windsurf docs, confirmed in monitor mode
