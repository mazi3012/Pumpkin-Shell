# Pumpkin-Shell: repository structure

Planned layout (create pieces as tasks need them; do not scaffold empty crates early):

```
Pumpkin-Shell/
├── Cargo.toml              # workspace
├── crates/
│   ├── pks-cli/            # binary `pumpkin-shell` (clap commands)
│   ├── pks-core/           # policy, events, rule/finding types, severity, receipts
│   ├── pks-scan/           # static workspace scanner (`pumpkin-shell scan`)
│   ├── pks-sandbox/        # SandboxBackend trait; linux/ and windows/ modules
│   ├── pks-proxy/          # egress proxy + relay
│   ├── pks-registry/       # npm/PyPI mirror, cooldown, OSV, typosquat
│   ├── pks-detect/         # detection engine, watcher, notifications
│   └── pks-ide/            # Code-OSS adapter + IDE profiles (data files)
├── profiles/               # IDE profile TOML (paths, exact domains, env keys)
├── tests/fixtures/         # one fixture per rule
├── docs/
│   ├── PRD.md              # canonical spec
│   ├── DECISIONS.md        # decisions + open questions
│   ├── PLAN.md             # current plan + machine baseline
│   └── poc/                # proof-of-concept findings
└── .kiro/steering/         # these context files
```

- Crate prefix `pks-`; binary name `pumpkin-shell` (pending spelling confirmation, DECISIONS Q1).
- Rule IDs follow the PRD (e.g. `WS-AUTOAPPROVE`, `NET-PRIVATE-IP`) and are stable once published.
