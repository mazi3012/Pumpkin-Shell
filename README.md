# Pumpkin-Shell

**Use an AI coding IDE in full auto-approve mode without giving it your
machine.**

Pumpkin-Shell opens your project in an IDE such as Kiro inside a sandbox. The
AI in the IDE can read and change the project, but it cannot reach your SSH
keys, cloud logins, host files outside the project, or the internet except
through a checked proxy.

Version 1.0.0 supports **Linux** and **Kiro**. Windows, VS Code, Cursor and
Windsurf come after the first release.

License: MIT (see [LICENSE](LICENSE)).

---

## What it is, in plain words

AI coding tools can run commands, install packages and edit files. Most of the
time that is what you want. Sometimes a README, a package, or a prompt
injection makes the tool do something harmful, such as:

- reading `~/.ssh` or `~/.aws` and sending the keys out,
- turning on "auto-approve" for itself by editing its settings file,
- installing a package whose install script steals tokens,
- running `terraform destroy` on your real infrastructure.

Pumpkin-Shell takes away what the tool needs to do that harm, and tells you
about what it tried.

## Who it is for

- **Solo developers and startups** who use an AI IDE with auto-approve and are
  afraid of a deleted folder or a leaked `.env` file.
- **DevOps engineers** whose IDE sits next to `kubectl`, `terraform` and
  `~/.aws`.
- **Security leads** who want a record of what the AI tried to do.

## What it does for you

| You get | In plain words |
|---|---|
| A sandbox | The IDE runs where it cannot see your home folder, SSH agent, Docker socket or D-Bus session. |
| A network gate | Only the hosts on the allowlist are reachable. Unknown hosts ask you first (for 20 seconds), and are refused when no one can answer. |
| A package guard | npm and PyPI installs go through a local mirror. New versions wait 72 hours, packages younger than 30 days are blocked, known malware is refused, and tarballs are checked against their published hashes. Install scripts are off. |
| Staged changes | Protected files (such as `.envrc`, `.vscode/`, `.git/hooks`) are not written directly. You review each change with `pumpkin-shell review`. |
| Alerts | Decoy credentials, risky commands, direct network attempts and auto-approve settings raise alerts. A CRITICAL alert pauses the session. |
| A signed log | Every decision goes into a log that is hash-chained and signed. `pumpkin-shell log verify` checks that nothing was edited. |
| Snapshots | The project is snapshotted before the IDE starts. `pumpkin-shell restore` brings it back. |

## What it does not do

- It does not make the AI's code correct.
- It does not stop you from running code it produced after you leave the
  sandbox.
- It does not protect data sent to a domain you allowed (for example the AI
  model's own API).
- It does not run on macOS, and Windows comes later.
- It is not a replacement for antivirus or an EDR product.
- Escape claims are measured, not promised. See
  [docs/ESCAPE-CORPUS.md](docs/ESCAPE-CORPUS.md): 32 of 32 attacks pass on
  corpus v1, on Linux.

---

## Install

### Requirements

| Need | Why | How to get it |
|---|---|---|
| Linux, x86_64 or ARM64, kernel 5.13 or newer (6.7 or newer recommended) | Landlock and seccomp | `uname -r` |
| `bubblewrap` 0.8 or newer | builds the sandbox | `sudo apt install bubblewrap` |
| `xserver-xephyr` and `xauth` | the IDE shows on a nested X display | `sudo apt install xserver-xephyr xauth` |
| Unprivileged user namespaces allowed | the sandbox runs without root | `pumpkin-shell doctor` tells you how to fix it |
| The IDE itself, for example Kiro | the program you protect | from [kiro.dev](https://kiro.dev/) |

Optional, for nicer alerts: `zenity` (popups), `xclip` (clipboard) and
`libnotify-bin` (desktop notifications).

The sandbox displays the IDE through X11. A Wayland desktop works only if
XWayland is running. This has not been tested yet.

### Quick install (Ubuntu, Debian, Linux Mint)

You need [cosign](https://github.com/sigstore/cosign/releases) to check the
download. Then run:

```sh
git clone https://github.com/mazi3012/Pumpkin-Shell.git
cd Pumpkin-Shell
packaging/install.sh 1.0.0
pumpkin-shell doctor
```

The script downloads the package and its signature, checks the signature, and
only then installs it with `apt` (it asks for your password). If the check
fails, nothing is installed. To check the download without installing, add
`--check-only`. Read the script first if you want to: it is short.

### Option 1: install the Debian package by hand (Ubuntu 24.04+, Debian 13+)

1. Download `pumpkin-shell_1.0.0_amd64.deb` from the
   [Releases page](https://github.com/mazi3012/pumpkin-shell/releases).
2. (Recommended) Check the signature, see [Verify the download](#verify-the-download).
3. Install it. `apt` also installs the dependencies:

   ```sh
   sudo apt install ./pumpkin-shell_1.0.0_amd64.deb
   ```

4. Check the machine:

   ```sh
   pumpkin-shell doctor
   ```

   Every line says PASS, WARN or FAIL. A FAIL line includes the fix to run.

### Option 2: install the RPM (Fedora 45 and later)

1. Download `pumpkin-shell-1.0.0-1.*.x86_64.rpm` from the
   [Releases page](https://github.com/mazi3012/pumpkin-shell/releases) and
   check its signature (see [Verify the download](#verify-the-download)).
2. Install it. `dnf` also installs the dependencies:

   ```sh
   sudo dnf install ./pumpkin-shell-1.0.0-1.*.x86_64.rpm
   pumpkin-shell doctor
   ```

### Ubuntu 24.04: if `doctor` says user namespaces are restricted

Ubuntu 24.04 blocks unprivileged user namespaces by default, so the sandbox
cannot start. The package ships an AppArmor profile that allows only this
permission. It is not installed automatically. Install it with root rights:

```sh
sudo install -m 0644 /usr/share/pumpkin-shell/apparmor/usr.bin.pumpkin-shell /etc/apparmor.d/usr.bin.pumpkin-shell
sudo apparmor_parser -r /etc/apparmor.d/usr.bin.pumpkin-shell
pumpkin-shell doctor
```

To remove it, run `sudo apparmor_parser -R /etc/apparmor.d/usr.bin.pumpkin-shell`
and delete the file. The profile does not confine the program. It only grants
the `userns` permission. The profile has been checked for syntax; it has not
yet been tested on a restricted Ubuntu 24.04 host.

### Option 3: build from source

The Rust version is pinned in `rust-toolchain.toml`. Install
[rustup](https://rustup.rs/) first, then:

```sh
git clone https://github.com/mazi3012/pumpkin-shell.git
cd pumpkin-shell
cargo build --release --locked -p pks-cli
sudo install -m 0755 target/release/pumpkin-shell /usr/local/bin/pumpkin-shell
pumpkin-shell doctor
```

### Verify the download

Each release is signed without a private key (keyless signing with
[Sigstore](https://www.sigstore.dev/)). The signature is tied to the release
workflow in this repository. Install `cosign`, then run:

```sh
cosign verify-blob \
  --bundle pumpkin-shell_1.0.0_amd64.deb.sigstore.json \
  --certificate-identity-regexp 'https://github.com/mazi3012/[Pp]umpkin-[Ss]hell/.github/workflows/release.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  pumpkin-shell_1.0.0_amd64.deb
```

Each release also has SLSA provenance, which says which workflow built the
package. The security model, its known risks and the measured escape corpus are
in [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) and
[docs/ESCAPE-CORPUS.md](docs/ESCAPE-CORPUS.md).

---

## Use it

Open a project in the sandboxed Kiro:

```sh
pumpkin-shell kiro ~/my-project
```

(`pumpkin-shell ide kiro ~/my-project` does the same.) VS Code, Cursor and
Windsurf are after the first release.

A window opens with Kiro. Watch the terminal you started it from: it prints
alerts, and it asks you when a site is not on the allowlist.

| Command | What it does |
|---|---|
| `pumpkin-shell doctor` | Checks that this machine can run the sandbox. |
| `pumpkin-shell scan [PATH]` | Scans a repo for setups that let an agent escape its folder. Use `--ci` in a pipeline. |
| `pumpkin-shell kiro [PATH]` | Opens the project in Kiro inside the sandbox. Same as `ide kiro`. |
| `pumpkin-shell ide kiro [PATH]` | The same, with the IDE name spelled out. |
| `pumpkin-shell watch` | Shows findings from running sessions (WARN and above). |
| `pumpkin-shell review SESSION` | Lists staged changes, then approve or reject each one. |
| `pumpkin-shell allow-write SESSION PATH` | Approves one staged change. |
| `pumpkin-shell allow DOMAIN` | Adds a domain to the allowlist in your policy. |
| `pumpkin-shell resume SESSION` / `kill SESSION` | Continues or stops a paused session. |
| `pumpkin-shell restore SESSION` | Writes the snapshot taken before the session. |
| `pumpkin-shell trust [PATH]` | Pins the repo's `pumpkin-shell.toml` after you have read it. |
| `pumpkin-shell policy check [PATH]` | Prints the effective policy for a repo, and fails if the repo policy is not applied or tries to loosen a rule. |
| `pumpkin-shell log verify FILE` | Checks a session log's chain, signatures and checkpoint. |
| `pumpkin-shell dashboard [--port N]` | Live read-only page on 127.0.0.1 (default 8765). |

Where things live:

- Your policy: `~/.config/pumpkin-shell/policy.toml`. The sandbox cannot see it.
- Sessions, snapshots and logs: `~/.local/share/pumpkin-shell/sessions/`.

---

## Live dashboard

```sh
pumpkin-shell dashboard          # then open http://127.0.0.1:8765/
```

Pumpkin-Shell Watch shows sessions, findings by severity, network blocks,
decoy reads, refused packages and each log's check, and refreshes every two
seconds. It listens on 127.0.0.1 only, is read-only, and loads nothing from the
internet. A tampered log is shown as failed.

![Pumpkin-Shell Watch](docs/dashboard.png)

## How it works

### The big picture

```mermaid
flowchart TB
  subgraph Host["Your computer: trusted"]
    CLI["pumpkin-shell ide kiro"] --> POL["Your policy"]
    CLI --> SNAP["Snapshot and staging"]
    PROXY["Egress proxy: exact hosts only"] --> ENG["Detection engine"]
    MIRROR["Package mirror: npm and PyPI"] --> PROXY
    BROKER["Brokers: open link, sign-in callback, git push"] --> ENG
    MON["Monitor: execve and connect"] --> ENG
    ENG --> LOG["Signed session log"]
    ENG --> ALERT["Desktop alerts and pause"]
  end
  subgraph SB["Sandbox: untrusted"]
    KIRO["Kiro IDE"] --> AGENT["AI agent, terminal, extensions, MCP servers"]
  end
  CLI --> SB
  SB -- "only route out" --> PROXY
  SB -- "package requests" --> MIRROR
  SB -- "open link or push" --> BROKER
  SB -- "program starts and connects" --> MON
```

### One session, step by step

```mermaid
sequenceDiagram
  autonumber
  actor You
  participant CLI as pumpkin-shell on the host
  participant SB as Sandbox
  participant K as Kiro
  You->>CLI: pumpkin-shell ide kiro project
  CLI->>CLI: take a snapshot of the project
  CLI->>CLI: protect sensitive files and plant decoy credentials
  CLI->>SB: start the sandbox with no host home, no SSH agent and no network
  SB->>CLI: hand the monitor's listener to the host
  SB->>K: start Kiro with Landlock and seccomp in place
  K->>CLI: ask to open a link, paste, or reach a host
  CLI-->>K: allow or deny by policy
  K-->>CLI: the session ends
  CLI->>CLI: keep staged changes for review and sign the log
```

### How the monitor decides

```mermaid
flowchart LR
  A["A program starts or connects"] --> B{"A watched call?"}
  B -- "no" --> Z["Runs unseen by the monitor"]
  B -- "yes" --> C["The host reads the arguments"]
  C --> D{"A rule matches?"}
  D -- "no" --> E["Call continues"]
  D -- "yes" --> F["Finding logged; CRITICAL pauses the session"]
  F --> E
```

The monitor only reports. It never blocks a call. What stops harm is that the
sandbox holds no credentials and only the proxy leads out.

### Where a network request goes

```mermaid
flowchart TD
  R["A request from inside the sandbox"] --> P{"Through the proxy?"}
  P -- "no" --> D1["Refused. NET-DIRECT-CONNECT is reported with a fix"]
  P -- "yes" --> H{"Host on the allowlist?"}
  H -- "yes" --> OK["Allowed"]
  H -- "no" --> Q{"Can you answer within 20 seconds?"}
  Q -- "yes" --> A["You allow once, allow for the session, or deny"]
  Q -- "no" --> N["Denied (headless)"]
```

### Packages

```mermaid
flowchart LR
  I["npm, pnpm, yarn, bun, pip, uv or poetry in the sandbox"] --> M["Local mirror"]
  M --> C{"Version older than 72 hours?"}
  C -- "no" --> HID["Hidden from the index"]
  C -- "yes" --> AGE{"Project older than 30 days?"}
  AGE -- "no" --> BLK["Blocked, REG-TOO-NEW"]
  AGE -- "yes" --> MAL{"Known malware (OSV MAL-)?"}
  MAL -- "yes" --> BLK2["Refused, REG-MALWARE"]
  MAL -- "no" --> HASH{"Hash matches the registry?"}
  HASH -- "no" --> BLK3["Refused, REG-INTEGRITY"]
  HASH -- "yes" --> OK2["Served. Install scripts are off"]
```

---

## Status

| Phase | What | Status |
|---|---|---|
| 1 to 4 | Dev setup, workspace, `doctor`, `scan` | done |
| 5 to 12 | Linux sandbox, policy and log, proxy, workspace integrity, alerts and review, brokers | done |
| 14 | npm and PyPI mirror, seven clients tested through it | done |
| 15 | Exec and connect monitor | done |
| 18 | v1.0 release: corpus, signed packages, threat model | done (v1.0.0) |
| 19 | Live local dashboard (Pumpkin-Shell Watch) | done |
| 6, 13, 16, 17 | Windows and other IDEs | after the first release |

The decisions and their reasons are in [docs/DECISIONS.md](docs/DECISIONS.md).
The full design is in [docs/PRD.md](docs/PRD.md). The roadmap is in
[docs/PHASES.md](docs/PHASES.md).

## Develop

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked --workspace
cargo deny check
scripts/escape-corpus.sh
```

The sandbox tests run real `bwrap`, `Xephyr` and `curl` sandboxes. Some of
them reach the public registries, so they need internet access.

## Security

Please report a vulnerability privately to the maintainer rather than in a
public issue. Contact details will be added before the release.

## License

MIT. See [LICENSE](LICENSE).
