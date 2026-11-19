# Linux PoC: Kiro in bubblewrap (Phase 5)

Script: `scripts/poc/linux-kiro.sh`. It starts an IDE in a bubblewrap sandbox on a nested X server (Xephyr) with no network. `--check` runs 23 isolation probes inside the sandbox and exits 1 if any fails.

Tested 2026-11-19 on Linux Mint 22.3, kernel 7.0.0-43, bubblewrap 0.9.0, Xephyr 21.1.12 (`xserver-xephyr 2:21.1.12-1ubuntu1.9`), Kiro 1.4.178, VS Code 1.146.0. Everything below was run on this machine. Items marked **not tested** were not.

## Result against the Done-when list

| Done when | Result |
|---|---|
| Kiro opens the repo and edits a file | **Partly met.** Kiro starts and opens a window titled `workspace - Kiro`, but its first screen is a **Sign in** gate (screenshot taken), so the editor cannot be used. The sandbox has no network, and sign-in needs a browser and an OAuth callback, which is the Phase 12 broker. The edit was shown with **VS Code 1.146.0**, the same Code-OSS base, in the same sandbox: text typed in the editor and saved with Ctrl+S appeared in the host file. That proves the mechanism, not Kiro |
| `cat ~/.ssh/*` from the IDE's terminal fails | **Met**, from VS Code's integrated terminal: `cat /home/mazidur/.ssh/id_rsa` gives "No such file or directory", `SSH_AUTH_SOCK` is empty, D-Bus is disabled. For Kiro, `--check --ide kiro` passes the same 23 probes in the same sandbox, but the check does not run from Kiro's own terminal |
| No network except the stub | **Met with no stub at all.** Only loopback exists. `curl http://1.1.1.1/` and `http://169.254.169.254/` fail. The stub proxy arrives in Phase 9 |

## What the sandbox looks like

```text
bwrap --unshare-all --die-with-parent --new-session --clearenv
  --ro-bind /usr /usr  (+ symlinks /bin /sbin /lib /lib64)
  generated /etc/passwd and /etc/group (one user, "sandbox")
  --ro-bind-try /etc/{ld.so.cache,fonts,ssl,alternatives,localtime}
  --proc /proc  --dev /dev  --tmpfs /tmp  --tmpfs /run
  --bind <persistent sandbox home> /home/sandbox
  --bind <repo> /workspace
  --ro-bind /tmp/.X11-unix/X<n> (the Xephyr socket only)  --ro-bind <cookie> /tmp/xauth
  --setenv HOME USER SHELL PATH LANG TERM DISPLAY XAUTHORITY      (nothing else)
```

Xephyr runs as `Xephyr :<n> -nolisten tcp -terminate -auth <cookie>`, with `n` starting at 20. The cookie is in a `mktemp -d` directory (mode 700).

## Breakages and fixes

Found while building this PoC and while reviewing the first version of it (PR #4).

| # | Problem | Cause | Fix | How it was verified |
|---|---|---|---|---|
| 1 | The old design leaked credentials and sockets | `--ro-bind / /` mounts the whole host. Inside, these were reachable: `/run/user/1000/bus` (D-Bus), `/run/user/1000/keyring/ssh` (ssh-agent), `/var/run/docker.sock`, `/run/docker.sock`, `~/.ssh`, `~/.aws`, `~/.config`, `/media` | Allowlist root: mount `/usr`, a few `/etc` entries and nothing else | Ran the old flags, listed each path. A mutant of the script with `--ro-bind / /` fails 8 of 23 probes |
| 2 | bwrap rejected the old script's options | bwrap 0.9.0 has `--setenv`, `--unsetenv`, `--clearenv`. There is no `--env` or `--unset-env` ("Unknown option") | `--clearenv`, then `--setenv` for six variables | `bwrap --help`, and the error message |
| 3 | Unsetting variables one by one leaks the rest | Any variable not named stays | `--clearenv` is an allowlist; probe `no unexpected environment variables` | Mutant without `--clearenv` fails 2 probes |
| 4 | Raw X11 gives the sandbox the host display | The host socket `/tmp/.X11-unix/X0` shared with the sandbox | Xephyr nested server (Q4). Only its socket is mounted. `/tmp` is a fresh tmpfs | Probe `only the nested X socket is visible`; mutant that mounts the whole directory fails it |
| 5 | The host `/tmp` was writable from the sandbox | `--bind /tmp /tmp` | `--tmpfs /tmp` | Probe list, `ls /tmp` shows only `.X11-unix` and `xauth` |
| 6 | Chromium's sandbox needs a nested user namespace | bwrap sets `NoNewPrivs=1` on the sandbox, so the setuid `chrome-sandbox` helper cannot work | Leave user namespaces on (the default). Never pass `--no-sandbox` | In the sandbox: 15 processes, none with `--no-sandbox`. Renderers run in their own user and network namespace with `Seccomp: 2`. Adding `--disable-userns` makes Chromium abort: "The SUID sandbox helper binary was found, but is not configured correctly. Rather than run without sandboxing I'm aborting now" |
| 7 | Kiro needs sign-in before the editor works | Product behavior. Sign-in needs a browser, a callback port and internet (see "How Kiro's sign-in works") | Not fixable in Phase 5. Needs the Phase 9 proxy and the Phase 12 callback relay | Screenshots: Sign in button, then the "We will take you to your default web browser" screen. The sign-in click was recorded by a stub `xdg-open` that opens nothing |
| 8 | D-Bus errors in the log | No session bus in the sandbox, on purpose | Ignore. Use `--password-store=basic` so the IDE does not look for a keyring | Log: `Failed to connect to the bus`; IDE still runs |
| 9 | `Error: Unable to retrieve mac address` in the log | No network interface to read | Harmless; IDE runs | Log |
| 10 | The script must not leave processes behind | | `--die-with-parent`, `-terminate` on Xephyr, a `trap` that removes the temp dir | `kill -9` of the script: all sandbox processes and Xephyr exit within 4 s. `kill -9` skips the trap, so the temp dir (cookie, mode 700) stays. It is useless once Xephyr exits |
| 11 | A repo path that contains `$HOME` would hand over the home directory | `--bind <repo>` is read-write | The script refuses a repo that is, or contains, `$HOME`. The test is by path component: `/tmp/pre/maz` is allowed when `HOME=/tmp/pre/mazidur` | 12 argument and path cases tested |

## How Kiro's sign-in works (observed, 2026-11-19)

Observed by clicking **Sign in** in the sandboxed Kiro with a stub `xdg-open` that only wrote down what it was asked to open. The link was never opened, and no account was used.

- Kiro asks the system to open `https://app.kiro.dev/signin?state=...&code_challenge=...&code_challenge_method=S256&redirect_uri=http://localhost:3128&redirect_from=KiroIDE`. It is an OAuth flow with PKCE, and the same link is shown on screen to copy.
- Kiro starts a listener on **`127.0.0.1:3128`**, and it did so inside the sandbox's own network namespace: the port was open there and not on the host. The browser is told to come back to `http://localhost:3128`, which on the host reaches nothing.
- So the flow cannot finish in this sandbox, for two separate reasons: nothing carries the browser's callback to the sandbox, and the sandbox has no network for the token exchange.
- Kiro's docs say sign-in "completes in the browser" and list Google, GitHub, AWS Builder ID and organization sign-in (kiro.dev/docs/getting-started/authentication). They also say Kiro honors `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` (kiro.dev/docs/getting-started/installation), which is what the Phase 9 proxy relies on.
- **Not tested:** whether Kiro picks another port when 3128 is taken, which domains Kiro needs after sign-in, and whether the callback also arrives by a `kiro://` link.

Design consequence for later phases. The callback needs a relay: a host listener on `127.0.0.1:3128` that forwards to the sandbox over a unix socket in a shared directory, with a small helper inside the sandbox (`socat` is installed here) that connects that socket to `127.0.0.1:3128`. Nothing goes out of the sandbox, and one port goes in. The token exchange needs the Phase 9 proxy with an exact-host allowlist.

## Minimum permissions

Each row removes one grant, starts VS Code, and checks that its window appears (about 12 s each).

| Grant | Needed? | Evidence |
|---|---|---|
| `/sys` read-only | No | Window opens without it |
| Most of `/etc` | No | Window opens with only `ld.so.cache`, `fonts`, `ssl`, `localtime`, `alternatives` |
| Real `/etc/passwd` | No | Window opens with no passwd at all. A generated one-user file is kept so tools can look up the uid without learning the other accounts on the machine |
| `/dev/dri` (GPU) | No, on Xephyr | Window opens with and without it. **Whether it renders faster with it is not tested.** `--gpu` adds it |
| `/dev/shm` bind | No | `--dev /dev` gives a private `/dev/shm` (tmpfs) |
| Nested user namespaces | **Yes** | Fix 6 above |
| Fonts | System fonts under `/usr/share/fonts` plus `/etc/fonts` | Text renders in the screenshots |
| Persistent home | Yes, for state | A marker file in the sandbox home survived a restart |

## What `--check` covers (23 probes)

Real home absent, a canary file in the real home unreadable, real `~/.ssh` unreachable, `SSH_AUTH_SOCK` unset, ssh-agent socket absent, D-Bus socket absent, `/run/user` absent, `docker.sock` absent in both paths, `/media` and `/mnt` absent, only loopback interface, `1.1.1.1` and `169.254.169.254` unreachable, `/usr` is a read-only **mount**, the IDE install is under it, a write to `/usr` fails, the IDE install is not writable, the repo is writable, only the nested X socket is visible, the nested X server answers, a nested user namespace can be created, few processes visible (own PID namespace), no unexpected environment variables.

Mutation check: five broken copies of the script were run. The old `--ro-bind /` design fails 8 probes, `--share-net` fails 2, mounting the whole X socket directory fails 1, keeping the host environment fails 2, and a writable `/usr` mount fails 1. An earlier version of the read-only probe passed the writable `/usr` mutant, because file permissions alone stopped the write. That probe was replaced by one that reads `/proc/self/mountinfo`.

## Not tested and known limits

- **Kiro editing a file.** Blocked by sign-in (fix 7). It needs the Phase 9 proxy and the Phase 12 callback relay, or a manual sign-in by the user with temporary network access (which weakens the sandbox for that test).
- **Wayland, ARM64, GPU speed, clipboard** between the sandbox and the host. Not tested.
- **AppArmor-restricted user namespaces.** This machine has `apparmor_restrict_unprivileged_userns = 0`. The restricted case is not tested here (`doctor` detects it).
- **Same-user access to Xephyr.** The cookie file is mode 700, but other processes of the same user could read it. The sandbox also runs as the same uid, so this is a limit of the design, not a leak from the sandbox.
- **The repo is mounted read-write as a whole**, including `.git/hooks`, `.kiro/settings` and `.kiro/hooks`. Protecting those is Phase 10.
- **No Landlock, no seccomp filter of our own, no `TIOCSTI` filter.** `--new-session` is used. The rest is Phase 8.
- **The GUI driving** (typing, Ctrl+S, the terminal commands, screenshots) was done with a throwaway `python-xlib` 0.33 script using the XTest extension. It is not committed. `--check` is the repeatable part.
- **Shell script lint.** `shellcheck` is not installed here; the script was checked with `bash -n` and by running it.
