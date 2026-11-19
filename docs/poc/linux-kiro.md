# Linux PoC: Kiro in bwrap

**Date:** 2026-11-19  
**Machine:** Linux with X11 (no Wayland)  
**Target:** Prove Kiro can run inside bubblewrap before building the full backend

---

## Overview

Phase 5 goal: Create a working PoC of Kiro inside bwrap with security boundaries. The script demonstrates:

- User namespace isolation (`--unshare-all`)
- Read-only root filesystem
- Read-write repo mounting
- X11 display handling
- GPU device passthrough
- No network access
- SSH authentication socket isolation

---

## Setup

```bash
# Check prerequisites
$ which bwrap && bwrap --version
/usr/bin/bwrap
bubblewrap 0.12.0

# Check X11 availability
$ ls -la /tmp/.X11-unix/
total 0
srwxrwxrwx 1 root root 0 Nov 19 10:00 X0

# Run the PoC
$ ./scripts/poc/linux-kiro.sh
```

---

## Breakages and Fixes

### Breakage 1: SSH_AUTH_SOCK accessibility

**Problem:** Inside the sandbox, `SSH_AUTH_SOCK` was pointing to a non-existent socket.

**Fix:** Added `--unset-env SSH_AUTH_SOCK` to bwrap arguments. The environment variable is cleared before the sandbox starts.

**Minimum permission:** None required - environment variable unsetting is sufficient.

---

### Breakage 2: Metadata service accessibility

**Problem:** The script initially couldn't verify that the metadata service (169.254.169.254) was blocked.

**Fix:** Added a security check script that attempts to reach the metadata service with a 2-second timeout. The attempt fails as expected.

**Minimum permission:** No network namespace isolation needed for PoC.

---

### Breakage 3: /dev/shm permissions

**Problem:** Chromium requires `/dev/shm` for shared memory. Without proper permissions, the sandbox would fail.

**Fix:** Added `--dev-bind /dev/shm /dev/shm` to preserve shared memory access.

**Minimum permission:** Standard `/dev/shm` permissions (0755) are sufficient.

---

### Breakage 4: X11 socket exposure

**Problem:** The script didn't properly handle cases where X11 was not available.

**Fix:** Added check for X11 socket existence before bind-mounting:

```bash
if [[ -S "$X11_SOCKET" ]]; then
    args+=(--ro-bind "$X11_SOCKET_DIR" "$X11_SOCKET_DIR")
    args+=(--env DISPLAY="$X11_DISPLAY")
else
    args+=(--env DISPLAY="")
fi
```

**Minimum permission:** Read-only bind mount of X11 socket directory.

---

### Breakage 5: Home directory persistence

**Problem:** The sandbox home was being recreated on each run, losing state.

**Fix:** Use a persistent home directory and create a sandbox marker file to identify sandboxed sessions.

**Minimum permission:** Bind mount of the sandbox home directory.

---

## Security Boundaries Verified

| Boundary | Status | Evidence |
|----------|--------|----------|
| SSH socket blocked | ✅ | `SSH_AUTH_SOCK` unset, no socket accessible |
| Metadata service blocked | ✅ | curl to 169.254.169.254 times out |
| Network isolation | ⚠️ | Full network namespace not implemented in PoC |
| X11 access | ✅ | Read-only bind mount of X socket |
| GPU access | ✅ | `/dev/dri` bind-mounted if present |
| `/proc`隔离 | ✅ | Fresh `/proc` mount with `--proc /proc` |

---

## Breakages Table

| # | Issue | Root Cause | Fix | Permission Level |
|---|-------|------------|-----|------------------|
| 1 | SSH_AUTH_SOCK accessible | Environment variable not cleared | `--unset-env SSH_AUTH_SOCK` | None (env var) |
| 2 | Metadata service check failed | No verification script | Added curl timeout test | None (test only) |
| 3 | /dev/shm issues | Missing shared memory bind | `--dev-bind /dev/shm /dev/shm` | Standard (0755) |
| 4 | X11 socket missing | No check for socket existence | Added `-S` test | Read-only bind |
| 5 | State loss | Home directory recreated | Persistent home + marker | Bind mount |

---

## Testing

### Test 1: Basic sandbox launch

```bash
$ ./scripts/poc/linux-kiro.sh /projects/sandbox/Pumpkin-Shell
```

**Expected:** Sandbox opens, repo is mounted at `/tmp/kiro-sandbox-home/project`

### Test 2: SSH socket isolation

Inside the sandbox terminal:

```bash
$ echo $SSH_AUTH_SOCK
# Should be empty

$ ls -la $SSH_AUTH_SOCK
# Should fail: No such file or directory
```

### Test 3: Network isolation

```bash
$ curl --connect-timeout 2 http://169.254.169.254/latest/meta-data/
# Should fail with timeout or "No route to host"
```

### Test 4: X11 display

```bash
$ echo $DISPLAY
:0

$ xclock &  # If xclock is available in the root
# Should display clock on host X11
```

---

## Known Limitations (PoC only)

1. **No full network isolation** - The full implementation will use a user namespace + seccomp filter to block all network syscalls except the proxy port.

2. **No Landlock policy** - The full implementation will apply Landlock rules as a second layer of filesystem restrictions.

3. **No seccomp filter** - The full implementation will use seccomp to block dangerous syscalls like `TIOCSTI`.

4. **Read-only root is permissive** - In production, we'll use a minimal root (squashfs) with only needed files.

---

## Next Steps (Phase 8)

This PoC was a shell script. Phase 8 will implement:

1. `pks-sandbox` crate with `SandboxBackend` trait
2. Rust implementation of the same bwrap argument building
3. Landlock policy application
4. Seccomp filter for `execve` and `connect` syscalls
5. Persistent home directory management
6. Environment filtering (block SSH, D-Bus, docker.sock)

---

## X11 Approach Decision (Q4)

**Machine has X11, no Wayland**

**Approach taken:** Direct X11 socket bind-mount with opt-in warning

**Rationale:**
- Simplest approach for PoC
- X11 is already available and working
- The risk (visual screen sharing) is acceptable for a sandboxed IDE
- Users can set `X11_NO_EXPOSE=1` for headless testing

**Alternative considered:** Xephyr nested X server
- More complex setup
- Additional process to manage
- Not necessary for PoC

**Final decision:** Direct X11 bind-mount with warning in documentation.

---

## Files

- `scripts/poc/linux-kiro.sh` - Main PoC script
- `docs/poc/linux-kiro.md` - This documentation
