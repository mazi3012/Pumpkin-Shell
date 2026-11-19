#!/usr/bin/env bash
# linux-kiro.sh: Linux proof of concept. Runs a Code-OSS IDE (Kiro or VS Code)
# inside bubblewrap, on a nested X server (Xephyr), with no network.
#
# This is a PoC (Phase 5). The Rust backend that replaces it is Phase 8.
# Findings and the reason for every flag: docs/poc/linux-kiro.md.
#
# Design rules, each one tested by `--check`:
#   - The sandbox root is an allowlist, never `--ro-bind / /`. The real home,
#     /run/user (D-Bus, ssh-agent), docker.sock and /media are not mounted.
#   - The environment is cleared and six variables are set again.
#   - The IDE talks to its own Xephyr display, never to the host display.
#   - No network namespace sharing: only loopback exists.
#   - Chromium keeps its own sandbox. `--no-sandbox` is never passed.
set -euo pipefail

SCRIPT_NAME=${0##*/}

usage() {
    cat <<EOF
Usage: $SCRIPT_NAME [--ide kiro|code] [--check] [--gpu] [--size WxH] [REPO]

Runs the IDE on REPO (default: current directory) inside a sandbox.

  --ide NAME   kiro (default) or code
  --check      do not start the IDE; run the isolation checks inside the
               sandbox and exit 1 if any fails
  --gpu        also pass /dev/dri (not needed on Xephyr; see the PoC doc)
  --size WxH   nested display size (default 1280x800)
EOF
}

die() {
    echo "$SCRIPT_NAME: $*" >&2
    exit 2
}

IDE=kiro
CHECK=0
GPU=0
SIZE=1280x800
REPO=""
while [ $# -gt 0 ]; do
    case $1 in
        --ide) [ $# -ge 2 ] || die "--ide needs a value"; IDE=$2; shift 2 ;;
        --check) CHECK=1; shift ;;
        --gpu) GPU=1; shift ;;
        --size) [ $# -ge 2 ] || die "--size needs a value"; SIZE=$2; shift 2 ;;
        -h | --help) usage; exit 0 ;;
        -*) die "unknown option: $1" ;;
        *) [ -z "$REPO" ] || die "only one repo path is allowed"; REPO=$1; shift ;;
    esac
done
[ -n "$REPO" ] || REPO=.

case $IDE in
    kiro) IDE_DIR=/usr/share/kiro; IDE_BIN=$IDE_DIR/kiro ;;
    code) IDE_DIR=/usr/share/code; IDE_BIN=$IDE_DIR/code ;;
    *) die "unknown IDE: $IDE (use kiro or code)" ;;
esac
[ -x "$IDE_BIN" ] || die "$IDE_BIN is not installed"
[[ $SIZE =~ ^[0-9]+x[0-9]+$ ]] || die "--size must look like 1280x800"
for tool in bwrap Xephyr xauth mcookie; do
    command -v "$tool" >/dev/null || die "missing tool: $tool"
done

REPO=$(realpath -e -- "$REPO") || die "no such path: $REPO"
[ -d "$REPO" ] || die "not a directory: $REPO"
# The repo is mounted read-write. Refuse a repo that is, or contains, the home
# directory: that would hand over every credential in it. The trailing slash
# makes this a path-component test, not a string-prefix test.
case "$HOME/" in
    "$REPO"/*) die "refusing to mount $REPO: it contains your home directory" ;;
esac
[ "$REPO" != / ] || die "refusing to mount /"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/pks-poc.XXXXXX")
XEPHYR_PID=""
CANARY=""
cleanup() {
    [ -z "$XEPHYR_PID" ] || kill "$XEPHYR_PID" 2>/dev/null || true
    [ -z "$CANARY" ] || rm -f -- "$CANARY"
    rm -rf -- "$WORK"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# Persistent sandbox home, one per IDE, outside the repo.
SANDBOX_HOME=${XDG_DATA_HOME:-$HOME/.local/share}/pumpkin-shell/poc-home-$IDE
mkdir -p -m 700 "$SANDBOX_HOME"

# --- nested X server ------------------------------------------------------
# Own display number from :20 up, a cookie file only this user can read, and
# no TCP. -terminate stops Xephyr when the last client disconnects.
N=20
while [ -e "/tmp/.X11-unix/X$N" ] || [ -e "/tmp/.X$N-lock" ]; do N=$((N + 1)); done
xauth -q -f "$WORK/xauth" add ":$N" . "$(mcookie)"
Xephyr ":$N" -screen "$SIZE" -nolisten tcp -terminate -auth "$WORK/xauth" \
    -title "Pumpkin-Shell PoC ($IDE)" >"$WORK/xephyr.log" 2>&1 &
XEPHYR_PID=$!
for _ in $(seq 1 50); do
    [ -S "/tmp/.X11-unix/X$N" ] && break
    sleep 0.2
done
[ -S "/tmp/.X11-unix/X$N" ] || die "Xephyr did not start (see $WORK/xephyr.log)"

# --- sandbox ----------------------------------------------------------------
# A minimal user database, so tools can look up the uid without learning the
# names of other accounts on this machine.
printf 'sandbox:x:%s:%s:sandbox:/home/sandbox:/bin/bash\n' "$(id -u)" "$(id -g)" >"$WORK/passwd"
printf 'sandbox:x:%s:\n' "$(id -g)" >"$WORK/group"

ARGS=(
    --unshare-all --die-with-parent --new-session --clearenv
    # Read-only system. The IDE install lives under /usr, so it is read-only.
    --ro-bind /usr /usr
    --symlink usr/bin /bin --symlink usr/sbin /sbin
    --symlink usr/lib /lib --symlink usr/lib64 /lib64
    # The few /etc entries the IDE needs: loader cache, fonts, TLS roots.
    --ro-bind "$WORK/passwd" /etc/passwd --ro-bind "$WORK/group" /etc/group
    --ro-bind-try /etc/ld.so.cache /etc/ld.so.cache
    --ro-bind-try /etc/fonts /etc/fonts
    --ro-bind-try /etc/ssl /etc/ssl
    --ro-bind-try /etc/alternatives /etc/alternatives
    --ro-bind-try /etc/localtime /etc/localtime
    # Fresh /proc, a private /dev (with its own /dev/shm), empty /tmp and /run.
    --proc /proc --dev /dev --tmpfs /tmp --tmpfs /run
    --bind "$SANDBOX_HOME" /home/sandbox
    --bind "$REPO" /workspace
    # Only the nested display's socket, and its cookie.
    --ro-bind "/tmp/.X11-unix/X$N" "/tmp/.X11-unix/X$N"
    --ro-bind "$WORK/xauth" /tmp/xauth
    --setenv HOME /home/sandbox --setenv USER sandbox --setenv SHELL /bin/bash
    --setenv PATH /usr/bin:/bin --setenv LANG C.UTF-8 --setenv TERM xterm-256color
    --setenv DISPLAY ":$N" --setenv XAUTHORITY /tmp/xauth
    --chdir /workspace
)
if [ "$GPU" = 1 ]; then
    ARGS+=(--dev-bind /dev/dri /dev/dri)
fi

# Probes run inside the sandbox. Arguments: real home, uid, display number,
# IDE install dir, canary path on the host.
CHECKS=$(
    cat <<'EOS'
pass=0; fail=0
ok() { echo "PASS  $1"; pass=$((pass + 1)); }
no() { echo "FAIL  $1"; fail=$((fail + 1)); }
chk() { n=$1; shift; if "$@" >/dev/null 2>&1; then ok "$n"; else no "$n"; fi; }
chk_not() { n=$1; shift; if "$@" >/dev/null 2>&1; then no "$n"; else ok "$n"; fi; }
REAL_HOME=$1; UID_=$2; N=$3; IDE_DIR=$4; CANARY=$5
chk_not "real home directory is not mounted" test -e "$REAL_HOME"
chk_not "canary file in the real home is unreadable" cat "$CANARY"
chk_not "real ~/.ssh is unreachable" ls "$REAL_HOME/.ssh"
chk "SSH_AUTH_SOCK is unset" test -z "${SSH_AUTH_SOCK:-}"
chk_not "ssh-agent socket (keyring) is absent" test -S "/run/user/$UID_/keyring/ssh"
chk_not "D-Bus session socket is absent" test -S "/run/user/$UID_/bus"
chk_not "/run/user is absent" test -e /run/user
chk_not "docker.sock is absent (/var/run)" test -e /var/run/docker.sock
chk_not "docker.sock is absent (/run)" test -e /run/docker.sock
chk_not "/media and /mnt are absent" sh -c 'test -e /media || test -e /mnt'
chk "only the loopback interface exists" awk 'NR>2 { sub(/:.*/, "", $1); if ($1 != "lo") exit 1 }' /proc/net/dev
chk_not "internet is unreachable (1.1.1.1, no DNS needed)" curl -s -m 3 http://1.1.1.1/
chk_not "cloud metadata is unreachable (169.254.169.254)" curl -s -m 3 http://169.254.169.254/
chk "/usr is a read-only mount (file permissions alone are not enough)" sh -c 'awk "\$5 == \"/usr\" { print \$6 }" /proc/self/mountinfo | grep -qw ro'
chk "IDE install is under that read-only mount" sh -c 'case "$1" in /usr/*) exit 0 ;; *) exit 1 ;; esac' sh "$IDE_DIR"
chk_not "/usr is read-only" touch /usr/pks-check
chk_not "IDE install is read-only" touch "$IDE_DIR/pks-check"
chk "repo is writable" sh -c 'touch /workspace/.pks-check && rm /workspace/.pks-check'
chk "only the nested X socket is visible" test "$(ls /tmp/.X11-unix)" = "X$N"
chk "nested X server answers" xdpyinfo -display ":$N"
chk "Chromium can create a nested user namespace" unshare --user true
chk "own pid namespace (few processes visible)" sh -c '[ "$(ls /proc | grep -c "^[0-9]")" -lt 10 ]'
chk_not "no unexpected environment variables" sh -c 'env | cut -d= -f1 | grep -vxE "HOME|USER|SHELL|PATH|LANG|TERM|DISPLAY|XAUTHORITY|PWD|SHLVL|OLDPWD|_" | grep .'
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
EOS
)

if [ "$CHECK" = 1 ]; then
    # A file only the real home can see. If the sandbox can read it, the home leaks.
    CANARY=$HOME/.pks-poc-canary-$$
    echo "canary, not a real secret" >"$CANARY"
    bwrap "${ARGS[@]}" /bin/sh -c "$CHECKS" sh "$HOME" "$(id -u)" "$N" "$IDE_DIR" "$CANARY"
    exit $?
fi

echo "$SCRIPT_NAME: starting $IDE on $REPO (nested display :$N)" >&2
# No --no-sandbox: Chromium must run its own sandbox inside ours.
# --password-store=basic: there is no keyring or D-Bus in the sandbox.
bwrap "${ARGS[@]}" "$IDE_BIN" --ozone-platform=x11 --password-store=basic /workspace
