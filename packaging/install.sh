#!/bin/sh
# Installs a Pumpkin-Shell release on Ubuntu, Debian or Linux Mint (Phase 18
# follow-up). It downloads the .deb and its signature bundle, checks the
# signature with cosign, and only then installs the package with apt.
#
# Usage:
#   packaging/install.sh [VERSION]              install VERSION (default 1.0.0)
#   packaging/install.sh --check-only [VERSION] download and verify, do not install
#   packaging/install.sh --from DIR [VERSION]   use files already in DIR (no download)
#
# This script never pipes a download into a shell. Read it before you run it.
set -eu

REPO="mazi3012/Pumpkin-Shell"
IDENTITY='https://github.com/mazi3012/[Pp]umpkin-[Ss]hell/.github/workflows/release.yml@refs/tags/v.*'
ISSUER='https://token.actions.githubusercontent.com'
DEFAULT_VERSION="1.0.0"

check_only=0
from_dir=""
version="$DEFAULT_VERSION"
while [ $# -gt 0 ]; do
    case "$1" in
        --check-only) check_only=1 ;;
        --from) shift; from_dir="${1:?--from needs a directory}" ;;
        -h|--help)
            sed -n '2,11p' "$0"
            exit 0
            ;;
        -*) echo "install: unknown option $1" >&2; exit 2 ;;
        *) version="$1" ;;
    esac
    shift
done

case "$version" in
    *[!0-9A-Za-z.+~-]*|"") echo "install: a version can only contain letters, digits and . + ~ -" >&2; exit 2 ;;
esac

say() { printf '%s\n' "$*"; }
fail() { printf 'install: %s\n' "$*" >&2; exit 1; }

# 1. This machine must be Debian-based, on amd64. Other systems get the manual steps.
[ "$(uname -m)" = "x86_64" ] || fail "this package is for x86_64; see the README for building from source"
command -v apt-get >/dev/null 2>&1 && command -v dpkg >/dev/null 2>&1 \
    || fail "this installer needs apt (Ubuntu, Debian, Linux Mint). For Fedora, see the RPM steps in the README"
[ "$(dpkg --print-architecture)" = "amd64" ] || fail "this package is amd64 only"

# 2. The signature check needs cosign. The script does not fetch tools for you.
command -v cosign >/dev/null 2>&1 || fail "cosign is needed to check the download. Install it from https://github.com/sigstore/cosign/releases and run this again"

deb="pumpkin-shell_${version}_amd64.deb"
bundle="$deb.sigstore.json"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# 3. Get the files: download from the release, or copy from --from DIR.
if [ -n "$from_dir" ]; then
    [ -f "$from_dir/$deb" ] && [ -f "$from_dir/$bundle" ] || fail "$from_dir does not have $deb and $bundle"
    cp "$from_dir/$deb" "$from_dir/$bundle" "$work/"
else
    url="https://github.com/$REPO/releases/download/v$version"
    say "Downloading $deb"
    curl -fsSL -o "$work/$deb" "$url/$deb" || fail "download failed: $url/$deb"
    curl -fsSL -o "$work/$bundle" "$url/$bundle" || fail "download failed: $url/$bundle"
fi

# 4. Check the signature. A failure stops here, before anything is installed.
say "Checking the signature"
if ! cosign verify-blob --bundle "$work/$bundle" \
        --certificate-identity-regexp "$IDENTITY" \
        --certificate-oidc-issuer "$ISSUER" \
        "$work/$deb" >/dev/null 2>&1; then
    fail "the signature check FAILED. Nothing was installed. Do not install this file"
fi
say "Signature OK: $deb was built by the release workflow of $REPO"

if [ "$check_only" -eq 1 ]; then
    say "Check only: not installing."
    exit 0
fi

# 5. Install with apt. apt also installs bubblewrap, Xephyr and xauth.
say "Installing (sudo will ask for your password)"
sudo apt-get install -y "$work/$deb"

# 6. Confirm the install.
pumpkin-shell --version
say "Next: pumpkin-shell doctor, then: pumpkin-shell kiro ~/your-project"
