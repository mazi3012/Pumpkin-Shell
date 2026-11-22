#!/bin/sh
# Builds dist/pumpkin-shell_<version>_amd64.deb from a release build (Phase 18.1).
# Usage: packaging/build-deb.sh <version>   (for example 1.0.0)
# The package installs one binary, the licence and the docs. Nothing runs
# as root at install time.
set -eu
version="${1:?usage: build-deb.sh <version>}"
case "$version" in
    *[!0-9A-Za-z.+~-]*|"") echo "build-deb: version has characters a Debian version cannot" >&2; exit 2 ;;
esac
cd "$(dirname "$0")/.."

# The binary reports the version in Cargo.toml, so the package must carry the same one.
cargo_version=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -1)
if [ "$cargo_version" != "$version" ]; then
    echo "build-deb: Cargo.toml says $cargo_version, not $version; bump the version first" >&2
    exit 2
fi

cargo build --release --locked -p pks-cli
binary=target/release/pumpkin-shell

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
root="$stage/pumpkin-shell_${version}_amd64"
mkdir -p "$root/DEBIAN" "$root/usr/bin" "$root/usr/share/doc/pumpkin-shell"
install -m 0755 "$binary" "$root/usr/bin/pumpkin-shell"
install -m 0644 LICENSE "$root/usr/share/doc/pumpkin-shell/copyright"
install -m 0644 docs/ESCAPE-CORPUS.md "$root/usr/share/doc/pumpkin-shell/ESCAPE-CORPUS.md"
install -m 0644 docs/THREAT-MODEL.md "$root/usr/share/doc/pumpkin-shell/THREAT-MODEL.md"
# The AppArmor profile is shipped but not loaded. Loading needs root (README).
mkdir -p "$root/usr/share/pumpkin-shell/apparmor"
install -m 0644 packaging/apparmor/usr.bin.pumpkin-shell "$root/usr/share/pumpkin-shell/apparmor/usr.bin.pumpkin-shell"

installed_kb=$(du -sk "$root/usr" | cut -f1)
cat > "$root/DEBIAN/control" <<CONTROL
Package: pumpkin-shell
Version: $version
Section: utils
Priority: optional
Architecture: amd64
Maintainer: Md Mazidur Rahman
Installed-Size: $installed_kb
Depends: bubblewrap (>= 0.8), xserver-xephyr, xauth
Recommends: zenity, xclip, libnotify-bin
Homepage: https://github.com/mazi3012/pumpkin-shell
Description: sandbox for AI-powered IDEs (Kiro first)
 Pumpkin-Shell launches an IDE inside an OS-level sandbox: no host
 credentials, filtered network through a proxy, staged writes to
 protected files, a guarded package mirror, and signed session logs.
CONTROL

# Maintainer scripts: load the AppArmor profile on Ubuntu 24.04 when needed, and remove it.
install -m 0755 packaging/debian/postinst "$root/DEBIAN/postinst"
install -m 0755 packaging/debian/postrm "$root/DEBIAN/postrm"
mkdir -p dist
out="dist/pumpkin-shell_${version}_amd64.deb"
dpkg-deb --root-owner-group --build "$root" "$out" >/dev/null
echo "$out"
