# RPM spec for pumpkin-shell (Phase 18.1). Built in CI in a Fedora container.
Name:           pumpkin-shell
Version:        1.0.1
Release:        1%{?dist}
Summary:        Sandbox for AI-powered IDEs (Kiro first)
License:        MIT
URL:            https://github.com/mazi3012/pumpkin-shell
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  cargo
BuildRequires:  rust
BuildRequires:  gcc
Requires:       bubblewrap >= 0.8
Requires:       xorg-x11-server-Xephyr
Requires:       xorg-x11-xauth
Recommends:     zenity
Recommends:     xclip
Recommends:     libnotify

%description
Pumpkin-Shell runs an IDE inside an OS-level sandbox. The IDE gets no host
credentials, a filtered network through a proxy, staged writes to protected
files, a guarded npm and PyPI mirror, and a signed session log.

%prep
%autosetup

%build
cargo build --release --locked -p pks-cli

%install
install -Dm0755 target/release/pumpkin-shell %{buildroot}%{_bindir}/pumpkin-shell
install -Dm0644 packaging/apparmor/usr.bin.pumpkin-shell %{buildroot}%{_datadir}/%{name}/apparmor/usr.bin.pumpkin-shell

%files
%license LICENSE
%{_bindir}/pumpkin-shell
%doc docs/ESCAPE-CORPUS.md docs/THREAT-MODEL.md
%{_datadir}/%{name}/apparmor/usr.bin.pumpkin-shell

%changelog
* Mon Nov 23 2026 Md Mazidur Rahman <mazidurrahman30122000@gmail.com> - 1.0.1-1
- Add pumpkin-shell dashboard (Pumpkin-Shell Watch), a read-only local page.
- Add pumpkin-shell kiro [PATH] shortcut.
- Simplify the README install to two steps.
* Sun Nov 22 2026 Md Mazidur Rahman <mazidurrahman30122000@gmail.com> - 1.0.0-1
- First release: Linux, Kiro first.
