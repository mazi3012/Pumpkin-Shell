//! Builds the bubblewrap command line. Every value is its own argument: no
//! shell, no string concatenation (tech.md).
//!
//! The mount list is an allowlist. The root is a fresh tmpfs with only the
//! paths below added to it. The host home, `/run/user` (D-Bus, ssh-agent),
//! `docker.sock`, `/media`, `/mnt`, the data directory and the config
//! directory are never added, so they do not exist inside the sandbox.
//!
//! The same allowlist is tested by the isolation probes in
//! `tests/sandbox.rs`, which were first proven by hand in
//! `scripts/poc/linux-kiro.sh --check` (Phase 5).

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// Where the repo appears inside the sandbox.
pub const WORKSPACE: &str = "/workspace";
/// The IDE's home inside the sandbox.
pub const SANDBOX_HOME: &str = "/home/sandbox";
/// Where the Xauthority cookie appears inside the sandbox.
pub const XAUTHORITY_IN: &str = "/tmp/.pks-xauthority";
/// The proxy URL the IDE is given.
pub const PROXY_URL: &str = "http://127.0.0.1:3129";
/// Proxy variables set in the IDE environment. Lowercase and uppercase are
/// both set, as tools differ.
pub const PROXY_ENV: [&str; 6] = [
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "http_proxy",
    "https_proxy",
    "NO_PROXY",
    "no_proxy",
];
/// Hosts that bypass the proxy (loopback only).
pub const NO_PROXY_VALUE: &str = "localhost,127.0.0.1,::1";
/// Where the relay listens inside the sandbox.
pub const PROXY_LISTEN: &str = "127.0.0.1:3129";
/// Where the proxy's socket appears inside the sandbox.
pub const PROXY_SOCKET_IN: &str = "/run/pks/proxy.sock";
/// Where the Pumpkin-Shell binary appears, to run the in-sandbox step.
pub const INIT_IN: &str = "/run/pks/pumpkin-shell";
/// Where the mirror listens inside the sandbox. Package managers are set to
/// reach it here (Phase 14).
pub const MIRROR_LISTEN: &str = "127.0.0.1:3130";
/// The same address as a URL, for the package managers' settings.
pub const MIRROR_URL: &str = "http://127.0.0.1:3130";
/// Where the mirror's Unix socket appears inside the sandbox.
pub const MIRROR_SOCKET_IN: &str = "/run/pks/mirror.sock";
/// Socket timeout for pip and uv, in seconds (Phase 14).
const MIRROR_TIMEOUT_SECS: &str = "120";
/// Where the broker directory appears inside the sandbox (Phase 12).
pub const BROKER_IN: &str = "/run/pks/broker";
/// The request socket the wrappers send to. Created by the host.
pub const BROKER_REQUEST_IN: &str = "/run/pks/broker/request.sock";
/// The callback socket the in-sandbox agent creates.
pub const BROKER_CALLBACK_IN: &str = "/run/pks/broker/callback.sock";
/// The IDE's OAuth callback listener inside the sandbox, and the host's port
/// for the same callback (PRD FR-NET, Phase 12.2).
pub const CALLBACK_TARGET: &str = "127.0.0.1:3128";
/// Where the real git is mounted, so the `git` wrapper can run it.
pub const REAL_GIT_IN: &str = "/run/pks/git-real";
/// The only environment variables the IDE gets (PRD §6.1, "filtered env").
pub const ENV_ALLOWLIST: [&str; 9] = [
    "HOME",
    "USER",
    "SHELL",
    "PATH",
    "LANG",
    "TERM",
    "DISPLAY",
    "XAUTHORITY",
    "PWD",
];

/// Everything the command line needs, resolved on the host.
#[derive(Debug, Clone)]
pub struct Plan {
    /// Host path of the repo (mounted read-write at `WORKSPACE`).
    pub repo: PathBuf,
    /// Host path of the IDE home (mounted read-write at `SANDBOX_HOME`).
    pub ide_home: PathBuf,
    /// Host path of the IDE program. Run at the same path inside the sandbox.
    pub ide_binary: PathBuf,
    /// Arguments for the IDE.
    pub ide_args: Vec<OsString>,
    /// Number of the nested display, for example 20 for `:20`.
    pub display: u32,
    /// Host path of the nested display's socket.
    pub display_socket: PathBuf,
    /// Host path of the Xauthority cookie file.
    pub xauthority: PathBuf,
    /// Host path of the generated `passwd` file.
    pub passwd: PathBuf,
    /// Host path of the generated `group` file.
    pub group: PathBuf,
    /// Host path of the Pumpkin-Shell binary (the in-sandbox step).
    pub init_exe: PathBuf,
    /// Host path of the egress proxy's Unix socket.
    pub proxy_socket: PathBuf,
    /// Host ports the IDE may reach on its loopback (PRD FR-NET).
    pub host_ports: Vec<u16>,
    /// Paths bound over parts of the repo, parents first.
    pub binds: Vec<crate::spec::Bind>,
    /// Host directory for the brokers, or `None` for no broker.
    pub broker_dir: Option<PathBuf>,
    /// Host path of the mirror's Unix socket, or `None` for no mirror.
    pub mirror_socket: Option<PathBuf>,
    /// System programs that get a broker wrapper: `xdg-open` and `git`, the
    /// ones installed on the host.
    pub shims: Vec<&'static str>,
}

fn push(args: &mut Vec<OsString>, values: &[&str]) {
    args.extend(values.iter().map(OsString::from));
}

fn push_path(args: &mut Vec<OsString>, flag: &str, source: &Path, dest: &str) {
    args.push(OsString::from(flag));
    args.push(source.as_os_str().to_owned());
    args.push(OsString::from(dest));
}

/// The bubblewrap arguments, not including the program name.
#[must_use]
pub fn bwrap_args(plan: &Plan) -> Vec<OsString> {
    let mut args = Vec::new();
    push(
        &mut args,
        &[
            "--unshare-all",
            "--die-with-parent",
            "--new-session",
            "--clearenv",
        ],
    );
    // System files, read-only. `/usr` holds the IDE install too.
    push_path(&mut args, "--ro-bind", Path::new("/usr"), "/usr");
    push(
        &mut args,
        &[
            "--symlink",
            "usr/bin",
            "/bin",
            "--symlink",
            "usr/sbin",
            "/sbin",
            "--symlink",
            "usr/lib",
            "/lib",
            "--symlink",
            "usr/lib64",
            "/lib64",
        ],
    );
    // Only the files a desktop program needs from /etc, plus a generated
    // one-user passwd and group, so the uid has a name without the real list.
    push_path(&mut args, "--ro-bind", &plan.passwd, "/etc/passwd");
    push_path(&mut args, "--ro-bind", &plan.group, "/etc/group");
    for path in [
        "/etc/ld.so.cache",
        "/etc/fonts",
        "/etc/ssl",
        "/etc/alternatives",
        "/etc/localtime",
    ] {
        push_path(&mut args, "--ro-bind-try", Path::new(path), path);
    }
    // Fresh proc and dev (own /dev/shm), and empty tmpfs /tmp and /run.
    push(
        &mut args,
        &[
            "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--tmpfs", "/run",
        ],
    );
    // The three things the IDE may write to, and the repo it opens.
    push_path(&mut args, "--bind", &plan.ide_home, SANDBOX_HOME);
    push_path(&mut args, "--bind", &plan.repo, WORKSPACE);
    // Staged copies of the protected paths, over what the repo has there. A
    // write to one lands in the staging area, not in the repo.
    for bind in &plan.binds {
        push_path(
            &mut args,
            "--bind",
            &bind.source,
            &format!("{WORKSPACE}/{}", bind.rel),
        );
    }
    // The nested display's socket, and only that. The host's own display
    // (:0) is never mounted.
    let socket_in = format!("/tmp/.X11-unix/X{}", plan.display);
    push_path(&mut args, "--ro-bind", &plan.display_socket, &socket_in);
    push_path(&mut args, "--ro-bind", &plan.xauthority, XAUTHORITY_IN);
    // The Pumpkin-Shell binary, for the in-sandbox step before the IDE runs.
    push_path(&mut args, "--ro-bind", &plan.init_exe, INIT_IN);
    // The egress proxy's socket. The IDE reaches it through the relay on
    // loopback; there is no other route out (the network is unshared).
    push_path(&mut args, "--ro-bind", &plan.proxy_socket, PROXY_SOCKET_IN);
    // The package mirror (Phase 14): its socket is the only thing mounted, and
    // the package managers are pointed at its loopback address.
    if let Some(socket) = &plan.mirror_socket {
        push_path(&mut args, "--ro-bind", socket, MIRROR_SOCKET_IN);
    }
    // The broker (Phase 12): a shared directory for the request and callback
    // sockets, and the wrappers over `xdg-open` and `git`. The real git is
    // mounted first, under a private path. Every wrapper is this binary.
    if let Some(dir) = &plan.broker_dir {
        push_path(&mut args, "--bind", dir, BROKER_IN);
        if plan.shims.contains(&"git") {
            push_path(
                &mut args,
                "--ro-bind",
                Path::new("/usr/bin/git"),
                REAL_GIT_IN,
            );
        }
        for name in &plan.shims {
            push_path(
                &mut args,
                "--ro-bind",
                &plan.init_exe,
                &format!("/usr/bin/{name}"),
            );
        }
    }
    // The environment: nothing but the allowlist.
    let display = format!(":{}", plan.display);
    push(&mut args, &["--setenv", "HOME", SANDBOX_HOME]);
    push(&mut args, &["--setenv", "USER", "sandbox"]);
    push(&mut args, &["--setenv", "SHELL", "/bin/bash"]);
    push(&mut args, &["--setenv", "PATH", "/usr/bin:/bin"]);
    push(&mut args, &["--setenv", "LANG", "C.UTF-8"]);
    push(&mut args, &["--setenv", "TERM", "xterm-256color"]);
    push(&mut args, &["--setenv", "DISPLAY", &display]);
    push(&mut args, &["--setenv", "XAUTHORITY", XAUTHORITY_IN]);
    // Apps that honor proxy variables (Kiro does) send their traffic through
    // the relay. Lowercase and uppercase are both set, as tools differ.
    for name in PROXY_ENV {
        let value = if name.to_ascii_lowercase().starts_with("no_proxy") {
            NO_PROXY_VALUE
        } else {
            PROXY_URL
        };
        push(&mut args, &["--setenv", name, value]);
    }
    if plan.mirror_socket.is_some() {
        // npm, yarn, pnpm, pip and uv read these. pnpm ignores the npm
        // variable, so it has its own. Scripts of installed packages do not
        // run by default (PRD FR-REG, install scripts).
        let npm = format!("{MIRROR_URL}/npm/");
        let pypi = format!("{MIRROR_URL}/pypi/simple/");
        push(&mut args, &["--setenv", "npm_config_registry", &npm]);
        push(&mut args, &["--setenv", "PNPM_CONFIG_REGISTRY", &npm]);
        push(
            &mut args,
            &["--setenv", "npm_config_ignore_scripts", "true"],
        );
        push(&mut args, &["--setenv", "PIP_INDEX_URL", &pypi]);
        push(&mut args, &["--setenv", "UV_DEFAULT_INDEX", &pypi]);
        // The mirror checks a file's checksum before it sends the first byte,
        // so a large wheel can take the whole upstream download time before
        // any response starts. pip's 15 s default and uv's default would
        // give up on a 17 MB wheel (see docs/DECISIONS.md, Phase 14).
        push(&mut args, &["--setenv", "PIP_TIMEOUT", MIRROR_TIMEOUT_SECS]);
        push(
            &mut args,
            &["--setenv", "UV_HTTP_TIMEOUT", MIRROR_TIMEOUT_SECS],
        );
    }
    push(&mut args, &["--chdir", WORKSPACE]);

    // The in-sandbox step: Landlock and the seccomp filter, then exec the IDE.
    args.push(OsString::from(INIT_IN));
    push(&mut args, &["sandbox-init"]);
    for (flag, path) in landlock_rw(&socket_in) {
        push(&mut args, &[flag, path]);
    }
    push(&mut args, &["--ro", "/usr", "--ro", "/etc", "--ro", "/sys"]);
    push(
        &mut args,
        &[
            "--ro",
            INIT_IN,
            "--ro",
            XAUTHORITY_IN,
            "--ro",
            PROXY_SOCKET_IN,
        ],
    );
    // Landlock needs every listed path to exist, so the mirror socket is listed
    // only when the sandbox has one.
    if plan.mirror_socket.is_some() {
        push(&mut args, &["--ro", MIRROR_SOCKET_IN]);
    }
    // The relay runs inside the sandbox, before the IDE: loopback to the proxy.
    push(
        &mut args,
        &[
            "--relay-listen",
            PROXY_LISTEN,
            "--relay-socket",
            PROXY_SOCKET_IN,
        ],
    );
    // The mirror's loopback relay (Phase 14), started the same way.
    if plan.mirror_socket.is_some() {
        push(
            &mut args,
            &[
                "--mirror-listen",
                MIRROR_LISTEN,
                "--mirror-socket",
                MIRROR_SOCKET_IN,
            ],
        );
    }
    for port in &plan.host_ports {
        push(&mut args, &["--relay-host-port", &port.to_string()]);
    }
    // The OAuth callback agent (Phase 12.2): listens in the broker directory
    // and passes each connection to the IDE's listener on loopback.
    if plan.broker_dir.is_some() {
        push(
            &mut args,
            &[
                "--callback-socket",
                BROKER_CALLBACK_IN,
                "--callback-target",
                CALLBACK_TARGET,
            ],
        );
    }
    // `--` ends the init options. Everything after it is the IDE command.
    args.push(OsString::from("--"));
    args.push(plan.ide_binary.as_os_str().to_owned());
    args.extend(plan.ide_args.iter().cloned());
    args
}

/// Paths the IDE may write to, as `--rw` options. `socket_in` is the nested
/// display's socket: connecting to it needs write access.
fn landlock_rw(socket_in: &str) -> Vec<(&'static str, &str)> {
    vec![
        ("--rw", WORKSPACE),
        ("--rw", SANDBOX_HOME),
        ("--rw", "/tmp"),
        ("--rw", "/dev"),
        ("--rw", "/run"),
        // Chromium writes `uid_map` and `gid_map` of the namespaces it creates,
        // under /proc/<pid>. The /proc mounted here is the sandbox's own: it
        // lists only sandbox processes, so no host process is reachable.
        ("--rw", "/proc"),
        ("--rw", socket_in),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> Plan {
        Plan {
            repo: PathBuf::from("/srv/project"),
            ide_home: PathBuf::from("/srv/data/ide-home/kiro"),
            ide_binary: PathBuf::from("/usr/share/kiro/kiro"),
            ide_args: vec![
                OsString::from("--password-store=basic"),
                OsString::from(WORKSPACE),
            ],
            display: 20,
            display_socket: PathBuf::from("/tmp/.X11-unix/X20"),
            xauthority: PathBuf::from("/srv/run/xauth"),
            passwd: PathBuf::from("/srv/run/passwd"),
            group: PathBuf::from("/srv/run/group"),
            init_exe: PathBuf::from("/usr/bin/pumpkin-shell"),
            proxy_socket: PathBuf::from("/srv/run/proxy.sock"),
            host_ports: Vec::new(),
            binds: Vec::new(),
            broker_dir: None,
            mirror_socket: None,
            shims: Vec::new(),
        }
    }

    #[test]
    fn binds_come_right_after_the_repo_and_land_below_the_workspace() {
        let mut p = plan();
        p.binds = vec![
            crate::spec::Bind {
                rel: ".git".to_owned(),
                source: PathBuf::from("/srv/project/.git"),
            },
            crate::spec::Bind {
                rel: ".git/hooks".to_owned(),
                source: PathBuf::from("/srv/session/staging/.git/hooks"),
            },
        ];
        let args = strings(&bwrap_args(&p));
        let repo_at = args
            .windows(3)
            .position(|w| w[0] == "--bind" && w[1] == "/srv/project" && w[2] == WORKSPACE);
        let git_at = args.windows(3).position(|w| {
            w[0] == "--bind" && w[1] == "/srv/project/.git" && w[2] == "/workspace/.git"
        });
        let hooks_at = args.windows(3).position(|w| {
            w[0] == "--bind"
                && w[1] == "/srv/session/staging/.git/hooks"
                && w[2] == "/workspace/.git/hooks"
        });
        assert!(repo_at < git_at, "{repo_at:?} {git_at:?}");
        assert!(git_at < hooks_at, "{git_at:?} {hooks_at:?}");
        assert!(hooks_at.is_some());
    }

    #[test]
    fn no_binds_means_only_the_repo_is_bound_at_the_workspace() {
        let args = strings(&bwrap_args(&plan()));
        let under_workspace = args.iter().filter(|a| a.starts_with("/workspace/")).count();
        assert_eq!(under_workspace, 0, "{args:?}");
    }

    fn strings(args: &[OsString]) -> Vec<String> {
        args.iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    /// The pair that follows `flag`, for every occurrence.
    fn values_after(args: &[String], flag: &str) -> Vec<String> {
        args.windows(2)
            .filter(|w| w[0] == flag)
            .map(|w| w[1].clone())
            .collect()
    }

    /// Source paths of every bind mount.
    fn bind_sources(args: &[String]) -> Vec<String> {
        args.windows(3)
            .filter(|w| w[0].starts_with("--") && w[0].contains("bind"))
            .map(|w| w[1].clone())
            .collect()
    }

    #[test]
    fn starts_with_isolation_flags_and_clears_the_environment() {
        let args = strings(&bwrap_args(&plan()));
        for flag in [
            "--unshare-all",
            "--die-with-parent",
            "--new-session",
            "--clearenv",
        ] {
            assert!(args.contains(&flag.to_owned()), "missing {flag}");
        }
    }

    #[test]
    fn never_disables_chromium_or_shares_the_network() {
        let args = strings(&bwrap_args(&plan()));
        for banned in [
            "--no-sandbox",
            "--share-net",
            "--disable-userns",
            "--no-proc",
        ] {
            assert!(
                !args.iter().any(|a| a.contains(banned)),
                "contains {banned}"
            );
        }
    }

    #[test]
    fn the_environment_is_exactly_the_allowlist() {
        let args = strings(&bwrap_args(&plan()));
        let set: Vec<String> = values_after(&args, "--setenv");
        let names: Vec<&str> = args
            .windows(2)
            .filter(|w| w[0] == "--setenv")
            .map(|w| w[1].as_str())
            .collect();
        assert_eq!(names.len(), set.len());
        for name in &names {
            assert!(
                ENV_ALLOWLIST.contains(name) || PROXY_ENV.contains(name) || *name == "PWD",
                "{name} is not in the allowlist"
            );
        }
        for required in ["HOME", "DISPLAY", "XAUTHORITY", "PATH"] {
            assert!(names.contains(&required), "missing {required}");
        }
        // No host variable can reach the IDE through the environment.
        for banned in [
            "SSH_AUTH_SOCK",
            "DBUS_SESSION_BUS_ADDRESS",
            "WAYLAND_DISPLAY",
            "SSH_AGENT_PID",
        ] {
            assert!(!names.contains(&banned), "{banned} must not be set");
        }
    }

    #[test]
    fn host_secrets_and_sockets_are_never_bind_mounted() {
        let args = strings(&bwrap_args(&plan()));
        let sources = bind_sources(&args);
        // The data directory is /srv/data in this plan; the IDE home is a
        // legitimate bind inside it, but the directory itself and anything
        // above the keys must never be a source.
        let data = Path::new("/srv/data");
        let keys = Path::new("/srv/data/keys");
        for source in &sources {
            let source = Path::new(source);
            assert!(source != data, "the data directory is bind-mounted");
            assert!(
                !keys.starts_with(source) || source == Path::new("/"),
                "{}",
                source.display()
            );
        }
        for banned in [
            "/home",
            "/root",
            "/run/user",
            "/var/run",
            "/run/docker.sock",
            "/media",
            "/mnt",
            "/tmp/.X11-unix/X0",
        ] {
            for source in &sources {
                assert!(
                    !(source == banned || source.starts_with(&format!("{banned}/"))),
                    "{source} is bind-mounted"
                );
            }
        }
    }

    #[test]
    fn only_the_nested_display_socket_is_visible_under_tmp_x11() {
        let args = strings(&bwrap_args(&plan()));
        // The plan's socket is /tmp/.X11-unix/X20. Every mention of the X11
        // directory must be that one socket, never the directory itself.
        let x11: Vec<&String> = args.iter().filter(|a| a.contains(".X11-unix")).collect();
        assert!(!x11.is_empty());
        for entry in x11 {
            assert_eq!(entry.as_str(), "/tmp/.X11-unix/X20", "{entry}");
        }
    }

    #[test]
    fn the_repo_and_the_ide_home_are_the_only_writable_binds() {
        let args = strings(&bwrap_args(&plan()));
        let writable: Vec<String> = args
            .windows(3)
            .filter(|w| w[0] == "--bind")
            .map(|w| w[1].clone())
            .collect();
        assert_eq!(writable, vec!["/srv/data/ide-home/kiro", "/srv/project"]);
        // The system is read-only: /usr is the only root bind, and it is ro.
        assert!(
            args.windows(3)
                .any(|w| w[0] == "--ro-bind" && w[1] == "/usr" && w[2] == "/usr")
        );
        assert!(!args.windows(3).any(|w| w[0] == "--bind" && w[1] == "/usr"));
    }

    #[test]
    fn the_ide_command_comes_after_the_init_step_and_is_not_a_shell_string() {
        let args = strings(&bwrap_args(&plan()));
        let init = args.iter().position(|a| a == INIT_IN).unwrap_or(usize::MAX);
        let sep = args.iter().rposition(|a| a == "--").unwrap_or(0);
        assert!(init < sep, "init must come before the IDE command");
        assert_eq!(args[sep + 1], "/usr/share/kiro/kiro");
        assert_eq!(args[sep + 2], "--password-store=basic");
        assert_eq!(args[sep + 3], WORKSPACE);
        assert!(args.iter().all(|a| !a.contains("sh -c")), "no shell string");
    }

    #[test]
    fn landlock_write_paths_are_the_documented_list() {
        let args = strings(&bwrap_args(&plan()));
        let rw = values_after(&args, "--rw");
        assert_eq!(
            rw,
            vec![
                WORKSPACE,
                SANDBOX_HOME,
                "/tmp",
                "/dev",
                "/run",
                "/proc",
                "/tmp/.X11-unix/X20"
            ]
        );
        // /proc is the sandbox's own fresh procfs, mounted by --proc.
        assert!(args.windows(2).any(|w| w[0] == "--proc" && w[1] == "/proc"));
    }

    #[test]
    fn paths_with_spaces_and_newlines_stay_one_argument() {
        let mut odd = plan();
        odd.repo = PathBuf::from("/srv/my project\nwith; rm -rf");
        let args = bwrap_args(&odd);
        assert!(args.iter().any(|a| a == odd.repo.as_os_str()));
    }

    /// A plan with the mirror on, for the mirror tests.
    fn plan_with_mirror() -> Plan {
        Plan {
            mirror_socket: Some(PathBuf::from("/srv/session/mirror.sock")),
            ..plan()
        }
    }

    #[test]
    fn with_a_mirror_the_socket_is_mounted_and_npm_and_pip_are_pointed_at_it() {
        let args: Vec<String> = bwrap_args(&plan_with_mirror())
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let joined = args.join(" ");
        assert!(
            joined.contains("--ro-bind /srv/session/mirror.sock /run/pks/mirror.sock"),
            "{joined}"
        );
        assert!(
            joined.contains("--setenv npm_config_registry http://127.0.0.1:3130/npm/"),
            "{joined}"
        );
        assert!(
            joined.contains("--setenv npm_config_ignore_scripts true"),
            "{joined}"
        );
        assert!(
            joined.contains("--setenv PIP_INDEX_URL http://127.0.0.1:3130/pypi/simple/"),
            "{joined}"
        );
        assert!(
            joined.contains("--setenv PNPM_CONFIG_REGISTRY http://127.0.0.1:3130/npm/"),
            "{joined}"
        );
        assert!(
            joined.contains("--setenv UV_DEFAULT_INDEX http://127.0.0.1:3130/pypi/simple/"),
            "{joined}"
        );
        assert!(joined.contains("--setenv PIP_TIMEOUT 120"), "{joined}");
        assert!(joined.contains("--setenv UV_HTTP_TIMEOUT 120"), "{joined}");
        assert!(
            joined.contains("--mirror-listen 127.0.0.1:3130 --mirror-socket /run/pks/mirror.sock"),
            "{joined}"
        );
    }

    #[test]
    fn without_a_mirror_none_of_the_mirror_settings_appear() {
        let joined = bwrap_args(&plan())
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(!joined.contains("mirror"), "{joined}");
        assert!(!joined.contains("npm_config_registry"), "{joined}");
        assert!(!joined.contains("PIP_INDEX_URL"), "{joined}");
        assert!(!joined.contains("PIP_TIMEOUT"), "{joined}");
    }
}
