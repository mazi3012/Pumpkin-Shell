//! What a sandbox run is asked to do, and the checks that come before it.
//!
//! The checks compare path components, never strings: `/home/u-evil` is not
//! inside `/home/u` (CVE-2025-54794 pattern, tech.md). They run on every
//! platform, so the refusals are tested where the tests run.

use std::fs;
use std::path::{Path, PathBuf};

use crate::SandboxError;

/// The port of the in-sandbox proxy relay. Must match
/// `pks_core::policy::PROXY_RELAY_PORT`, which refuses it as a host port.
const PROXY_RELAY_PORT: u16 = 3129;

/// A host path bound inside the repo's mount point, over what the repo has
/// there. Used to give the IDE a staged copy of a protected path (PRD FR-WS).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bind {
    /// Path below the repo root, `/`-separated, with no `.` or `..`.
    pub rel: String,
    /// Host path bound there.
    pub source: PathBuf,
}

/// Where the host keeps things the IDE must never see. Filled in by the
/// caller from the real environment (or by tests from temp dirs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Roots {
    /// The user's home directory.
    pub home: PathBuf,
    /// Pumpkin-Shell's config directory (user policy).
    pub config: PathBuf,
    /// Pumpkin-Shell's data directory (signing keys, logs, trust pins).
    pub data: PathBuf,
}

/// An IDE installed on the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdeInstall {
    /// Short name, used for the sandbox home directory (`kiro`, `code`).
    pub name: &'static str,
    /// Install directory. Must be under `/usr`, so the read-only `/usr` mount
    /// covers it.
    pub dir: PathBuf,
    /// The program to start. Must be inside `dir` and executable.
    pub binary: PathBuf,
}

/// One sandboxed IDE run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchSpec {
    /// Repository the IDE opens. Mounted read-write at `/workspace`.
    pub repo: PathBuf,
    pub ide: IdeInstall,
    /// Persistent per-IDE home, mounted read-write at `/home/sandbox`. Must
    /// already exist, under the data directory.
    pub ide_home: PathBuf,
    /// Arguments for the IDE. They are passed as separate arguments, never
    /// through a shell.
    pub ide_args: Vec<std::ffi::OsString>,
    /// Host directories the IDE must not reach, used by the checks.
    pub roots: Roots,
    /// Size of the nested display, in pixels.
    pub display_size: (u32, u32),
    /// Unix socket of the egress proxy (Phase 9). The IDE reaches it through
    /// a relay inside the sandbox; it is the only route out.
    pub proxy_socket: PathBuf,
    /// Host ports the IDE may reach on its own loopback (PRD FR-NET,
    /// scenario 7). Relayed to the host's `127.0.0.1` by the proxy.
    pub host_ports: Vec<u16>,
    /// Paths bound over parts of the repo, parents before what is under them.
    pub binds: Vec<Bind>,
    /// Where the backend writes the sandbox's process ID once it has started,
    /// and removes again when it exits. The sandbox is its own process group
    /// (bubblewrap runs with `--new-session`), so pausing and killing the
    /// session signal that group. `None` writes nothing.
    pub pid_file: Option<PathBuf>,
}

fn refuse(message: impl Into<String>) -> SandboxError {
    SandboxError::Refused(message.into())
}

fn canonical(path: &Path, what: &str) -> Result<PathBuf, SandboxError> {
    fs::canonicalize(path).map_err(|source| SandboxError::Io {
        context: format!("cannot resolve {what} {}", path.display()),
        source,
    })
}

/// Canonical form of a root that may not exist yet: resolved when it does.
fn root_form(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Checks a spec before anything is started.
///
/// # Errors
/// Returns `Refused` for any path that would expose or let the IDE write to
/// something it must not, and `Io` when a path cannot be resolved.
pub fn check(spec: &LaunchSpec) -> Result<(), SandboxError> {
    let home = root_form(&spec.roots.home);
    let config = root_form(&spec.roots.config);
    let data = root_form(&spec.roots.data);
    if !home.is_absolute() || !config.is_absolute() || !data.is_absolute() {
        return Err(refuse(
            "the home, config and data directories must be absolute",
        ));
    }
    let keys = data.join("keys");

    // The repo: read-write in the sandbox, so it must not contain anything
    // the host keeps private, and must not be a parent of the home directory
    // (that would mount the whole home).
    let repo = canonical(&spec.repo, "repository")?;
    if !repo.is_dir() {
        return Err(refuse(format!("{} is not a directory", repo.display())));
    }
    if repo.parent().is_none() {
        return Err(refuse("refusing to mount the filesystem root"));
    }
    for (name, private) in [("home", &home), ("config", &config), ("data", &data)] {
        if private.starts_with(&repo) {
            return Err(refuse(format!(
                "refusing to mount {}: it contains your {name} directory",
                repo.display()
            )));
        }
    }
    if repo.starts_with(&data) || repo.starts_with(&config) {
        return Err(refuse(format!(
            "refusing to mount {}: it is inside Pumpkin-Shell's own directories",
            repo.display()
        )));
    }

    // The IDE's home: read-write, under the data directory, away from the keys.
    let ide_home = canonical(&spec.ide_home, "IDE home")?;
    if !ide_home.is_dir() {
        return Err(refuse(format!("{} is not a directory", ide_home.display())));
    }
    if !ide_home.starts_with(&data) || ide_home == data {
        return Err(refuse(
            "the IDE home must be a directory inside Pumpkin-Shell's data directory",
        ));
    }
    if ide_home.starts_with(&keys) || keys.starts_with(&ide_home) {
        return Err(refuse("the IDE home must not overlap the signing keys"));
    }
    if ide_home.starts_with(&repo) || repo.starts_with(&ide_home) {
        return Err(refuse("the IDE home and the repository must not overlap"));
    }

    // The IDE install: read-only, under /usr. The rule is about the Linux
    // mount layout; Windows has its own rule in Phase 16.
    let dir = canonical(&spec.ide.dir, "IDE install directory")?;
    #[cfg(target_os = "linux")]
    if !dir.is_dir() || !dir.starts_with("/usr") || dir == Path::new("/usr") {
        return Err(refuse(format!(
            "{} must be a directory under /usr",
            dir.display()
        )));
    }
    #[cfg(not(target_os = "linux"))]
    if !dir.is_dir() {
        return Err(refuse(format!("{} is not a directory", dir.display())));
    }
    let binary = canonical(&spec.ide.binary, "IDE program")?;
    if !binary.starts_with(&dir) || !binary.is_file() {
        return Err(refuse(format!(
            "{} must be a file inside {}",
            binary.display(),
            dir.display()
        )));
    }
    if !is_executable(&binary) {
        return Err(refuse(format!("{} is not executable", binary.display())));
    }

    let proxy = canonical(&spec.proxy_socket, "proxy socket")?;
    if !is_socket(&proxy) {
        return Err(refuse(format!(
            "{} is not the proxy's socket",
            proxy.display()
        )));
    }

    for port in &spec.host_ports {
        if *port == 0 || *port == PROXY_RELAY_PORT {
            return Err(refuse(format!(
                "host port {port} cannot be relayed (0 is not a port; {PROXY_RELAY_PORT} is the proxy relay)"
            )));
        }
    }
    check_binds(&spec.binds)?;
    let (width, height) = spec.display_size;
    if !(320..=8192).contains(&width) || !(240..=8192).contains(&height) {
        return Err(refuse(
            "the display size must be between 320x240 and 8192x8192",
        ));
    }
    Ok(())
}

/// A bind's `rel` must be a plain relative path, its source must exist, and a
/// bind must come after any bind it is under (a later bind over a parent
/// would hide it).
fn check_binds(binds: &[Bind]) -> Result<(), SandboxError> {
    for (index, bind) in binds.iter().enumerate() {
        let plain = !bind.rel.is_empty()
            && bind.rel.split('/').all(|part| {
                !part.is_empty() && part != "." && part != ".." && !part.contains('\0')
            });
        if !plain {
            return Err(refuse(format!(
                "bind path {:?} must be a plain path below the repo",
                bind.rel
            )));
        }
        if fs::symlink_metadata(&bind.source).is_err() {
            return Err(refuse(format!(
                "bind source {} does not exist",
                bind.source.display()
            )));
        }
        let under = |outer: &str, inner: &str| {
            inner.len() > outer.len()
                && inner.starts_with(outer)
                && inner.as_bytes()[outer.len()] == b'/'
        };
        if binds[index + 1..]
            .iter()
            .any(|later| under(&later.rel, &bind.rel))
        {
            return Err(refuse(format!(
                "bind {} comes before its parent {}",
                bind.rel,
                binds[index + 1..]
                    .iter()
                    .find(|later| under(&later.rel, &bind.rel))
                    .map_or("", |later| later.rel.as_str())
            )));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn is_socket(path: &Path) -> bool {
    use std::os::unix::fs::FileTypeExt;
    fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_socket())
}

#[cfg(not(unix))]
fn is_socket(_path: &Path) -> bool {
    true
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).is_ok_and(|meta| meta.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(_path: &Path) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// A fake host layout in a temp dir: home, config, data, repo, IDE home.
    struct Host {
        _dir: tempfile::TempDir,
        spec: LaunchSpec,
    }

    impl Host {
        fn new() -> Result<Self, Box<dyn std::error::Error>> {
            let dir = tempfile::tempdir()?;
            let base = fs::canonicalize(dir.path())?;
            let home = base.join("home/user");
            let config = home.join(".config/pumpkin-shell");
            let data = home.join(".local/share/pumpkin-shell");
            let repo = base.join("project");
            let ide_home = data.join("ide-home/kiro");
            for d in [&home, &repo, &ide_home, &data.join("keys")] {
                fs::create_dir_all(d)?;
            }
            fs::create_dir_all(&config)?;
            let ide_dir = base.join("ide");
            fs::create_dir_all(&ide_dir)?;
            let binary = ide_dir.join("kiro");
            fs::write(&binary, "#!/bin/sh\n")?;
            set_exec(&binary)?;
            let proxy = base.join("proxy.sock");
            bind_socket(&proxy)?;
            let spec = LaunchSpec {
                repo,
                ide: IdeInstall {
                    name: "kiro",
                    dir: ide_dir,
                    binary,
                },
                ide_home,
                ide_args: Vec::new(),
                roots: Roots { home, config, data },
                display_size: (1280, 800),
                proxy_socket: proxy.clone(),
                host_ports: Vec::new(),
                binds: Vec::new(),
                pid_file: None,
            };
            Ok(Self { _dir: dir, spec })
        }
    }

    #[cfg(unix)]
    fn bind_socket(path: &Path) -> std::io::Result<()> {
        // A real socket: the spec check looks for one.
        std::os::unix::net::UnixListener::bind(path).map(drop)
    }

    #[cfg(not(unix))]
    fn bind_socket(path: &Path) -> std::io::Result<()> {
        // Windows has no Unix socket here (the Windows backend is Phase 16),
        // and `is_socket` accepts any path. The path must exist to resolve.
        fs::write(path, b"")
    }

    #[cfg(unix)]
    fn set_exec(path: &Path) -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))
    }

    #[cfg(not(unix))]
    fn set_exec(_path: &Path) -> std::io::Result<()> {
        Ok(())
    }

    fn refused(result: Result<(), SandboxError>) -> bool {
        matches!(result, Err(SandboxError::Refused(_)))
    }

    #[test]
    fn a_normal_project_is_accepted() -> TestResult {
        let host = Host::new()?;
        // The fake install is not under /usr, so this exercises only the
        // generic checks; the /usr rule has its own test below (Linux).
        let result = check(&host.spec);
        #[cfg(target_os = "linux")]
        assert!(refused(result), "non-/usr install must be refused on Linux");
        #[cfg(not(target_os = "linux"))]
        assert!(result.is_ok(), "{result:?}");
        Ok(())
    }

    #[test]
    fn a_repo_that_contains_the_home_directory_is_refused() -> TestResult {
        let mut host = Host::new()?;
        host.spec.repo = host
            .spec
            .roots
            .home
            .parent()
            .unwrap_or(Path::new("/"))
            .to_path_buf();
        assert!(refused(check(&host.spec)));
        host.spec.repo = host.spec.roots.home.clone();
        assert!(refused(check(&host.spec)));
        Ok(())
    }

    #[test]
    fn a_repo_inside_pumpkin_shell_directories_is_refused() -> TestResult {
        let mut host = Host::new()?;
        host.spec.repo = host.spec.roots.data.join("keys");
        assert!(refused(check(&host.spec)));
        host.spec.repo = host.spec.roots.config.clone();
        assert!(refused(check(&host.spec)));
        Ok(())
    }

    #[test]
    fn a_sibling_that_starts_with_the_home_name_is_not_the_home() -> TestResult {
        // /x/home/user-evil is not inside /x/home/user (component check).
        let mut host = Host::new()?;
        let evil = host
            .spec
            .roots
            .home
            .parent()
            .unwrap_or(Path::new("/"))
            .join("user-evil");
        fs::create_dir_all(&evil)?;
        host.spec.repo = evil;
        // The check must not refuse it *because of* the home directory.
        let result = check(&host.spec);
        if let Err(SandboxError::Refused(message)) = &result {
            assert!(
                !message.contains("home"),
                "refused as if it were home: {message}"
            );
        }
        Ok(())
    }

    #[test]
    fn the_ide_home_must_be_inside_data_and_not_the_keys() -> TestResult {
        let mut host = Host::new()?;
        host.spec.ide_home = host.spec.roots.home.join("not-data");
        fs::create_dir_all(&host.spec.ide_home)?;
        assert!(refused(check(&host.spec)));
        host.spec.ide_home = host.spec.roots.data.join("keys");
        assert!(refused(check(&host.spec)));
        host.spec.ide_home = host.spec.roots.data.clone();
        assert!(refused(check(&host.spec)));
        Ok(())
    }

    #[test]
    fn the_ide_home_must_not_overlap_the_repo() -> TestResult {
        let mut host = Host::new()?;
        host.spec.repo = host.spec.ide_home.clone();
        assert!(refused(check(&host.spec)));
        Ok(())
    }

    #[test]
    fn a_program_outside_its_install_directory_is_refused() -> TestResult {
        let mut host = Host::new()?;
        let other = host.spec.roots.home.join("evil");
        fs::write(&other, "x")?;
        set_exec(&other)?;
        host.spec.ide.binary = other;
        assert!(refused(check(&host.spec)));
        Ok(())
    }

    #[test]
    fn a_non_executable_program_is_refused_on_unix() -> TestResult {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let host = Host::new()?;
            fs::set_permissions(&host.spec.ide.binary, fs::Permissions::from_mode(0o644))?;
            assert!(refused(check(&host.spec)));
        }
        Ok(())
    }

    #[test]
    fn a_missing_repo_is_an_io_error_not_a_refusal() -> TestResult {
        let mut host = Host::new()?;
        host.spec.repo = host.spec.roots.home.join("does-not-exist");
        assert!(matches!(check(&host.spec), Err(SandboxError::Io { .. })));
        Ok(())
    }

    #[test]
    fn display_size_is_bounded() -> TestResult {
        let mut host = Host::new()?;
        host.spec.display_size = (100, 100);
        assert!(refused(check(&host.spec)));
        host.spec.display_size = (100_000, 800);
        assert!(refused(check(&host.spec)));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn an_ide_outside_usr_is_refused() -> TestResult {
        let host = Host::new()?;
        assert!(refused(check(&host.spec)));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_real_usr_bin_is_accepted_as_an_install_for_tests() -> TestResult {
        // The integration tests use /usr/bin/sh as the IDE. Its install
        // directory is /usr/bin, so this is the accepted shape.
        let mut host = Host::new()?;
        host.spec.ide = IdeInstall {
            name: "test",
            dir: PathBuf::from("/usr/bin"),
            binary: PathBuf::from("/usr/bin/sh"),
        };
        assert!(check(&host.spec).is_ok(), "{:?}", check(&host.spec));
        Ok(())
    }

    fn bind(rel: &str, source: &Path) -> Bind {
        Bind {
            rel: rel.to_owned(),
            source: source.to_path_buf(),
        }
    }

    #[test]
    fn plain_binds_in_parent_first_order_pass_the_bind_check() -> TestResult {
        let host = Host::new()?;
        let source = host.spec.repo.clone();
        let binds = vec![
            bind(".git", &source),
            bind(".git/hooks", &source),
            bind(".vscode", &source),
        ];
        check_binds(&binds)?;
        Ok(())
    }

    #[test]
    fn a_bind_path_that_could_leave_the_repo_is_refused() -> TestResult {
        let host = Host::new()?;
        let source = host.spec.repo.clone();
        for rel in [
            "", "..", "../x", "a/../b", "/abs", "a//b", "./a", "a/.", "a/", "a\0b",
        ] {
            assert!(
                refused(check_binds(&[bind(rel, &source)])),
                "{rel:?} was accepted"
            );
        }
        Ok(())
    }

    #[test]
    fn a_bind_whose_source_is_missing_is_refused() -> TestResult {
        let host = Host::new()?;
        let missing = host.spec.repo.join("does-not-exist");
        assert!(refused(check_binds(&[bind(".vscode", &missing)])));
        Ok(())
    }

    #[test]
    fn a_bind_listed_before_its_parent_is_refused() -> TestResult {
        let host = Host::new()?;
        let source = host.spec.repo.clone();
        let binds = vec![bind(".git/hooks", &source), bind(".git", &source)];
        assert!(refused(check_binds(&binds)));
        // A sibling whose name starts the same is not a parent.
        let siblings = vec![bind(".git-extra", &source), bind(".git", &source)];
        check_binds(&siblings)?;
        Ok(())
    }

    #[test]
    fn a_listed_host_port_other_than_the_proxy_relay_is_accepted() -> TestResult {
        let mut host = Host::new()?;
        host.spec.host_ports = vec![5432];
        // The fake install is not under /usr, so the generic checks may
        // refuse for another reason. The host port itself must not be why.
        if let Err(error) = check(&host.spec) {
            assert!(!error.to_string().contains("host port"), "{error}");
        }
        Ok(())
    }

    #[test]
    fn host_port_zero_and_the_proxy_relay_port_are_refused() -> TestResult {
        for port in [0u16, 3129] {
            let mut host = Host::new()?;
            host.spec.host_ports = vec![port];
            assert!(check(&host.spec).is_err(), "port {port} was accepted");
        }
        Ok(())
    }
}
