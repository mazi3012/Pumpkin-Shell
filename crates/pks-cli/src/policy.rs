//! `pumpkin-shell trust`, `pumpkin-shell allow` and `pumpkin-shell policy check`.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use pks_core::Finding;
use pks_core::net::HostPort;
use pks_core::paths::{self, process_env};
use pks_core::policy::{
    self, Effective, PolicyFile, REPO_POLICY_FILE, RepoOutcome, RepoPolicyFile, USER_POLICY_FILE,
};
use pks_core::trust::{TrustState, TrustStore};

const EXIT_FINDINGS: u8 = 1;
const EXIT_ERROR: u8 = 2;

fn fail(message: &str) -> ExitCode {
    eprintln!("{message}");
    ExitCode::from(EXIT_ERROR)
}

struct Dirs {
    config: PathBuf,
    data: PathBuf,
}

fn dirs() -> Result<Dirs, &'static str> {
    const HINT: &str = "cannot find your config and data directories (is HOME set?)";
    Ok(Dirs {
        config: paths::config_dir(&process_env).ok_or(HINT)?,
        data: paths::data_dir(&process_env).ok_or(HINT)?,
    })
}

fn load_user_policy(config: &Path) -> Result<PolicyFile, String> {
    policy::read_user_policy(config)
        .map(|found| found.unwrap_or_else(policy::empty_user_policy))
        .map_err(|error| format!("user policy: {error}"))
}

fn load_repo_policy(repo: &Path) -> Result<Option<RepoPolicyFile>, String> {
    policy::read_repo_policy(repo).map_err(|error| format!("repo policy: {error}"))
}

fn print_findings(findings: &[Finding]) {
    for finding in findings {
        println!(
            "[{:?}] {} {}\n    {}\n    fix: {}",
            finding.severity,
            finding.rule.as_str(),
            finding.target,
            finding.message,
            finding.fix
        );
    }
}

fn print_effective(effective: &Effective) {
    println!("mode: {}", effective.mode.as_str());
    for (rule, action) in &effective.actions {
        println!("  {} = {}", rule.as_str(), action.as_str());
    }
    println!("policy hash: {}", effective.hash());
}

/// `pumpkin-shell trust [PATH]`: pins the repo policy's hash.
pub fn trust(repo: &Path) -> ExitCode {
    let dirs = match dirs() {
        Ok(dirs) => dirs,
        Err(message) => return fail(message),
    };
    let user = match load_user_policy(&dirs.config) {
        Ok(user) => user,
        Err(message) => return fail(&message),
    };
    let file = match load_repo_policy(repo) {
        Ok(Some(file)) => file,
        Ok(None) => return fail(&format!("no {REPO_POLICY_FILE} in {}", repo.display())),
        Err(message) => return fail(&message),
    };
    // Never pin a file that could not be applied.
    let parsed = match std::str::from_utf8(&file.bytes)
        .map_err(|_| "not valid UTF-8".to_owned())
        .and_then(|text| PolicyFile::parse_repo(text).map_err(|error| error.to_string()))
    {
        Ok(parsed) => parsed,
        Err(reason) => {
            return fail(&format!(
                "not trusting {REPO_POLICY_FILE}: it is not valid ({reason})"
            ));
        }
    };
    let (_, findings) = policy::merge(&user, &parsed);

    let store = TrustStore::new(&dirs.data);
    if let Err(error) = store.pin(repo, &file.sha256) {
        return fail(&format!("cannot save the trust pin: {error}"));
    }
    println!("Trusted {REPO_POLICY_FILE} in {}", repo.display());
    println!("  sha256: {}", file.sha256);
    println!("  Editing the file, or moving the repo, means running `pumpkin-shell trust` again.");
    if !findings.is_empty() {
        println!("These entries loosen your policy and will be ignored:");
        print_findings(&findings);
    }
    ExitCode::SUCCESS
}

/// `pumpkin-shell policy check [PATH]`: shows the policy that would apply.
pub fn check(repo: &Path) -> ExitCode {
    let dirs = match dirs() {
        Ok(dirs) => dirs,
        Err(message) => return fail(message),
    };
    let user = match load_user_policy(&dirs.config) {
        Ok(user) => user,
        Err(message) => return fail(&message),
    };
    let file = match load_repo_policy(repo) {
        Ok(file) => file,
        Err(message) => return fail(&message),
    };
    let state = match &file {
        Some(file) => match TrustStore::new(&dirs.data).check(repo, &file.sha256) {
            Ok(state) => state,
            Err(error) => return fail(&format!("trust pins: {error}")),
        },
        None => TrustState::Unpinned,
    };
    let resolution = policy::resolve(&user, file.as_ref(), state);
    let repo_line = match resolution.repo {
        RepoOutcome::Absent => "none",
        RepoOutcome::Applied => "trusted and applied",
        RepoOutcome::Ignored => "not applied",
    };
    println!("repo policy: {repo_line}");
    print_effective(&resolution.effective);
    print_findings(&resolution.findings);
    if resolution.findings.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(EXIT_FINDINGS)
    }
}

/// `pumpkin-shell allow <domain>`: adds a domain to the user policy.
pub fn allow_domain(domain: &str) -> ExitCode {
    let dirs = match dirs() {
        Ok(dirs) => dirs,
        Err(message) => return fail(message),
    };

    // Parse the domain as a host:port endpoint.
    let endpoint = match HostPort::parse(domain) {
        Ok(ep) => ep,
        Err(e) => {
            eprintln!("allow: invalid domain '{domain}': {e}");
            return ExitCode::from(EXIT_ERROR);
        }
    };

    // Read the existing user policy, or start from defaults.
    let mut user = match load_user_policy(&dirs.config) {
        Ok(user) => user,
        Err(message) => return fail(&message),
    };

    // Add the endpoint if not already present.
    if user.allow.contains(&endpoint) {
        println!("allow: {endpoint} is already in the policy");
        return ExitCode::SUCCESS;
    }
    user.allow.insert(endpoint.clone());

    // Write the policy back.
    let path = dirs.config.join(USER_POLICY_FILE);
    if let Err(e) = write_user_policy(&path, &user) {
        return fail(&format!("cannot write policy: {e}"));
    }

    println!("allow: added {endpoint} to {}", path.display());
    ExitCode::SUCCESS
}

/// Writes a user policy to disk as TOML.
fn write_user_policy(path: &Path, policy: &PolicyFile) -> Result<(), String> {
    // Ensure the parent directory exists.
    if let Some(parent) = path.parent()
        && !parent.exists()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        return Err(format!("cannot create {}: {e}", parent.display()));
    }

    // Build the TOML representation.
    let mut lines = vec!["version = 1".to_owned()];
    if let Some(mode) = &policy.mode {
        lines.push(format!("mode = \"{}\"", mode.as_str()));
    }
    if !policy.allow.is_empty() {
        lines.push("[network]".to_owned());
        lines.push("allow = [".to_owned());
        for endpoint in &policy.allow {
            lines.push(format!("  \"{}\",", endpoint));
        }
        lines.push("]".to_owned());
    }
    if !policy.host_ports.is_empty() {
        if !policy.allow.is_empty() {
            // network section already open
        } else {
            lines.push("[network]".to_owned());
        }
        let ports: Vec<String> = policy.host_ports.iter().map(|p| p.to_string()).collect();
        lines.push(format!("host_ports = [{}]", ports.join(", ")));
    }
    if !policy.rules.is_empty() {
        lines.push("[rules]".to_owned());
        for (id, action) in &policy.rules {
            lines.push(format!(
                "\"{}\" = {{ action = \"{}\" }}",
                id.as_str(),
                action.as_str()
            ));
        }
    }

    let content = lines.join("\n") + "\n";
    std::fs::write(path, content).map_err(|e| format!("cannot write {}: {e}", path.display()))
}
