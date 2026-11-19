//! Where pumpkin-shell keeps its host-side files. These directories are
//! never mounted into the sandbox.
//!
//! Linux: `$XDG_CONFIG_HOME/pumpkin-shell` or `~/.config/pumpkin-shell` for
//! policy (PRD FR-POL), `$XDG_DATA_HOME/pumpkin-shell` or
//! `~/.local/share/pumpkin-shell` for keys, logs and trust pins.
//! Windows: `%APPDATA%\Pumpkin-Shell` for policy (PRD FR-POL) and
//! `%LOCALAPPDATA%\Pumpkin-Shell` for data.

use std::ffi::OsString;
use std::path::PathBuf;

/// Reads one environment variable. Tests pass their own lookup instead.
pub type Env<'a> = &'a dyn Fn(&str) -> Option<OsString>;

/// Looks a variable up in the real process environment.
#[must_use]
pub fn process_env(name: &str) -> Option<OsString> {
    std::env::var_os(name)
}

#[cfg(not(windows))]
fn xdg_dir(env: Env<'_>, variable: &str, home_relative: &str) -> Option<PathBuf> {
    // The XDG spec says a relative value must be ignored.
    if let Some(value) = env(variable) {
        let path = PathBuf::from(value);
        if path.is_absolute() {
            return Some(path.join("pumpkin-shell"));
        }
    }
    let home = PathBuf::from(env("HOME")?);
    if !home.is_absolute() {
        return None;
    }
    Some(home.join(home_relative).join("pumpkin-shell"))
}

#[cfg(windows)]
fn windows_dir(env: Env<'_>, variable: &str) -> Option<PathBuf> {
    let path = PathBuf::from(env(variable)?);
    path.is_absolute().then(|| path.join("Pumpkin-Shell"))
}

/// Directory of the user policy file.
#[must_use]
pub fn config_dir(env: Env<'_>) -> Option<PathBuf> {
    #[cfg(windows)]
    {
        windows_dir(env, "APPDATA")
    }
    #[cfg(not(windows))]
    {
        xdg_dir(env, "XDG_CONFIG_HOME", ".config")
    }
}

/// Directory for keys, logs and trust pins.
#[must_use]
pub fn data_dir(env: Env<'_>) -> Option<PathBuf> {
    #[cfg(windows)]
    {
        windows_dir(env, "LOCALAPPDATA")
    }
    #[cfg(not(windows))]
    {
        xdg_dir(env, "XDG_DATA_HOME", ".local/share")
    }
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn lookup(pairs: &[(&'static str, &'static str)]) -> impl Fn(&str) -> Option<OsString> {
        let map: HashMap<_, _> = pairs.iter().copied().collect();
        move |name: &str| map.get(name).map(OsString::from)
    }

    #[test]
    fn falls_back_to_home_directories() {
        let env = lookup(&[("HOME", "/home/u")]);
        assert_eq!(
            config_dir(&env),
            Some(PathBuf::from("/home/u/.config/pumpkin-shell"))
        );
        assert_eq!(
            data_dir(&env),
            Some(PathBuf::from("/home/u/.local/share/pumpkin-shell"))
        );
    }

    #[test]
    fn uses_xdg_variables_when_absolute() {
        let env = lookup(&[
            ("HOME", "/home/u"),
            ("XDG_CONFIG_HOME", "/cfg"),
            ("XDG_DATA_HOME", "/data"),
        ]);
        assert_eq!(config_dir(&env), Some(PathBuf::from("/cfg/pumpkin-shell")));
        assert_eq!(data_dir(&env), Some(PathBuf::from("/data/pumpkin-shell")));
    }

    #[test]
    fn ignores_relative_xdg_values() {
        let env = lookup(&[
            ("HOME", "/home/u"),
            ("XDG_CONFIG_HOME", "relative/dir"),
            ("XDG_DATA_HOME", ""),
        ]);
        assert_eq!(
            config_dir(&env),
            Some(PathBuf::from("/home/u/.config/pumpkin-shell"))
        );
        assert_eq!(
            data_dir(&env),
            Some(PathBuf::from("/home/u/.local/share/pumpkin-shell"))
        );
    }

    #[test]
    fn gives_nothing_without_a_usable_home() {
        assert_eq!(config_dir(&lookup(&[])), None);
        assert_eq!(data_dir(&lookup(&[("HOME", "relative")])), None);
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn lookup(pairs: &[(&'static str, &'static str)]) -> impl Fn(&str) -> Option<OsString> {
        let map: HashMap<_, _> = pairs.iter().copied().collect();
        move |name: &str| map.get(name).map(OsString::from)
    }

    #[test]
    fn uses_appdata_and_localappdata() {
        let env = lookup(&[
            ("APPDATA", r"C:\Users\u\AppData\Roaming"),
            ("LOCALAPPDATA", r"C:\Users\u\AppData\Local"),
        ]);
        assert_eq!(
            config_dir(&env),
            Some(PathBuf::from(r"C:\Users\u\AppData\Roaming\Pumpkin-Shell"))
        );
        assert_eq!(
            data_dir(&env),
            Some(PathBuf::from(r"C:\Users\u\AppData\Local\Pumpkin-Shell"))
        );
    }

    #[test]
    fn gives_nothing_for_a_missing_or_relative_value() {
        assert_eq!(config_dir(&lookup(&[])), None);
        assert_eq!(data_dir(&lookup(&[("LOCALAPPDATA", "relative")])), None);
    }
}
