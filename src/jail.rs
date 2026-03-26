use anyhow::{Result, bail};
use std::ffi::OsString;
use std::hash::Hasher;
use std::path::PathBuf;
use twox_hash::XxHash64;

pub(crate) const AUTO_NAME_PREFIX: &str = "unnamed-";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct JailPaths {
    pub(crate) name: String,
    pub(crate) state_dir: PathBuf,
    pub(crate) runtime_dir: PathBuf,
    pub(crate) profile_path: PathBuf,
    pub(crate) record_path: PathBuf,
    pub(crate) ipcns_path: PathBuf,
    pub(crate) mntns_path: PathBuf,
}

pub(crate) fn current_pwd() -> Result<PathBuf> {
    if let Some(raw) = std::env::var_os("PWD")
        && !raw.is_empty()
    {
        return Ok(PathBuf::from(raw));
    }
    std::env::current_dir().map_err(|err| anyhow::anyhow!("failed to get current directory: {err}"))
}

pub(crate) fn validate_explicit_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("jail name must not be empty");
    }
    if name == "." || name == ".." {
        bail!("jail name must not be '.' or '..'");
    }
    if name.starts_with(AUTO_NAME_PREFIX) {
        bail!("jail name must not start with reserved prefix '{AUTO_NAME_PREFIX}'");
    }
    if name.contains('/') {
        bail!("jail name must not contain '/'");
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        bail!("jail name may only contain ASCII letters, digits, '.', '_' or '-'");
    }
    Ok(())
}

pub(crate) fn derive_auto_name(normalized_profile: &str) -> String {
    let mut hasher = XxHash64::default();
    hasher.write(normalized_profile.as_bytes());
    format!("{AUTO_NAME_PREFIX}{:016x}", hasher.finish())
}

pub(crate) fn is_generated_name(name: &str) -> bool {
    name.starts_with(AUTO_NAME_PREFIX)
}

pub(crate) fn config_root() -> Result<PathBuf> {
    Ok(home_dir()?.join(".config/cowjail"))
}

pub(crate) fn profiles_dir() -> Result<PathBuf> {
    Ok(config_root()?.join("profiles"))
}

pub(crate) fn profile_definition_path(name: &str) -> Result<PathBuf> {
    Ok(profiles_dir()?.join(name))
}

pub(crate) fn state_root() -> Result<PathBuf> {
    Ok(home_dir()?.join(".local/state/cowjail"))
}

pub(crate) fn runtime_root() -> PathBuf {
    PathBuf::from("/run/cowjail")
}

pub(crate) fn jail_paths(name: &str) -> Result<JailPaths> {
    let state_dir = state_root()?.join(name);
    let runtime_dir = runtime_root().join(name);
    Ok(JailPaths {
        name: name.to_string(),
        profile_path: state_dir.join("profile"),
        record_path: state_dir.join("record"),
        ipcns_path: runtime_dir.join("ipcns"),
        mntns_path: runtime_dir.join("mntns"),
        state_dir,
        runtime_dir,
    })
}

pub(crate) fn list_named_jails() -> Result<Vec<OsString>> {
    let root = state_root()?;
    if !root.exists() {
        return Ok(Vec::new());
    }

    let mut names = Vec::new();
    for entry in fs_err::read_dir(&root)
        .map_err(|err| anyhow::anyhow!("failed to list state root {}: {err}", root.display()))?
    {
        let entry = entry
            .map_err(|err| anyhow::anyhow!("failed to read entry under {}: {err}", root.display()))?;
        let name = entry.file_name();
        let meta = entry.metadata().map_err(|err| {
            anyhow::anyhow!(
                "failed to stat jail state entry {}: {err}",
                entry.path().display()
            )
        })?;
        if meta.is_dir() {
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

fn home_dir() -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .ok_or_else(|| anyhow::anyhow!("HOME is not set; cannot resolve cowjail home paths"))?;
    Ok(PathBuf::from(home))
}
