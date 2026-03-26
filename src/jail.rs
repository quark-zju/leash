use anyhow::{Result, bail};
use fs_err as fs;
use std::ffi::OsString;
use std::hash::Hasher;
use std::path::{Path, PathBuf};
use twox_hash::XxHash64;

use crate::cli;
use crate::profile_loader;

pub(crate) const AUTO_NAME_PREFIX: &str = "unnamed-";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct JailLayout {
    pub(crate) config_root: PathBuf,
    pub(crate) state_root: PathBuf,
    pub(crate) runtime_root: PathBuf,
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResolveMode {
    EnsureExists,
    MustExist,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedJail {
    pub(crate) name: String,
    pub(crate) generated: bool,
    pub(crate) paths: JailPaths,
    pub(crate) normalized_profile: String,
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

pub(crate) fn profile_definition_path(name: &str) -> Result<PathBuf> {
    Ok(profile_definition_path_in(&layout()?, name))
}

pub(crate) fn runtime_root() -> PathBuf {
    PathBuf::from("/run/cowjail")
}

pub(crate) fn jail_paths_in(layout: &JailLayout, name: &str) -> JailPaths {
    let state_dir = layout.state_root.join(name);
    let runtime_dir = layout.runtime_root.join(name);
    JailPaths {
        name: name.to_string(),
        profile_path: state_dir.join("profile"),
        record_path: state_dir.join("record"),
        ipcns_path: runtime_dir.join("ipcns"),
        mntns_path: runtime_dir.join("mntns"),
        state_dir,
        runtime_dir,
    }
}

pub(crate) fn list_named_jails() -> Result<Vec<OsString>> {
    list_named_jails_in(&layout()?)
}

pub(crate) fn list_named_jails_in(layout: &JailLayout) -> Result<Vec<OsString>> {
    let root = &layout.state_root;
    if !root.exists() {
        return Ok(Vec::new());
    }

    let mut names = Vec::new();
    for entry in fs_err::read_dir(&root)
        .map_err(|err| anyhow::anyhow!("failed to list state root {}: {err}", root.display()))?
    {
        let entry = entry.map_err(|err| {
            anyhow::anyhow!("failed to read entry under {}: {err}", root.display())
        })?;
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

pub(crate) fn resolve(
    name: Option<&str>,
    profile: Option<&str>,
    mode: ResolveMode,
) -> Result<ResolvedJail> {
    resolve_in(&layout()?, name, profile, mode)
}

pub(crate) fn resolve_in(
    layout: &JailLayout,
    name: Option<&str>,
    profile: Option<&str>,
    mode: ResolveMode,
) -> Result<ResolvedJail> {
    match name {
        Some(name) => resolve_named(layout, name, profile, mode),
        None => resolve_generated(layout, profile, mode),
    }
}

fn resolve_named(
    layout: &JailLayout,
    name: &str,
    profile: Option<&str>,
    mode: ResolveMode,
) -> Result<ResolvedJail> {
    let paths = jail_paths_in(layout, name);
    if paths.state_dir.exists() {
        let normalized_profile = fs::read_to_string(&paths.profile_path).map_err(|err| {
            anyhow::anyhow!(
                "failed to read jail profile file {}: {err}",
                paths.profile_path.display()
            )
        })?;
        if let Some(profile_name) = profile {
            let loaded = profile_loader::load_profile(std::path::Path::new(profile_name))?;
            if loaded.normalized_source != normalized_profile {
                bail!("existing jail '{name}' is bound to a different profile");
            }
        }
        return Ok(ResolvedJail {
            name: name.to_string(),
            generated: is_generated_name(name),
            paths,
            normalized_profile,
        });
    }

    if mode == ResolveMode::MustExist {
        bail!("jail does not exist: {name}");
    }

    validate_explicit_name(name)?;
    let profile_name = profile.unwrap_or(cli::DEFAULT_PROFILE);
    let loaded = profile_loader::load_profile(std::path::Path::new(profile_name))?;
    materialize_jail(&paths, &loaded.normalized_source)?;
    Ok(ResolvedJail {
        name: name.to_string(),
        generated: false,
        paths,
        normalized_profile: loaded.normalized_source,
    })
}

fn resolve_generated(
    layout: &JailLayout,
    profile: Option<&str>,
    mode: ResolveMode,
) -> Result<ResolvedJail> {
    let profile_name = profile.unwrap_or(cli::DEFAULT_PROFILE);
    let loaded = profile_loader::load_profile(std::path::Path::new(profile_name))?;
    let name = derive_auto_name(&loaded.normalized_source);
    let paths = jail_paths_in(layout, &name);
    if !paths.state_dir.exists() {
        if mode == ResolveMode::MustExist {
            bail!("jail does not exist: {name}");
        }
        materialize_jail(&paths, &loaded.normalized_source)?;
    }
    Ok(ResolvedJail {
        name,
        generated: true,
        paths,
        normalized_profile: loaded.normalized_source,
    })
}

pub(crate) fn materialize_jail(paths: &JailPaths, normalized_profile: &str) -> Result<()> {
    fs::create_dir_all(&paths.state_dir).map_err(|err| {
        anyhow::anyhow!(
            "failed to create jail state directory {}: {err}",
            paths.state_dir.display()
        )
    })?;
    fs::write(&paths.profile_path, normalized_profile).map_err(|err| {
        anyhow::anyhow!(
            "failed to write jail profile file {}: {err}",
            paths.profile_path.display()
        )
    })?;
    if !paths.record_path.exists() {
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&paths.record_path)
            .map_err(|err| {
                anyhow::anyhow!(
                    "failed to create jail record file {}: {err}",
                    paths.record_path.display()
                )
            })?;
    }
    Ok(())
}

pub(crate) fn remove_jail(paths: &JailPaths) -> Result<()> {
    crate::ns_runtime::remove_runtime(paths)?;
    fs::remove_dir_all(&paths.state_dir).map_err(|err| {
        anyhow::anyhow!(
            "failed to remove jail state directory {}: {err}",
            paths.state_dir.display()
        )
    })
}

fn home_dir() -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .ok_or_else(|| anyhow::anyhow!("HOME is not set; cannot resolve cowjail home paths"))?;
    Ok(PathBuf::from(home))
}

pub(crate) fn layout() -> Result<JailLayout> {
    Ok(layout_from_home(&home_dir()?))
}

pub(crate) fn layout_from_home(home: &Path) -> JailLayout {
    JailLayout {
        config_root: config_root_from_home(home),
        state_root: state_root_from_home(home),
        runtime_root: runtime_root(),
    }
}

pub(crate) fn config_root_from_home(home: &Path) -> PathBuf {
    home.join(".config/cowjail")
}

pub(crate) fn state_root_from_home(home: &Path) -> PathBuf {
    home.join(".local/state/cowjail")
}

pub(crate) fn profile_definition_path_in(layout: &JailLayout, name: &str) -> PathBuf {
    layout.config_root.join("profiles").join(name)
}
