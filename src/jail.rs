use anyhow::{Result, bail};
use fs_err as fs;
use std::ffi::{CString, OsString};
use std::hash::Hasher;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use twox_hash::XxHash64;

use crate::cli;
use crate::profile_loader::{self, RuleSource};

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
    pub(crate) profile_sources_path: PathBuf,
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
    pub(crate) normalized_rule_sources: Option<Vec<RuleSource>>,
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
    format!("{:016x}", hasher.finish())
}

pub(crate) fn profile_definition_path(name: &str) -> Result<PathBuf> {
    Ok(profile_definition_path_in(&layout()?, name))
}

pub(crate) fn runtime_root() -> PathBuf {
    if let Some(raw) = std::env::var_os("XDG_RUNTIME_DIR")
        && !raw.is_empty()
    {
        return PathBuf::from(raw).join("cowjail");
    }
    let uid = unsafe { libc::getuid() };
    PathBuf::from(format!("/run/user/{uid}/cowjail"))
}

pub(crate) fn jail_paths_in(layout: &JailLayout, name: &str) -> JailPaths {
    let state_dir = layout.state_root.join(name);
    let runtime_dir = layout.runtime_root.join(name);
    JailPaths {
        name: name.to_string(),
        profile_path: state_dir.join("profile"),
        profile_sources_path: state_dir.join("profile.sources"),
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
    for entry in fs_err::read_dir(root)
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
        let normalized_rule_sources = read_rule_sources(&paths.profile_sources_path)?;
        return Ok(ResolvedJail {
            name: name.to_string(),
            generated: false,
            paths,
            normalized_profile,
            normalized_rule_sources,
        });
    }

    if mode == ResolveMode::MustExist {
        bail!("jail does not exist: {name}");
    }

    validate_explicit_name(name)?;
    let profile_name = profile.unwrap_or(cli::DEFAULT_PROFILE);
    let loaded = profile_loader::load_profile(std::path::Path::new(profile_name))?;
    materialize_jail(
        &paths,
        &loaded.normalized_source,
        Some(&loaded.normalized_rule_sources),
    )?;
    Ok(ResolvedJail {
        name: name.to_string(),
        generated: false,
        paths,
        normalized_profile: loaded.normalized_source,
        normalized_rule_sources: Some(loaded.normalized_rule_sources),
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
        materialize_jail(
            &paths,
            &loaded.normalized_source,
            Some(&loaded.normalized_rule_sources),
        )?;
    }
    Ok(ResolvedJail {
        name,
        generated: true,
        paths,
        normalized_profile: loaded.normalized_source,
        normalized_rule_sources: Some(loaded.normalized_rule_sources),
    })
}

pub(crate) fn materialize_jail(
    paths: &JailPaths,
    normalized_profile: &str,
    normalized_rule_sources: Option<&[RuleSource]>,
) -> Result<()> {
    fs::create_dir_all(&paths.state_dir).map_err(|err| {
        anyhow::anyhow!(
            "failed to create jail state directory {}: {err}",
            paths.state_dir.display()
        )
    })?;
    ensure_owned_by_real_user(&paths.state_dir)?;
    fs::write(&paths.profile_path, normalized_profile).map_err(|err| {
        anyhow::anyhow!(
            "failed to write jail profile file {}: {err}",
            paths.profile_path.display()
        )
    })?;
    ensure_owned_by_real_user(&paths.profile_path)?;
    if let Some(rule_sources) = normalized_rule_sources {
        let cbor = serde_cbor::to_vec(&rule_sources.to_vec())
            .map_err(|err| anyhow::anyhow!("failed to encode profile sources CBOR: {err}"))?;
        fs::write(&paths.profile_sources_path, cbor).map_err(|err| {
            anyhow::anyhow!(
                "failed to write jail profile sources file {}: {err}",
                paths.profile_sources_path.display()
            )
        })?;
        ensure_owned_by_real_user(&paths.profile_sources_path)?;
    }
    Ok(())
}

pub(crate) fn remove_jail(paths: &JailPaths) -> Result<()> {
    crate::ns_runtime::remove_runtime(paths)?;
    remove_known_state_artifacts(paths)
}

pub(crate) fn home_dir() -> Result<PathBuf> {
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

pub(crate) fn state_root_from_home(_home: &Path) -> PathBuf {
    runtime_root().join("state")
}

pub(crate) fn profile_definition_path_in(layout: &JailLayout, name: &str) -> PathBuf {
    layout.config_root.join("profiles").join(name)
}

fn remove_known_state_artifacts(paths: &JailPaths) -> Result<()> {
    if !paths.state_dir.exists() {
        return Ok(());
    }
    let unknown = list_unknown_state_entries(paths)?;
    if !unknown.is_empty() {
        bail!(
            "refusing to remove state directory {}: found unknown entries: {}",
            paths.state_dir.display(),
            unknown.join(", ")
        );
    }

    remove_file_if_exists_with_owner_fix(&paths.state_dir, &paths.profile_path)?;
    remove_file_if_exists_with_owner_fix(&paths.state_dir, &paths.profile_sources_path)?;
    match fs::remove_dir(&paths.state_dir) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(anyhow::anyhow!(
            "failed to remove jail state directory {}: {err}",
            paths.state_dir.display()
        )),
    }
}

fn list_unknown_state_entries(paths: &JailPaths) -> Result<Vec<String>> {
    let mut unknown = Vec::new();
    for entry in fs::read_dir(&paths.state_dir).map_err(|err| {
        anyhow::anyhow!(
            "failed to read state directory {}: {err}",
            paths.state_dir.display()
        )
    })? {
        let entry = entry.map_err(|err| {
            anyhow::anyhow!(
                "failed to read entry in state directory {}: {err}",
                paths.state_dir.display()
            )
        })?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            unknown.push(format!("{:?}", name));
            continue;
        };
        if !matches!(name, "profile" | "profile.sources") {
            unknown.push(name.to_string());
        }
    }
    unknown.sort();
    Ok(unknown)
}

fn read_rule_sources(path: &Path) -> Result<Option<Vec<RuleSource>>> {
    let data = match fs::read(path) {
        Ok(data) => data,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(anyhow::anyhow!(
                "failed to read jail profile sources file {}: {err}",
                path.display()
            ));
        }
    };
    let parsed = serde_cbor::from_slice::<Vec<RuleSource>>(&data).map_err(|err| {
        anyhow::anyhow!(
            "failed to parse jail profile sources file {}: {err}",
            path.display()
        )
    })?;
    Ok(Some(parsed))
}

fn remove_file_if_exists_with_owner_fix(state_dir: &Path, path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            ensure_owned_by_real_user(state_dir)?;
            match fs::remove_file(path) {
                Ok(()) => Ok(()),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(err) => Err(anyhow::anyhow!(
                    "failed to remove file {}: {err}",
                    path.display()
                )),
            }
        }
        Err(err) => Err(anyhow::anyhow!(
            "failed to remove file {}: {err}",
            path.display()
        )),
    }
}

fn ensure_owned_by_real_user(path: &Path) -> Result<()> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(anyhow::anyhow!("failed to stat {}: {err}", path.display()));
        }
    };
    let target_uid = unsafe { libc::getuid() };
    let target_gid = unsafe { libc::getgid() };
    if meta.uid() == target_uid && meta.gid() == target_gid {
        return Ok(());
    }
    if unsafe { libc::geteuid() } != 0 {
        return Ok(());
    }

    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| anyhow::anyhow!("path contains interior NUL: {}", path.display()))?;
    let rc = unsafe { libc::chown(c_path.as_ptr(), target_uid, target_gid) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        return Err(anyhow::anyhow!(
            "failed to chown {} to {target_uid}:{target_gid}: {err}",
            path.display()
        ));
    }
    Ok(())
}
