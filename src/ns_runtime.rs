use anyhow::{Context, Result, bail};
use fs_err as fs;
#[cfg(test)]
use std::fs::TryLockError;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::jail::JailPaths;
use crate::run_with_log;

pub(crate) const LOCK_FILE_NAME: &str = "lock";
pub(crate) const ROOT_LOCK_FILE_NAME: &str = ".lock";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NsRuntimePaths {
    pub(crate) runtime_dir: PathBuf,
    pub(crate) mntns_path: PathBuf,
    pub(crate) ipcns_path: PathBuf,
    pub(crate) lock_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RuntimeStatus {
    pub(crate) runtime_dir_exists: bool,
    pub(crate) lock_exists: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeState {
    Missing,
    SkeletonOnly,
    Ready,
    PartialHandles,
}

#[derive(Debug)]
pub(crate) struct RuntimeLock {
    file: fs::File,
    #[cfg(test)]
    path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EnsuredRuntime {
    pub(crate) paths: NsRuntimePaths,
    pub(crate) state_before: RuntimeState,
    pub(crate) state_after: RuntimeState,
    pub(crate) rebuilt: bool,
}

pub(crate) struct ExecRuntime {
    pub(crate) ensured: EnsuredRuntime,
}

pub(crate) fn paths_for(jail: &JailPaths) -> NsRuntimePaths {
    NsRuntimePaths {
        runtime_dir: jail.runtime_dir.clone(),
        mntns_path: jail.mntns_path.clone(),
        ipcns_path: jail.ipcns_path.clone(),
        lock_path: jail.runtime_dir.join(LOCK_FILE_NAME),
    }
}

pub(crate) fn ensure_runtime_dir(jail: &JailPaths) -> Result<NsRuntimePaths> {
    let root = jail
        .runtime_dir
        .parent()
        .ok_or_else(|| {
            anyhow::anyhow!("runtime dir has no parent: {}", jail.runtime_dir.display())
        })?
        .to_path_buf();
    let _root_lock = open_root_lock(&root)?;
    let paths = paths_for(jail);
    fs::create_dir_all(&paths.runtime_dir).with_context(|| {
        format!(
            "failed to create jail runtime directory {}",
            paths.runtime_dir.display()
        )
    })?;
    ensure_runtime_dirs_private(
        &root,
        &paths.runtime_dir,
        !crate::jail::has_configured_xdg_runtime_dir(),
    )?;
    crate::privileges::ensure_owned_by_real_user(&root)?;
    crate::privileges::ensure_owned_by_real_user(&paths.runtime_dir)?;
    Ok(paths)
}

fn open_root_lock(root: &Path) -> Result<RuntimeLock> {
    fs::create_dir_all(root)
        .with_context(|| format!("failed to create runtime root directory {}", root.display()))?;
    open_lock_file(root.join(ROOT_LOCK_FILE_NAME))
}

fn ensure_runtime_dirs_private(
    root: &Path,
    runtime_dir: &Path,
    enforce_private: bool,
) -> Result<()> {
    if !enforce_private {
        return Ok(());
    }
    ensure_dir_mode(root, 0o700)?;
    ensure_dir_mode(runtime_dir, 0o700)?;
    Ok(())
}

fn ensure_dir_mode(path: &Path, mode: u32) -> Result<()> {
    let meta = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect runtime directory {}", path.display()))?;
    if !meta.file_type().is_dir() {
        bail!("runtime path is not a directory: {}", path.display());
    }
    let current_mode = meta.permissions().mode() & 0o777;
    if current_mode == mode {
        return Ok(());
    }
    fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("failed to chmod runtime directory {}", path.display()))
}

pub(crate) fn open_lock(jail: &JailPaths) -> Result<RuntimeLock> {
    let paths = ensure_runtime_dir(jail)?;
    open_lock_file(paths.lock_path)
}

#[cfg(test)]
pub(crate) fn try_open_lock(jail: &JailPaths) -> Result<Option<RuntimeLock>> {
    let paths = ensure_runtime_dir(jail)?;
    let file = fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(&paths.lock_path)
        .with_context(|| format!("failed to open runtime lock {}", paths.lock_path.display()))?;
    match file.try_lock() {
        Ok(()) => Ok(Some(RuntimeLock {
            file,
            #[cfg(test)]
            path: paths.lock_path,
        })),
        Err(TryLockError::WouldBlock) => Ok(None),
        Err(TryLockError::Error(err)) => Err(err).with_context(|| {
            format!(
                "failed to try-lock runtime lock {}",
                paths.lock_path.display()
            )
        }),
    }
}

pub(crate) fn inspect(jail: &JailPaths) -> Result<RuntimeStatus> {
    let paths = paths_for(jail);
    Ok(RuntimeStatus {
        runtime_dir_exists: paths.runtime_dir.exists(),
        lock_exists: exists_file(&paths.lock_path)?,
    })
}

pub(crate) fn classify(status: &RuntimeStatus) -> RuntimeState {
    match (status.runtime_dir_exists, status.lock_exists) {
        (false, false) => RuntimeState::Missing,
        (true, true) => RuntimeState::Ready,
        (true, false) => RuntimeState::SkeletonOnly,
        (false, true) => RuntimeState::PartialHandles,
    }
}

#[cfg(test)]
pub(crate) fn ensure_runtime_skeleton(jail: &JailPaths) -> Result<RuntimeStatus> {
    let lock = open_lock(jail)?;
    let status = inspect(jail)?;
    drop(lock);
    Ok(status)
}

pub(crate) fn ensure_runtime_with<F>(
    jail: &JailPaths,
    mut build_handles: F,
) -> Result<EnsuredRuntime>
where
    F: FnMut(&NsRuntimePaths) -> Result<()>,
{
    let _lock = open_lock(jail)?;
    let paths = paths_for(jail);
    let initial_status = inspect(jail)?;
    let state_before = classify(&initial_status);
    let rebuilt = matches!(
        state_before,
        RuntimeState::Missing | RuntimeState::SkeletonOnly | RuntimeState::PartialHandles
    );

    match state_before {
        RuntimeState::Ready => {}
        RuntimeState::Missing | RuntimeState::SkeletonOnly => {
            remove_if_present(&paths.mntns_path)?;
            build_handles(&paths)?;
        }
        RuntimeState::PartialHandles => {
            reset_to_skeleton(&paths)?;
            build_handles(&paths)?;
        }
    }

    let final_status = inspect(jail)?;
    let state_after = classify(&final_status);
    Ok(EnsuredRuntime {
        paths,
        state_before,
        state_after,
        rebuilt,
    })
}

#[cfg(test)]
pub(crate) fn ensure_runtime_placeholders(jail: &JailPaths) -> Result<EnsuredRuntime> {
    ensure_runtime_with(jail, |_paths| Ok(()))
}

pub(crate) fn ensure_runtime_namespaces(jail: &JailPaths) -> Result<EnsuredRuntime> {
    ensure_runtime_with(jail, |_paths| Ok(()))
}

pub(crate) fn ensure_runtime_for_exec(jail: &JailPaths) -> Result<ExecRuntime> {
    let ensured = ensure_runtime_namespaces(jail)?;
    Ok(ExecRuntime { ensured })
}

pub(crate) fn remove_runtime(jail: &JailPaths) -> Result<()> {
    let paths = paths_for(jail);
    run_with_log(
        || remove_known_runtime_artifacts(&paths),
        || {
            format!(
                "remove runtime artifacts under {}",
                paths.runtime_dir.display()
            )
        },
    )
}

fn remove_known_runtime_artifacts(paths: &NsRuntimePaths) -> Result<()> {
    if !paths.runtime_dir.exists() {
        return Ok(());
    }

    let unknown = list_unknown_runtime_entries(paths).with_context(|| {
        format!(
            "failed to inspect runtime directory {}",
            paths.runtime_dir.display()
        )
    })?;

    if !unknown.is_empty() {
        bail!(
            "refusing to remove runtime directory {}: found unknown entries: {}",
            paths.runtime_dir.display(),
            unknown.join(", ")
        );
    }

    crate::privileges::remove_file_if_exists_with_owner_fix(&paths.runtime_dir, &paths.lock_path)?;
    crate::privileges::remove_file_if_exists_with_owner_fix(&paths.runtime_dir, &paths.mntns_path)?;
    crate::privileges::remove_file_if_exists_with_owner_fix(&paths.runtime_dir, &paths.ipcns_path)?;

    match fs::remove_dir(&paths.runtime_dir) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| {
            format!(
                "failed to remove jail runtime directory {}",
                paths.runtime_dir.display()
            )
        }),
    }
}

fn list_unknown_runtime_entries(paths: &NsRuntimePaths) -> Result<Vec<String>> {
    let mut unknown = Vec::new();
    for entry in fs::read_dir(&paths.runtime_dir).with_context(|| {
        format!(
            "failed to read runtime directory {}",
            paths.runtime_dir.display()
        )
    })? {
        let entry = entry.with_context(|| {
            format!(
                "failed to read entry in runtime directory {}",
                paths.runtime_dir.display()
            )
        })?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            unknown.push(format!("{:?}", name));
            continue;
        };
        if !matches!(name, LOCK_FILE_NAME | "mntns" | "ipcns") {
            unknown.push(name.to_string());
        }
    }
    unknown.sort();
    Ok(unknown)
}

fn exists_file(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err).with_context(|| format!("failed to inspect {}", path.display())),
    }
}

fn reset_to_skeleton(paths: &NsRuntimePaths) -> Result<()> {
    remove_if_present(&paths.mntns_path)?;
    remove_if_present(&paths.ipcns_path)?;
    Ok(())
}

fn remove_if_present(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("failed to remove {}", path.display())),
    }
}

impl Drop for RuntimeLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

impl RuntimeLock {
    #[cfg(test)]
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn private_runtime_dir_helper_enforces_0700_when_requested() {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("root");
        let runtime = root.join("demo");
        fs::create_dir_all(&runtime).expect("mkdir runtime");
        fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).expect("chmod root");
        fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o755))
            .expect("chmod runtime");

        ensure_runtime_dirs_private(&root, &runtime, true).expect("enforce private runtime dirs");

        let root_mode = fs::metadata(&root)
            .expect("root metadata")
            .permissions()
            .mode()
            & 0o777;
        let runtime_mode = fs::metadata(&runtime)
            .expect("runtime metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(root_mode, 0o700);
        assert_eq!(runtime_mode, 0o700);
    }

    #[test]
    fn private_runtime_dir_helper_skips_chmod_when_not_requested() {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("root");
        let runtime = root.join("demo");
        fs::create_dir_all(&runtime).expect("mkdir runtime");
        fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).expect("chmod root");
        fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o755))
            .expect("chmod runtime");

        ensure_runtime_dirs_private(&root, &runtime, false).expect("skip private runtime dirs");

        let root_mode = fs::metadata(&root)
            .expect("root metadata")
            .permissions()
            .mode()
            & 0o777;
        let runtime_mode = fs::metadata(&runtime)
            .expect("runtime metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(root_mode, 0o755);
        assert_eq!(runtime_mode, 0o755);
    }
}

fn open_lock_file(path: PathBuf) -> Result<RuntimeLock> {
    let file = fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(&path)
        .with_context(|| format!("failed to open runtime lock {}", path.display()))?;
    file.lock()
        .with_context(|| format!("failed to lock runtime lock {}", path.display()))?;
    Ok(RuntimeLock {
        file,
        #[cfg(test)]
        path,
    })
}
