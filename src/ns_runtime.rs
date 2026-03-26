use anyhow::{Context, Result};
use fs_err as fs;
use std::path::{Path, PathBuf};

use crate::jail::JailPaths;

pub(crate) const LOCK_FILE_NAME: &str = "lock";

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
    pub(crate) mntns_exists: bool,
    pub(crate) ipcns_exists: bool,
    pub(crate) lock_exists: bool,
}

#[derive(Debug)]
pub(crate) struct RuntimeLock {
    file: fs::File,
    path: PathBuf,
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
    let paths = paths_for(jail);
    fs::create_dir_all(&paths.runtime_dir).with_context(|| {
        format!(
            "failed to create jail runtime directory {}",
            paths.runtime_dir.display()
        )
    })?;
    Ok(paths)
}

pub(crate) fn open_lock(jail: &JailPaths) -> Result<RuntimeLock> {
    let paths = ensure_runtime_dir(jail)?;
    let file = fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(&paths.lock_path)
        .with_context(|| format!("failed to open runtime lock {}", paths.lock_path.display()))?;
    file.lock()
        .with_context(|| format!("failed to lock runtime lock {}", paths.lock_path.display()))?;
    Ok(RuntimeLock {
        file,
        path: paths.lock_path,
    })
}

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
            path: paths.lock_path,
        })),
        Err(std::fs::TryLockError::WouldBlock) => Ok(None),
        Err(std::fs::TryLockError::Error(err)) => Err(err).with_context(|| {
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
        mntns_exists: exists_file(&paths.mntns_path)?,
        ipcns_exists: exists_file(&paths.ipcns_path)?,
        lock_exists: exists_file(&paths.lock_path)?,
    })
}

pub(crate) fn remove_runtime(jail: &JailPaths) -> Result<()> {
    let paths = paths_for(jail);
    match fs::remove_dir_all(&paths.runtime_dir) {
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

fn exists_file(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err).with_context(|| format!("failed to inspect {}", path.display())),
    }
}

impl Drop for RuntimeLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

impl RuntimeLock {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}
