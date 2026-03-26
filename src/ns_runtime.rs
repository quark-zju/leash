use anyhow::{Context, Result};
use fs_err as fs;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
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
    path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EnsuredRuntime {
    pub(crate) paths: NsRuntimePaths,
    pub(crate) state_before: RuntimeState,
    pub(crate) state_after: RuntimeState,
    pub(crate) rebuilt: bool,
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

pub(crate) fn classify(status: &RuntimeStatus) -> RuntimeState {
    match (
        status.runtime_dir_exists,
        status.lock_exists,
        status.mntns_exists,
        status.ipcns_exists,
    ) {
        (false, false, false, false) => RuntimeState::Missing,
        (true, true, false, false) => RuntimeState::SkeletonOnly,
        (_, _, true, true) => RuntimeState::Ready,
        _ => RuntimeState::PartialHandles,
    }
}

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

pub(crate) fn ensure_runtime_placeholders(jail: &JailPaths) -> Result<EnsuredRuntime> {
    ensure_runtime_with(jail, |paths| {
        write_placeholder(&paths.mntns_path, b"mntns-placeholder")?;
        write_placeholder(&paths.ipcns_path, b"ipcns-placeholder")?;
        Ok(())
    })
}

pub(crate) fn ensure_runtime_namespaces(jail: &JailPaths) -> Result<EnsuredRuntime> {
    ensure_runtime_with(jail, bootstrap_namespace_handles)
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

fn reset_to_skeleton(paths: &NsRuntimePaths) -> Result<()> {
    remove_if_present(&paths.mntns_path)?;
    remove_if_present(&paths.ipcns_path)?;
    Ok(())
}

fn remove_if_present(path: &Path) -> Result<()> {
    let target_c = CString::new(path.as_os_str().as_bytes())
        .with_context(|| format!("invalid path: {}", path.display()))?;
    let rc = unsafe { libc::umount2(target_c.as_ptr(), libc::MNT_DETACH) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        if !matches!(
            err.raw_os_error(),
            Some(libc::EINVAL) | Some(libc::ENOENT) | Some(libc::EPERM)
        ) {
            return Err(anyhow::anyhow!(
                "failed to detach mount at {}: {err}",
                path.display()
            ));
        }
    }
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("failed to remove {}", path.display())),
    }
}

fn write_placeholder(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::write(path, bytes).with_context(|| format!("failed to write {}", path.display()))
}

fn bind_namespace_handle(source: &str, target: &Path) -> Result<()> {
    fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(target)
        .with_context(|| format!("failed to create namespace handle {}", target.display()))?;
    let source_c =
        CString::new(source).with_context(|| format!("invalid source path: {source}"))?;
    let target_c = CString::new(target.as_os_str().as_bytes())
        .with_context(|| format!("invalid target path: {}", target.display()))?;

    let rc = unsafe {
        libc::mount(
            source_c.as_ptr(),
            target_c.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND as libc::c_ulong,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        return Err(anyhow::anyhow!(
            "failed to bind namespace handle {} -> {}: {err}",
            source,
            target.display()
        ));
    }
    Ok(())
}

fn bootstrap_namespace_handles(paths: &NsRuntimePaths) -> Result<()> {
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(anyhow::anyhow!(
            "failed to fork namespace bootstrap process: {}",
            std::io::Error::last_os_error()
        ));
    }

    if pid == 0 {
        let rc = unsafe { libc::unshare(libc::CLONE_NEWIPC) };
        if rc != 0 {
            eprintln!("unshare failed: {}", std::io::Error::last_os_error());
            unsafe { libc::_exit(101) };
        }

        if let Err(err) = bind_namespace_handle("/proc/self/ns/mnt", &paths.mntns_path) {
            eprintln!("{err:#}");
            unsafe { libc::_exit(103) };
        }
        if let Err(err) = bind_namespace_handle("/proc/self/ns/ipc", &paths.ipcns_path) {
            eprintln!("{err:#}");
            unsafe { libc::_exit(104) };
        }
        unsafe { libc::_exit(0) };
    }

    let mut status: libc::c_int = 0;
    let wait_rc = unsafe { libc::waitpid(pid, &mut status as *mut libc::c_int, 0) };
    if wait_rc < 0 {
        return Err(anyhow::anyhow!(
            "failed to wait for namespace bootstrap process: {}",
            std::io::Error::last_os_error()
        ));
    }
    if libc::WIFEXITED(status) {
        let code = libc::WEXITSTATUS(status);
        if code == 0 {
            return Ok(());
        }
        return Err(anyhow::anyhow!(
            "namespace bootstrap process exited with code {code}"
        ));
    }
    if libc::WIFSIGNALED(status) {
        let sig = libc::WTERMSIG(status);
        return Err(anyhow::anyhow!(
            "namespace bootstrap process killed by signal {sig}"
        ));
    }
    Err(anyhow::anyhow!(
        "namespace bootstrap process ended unexpectedly: status={status}"
    ))
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
