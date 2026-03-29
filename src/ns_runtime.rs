use anyhow::{Context, Result, bail};
use fs_err as fs;
use std::ffi::CString;
#[cfg(test)]
use std::fs::TryLockError;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::jail::JailPaths;
use crate::run_with_log;

pub(crate) const LOCK_FILE_NAME: &str = "lock";
pub(crate) const ROOT_LOCK_FILE_NAME: &str = ".lock";
pub(crate) const MOUNT_DIR_NAME: &str = "mount";
pub(crate) const FUSE_PID_NAME: &str = "fuse.pid";
pub(crate) const FUSE_LOG_NAME: &str = "fuse.log";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NsRuntimePaths {
    pub(crate) runtime_dir: PathBuf,
    pub(crate) mntns_path: PathBuf,
    pub(crate) ipcns_path: PathBuf,
    pub(crate) lock_path: PathBuf,
    pub(crate) mount_dir: PathBuf,
    pub(crate) fuse_pid_path: PathBuf,
    pub(crate) fuse_log_path: PathBuf,
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
        mount_dir: jail.runtime_dir.join(MOUNT_DIR_NAME),
        fuse_pid_path: jail.runtime_dir.join(FUSE_PID_NAME),
        fuse_log_path: jail.runtime_dir.join(FUSE_LOG_NAME),
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
    ensure_runtime_dirs_private(&root, &paths.runtime_dir, !crate::jail::has_configured_xdg_runtime_dir())?;
    ensure_owned_by_real_user(&root)?;
    ensure_owned_by_real_user(&paths.runtime_dir)?;
    Ok(paths)
}

fn open_root_lock(root: &Path) -> Result<RuntimeLock> {
    fs::create_dir_all(root)
        .with_context(|| format!("failed to create runtime root directory {}", root.display()))?;
    open_lock_file(root.join(ROOT_LOCK_FILE_NAME))
}

fn ensure_runtime_dirs_private(root: &Path, runtime_dir: &Path, enforce_private: bool) -> Result<()> {
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
            // Legacy versions persisted mntns handles. Remove stale files before rebuilding
            // runtime state so the new ipc-only runtime layout stays clean.
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

pub(crate) fn cleanup_before_fuse_start(paths: &NsRuntimePaths) -> Result<()> {
    terminate_recorded_fuse_server(paths)?;
    unmount_runtime_mount_dir(paths)?;
    remove_file_if_exists_with_owner_fix(&paths.runtime_dir, &paths.fuse_pid_path)?;
    fs::create_dir_all(&paths.mount_dir).with_context(|| {
        format!(
            "failed to ensure runtime mount directory {}",
            paths.mount_dir.display()
        )
    })?;
    Ok(())
}

pub(crate) fn remove_runtime(jail: &JailPaths) -> Result<()> {
    let paths = paths_for(jail);
    run_with_log(
        || unmount_runtime_mount_dir(&paths),
        || format!("unmount {}", paths.mount_dir.display()),
    )?;
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

fn unmount_runtime_mount_dir(paths: &NsRuntimePaths) -> Result<()> {
    let mnt = CString::new(paths.mount_dir.as_os_str().as_bytes())
        .context("mount path contains interior NUL byte")?;
    crate::vlog!(
        "rm: syscall umount2({}, MNT_DETACH)",
        paths.mount_dir.display()
    );
    let rc = unsafe { libc::umount2(mnt.as_ptr(), libc::MNT_DETACH) };
    if rc == 0 {
        crate::vlog!(
            "rm: syscall umount2 succeeded: {}",
            paths.mount_dir.display()
        );
        return Ok(());
    }
    let err = std::io::Error::last_os_error();
    crate::vlog!(
        "rm: syscall umount2 failed for {}: {}",
        paths.mount_dir.display(),
        err
    );
    if matches!(
        err.raw_os_error(),
        Some(libc::EINVAL | libc::ENOENT | libc::ENOTCONN)
    ) {
        // Not mounted, already gone, or stale/disconnected endpoint.
        crate::vlog!(
            "rm: syscall umount2 reports already handled for {}: {}",
            paths.mount_dir.display(),
            err
        );
        return Ok(());
    }
    if err.kind() != std::io::ErrorKind::PermissionDenied {
        return Err(err).with_context(|| {
            format!(
                "umount2(MNT_DETACH) failed for {}",
                paths.mount_dir.display()
            )
        });
    }
    Err(err).with_context(|| {
        format!(
            "umount2(MNT_DETACH) permission denied for {}",
            paths.mount_dir.display()
        )
    })
}

fn remove_known_runtime_artifacts(paths: &NsRuntimePaths) -> Result<()> {
    if !paths.runtime_dir.exists() {
        return Ok(());
    }

    // If a stale FUSE mount survived, ENOTCONN can appear while traversing.
    // Retry unmount once before declaring failure.
    let unknown = match list_unknown_runtime_entries(paths) {
        Ok(v) => v,
        Err(err) if is_enotconn(&err) => {
            unmount_runtime_mount_dir(paths).with_context(|| {
                format!(
                    "failed to recover stale mountpoint {} after ENOTCONN",
                    paths.mount_dir.display()
                )
            })?;
            list_unknown_runtime_entries(paths).with_context(|| {
                format!(
                    "failed to inspect runtime directory {} after ENOTCONN recovery",
                    paths.runtime_dir.display()
                )
            })?
        }
        Err(err) => {
            return Err(err).with_context(|| {
                format!(
                    "failed to inspect runtime directory {}",
                    paths.runtime_dir.display()
                )
            });
        }
    };

    if !unknown.is_empty() {
        bail!(
            "refusing to remove runtime directory {}: found unknown entries: {}",
            paths.runtime_dir.display(),
            unknown.join(", ")
        );
    }

    remove_file_if_exists_with_owner_fix(&paths.runtime_dir, &paths.fuse_pid_path)?;
    remove_file_if_exists_with_owner_fix(&paths.runtime_dir, &paths.fuse_log_path)?;
    remove_file_if_exists_with_owner_fix(&paths.runtime_dir, &paths.lock_path)?;
    remove_file_if_exists_with_owner_fix(&paths.runtime_dir, &paths.mntns_path)?;
    remove_file_if_exists_with_owner_fix(&paths.runtime_dir, &paths.ipcns_path)?;

    remove_mount_dir_with_retry(paths)?;

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
        if !matches!(
            name,
            LOCK_FILE_NAME | MOUNT_DIR_NAME | FUSE_PID_NAME | FUSE_LOG_NAME | "mntns" | "ipcns"
        ) {
            unknown.push(name.to_string());
        }
    }
    unknown.sort();
    Ok(unknown)
}

fn remove_file_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("failed to remove file {}", path.display())),
    }
}

fn remove_file_if_exists_with_owner_fix(runtime_dir: &Path, path: &Path) -> Result<()> {
    crate::vlog!("rm: syscall unlink {}", path.display());
    match remove_file_if_exists(path) {
        Ok(()) => {
            crate::vlog!("rm: unlink ok {}", path.display());
            Ok(())
        }
        Err(err)
            if err
                .downcast_ref::<std::io::Error>()
                .is_some_and(|ioe| ioe.kind() == std::io::ErrorKind::PermissionDenied) =>
        {
            ensure_owned_by_real_user(runtime_dir)?;
            let retried = remove_file_if_exists(path);
            if retried.is_ok() {
                crate::vlog!("rm: unlink ok after owner-fix {}", path.display());
            }
            retried
        }
        Err(err) => {
            crate::vlog!("rm: unlink failed {}: {err:#}", path.display());
            Err(err)
        }
    }
}

fn remove_mount_dir_with_retry(paths: &NsRuntimePaths) -> Result<()> {
    crate::vlog!("rm: syscall rmdir {}", paths.mount_dir.display());
    match fs::remove_dir(&paths.mount_dir) {
        Ok(()) => {
            crate::vlog!("rm: rmdir ok {}", paths.mount_dir.display());
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) if err.raw_os_error() == Some(libc::EBUSY) => {
            // Last chance for lingering mount references: stop the recorded
            // FUSE server first, then retry unmount and rmdir.
            crate::vlog!(
                "rm: mount dir busy, retry cleanup for {}",
                paths.mount_dir.display()
            );
            terminate_recorded_fuse_server(paths)?;
            unmount_runtime_mount_dir(paths).with_context(|| {
                format!(
                    "failed to unmount busy runtime mount {}",
                    paths.mount_dir.display()
                )
            })?;
            match fs::remove_dir(&paths.mount_dir) {
                Ok(()) => {
                    crate::vlog!("rm: rmdir ok after retry {}", paths.mount_dir.display());
                    Ok(())
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(err) => Err(err).with_context(|| {
                    format!(
                        "failed to remove runtime mount dir {} after busy-unmount retry",
                        paths.mount_dir.display()
                    )
                }),
            }
        }
        Err(err) => Err(err).with_context(|| {
            format!(
                "failed to remove runtime mount dir {}",
                paths.mount_dir.display()
            )
        }),
    }
}

fn terminate_recorded_fuse_server(paths: &NsRuntimePaths) -> Result<()> {
    let Some(pid) = read_fuse_pid(paths)? else {
        return Ok(());
    };
    crate::vlog!("rm: syscall kill(SIGTERM,{pid})");
    let kill_rc = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
    if kill_rc != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::ESRCH) {
            return Err(err).with_context(|| format!("failed to SIGTERM fuse server pid={pid}"));
        }
        crate::vlog!("rm: kill skipped (pid not found): {pid}");
    } else {
        crate::vlog!("rm: kill ok pid={pid}");
    }
    std::thread::sleep(Duration::from_millis(120));
    Ok(())
}

fn ensure_owned_by_real_user(path: &Path) -> Result<()> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(err).with_context(|| format!("failed to stat {}", path.display()));
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
        .context("path contains interior NUL byte while fixing ownership")?;
    let rc = unsafe { libc::chown(c_path.as_ptr(), target_uid, target_gid) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!(
                "failed to chown {} to {target_uid}:{target_gid}",
                path.display()
            )
        });
    }
    Ok(())
}

fn is_enotconn(err: &anyhow::Error) -> bool {
    err.downcast_ref::<std::io::Error>()
        .is_some_and(|ioe| ioe.raw_os_error() == Some(libc::ENOTCONN))
}

pub(crate) fn read_fuse_pid(paths: &NsRuntimePaths) -> Result<Option<u32>> {
    let raw = match fs::read_to_string(&paths.fuse_pid_path) {
        Ok(raw) => raw,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(err).with_context(|| {
                format!(
                    "failed to read fuse pid file {}",
                    paths.fuse_pid_path.display()
                )
            });
        }
    };
    let pid = raw
        .trim()
        .parse::<u32>()
        .with_context(|| format!("invalid pid content in {}", paths.fuse_pid_path.display()))?;
    Ok(Some(pid))
}

pub(crate) fn process_has_mount(pid: u32, mountpoint: &Path) -> Result<bool> {
    let path = PathBuf::from(format!("/proc/{pid}/mountinfo"));
    let raw = match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(err)
            if err.kind() == std::io::ErrorKind::NotFound
                || err.kind() == std::io::ErrorKind::InvalidInput =>
        {
            return Ok(false);
        }
        Err(err) => {
            return Err(err)
                .with_context(|| format!("failed to read mountinfo from {}", path.display()));
        }
    };
    Ok(mountinfo_has_mountpoint(&raw, mountpoint))
}

pub(crate) fn wait_for_process_mount(
    pid: u32,
    mountpoint: &Path,
    timeout: Duration,
) -> Result<bool> {
    let deadline = Instant::now() + timeout;
    loop {
        if process_has_mount(pid, mountpoint)? {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn exists_file(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err).with_context(|| format!("failed to inspect {}", path.display())),
    }
}

fn mountinfo_has_mountpoint(raw: &str, mountpoint: &Path) -> bool {
    let Some(target) = mountpoint.to_str() else {
        return false;
    };
    for line in raw.lines() {
        let mut fields = line.split_whitespace();
        let _id = fields.next();
        let _parent = fields.next();
        let _major_minor = fields.next();
        let _root = fields.next();
        let Some(enc_mountpoint) = fields.next() else {
            continue;
        };
        let parsed = decode_mountinfo_path(enc_mountpoint);
        if parsed == target {
            return true;
        }
    }
    false
}

#[cfg(test)]
pub(crate) fn mountinfo_has_mountpoint_for_test(raw: &str, mountpoint: &Path) -> bool {
    mountinfo_has_mountpoint(raw, mountpoint)
}

fn decode_mountinfo_path(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            let d0 = bytes[i + 1];
            let d1 = bytes[i + 2];
            let d2 = bytes[i + 3];
            if d0.is_ascii_digit() && d1.is_ascii_digit() && d2.is_ascii_digit() {
                let v = (d0 - b'0') * 64 + (d1 - b'0') * 8 + (d2 - b'0');
                out.push(v as char);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
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

        let root_mode = fs::metadata(&root).expect("root metadata").permissions().mode() & 0o777;
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

        let root_mode = fs::metadata(&root).expect("root metadata").permissions().mode() & 0o777;
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
