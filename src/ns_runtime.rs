use anyhow::{Context, Result};
use fs_err as fs;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::jail::JailPaths;

pub(crate) const LOCK_FILE_NAME: &str = "lock";
pub(crate) const ROOT_LOCK_FILE_NAME: &str = ".lock";
pub(crate) const MOUNT_DIR_NAME: &str = "mount";
pub(crate) const FUSE_PID_NAME: &str = "fuse.pid";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NsRuntimePaths {
    pub(crate) runtime_dir: PathBuf,
    pub(crate) mntns_path: PathBuf,
    pub(crate) ipcns_path: PathBuf,
    pub(crate) lock_path: PathBuf,
    pub(crate) mount_dir: PathBuf,
    pub(crate) fuse_pid_path: PathBuf,
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
    pub(crate) mntns_file: fs::File,
    pub(crate) ipcns_file: fs::File,
}

pub(crate) fn paths_for(jail: &JailPaths) -> NsRuntimePaths {
    NsRuntimePaths {
        runtime_dir: jail.runtime_dir.clone(),
        mntns_path: jail.mntns_path.clone(),
        ipcns_path: jail.ipcns_path.clone(),
        lock_path: jail.runtime_dir.join(LOCK_FILE_NAME),
        mount_dir: jail.runtime_dir.join(MOUNT_DIR_NAME),
        fuse_pid_path: jail.runtime_dir.join(FUSE_PID_NAME),
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
    Ok(paths)
}

fn open_root_lock(root: &Path) -> Result<RuntimeLock> {
    fs::create_dir_all(&root)
        .with_context(|| format!("failed to create runtime root directory {}", root.display()))?;
    open_lock_file(root.join(ROOT_LOCK_FILE_NAME))
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
    ensure_runtime_with(jail, |paths| {
        write_placeholder(&paths.mntns_path, b"mntns-placeholder")?;
        write_placeholder(&paths.ipcns_path, b"ipcns-placeholder")?;
        Ok(())
    })
}

pub(crate) fn ensure_runtime_namespaces(jail: &JailPaths) -> Result<EnsuredRuntime> {
    ensure_runtime_with(jail, bootstrap_namespace_handles)
}

pub(crate) fn open_namespace_handles(paths: &NsRuntimePaths) -> Result<(fs::File, fs::File)> {
    let mntns_file = fs::File::open(&paths.mntns_path).with_context(|| {
        format!(
            "failed to open mount namespace handle {}",
            paths.mntns_path.display()
        )
    })?;
    let ipcns_file = fs::File::open(&paths.ipcns_path).with_context(|| {
        format!(
            "failed to open ipc namespace handle {}",
            paths.ipcns_path.display()
        )
    })?;
    Ok((mntns_file, ipcns_file))
}

pub(crate) fn ensure_runtime_for_exec(jail: &JailPaths) -> Result<ExecRuntime> {
    let ensured = ensure_runtime_namespaces(jail)?;
    let (mntns_file, ipcns_file) = open_namespace_handles(&ensured.paths)?;
    Ok(ExecRuntime {
        ensured,
        mntns_file,
        ipcns_file,
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
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
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

#[cfg(test)]
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
        let rc = unsafe { libc::unshare(libc::CLONE_NEWNS | libc::CLONE_NEWIPC) };
        if rc != 0 {
            eprintln!("unshare failed: {}", std::io::Error::last_os_error());
            unsafe { libc::_exit(101) };
        }

        let rc = unsafe {
            libc::mount(
                std::ptr::null(),
                b"/\0".as_ptr().cast(),
                std::ptr::null(),
                (libc::MS_REC | libc::MS_PRIVATE) as libc::c_ulong,
                std::ptr::null(),
            )
        };
        if rc != 0 {
            eprintln!(
                "mount propagation setup failed: {}",
                std::io::Error::last_os_error()
            );
            unsafe { libc::_exit(102) };
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
    #[cfg(test)]
    pub(crate) fn path(&self) -> &Path {
        &self.path
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
