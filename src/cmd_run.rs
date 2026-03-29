use anyhow::{Context, Result, bail};
use std::ffi::{CStr, CString};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command as ProcessCommand;
use std::process::Stdio;
use std::time::Duration;

use crate::cli::RunCommand;
use crate::jail;
use crate::mount_plan::{self, MountPlanEntry};
use crate::ns_runtime;
use crate::privileges;
use crate::run_with_log;

pub(crate) fn run_command(run: RunCommand) -> Result<i32> {
    privileges::require_root_euid("cowjail run")?;
    set_process_name(c"cowjail-run")?;

    let cwd = run_with_log(jail::current_pwd, || {
        "resolve current working directory".to_string()
    })?;
    let resolved = run_with_log(
        || {
            jail::resolve(
                run.name.as_deref(),
                run.profile.as_deref(),
                jail::ResolveMode::EnsureExists,
            )
        },
        || "resolve run jail".to_string(),
    )?;
    let runtime = run_with_log(
        || ns_runtime::ensure_runtime_for_exec(&resolved.paths),
        || "ensure runtime".to_string(),
    )?;
    let mount_plan = run_with_log(
        || {
            mount_plan::build_mount_plan_with_sources(
                &resolved.normalized_profile,
                resolved.normalized_rule_sources.as_deref(),
            )
        },
        || "build run mount plan".to_string(),
    )?;
    crate::vlog!(
        "run: runtime={} state_before={:?} state_after={:?} rebuilt={}",
        runtime.ensured.paths.runtime_dir.display(),
        runtime.ensured.state_before,
        runtime.ensured.state_after,
        runtime.ensured.rebuilt
    );
    ensure_fuse_server(
        &resolved.paths,
        &runtime.ensured.paths,
        &resolved.paths.profile_path,
        &resolved.paths.record_path,
        run.verbose,
    )?;

    crate::vlog!(
        "run: preparing child pivot_root into {} then chdir to {}",
        runtime.ensured.paths.mount_dir.display(),
        cwd.display()
    );
    run_with_log(setup_run_namespaces, || {
        "unshare run namespaces".to_string()
    })?;
    let status = run_with_log(
        || {
            run_child_in_jail(
                &run,
                &runtime.ensured.paths.mount_dir,
                &cwd,
                mount_plan.clone(),
            )
        },
        || format!("execute jailed command {:?}", run.program),
    );

    let status = status?;
    Ok(exit_code_from_status(status))
}

fn run_child_in_jail(
    run: &RunCommand,
    mountpoint: &Path,
    old_cwd: &Path,
    mount_plan: Vec<MountPlanEntry>,
) -> Result<std::process::ExitStatus> {
    let mount_root = mountpoint.to_path_buf();
    let cwd_c = CString::new(old_cwd.as_os_str().as_encoded_bytes())
        .context("cwd contains interior NUL byte")?;

    let mut cmd = ProcessCommand::new(&run.program);
    cmd.args(&run.args);
    unsafe {
        cmd.pre_exec(move || {
            if let Err(err) = make_mounts_private() {
                return Err(std::io::Error::other(err.to_string()));
            }
            if let Err(err) = apply_mount_plan_in_namespace(&mount_root, &mount_plan) {
                return Err(std::io::Error::other(err.to_string()));
            }
            // FUSE mount access is keyed by fsuid/fsgid, not effective uid.
            // Align fs creds with the real user before pivot_root/chdir so kernel-side
            // FUSE permission checks do not reject the mount root with EACCES.
            libc::setfsgid(libc::getgid());
            libc::setfsuid(libc::getuid());
            if let Err(err) = pivot_into_mount_root(&mount_root) {
                return Err(std::io::Error::other(err.to_string()));
            }
            if libc::chdir(cwd_c.as_ptr()) != 0 {
                let err = std::io::Error::last_os_error();
                let not_found =
                    matches!(err.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR | libc::EACCES));
                if not_found {
                    let root = CString::new("/").expect("literal '/' cannot contain NUL");
                    if libc::chdir(root.as_ptr()) != 0 {
                        let fallback_err = std::io::Error::last_os_error();
                        return Err(std::io::Error::new(
                            fallback_err.kind(),
                            format!(
                                "chdir to cwd failed ({err}); fallback chdir('/') also failed: {fallback_err}"
                            ),
                        ));
                    }
                } else {
                    return Err(std::io::Error::new(
                        err.kind(),
                        format!("chdir failed: {err}"),
                    ));
                }
            }
            // Child is already PID 1 in the new pid namespace; fork a worker so
            // PID 1 can remain as a minimal child reaper.
            if let Err(err) = enter_pid_namespace_worker_or_reap() {
                return Err(std::io::Error::other(err.to_string()));
            }
            if let Err(err) = privileges::drop_to_real_user() {
                return Err(std::io::Error::other(err.to_string()));
            }
            close_fds_best_effort_from(3);
            Ok(())
        });
    }
    let mut child = cmd
        .spawn()
        .context("failed to spawn child command in jail")?;
    run_with_log(privileges::drop_root_euid_if_needed, || {
        "drop outer run euid after child spawn".to_string()
    })?;
    child.wait().context("failed waiting for child command")
}

fn enter_pid_namespace_worker_or_reap() -> Result<()> {
    // We are PID 1 in the new namespace. Keep this process as a minimal init
    // that reaps all children and exits with the worker's status.
    let worker_pid = unsafe { libc::fork() };
    if worker_pid < 0 {
        return Err(std::io::Error::last_os_error()).context("fork for pidns worker failed");
    }
    if worker_pid > 0 {
        close_fds_best_effort_from(0);
        if let Err(_err) = privileges::drop_to_real_user() {
            unsafe { libc::_exit(1) };
        }
        let _ = set_process_name(c"cowjail-init");
        run_pidns_init_reaper(worker_pid);
    }
    Ok(())
}

fn setup_run_namespaces() -> Result<()> {
    let flags = libc::CLONE_NEWIPC | libc::CLONE_NEWNS | libc::CLONE_NEWPID;
    let rc = unsafe { libc::unshare(flags) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .context("unshare(CLONE_NEWIPC|CLONE_NEWNS|CLONE_NEWPID) failed");
    }
    Ok(())
}

fn run_pidns_init_reaper(worker_pid: libc::pid_t) -> ! {
    let mut worker_status: Option<libc::c_int> = None;
    loop {
        let mut status: libc::c_int = 0;
        let rc = unsafe { libc::waitpid(-1, &mut status, 0) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::ECHILD) => break,
                _ => unsafe { libc::_exit(1) },
            }
        }
        if rc == worker_pid {
            worker_status = Some(status);
        }
    }
    if let Some(status) = worker_status {
        exit_from_wait_status(status);
    }
    unsafe { libc::_exit(1) }
}

fn exit_from_wait_status(status: libc::c_int) -> ! {
    if libc::WIFEXITED(status) {
        unsafe { libc::_exit(libc::WEXITSTATUS(status)) };
    }
    if libc::WIFSIGNALED(status) {
        let sig = libc::WTERMSIG(status);
        unsafe { libc::_exit(128 + sig) };
    }
    unsafe { libc::_exit(1) }
}

fn close_fds_best_effort_from(first: libc::c_uint) {
    if try_close_range(first).is_ok() {
        return;
    }
    let max_fd: i32 = 65536;
    for fd in first as i32..max_fd {
        unsafe {
            libc::close(fd);
        }
    }
}

fn set_process_name(name: &CStr) -> Result<()> {
    let rc = unsafe { libc::prctl(libc::PR_SET_NAME, name.as_ptr() as libc::c_ulong, 0, 0, 0) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("prctl(PR_SET_NAME) failed");
    }
    Ok(())
}

fn pivot_into_mount_root(mount_root: &Path) -> Result<()> {
    let mount_c = CString::new(mount_root.as_os_str().as_encoded_bytes())
        .context("mount path contains interior NUL byte")?;
    let dot = CString::new(".").expect("literal '.' cannot contain NUL");
    let root = CString::new("/").expect("literal '/' cannot contain NUL");

    if unsafe { libc::chdir(mount_c.as_ptr()) } != 0 {
        let err = std::io::Error::last_os_error();
        return Err(err).context("chdir into mount root failed before pivot_root");
    }
    let rc = unsafe { libc::syscall(libc::SYS_pivot_root, dot.as_ptr(), dot.as_ptr()) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("pivot_root('.', '.') failed");
    }
    if unsafe { libc::umount2(dot.as_ptr(), libc::MNT_DETACH) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("umount2('.', MNT_DETACH) failed after pivot_root");
    }
    if unsafe { libc::chdir(root.as_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error()).context("chdir('/') failed after pivot_root");
    }
    Ok(())
}

fn try_close_range(first: libc::c_uint) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let rc = unsafe {
            libc::syscall(
                libc::SYS_close_range,
                first,
                libc::c_uint::MAX,
                0 as libc::c_uint,
            )
        };
        if rc == 0 {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        if matches!(
            err.raw_os_error(),
            Some(libc::ENOSYS | libc::EINVAL | libc::EPERM)
        ) {
            return Err(anyhow::anyhow!("close_range unavailable: {err}"));
        }
        return Err(err).context("close_range failed");
    }
    #[allow(unreachable_code)]
    Err(anyhow::anyhow!(
        "close_range is unsupported on this platform"
    ))
}

fn ensure_fuse_server(
    jail_paths: &crate::jail::JailPaths,
    runtime_paths: &ns_runtime::NsRuntimePaths,
    profile_path: &Path,
    record_path: &Path,
    verbose: bool,
) -> Result<()> {
    let _lock = ns_runtime::open_lock(jail_paths)?;
    if let Some(pid) = ns_runtime::read_fuse_pid(runtime_paths)?
        && ns_runtime::process_has_mount(pid, &runtime_paths.mount_dir)?
    {
        crate::vlog!(
            "run: reusing fuse server pid={} mount={}",
            pid,
            runtime_paths.mount_dir.display()
        );
        return Ok(());
    }

    crate::vlog!(
        "run: starting fuse server for mount {}",
        runtime_paths.mount_dir.display()
    );
    run_with_log(
        || ns_runtime::cleanup_before_fuse_start(runtime_paths),
        || {
            format!(
                "cleanup stale fuse runtime before start at {}",
                runtime_paths.mount_dir.display()
            )
        },
    )?;
    let exe = std::env::current_exe().context("failed to locate current executable")?;
    let mut cmd = ProcessCommand::new(exe);
    let fuse_log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&runtime_paths.fuse_log_path)
        .with_context(|| {
            format!(
                "failed to open fuse log file {}",
                runtime_paths.fuse_log_path.display()
            )
        })?;
    let fuse_log_err = fuse_log.try_clone().with_context(|| {
        format!(
            "failed to clone fuse log handle {}",
            runtime_paths.fuse_log_path.display()
        )
    })?;
    cmd.arg("_fuse")
        .arg("--profile")
        .arg(profile_path)
        .arg("--record")
        .arg(record_path)
        .arg("--mountpoint")
        .arg(&runtime_paths.mount_dir)
        .arg("--pid-path")
        .arg(&runtime_paths.fuse_pid_path)
        // Keep _fuse detached from caller stdio while preserving diagnostics in
        // per-runtime logs.
        .stdin(Stdio::null())
        .stdout(Stdio::from(fuse_log))
        .stderr(Stdio::from(fuse_log_err));
    if verbose {
        cmd.arg("-v");
    }

    let child = cmd
        .spawn()
        .context("failed to spawn _fuse server process")?;
    let pid = child.id();
    let ok =
        ns_runtime::wait_for_process_mount(pid, &runtime_paths.mount_dir, Duration::from_secs(5))?;
    if !ok {
        bail!(
            "fuse server pid={} did not mount {} within timeout",
            pid,
            runtime_paths.mount_dir.display()
        );
    }
    Ok(())
}

fn apply_mount_plan_in_namespace(mount_root: &Path, mount_plan: &[MountPlanEntry]) -> Result<()> {
    if mount_plan.is_empty() {
        return Ok(());
    }
    for entry in mount_plan {
        apply_one_mount_in_namespace(mount_root, entry)?;
    }
    Ok(())
}

fn apply_one_mount_in_namespace(mount_root: &Path, entry: &MountPlanEntry) -> Result<()> {
    let (path, read_only, procfs, sysfs) = match entry {
        MountPlanEntry::Bind { path, read_only } => (path, *read_only, false, false),
        MountPlanEntry::Proc { path, read_only } => (path, *read_only, true, false),
        MountPlanEntry::Sys { path, read_only } => (path, *read_only, false, true),
    };
    let rel = path
        .strip_prefix("/")
        .with_context(|| format!("mount path must be absolute: {}", path.display()))?;
    let target = if rel.as_os_str().is_empty() {
        mount_root.to_path_buf()
    } else {
        mount_root.join(rel)
    };
    if procfs {
        mount_procfs(&target, read_only)?;
        return Ok(());
    }
    if sysfs {
        mount_sysfs(&target, read_only)?;
        return Ok(());
    }

    let src_meta = std::fs::metadata(path).with_context(|| {
        format!(
            "bind source does not exist or is inaccessible: {}",
            path.display()
        )
    })?;
    let dst_meta = std::fs::metadata(&target).with_context(|| {
        format!(
            "bind target path does not exist in jail view: {}",
            target.display()
        )
    })?;

    if src_meta.is_dir() != dst_meta.is_dir() {
        bail!(
            "bind source/target type mismatch: source={} target={}",
            path.display(),
            target.display()
        );
    }

    bind_mount(path, &target)?;
    if read_only {
        remount_bind_read_only(&target)?;
    }
    Ok(())
}

fn make_mounts_private() -> Result<()> {
    let root = CString::new("/").expect("literal '/' cannot contain NUL");
    let rc = unsafe {
        libc::mount(
            std::ptr::null(),
            root.as_ptr(),
            std::ptr::null(),
            (libc::MS_REC | libc::MS_PRIVATE) as libc::c_ulong,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("mount(MS_PRIVATE) failed");
    }
    Ok(())
}

fn bind_mount(source: &Path, target: &Path) -> Result<()> {
    let src_c = CString::new(source.as_os_str().as_encoded_bytes())
        .context("bind source path contains interior NUL byte")?;
    let dst_c = CString::new(target.as_os_str().as_encoded_bytes())
        .context("bind target path contains interior NUL byte")?;
    let rc = unsafe {
        libc::mount(
            src_c.as_ptr(),
            dst_c.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND as libc::c_ulong,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!(
                "bind mount failed: {} -> {}",
                source.display(),
                target.display()
            )
        });
    }
    Ok(())
}

fn remount_bind_read_only(target: &Path) -> Result<()> {
    let dst_c = CString::new(target.as_os_str().as_encoded_bytes())
        .context("bind target path contains interior NUL byte")?;
    let rc = unsafe {
        libc::mount(
            std::ptr::null(),
            dst_c.as_ptr(),
            std::ptr::null(),
            (libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY) as libc::c_ulong,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("bind remount read-only failed: {}", target.display()));
    }
    Ok(())
}

fn remount_read_only(target: &Path) -> Result<()> {
    let dst_c = CString::new(target.as_os_str().as_encoded_bytes())
        .context("remount target path contains interior NUL byte")?;
    let rc = unsafe {
        libc::mount(
            std::ptr::null(),
            dst_c.as_ptr(),
            std::ptr::null(),
            (libc::MS_REMOUNT | libc::MS_RDONLY) as libc::c_ulong,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("remount read-only failed: {}", target.display()));
    }
    Ok(())
}

fn mount_procfs(target: &Path, read_only: bool) -> Result<()> {
    let target_c = CString::new(target.as_os_str().as_encoded_bytes())
        .context("procfs target path contains interior NUL byte")?;
    let fstype = CString::new("proc").expect("literal has no NUL");
    let source = CString::new("proc").expect("literal has no NUL");
    let rc = unsafe {
        libc::mount(
            source.as_ptr(),
            target_c.as_ptr(),
            fstype.as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("mount procfs failed at {}", target.display()));
    }
    if read_only {
        remount_read_only(target)?;
    }
    Ok(())
}

fn mount_sysfs(target: &Path, read_only: bool) -> Result<()> {
    let target_c = CString::new(target.as_os_str().as_encoded_bytes())
        .context("sysfs target path contains interior NUL byte")?;
    let fstype = CString::new("sysfs").expect("literal has no NUL");
    let source = CString::new("sysfs").expect("literal has no NUL");
    let rc = unsafe {
        libc::mount(
            source.as_ptr(),
            target_c.as_ptr(),
            fstype.as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("mount sysfs failed at {}", target.display()));
    }
    if read_only {
        remount_read_only(target)?;
    }
    Ok(())
}

fn exit_code_from_status(status: std::process::ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return 128 + sig;
        }
    }
    1
}
