use anyhow::{Context, Result};
use std::ffi::{CStr, CString};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;

use crate::cli::RunCommand;
use crate::cmd_daemon;
use crate::privileges;
use crate::proc_mounts;

pub(crate) fn set_process_name(name: &CStr) -> Result<()> {
    let rc = unsafe { libc::prctl(libc::PR_SET_NAME, name.as_ptr() as libc::c_ulong, 0, 0, 0) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("prctl(PR_SET_NAME) failed");
    }
    Ok(())
}

pub(crate) fn run_child_in_jail(
    run: &RunCommand,
    old_cwd: &Path,
    profile_source: &str,
) -> Result<std::process::ExitStatus> {
    let cwd_c = CString::new(old_cwd.as_os_str().as_encoded_bytes())
        .context("cwd contains interior NUL byte")?;
    let profile_source = profile_source.to_string();

    let mut cmd = ProcessCommand::new(&run.program);
    cmd.args(&run.args);
    unsafe {
        cmd.pre_exec(move || {
            if let Err(err) = make_mounts_private() {
                return Err(std::io::Error::other(err.to_string()));
            }
            if let Err(err) = unmount_uncovered_mounts(&profile_source) {
                return Err(std::io::Error::other(err.to_string()));
            }
            if let Err(err) = remount_procfs() {
                return Err(std::io::Error::other(err.to_string()));
            }
            if libc::chdir(cwd_c.as_ptr()) != 0 {
                let err = std::io::Error::last_os_error();
                let fallback_to_root = matches!(
                    err.raw_os_error(),
                    Some(libc::ENOENT | libc::ENOTDIR | libc::EACCES)
                );
                if fallback_to_root {
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
            if let Err(err) = enter_pid_namespace_worker_or_reap() {
                return Err(std::io::Error::other(err.to_string()));
            }
            if let Err(err) = privileges::drop_to_real_user() {
                return Err(std::io::Error::other(err.to_string()));
            }
            Ok(())
        });
    }
    let mut child = cmd
        .spawn()
        .context("failed to spawn child command in jail")?;
    crate::run_with_log(privileges::drop_root_euid_if_needed, || {
        "drop outer run euid after child spawn".to_string()
    })?;
    child.wait().context("failed waiting for child command")
}

pub(crate) fn setup_run_namespaces() -> Result<()> {
    let flags = libc::CLONE_NEWIPC | libc::CLONE_NEWNS | libc::CLONE_NEWPID;
    let rc = unsafe { libc::unshare(flags) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .context("unshare(CLONE_NEWIPC|CLONE_NEWNS|CLONE_NEWPID) failed");
    }
    Ok(())
}

fn enter_pid_namespace_worker_or_reap() -> Result<()> {
    let worker_pid = unsafe { libc::fork() };
    if worker_pid < 0 {
        return Err(std::io::Error::last_os_error()).context("fork for pidns worker failed");
    }
    if worker_pid > 0 {
        if let Err(_err) = privileges::drop_to_real_user() {
            unsafe { libc::_exit(1) };
        }
        let _ = set_process_name(c"leash-init");
        run_pidns_init_reaper(worker_pid);
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

fn remount_procfs() -> Result<()> {
    let proc_path = CString::new("/proc").expect("literal '/proc' cannot contain NUL");
    let proc_source = CString::new("proc").expect("literal 'proc' cannot contain NUL");
    let proc_fstype = CString::new("proc").expect("literal 'proc' cannot contain NUL");

    let umount_rc = unsafe { libc::umount2(proc_path.as_ptr(), libc::MNT_DETACH) };
    if umount_rc != 0 {
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EINVAL) | Some(libc::ENOENT) => {}
            _ => return Err(err).context("umount2('/proc', MNT_DETACH) failed"),
        }
    }

    let mount_rc = unsafe {
        libc::mount(
            proc_source.as_ptr(),
            proc_path.as_ptr(),
            proc_fstype.as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    if mount_rc != 0 {
        return Err(std::io::Error::last_os_error()).context("mount procfs at /proc failed");
    }
    Ok(())
}

fn unmount_uncovered_mounts(profile_source: &str) -> Result<()> {
    let mounts = proc_mounts::read_mount_table()?;
    let mut patterns = crate::profile::monitor_glob_patterns_for_normalized_source(profile_source)?;
    patterns.extend(crate::profile::monitor_glob_patterns_for_path(Path::new("/proc"))?);
    for path in cmd_daemon::baseline_monitor_paths() {
        patterns.extend(crate::profile::monitor_glob_patterns_for_path(&path)?);
    }
    let uncovered = proc_mounts::uncovered_mount_points(&mounts, &patterns)?;
    let mut sorted = uncovered;
    sorted.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for mount_point in sorted {
        if mount_point == PathBuf::from("/") {
            continue;
        }
        let mount_point_c = CString::new(mount_point.as_os_str().as_encoded_bytes())
            .context("mount point contains interior NUL byte")?;
        let rc = unsafe { libc::umount2(mount_point_c.as_ptr(), libc::MNT_DETACH) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EINVAL) | Some(libc::ENOENT) => {}
                _ => {
                    return Err(err).with_context(|| {
                        format!("umount2('{}', MNT_DETACH) failed", mount_point.display())
                    });
                }
            }
        }
    }
    Ok(())
}
