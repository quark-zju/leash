use anyhow::{Context, Result, bail};
use std::ffi::CString;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command as ProcessCommand;
use std::process::Stdio;
use std::time::Duration;

use crate::cli::RunCommand;
use crate::jail;
use crate::ns_runtime;
use crate::privileges;
use crate::run_with_log;

pub(crate) fn run_command(run: RunCommand) -> Result<i32> {
    privileges::require_root_euid("cowjail run")?;

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
        "run: preparing child pivot_root to {} (root={}, old-root={}) then chdir to {}",
        runtime.ensured.paths.mount_dir.display(),
        runtime.ensured.paths.mount_root_dir.display(),
        runtime.ensured.paths.mount_old_root_dir.display(),
        cwd.display()
    );
    let status = run_with_log(
        || {
            run_child_in_chroot(
                &run,
                &runtime.ensured.paths.mount_dir,
                &runtime.ensured.paths.mount_old_root_dir,
                &cwd,
            )
        },
        || format!("execute jailed command {:?}", run.program),
    );

    let status = status?;
    Ok(exit_code_from_status(status))
}

fn run_child_in_chroot(
    run: &RunCommand,
    pivot_root: &Path,
    put_old: &Path,
    old_cwd: &Path,
) -> Result<std::process::ExitStatus> {
    let pivot_root_c = CString::new(pivot_root.as_os_str().as_encoded_bytes())
        .context("pivot root path contains interior NUL byte")?;
    let put_old_c = CString::new(put_old.as_os_str().as_encoded_bytes())
        .context("put_old path contains interior NUL byte")?;
    let cwd_c = CString::new(old_cwd.as_os_str().as_encoded_bytes())
        .context("cwd contains interior NUL byte")?;
    let slash = CString::new("/").expect("literal '/' cannot contain NUL");
    let old_root_in_new =
        CString::new("/old-root").expect("literal '/old-root' cannot contain NUL");
    let new_root_in_new = CString::new("/root").expect("literal '/root' cannot contain NUL");

    let mut cmd = ProcessCommand::new(&run.program);
    cmd.args(&run.args);
    unsafe {
        cmd.pre_exec(move || {
            if libc::unshare(libc::CLONE_NEWIPC | libc::CLONE_NEWNS) != 0 {
                let err = std::io::Error::last_os_error();
                return Err(std::io::Error::new(
                    err.kind(),
                    format!("unshare(CLONE_NEWIPC|CLONE_NEWNS) failed: {err}"),
                ));
            }
            if libc::mount(
                std::ptr::null(),
                slash.as_ptr(),
                std::ptr::null(),
                (libc::MS_REC | libc::MS_PRIVATE) as libc::c_ulong,
                std::ptr::null(),
            ) != 0
            {
                let err = std::io::Error::last_os_error();
                return Err(std::io::Error::new(
                    err.kind(),
                    format!("mount(MS_PRIVATE) failed: {err}"),
                ));
            }
            if libc::mount(
                pivot_root_c.as_ptr(),
                pivot_root_c.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND as libc::c_ulong,
                std::ptr::null(),
            ) != 0
            {
                let err = std::io::Error::last_os_error();
                return Err(std::io::Error::new(
                    err.kind(),
                    format!("bind-mount pivot root failed: {err}"),
                ));
            }
            // FUSE mount access is keyed by fsuid/fsgid, not effective uid.
            // Align fs creds with the real user before chroot/chdir so kernel-side
            // FUSE permission checks do not reject the mount root with EACCES.
            libc::setfsgid(libc::getgid());
            libc::setfsuid(libc::getuid());
            if libc::syscall(
                libc::SYS_pivot_root as libc::c_long,
                pivot_root_c.as_ptr(),
                put_old_c.as_ptr(),
            ) != 0
            {
                let err = std::io::Error::last_os_error();
                return Err(std::io::Error::new(
                    err.kind(),
                    format!("pivot_root failed: {err}"),
                ));
            }
            if libc::chdir(slash.as_ptr()) != 0 {
                let err = std::io::Error::last_os_error();
                return Err(std::io::Error::new(
                    err.kind(),
                    format!("chdir('/') after pivot_root failed: {err}"),
                ));
            }
            if libc::umount2(old_root_in_new.as_ptr(), libc::MNT_DETACH) != 0 {
                let err = std::io::Error::last_os_error();
                return Err(std::io::Error::new(
                    err.kind(),
                    format!("umount2('/old-root', MNT_DETACH) failed: {err}"),
                ));
            }
            if libc::rmdir(old_root_in_new.as_ptr()) != 0 {
                let err = std::io::Error::last_os_error();
                return Err(std::io::Error::new(
                    err.kind(),
                    format!("rmdir('/old-root') failed: {err}"),
                ));
            }
            if libc::chroot(new_root_in_new.as_ptr()) != 0 {
                let err = std::io::Error::last_os_error();
                return Err(std::io::Error::new(
                    err.kind(),
                    format!("chroot('/root') failed: {err}"),
                ));
            }
            if libc::chdir(cwd_c.as_ptr()) != 0 {
                let err = std::io::Error::last_os_error();
                let not_found =
                    matches!(err.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR | libc::EACCES));
                if not_found {
                    if libc::chdir(slash.as_ptr()) != 0 {
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
            if let Err(err) = privileges::drop_to_real_user() {
                return Err(std::io::Error::other(err.to_string()));
            }
            Ok(())
        });
    }
    let mut child = cmd
        .spawn()
        .context("failed to spawn child command in jail")?;
    child.wait().context("failed waiting for child command")
}

fn ensure_fuse_server(
    jail_paths: &crate::jail::JailPaths,
    runtime_paths: &ns_runtime::NsRuntimePaths,
    profile_path: &Path,
    record_path: &Path,
    verbose: bool,
) -> Result<u32> {
    let _lock = ns_runtime::open_lock(jail_paths)?;
    if let Some(pid) = ns_runtime::read_fuse_pid(runtime_paths)?
        && ns_runtime::process_has_mount(pid, &runtime_paths.mount_root_dir)?
    {
        crate::vlog!(
            "run: reusing fuse server pid={} mount={}",
            pid,
            runtime_paths.mount_root_dir.display()
        );
        return Ok(pid);
    }

    crate::vlog!(
        "run: starting fuse server for mount {}",
        runtime_paths.mount_root_dir.display()
    );
    let exe = std::env::current_exe().context("failed to locate current executable")?;
    let mut cmd = ProcessCommand::new(exe);
    cmd.arg("_fuse")
        .arg("--profile")
        .arg(profile_path)
        .arg("--record")
        .arg(record_path)
        .arg("--mountpoint")
        .arg(&runtime_paths.mount_root_dir)
        .arg("--pid-path")
        .arg(&runtime_paths.fuse_pid_path)
        // Detach _fuse from caller stdio; otherwise a failing `cowjail run` can
        // keep capture_output() callers blocked because _fuse still holds pipes.
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if verbose {
        cmd.arg("-v");
    }

    let child = cmd
        .spawn()
        .context("failed to spawn _fuse server process")?;
    let pid = child.id();
    let ok = ns_runtime::wait_for_process_mount(
        pid,
        &runtime_paths.mount_root_dir,
        Duration::from_secs(5),
    )?;
    if !ok {
        bail!(
            "fuse server pid={} did not mount {} within timeout",
            pid,
            runtime_paths.mount_root_dir.display()
        );
    }
    Ok(pid)
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
