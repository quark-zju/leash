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
use crate::profile;
use crate::profile_loader;
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
    let fuse = ensure_fuse_server(
        &resolved.paths,
        &runtime.ensured.paths,
        &resolved.paths.profile_path,
        &resolved.paths.record_path,
        run.verbose,
    )?;
    if fuse.started_new {
        run_with_log(
            || apply_profile_bind_mounts(&runtime.ensured.paths.mount_dir, &resolved.normalized_profile),
            || format!("apply bind mounts under {}", runtime.ensured.paths.mount_dir.display()),
        )?;
    }

    crate::vlog!(
        "run: preparing child chroot to {} then chdir to {}",
        runtime.ensured.paths.mount_dir.display(),
        cwd.display()
    );
    let status = run_with_log(
        || run_child_in_chroot(&run, &runtime.ensured.paths.mount_dir, &cwd),
        || format!("execute jailed command {:?}", run.program),
    );

    let status = status?;
    Ok(exit_code_from_status(status))
}

fn run_child_in_chroot(
    run: &RunCommand,
    mountpoint: &Path,
    old_cwd: &Path,
) -> Result<std::process::ExitStatus> {
    let mount_c = CString::new(mountpoint.as_os_str().as_encoded_bytes())
        .context("mount path contains interior NUL byte")?;
    let cwd_c = CString::new(old_cwd.as_os_str().as_encoded_bytes())
        .context("cwd contains interior NUL byte")?;

    let mut cmd = ProcessCommand::new(&run.program);
    cmd.args(&run.args);
    unsafe {
        cmd.pre_exec(move || {
            if libc::unshare(libc::CLONE_NEWIPC) != 0 {
                let err = std::io::Error::last_os_error();
                return Err(std::io::Error::new(
                    err.kind(),
                    format!("unshare(CLONE_NEWIPC) failed: {err}"),
                ));
            }
            // FUSE mount access is keyed by fsuid/fsgid, not effective uid.
            // Align fs creds with the real user before chroot/chdir so kernel-side
            // FUSE permission checks do not reject the mount root with EACCES.
            libc::setfsgid(libc::getgid());
            libc::setfsuid(libc::getuid());
            if libc::chroot(mount_c.as_ptr()) != 0 {
                let err = std::io::Error::last_os_error();
                return Err(std::io::Error::new(
                    err.kind(),
                    format!("chroot failed: {err}"),
                ));
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

struct FuseEnsureResult {
    started_new: bool,
}

fn ensure_fuse_server(
    jail_paths: &crate::jail::JailPaths,
    runtime_paths: &ns_runtime::NsRuntimePaths,
    profile_path: &Path,
    record_path: &Path,
    verbose: bool,
) -> Result<FuseEnsureResult> {
    let _lock = ns_runtime::open_lock(jail_paths)?;
    if let Some(pid) = ns_runtime::read_fuse_pid(runtime_paths)?
        && ns_runtime::process_has_mount(pid, &runtime_paths.mount_dir)?
    {
        crate::vlog!(
            "run: reusing fuse server pid={} mount={}",
            pid,
            runtime_paths.mount_dir.display()
        );
        return Ok(FuseEnsureResult {
            started_new: false,
        });
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
    Ok(FuseEnsureResult {
        started_new: true,
    })
}

fn apply_profile_bind_mounts(mount_root: &Path, normalized_profile: &str) -> Result<()> {
    let profile = profile_loader::parse_profile_from_normalized_source(normalized_profile)?;
    let bind_mounts = profile.bind_mounts();
    if bind_mounts.is_empty() {
        return Ok(());
    }
    for bind in bind_mounts {
        apply_one_bind_mount(mount_root, bind)?;
    }
    Ok(())
}

fn apply_one_bind_mount(mount_root: &Path, bind: &profile::BindMount) -> Result<()> {
    let source = &bind.source;
    let rel = source
        .strip_prefix("/")
        .with_context(|| format!("bind source must be absolute: {}", source.display()))?;
    let target = if rel.as_os_str().is_empty() {
        mount_root.to_path_buf()
    } else {
        mount_root.join(rel)
    };

    let src_meta = std::fs::metadata(source)
        .with_context(|| format!("bind source does not exist or is inaccessible: {}", source.display()))?;
    let dst_meta = std::fs::metadata(&target)
        .with_context(|| format!("bind target path does not exist in jail view: {}", target.display()))?;

    if src_meta.is_dir() != dst_meta.is_dir() {
        bail!(
            "bind source/target type mismatch: source={} target={}",
            source.display(),
            target.display()
        );
    }

    bind_mount(source, &target)?;
    if bind.read_only {
        remount_bind_read_only(&target)?;
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
