use anyhow::{Context, Result, bail};
use fs_err as fs;
use std::ffi::CString;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;

use crate::cli::RunCommand;
use crate::cowfs;
use crate::jail;
use crate::ns_runtime;
use crate::profile_loader::{
    append_profile_header, ensure_record_parent_dir, parse_profile_from_normalized_source,
};
use crate::record;
use crate::vlog;

pub(crate) fn run_command(run: RunCommand) -> Result<i32> {
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        bail!(
            concat!(
                "cowjail run requires root euid (current euid={euid}).\n",
                "Example setuid setup:\n",
                "sudo chown root:root $(command -v cowjail)\n",
                "sudo chmod u+s $(command -v cowjail)"
            ),
            euid = euid
        );
    }

    let cwd = jail::current_pwd().context("failed to resolve current working directory")?;
    let ruid = unsafe { libc::getuid() };
    let rgid = unsafe { libc::getgid() };
    let resolved = jail::resolve(
        run.name.as_deref(),
        run.profile.as_deref(),
        jail::ResolveMode::EnsureExists,
    )
    .context("failed to resolve run jail")?;
    let runtime = ns_runtime::ensure_runtime_placeholders(&resolved.paths)
        .context("failed to ensure named runtime skeleton")?;
    vlog(
        run.verbose,
        format!(
            "run: runtime={} state_before={:?} state_after={:?} rebuilt={}",
            runtime.paths.runtime_dir.display(),
            runtime.state_before,
            runtime.state_after,
            runtime.rebuilt
        ),
    );
    let jail_profile = parse_profile_from_normalized_source(&resolved.normalized_profile)
        .context("failed to parse resolved jail profile")?;
    let record_path = resolved.paths.record_path.clone();
    ensure_record_parent_dir(&record_path)?;
    let writer = record::Writer::open_append(&record_path).with_context(|| {
        format!(
            "failed to open run record writer at {}",
            record_path.display()
        )
    })?;
    append_profile_header(&writer, &resolved.normalized_profile).with_context(|| {
        format!(
            "failed to append run profile header into {}",
            record_path.display()
        )
    })?;
    let cowfs = cowfs::CowFs::new(jail_profile, writer);

    let mountpoint = make_run_mountpoint()?;
    vlog(
        run.verbose,
        format!(
            "run: creating temporary mountpoint {}",
            mountpoint.display()
        ),
    );
    fs::create_dir_all(&mountpoint).with_context(|| {
        format!(
            "failed to create run mountpoint directory: {}",
            mountpoint.display()
        )
    })?;

    let bg = {
        vlog(
            run.verbose,
            format!("run: mounting fuse filesystem at {}", mountpoint.display()),
        );
        unsafe { cowfs.mount_background(&mountpoint) }.with_context(|| {
            format!(
                "failed to mount run filesystem at temporary mountpoint {}",
                mountpoint.display()
            )
        })?
    };

    vlog(
        run.verbose,
        format!(
            "run: preparing child chroot to {} then chdir to {}",
            mountpoint.display(),
            cwd.display()
        ),
    );
    let status = run_child_in_chroot(&run, &mountpoint, &cwd, ruid, rgid)
        .with_context(|| format!("failed to execute jailed command {:?}", run.program));

    vlog(
        run.verbose,
        "run: waiting for child completion done".to_string(),
    );
    vlog(
        run.verbose,
        format!("run: unmounting fuse mount {}", mountpoint.display()),
    );
    drop(bg);
    vlog(
        run.verbose,
        format!(
            "run: removing temporary mountpoint {}",
            mountpoint.display()
        ),
    );
    let _ = fs::remove_dir(&mountpoint);
    vlog(run.verbose, "run: cleanup complete".to_string());

    let status = status?;
    Ok(exit_code_from_status(status))
}

fn run_child_in_chroot(
    run: &RunCommand,
    mountpoint: &Path,
    old_cwd: &Path,
    ruid: libc::uid_t,
    rgid: libc::gid_t,
) -> Result<std::process::ExitStatus> {
    let mount_c = CString::new(mountpoint.as_os_str().as_encoded_bytes())
        .context("mount path contains interior NUL byte")?;
    let cwd_c = CString::new(old_cwd.as_os_str().as_encoded_bytes())
        .context("cwd contains interior NUL byte")?;

    let mut cmd = ProcessCommand::new(&run.program);
    cmd.args(&run.args);
    unsafe {
        cmd.pre_exec(move || {
            if libc::chroot(mount_c.as_ptr()) != 0 {
                let err = std::io::Error::last_os_error();
                return Err(std::io::Error::new(
                    err.kind(),
                    format!("chroot failed: {err}"),
                ));
            }
            if libc::chdir(cwd_c.as_ptr()) != 0 {
                let err = std::io::Error::last_os_error();
                return Err(std::io::Error::new(
                    err.kind(),
                    format!("chdir failed: {err}"),
                ));
            }
            if libc::setgroups(0, std::ptr::null()) != 0 {
                let err = std::io::Error::last_os_error();
                return Err(std::io::Error::new(
                    err.kind(),
                    format!("setgroups([]) failed: {err}"),
                ));
            }
            if libc::setgid(rgid) != 0 {
                let err = std::io::Error::last_os_error();
                return Err(std::io::Error::new(
                    err.kind(),
                    format!("setgid({rgid}) failed: {err}"),
                ));
            }
            if libc::setuid(ruid) != 0 {
                let err = std::io::Error::last_os_error();
                return Err(std::io::Error::new(
                    err.kind(),
                    format!("setuid({ruid}) failed: {err}"),
                ));
            }
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                let err = std::io::Error::last_os_error();
                return Err(std::io::Error::new(
                    err.kind(),
                    format!("prctl(PR_SET_NO_NEW_PRIVS) failed: {err}"),
                ));
            }
            Ok(())
        });
    }
    let mut child = cmd
        .spawn()
        .context("failed to spawn child command in jail")?;
    child.wait().context("failed waiting for child command")
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

fn make_run_mountpoint() -> Result<PathBuf> {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before unix epoch")?
        .as_nanos();
    Ok(PathBuf::from(format!("/tmp/cowjail-run-{pid}-{nanos}")))
}
