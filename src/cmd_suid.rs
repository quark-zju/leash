use std::ffi::CString;
use std::fs::Metadata;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::process::Command as ProcessCommand;

use anyhow::{Context, Result, bail};
use fs_err as fs;

use crate::cli::LowLevelSuidCommand;
use crate::run_with_log;

pub(crate) fn suid_command(cmd: LowLevelSuidCommand) -> Result<()> {
    let exe = run_with_log(
        || Ok(std::env::current_exe()?),
        || "resolve current executable path".to_string(),
    )?;
    let meta = run_with_log(
        || Ok(fs::symlink_metadata(&exe)?),
        || format!("stat current executable {}", exe.display()),
    )?;
    if is_suid_root(&meta) {
        crate::vlog!(
            "_suid: {} is already setuid-root, skipping",
            exe.display()
        );
        return Ok(());
    }

    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        let mut sudo = ProcessCommand::new("sudo");
        sudo.arg(&exe).arg("_suid");
        if cmd.verbose {
            sudo.arg("--verbose");
        }
        crate::vlog!("_suid: reinvoking via sudo for {}", exe.display());
        let status = run_with_log(
            || Ok(sudo.status()?),
            || "start sudo for _suid self-reexec".to_string(),
        )?;
        if !status.success() {
            bail!("sudo _suid failed with status {status}");
        }

        let meta = run_with_log(
            || Ok(fs::symlink_metadata(&exe)?),
            || format!("stat current executable after sudo {}", exe.display()),
        )?;
        if is_suid_root(&meta) {
            return Ok(());
        }
        bail!(
            "_suid completed via sudo but binary is still not setuid-root: {}",
            exe.display()
        );
    }

    run_with_log(
        || apply_setuid_root(&exe),
        || format!("apply setuid root to {}", exe.display()),
    )?;
    let meta = run_with_log(
        || Ok(fs::symlink_metadata(&exe)?),
        || format!("stat executable after _suid {}", exe.display()),
    )?;
    if !is_suid_root(&meta) {
        bail!(
            "_suid attempted updates but binary is still not setuid-root: {}",
            exe.display()
        );
    }

    crate::vlog!("_suid: setuid-root ready for {}", exe.display());
    Ok(())
}

fn apply_setuid_root(path: &std::path::Path) -> Result<()> {
    let path_c = CString::new(path.as_os_str().as_bytes())
        .context("executable path contains interior NUL byte")?;

    if unsafe { libc::chown(path_c.as_ptr(), 0, 0) } != 0 {
        let err = std::io::Error::last_os_error();
        return Err(anyhow::anyhow!(
            "chown(root:root) failed for {}: {}",
            path.display(),
            err
        ));
    }

    let meta = fs::symlink_metadata(path)
        .with_context(|| format!("failed to stat executable {}", path.display()))?;
    let current_mode = meta.permissions().mode();
    let target_mode = current_mode | libc::S_ISUID;
    if unsafe { libc::chmod(path_c.as_ptr(), target_mode as libc::mode_t) } != 0 {
        let err = std::io::Error::last_os_error();
        return Err(anyhow::anyhow!(
            "chmod(u+s) failed for {}: {}",
            path.display(),
            err
        ));
    }

    Ok(())
}

fn is_suid_root(meta: &Metadata) -> bool {
    meta.uid() == 0 && (meta.mode() & libc::S_ISUID) != 0
}
