use anyhow::{Result, bail};
use fs_err as fs;
use std::time::Duration;

use crate::cli::LowLevelFuseCommand;
use crate::leashfs;
use crate::privileges;
use crate::profile_loader::load_profile;
use crate::run_with_log;

pub(crate) fn fuse_command(cmd: LowLevelFuseCommand) -> Result<()> {
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        bail!("_fuse requires root euid (current euid={euid})");
    }

    run_with_log(
        || Ok(fs::create_dir_all(&cmd.mountpoint)?),
        || format!("create mountpoint directory {}", cmd.mountpoint.display()),
    )?;
    if let Some(parent) = cmd.pid_path.parent() {
        run_with_log(
            || Ok(fs::create_dir_all(parent)?),
            || format!("create pid file directory {}", parent.display()),
        )?;
    }

    let loaded = run_with_log(
        || load_profile(std::path::Path::new(&cmd.profile)),
        || format!("load fuse profile '{}'", cmd.profile),
    )?;
    let fs = leashfs::LeashFs::new(loaded.profile).with_mount_root(cmd.mountpoint.clone());
    crate::vlog!("_fuse: mounting fuse at {}", cmd.mountpoint.display());
    let needs_real_root_for_allow_other =
        !leashfs::allow_other_enabled_in_fuse_conf() && unsafe { libc::getuid() } != 0;
    if needs_real_root_for_allow_other {
        crate::vlog!(
            "{}",
            "_fuse: user_allow_other not set; temporarily switching real uid/gid to root for allow_other mount"
        );
    }
    // Keep the background session alive in this process, then drop privileges.
    // On Linux/NPTL credential changes are process-wide, so worker threads
    // spawned by mount_background also lose root credentials after the drop.
    // If that kernel/userspace assumption changes, this ordering must be
    // revisited because the mount thread is created before drop_to_real_user().
    let session = if needs_real_root_for_allow_other {
        run_with_log(
            || {
                privileges::with_temporary_real_root(|| unsafe {
                    fs.mount_background(&cmd.mountpoint, true)
                })
            },
            || format!("mount fuse at {}", cmd.mountpoint.display()),
        )?
    } else {
        run_with_log(
            || unsafe { fs.mount_background(&cmd.mountpoint, true) },
            || format!("mount fuse at {}", cmd.mountpoint.display()),
        )?
    };

    let pid = std::process::id();
    run_with_log(
        || Ok(fs::write(&cmd.pid_path, format!("{pid}\n"))?),
        || format!("write fuse pid file {}", cmd.pid_path.display()),
    )?;

    run_with_log(privileges::drop_to_real_user, || {
        "drop to real user".to_string()
    })?;
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    crate::vlog!("_fuse: running as uid={} gid={}", uid, gid);

    loop {
        std::thread::sleep(Duration::from_millis(400));
        let session_alive = !session.guard.is_finished();
        let host_has_mount = crate::ns_runtime::process_has_mount(1, &cmd.mountpoint)?;
        let self_has_mount = crate::ns_runtime::process_has_mount(pid, &cmd.mountpoint)?;
        if !session_alive || !host_has_mount || !self_has_mount {
            crate::vlog!(
                "_fuse: exiting because mount liveness failed (session_alive={} host_pid1_has_mount={} self_has_mount={}) for {}",
                session_alive,
                host_has_mount,
                self_has_mount,
                cmd.mountpoint.display(),
            );
            break;
        }
    }
    Ok(())
}
