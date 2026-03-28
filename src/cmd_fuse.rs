use anyhow::{Context, Result, bail};
use fs_err as fs;

use crate::cli::LowLevelFuseCommand;
use crate::cowfs;
use crate::privileges;
use crate::profile_loader::{append_profile_header, ensure_record_parent_dir, load_profile};
use crate::record;
use crate::vlog;

pub(crate) fn fuse_command(cmd: LowLevelFuseCommand) -> Result<()> {
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        bail!("_fuse requires root euid (current euid={euid})");
    }
    if std::env::var_os("COWJAIL_UNSHARE_IPC").as_deref() == Some(std::ffi::OsStr::new("1")) {
        let rc = unsafe { libc::unshare(libc::CLONE_NEWIPC) };
        if rc != 0 {
            bail!(
                "_fuse failed to unshare ipc namespace: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    fs::create_dir_all(&cmd.mountpoint).with_context(|| {
        format!(
            "failed to create mountpoint directory {}",
            cmd.mountpoint.display()
        )
    })?;
    if let Some(parent) = cmd.pid_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create pid file directory {}", parent.display()))?;
    }

    let loaded = load_profile(std::path::Path::new(&cmd.profile))
        .with_context(|| format!("failed to load fuse profile '{}'", cmd.profile))?;
    ensure_record_parent_dir(&cmd.record)?;
    let writer = record::Writer::open_append(&cmd.record).with_context(|| {
        format!(
            "failed to open fuse record writer at {}",
            cmd.record.display()
        )
    })?;
    append_profile_header(&writer, &loaded.normalized_source).with_context(|| {
        format!(
            "failed to append fuse profile header into {}",
            cmd.record.display()
        )
    })?;

    let frames = record::read_frames_best_effort(&cmd.record)
        .with_context(|| format!("failed to read record frames from {}", cmd.record.display()))?;
    let mut fs = cowfs::CowFs::new(loaded.profile, writer);
    let replay = fs.replay_from_record_frames(&frames);
    vlog(
        cmd.verbose,
        format!(
            "_fuse: replay record={} total_frames={} pending_ops={} applied_ops={} skipped_frames={} skipped_ops={}",
            cmd.record.display(),
            replay.total_frames,
            replay.pending_ops,
            replay.applied_ops,
            replay.skipped_frames,
            replay.skipped_ops
        ),
    );
    vlog(
        cmd.verbose,
        format!(
            "_fuse: mounting fuse at {} with record {}",
            cmd.mountpoint.display(),
            cmd.record.display()
        ),
    );
    let needs_real_root_for_allow_other =
        !cowfs::allow_other_enabled_in_fuse_conf() && unsafe { libc::getuid() } != 0;
    if needs_real_root_for_allow_other {
        vlog(
            cmd.verbose,
            "_fuse: user_allow_other not set; temporarily switching real uid/gid to root for allow_other mount".to_string(),
        );
    }
    let _session = if needs_real_root_for_allow_other {
        with_temporary_real_root(|| unsafe { fs.mount_background(&cmd.mountpoint, true) })?
    } else {
        unsafe { fs.mount_background(&cmd.mountpoint, true) }?
    };

    let pid = std::process::id();
    fs::write(&cmd.pid_path, format!("{pid}\n"))
        .with_context(|| format!("failed to write fuse pid file {}", cmd.pid_path.display()))?;

    privileges::drop_to_real_user()?;
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    vlog(
        cmd.verbose,
        format!("_fuse: running as uid={} gid={}", uid, gid),
    );

    loop {
        std::thread::park();
    }
}

fn with_temporary_real_root<T, F>(f: F) -> Result<T>
where
    F: FnOnce() -> Result<T>,
{
    let mut ruid: libc::uid_t = 0;
    let mut euid: libc::uid_t = 0;
    let mut suid: libc::uid_t = 0;
    let mut rgid: libc::gid_t = 0;
    let mut egid: libc::gid_t = 0;
    let mut sgid: libc::gid_t = 0;

    let get_uid_rc = unsafe { libc::getresuid(&mut ruid, &mut euid, &mut suid) };
    if get_uid_rc != 0 {
        bail!(
            "_fuse failed to read current uid triplet: {}",
            std::io::Error::last_os_error()
        );
    }
    let get_gid_rc = unsafe { libc::getresgid(&mut rgid, &mut egid, &mut sgid) };
    if get_gid_rc != 0 {
        bail!(
            "_fuse failed to read current gid triplet: {}",
            std::io::Error::last_os_error()
        );
    }

    let set_gid_root_rc = unsafe { libc::setresgid(0, 0, 0) };
    if set_gid_root_rc != 0 {
        bail!(
            "_fuse failed to switch gid triplet to root: {}",
            std::io::Error::last_os_error()
        );
    }
    let set_uid_root_rc = unsafe { libc::setresuid(0, 0, 0) };
    if set_uid_root_rc != 0 {
        let _ = unsafe { libc::setresgid(rgid, egid, sgid) };
        bail!(
            "_fuse failed to switch uid triplet to root: {}",
            std::io::Error::last_os_error()
        );
    }

    let run_result = f();

    let restore_uid_rc = unsafe { libc::setresuid(ruid, euid, suid) };
    let restore_uid_err = std::io::Error::last_os_error();
    let restore_gid_rc = unsafe { libc::setresgid(rgid, egid, sgid) };
    let restore_gid_err = std::io::Error::last_os_error();

    if restore_uid_rc != 0 {
        bail!(
            "_fuse failed to restore uid triplet after mount: {}",
            restore_uid_err
        );
    }
    if restore_gid_rc != 0 {
        bail!(
            "_fuse failed to restore gid triplet after mount: {}",
            restore_gid_err
        );
    }

    run_result
}
