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
    let _session = unsafe { fs.mount_background(&cmd.mountpoint) }?;

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
