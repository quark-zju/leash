use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use log::{debug, info};

use crate::cli::LowLevelFuseCommand;
use crate::fuse_runtime::{self, MountState};
use crate::mirrorfs::MirrorFs;
use crate::profile::ProfileController;
use crate::profile_store;

pub(crate) fn fuse_command(_command: LowLevelFuseCommand) -> Result<()> {
    let mountpoint = fuse_runtime::ensure_global_mountpoint()?;
    let state = fuse_runtime::read_global_mount_state(&mountpoint)?;
    match state {
        MountState::Unmounted => {}
        MountState::Fuse { fs_type } => {
            bail!(
                "shared FUSE mountpoint {} is already mounted as {}",
                mountpoint.display(),
                fs_type
            );
        }
        MountState::Other { fs_type } => {
            bail!(
                "shared mountpoint {} is occupied by non-FUSE filesystem {}",
                mountpoint.display(),
                fs_type
            );
        }
    }

    let cwd = std::env::current_dir().context("failed to resolve daemon startup cwd")?;
    let profile = profile_store::load_default_profile(&cwd)?;
    let fs = MirrorFs::new(PathBuf::from("/"), ProfileController::new(profile));

    info!("mounting shared mirrorfs at {}", mountpoint.display());
    debug!("_fuse: policy compiled with startup cwd {}", cwd.display());
    fs.mount(Path::new(&mountpoint))
}
