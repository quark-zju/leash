use anyhow::Result;

use crate::cli::MountCommand;
use crate::cowfs;
use crate::profile_loader::load_profile;
use crate::run_with_log;

pub(crate) fn mount_command(mount: MountCommand) -> Result<()> {
    let loaded = run_with_log(
        || load_profile(std::path::Path::new(&mount.profile)),
        || format!("load mount profile '{}'", mount.profile),
    )?;
    let fs = cowfs::CowFs::new(loaded.profile).with_mount_root(mount.path.clone());
    crate::vlog!("mount: mounting fuse at {}", mount.path.display());
    run_with_log(
        || fs.mount(&mount.path, false),
        || format!("mount fuse at {}", mount.path.display()),
    )
}
