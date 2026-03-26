use anyhow::{Context, Result};

use crate::cli::MountCommand;
use crate::cowfs;
use crate::profile_loader::{append_profile_header, ensure_record_parent_dir, load_profile};
use crate::record;
use crate::vlog;

pub(crate) fn mount_command(mount: MountCommand) -> Result<()> {
    let loaded = load_profile(std::path::Path::new(&mount.profile))
        .with_context(|| format!("failed to load mount profile '{}'", mount.profile))?;
    ensure_record_parent_dir(&mount.record)?;
    let writer = record::Writer::open_append(&mount.record).with_context(|| {
        format!(
            "failed to open mount record writer at {}",
            mount.record.display()
        )
    })?;
    append_profile_header(&writer, &loaded.normalized_source).with_context(|| {
        format!(
            "failed to append mount profile header into {}",
            mount.record.display()
        )
    })?;

    let fs = cowfs::CowFs::new(loaded.profile, writer);
    vlog(
        mount.verbose,
        format!(
            "mount: mounting fuse at {} with record {}",
            mount.path.display(),
            mount.record.display()
        ),
    );
    fs.mount(&mount.path)
}
