use anyhow::{Context, Result};
use fs_err as fs;
use std::path::Path;

use crate::cli::{AddCommand, ListCommand, RmCommand};
use crate::jail;
use crate::profile_loader;

pub(crate) fn add_command(add: AddCommand) -> Result<()> {
    jail::validate_explicit_name(&add.name)
        .with_context(|| format!("invalid jail name '{}'", add.name))?;
    let profile_name = add
        .profile
        .clone()
        .unwrap_or_else(|| crate::cli::DEFAULT_PROFILE.to_string());
    let loaded = profile_loader::load_profile(Path::new(&profile_name))
        .with_context(|| format!("failed to load profile '{}'", profile_name))?;
    let paths = jail::jail_paths(&add.name)?;

    fs::create_dir_all(&paths.state_dir).with_context(|| {
        format!(
            "failed to create jail state directory {}",
            paths.state_dir.display()
        )
    })?;
    fs::write(&paths.profile_path, loaded.normalized_source).with_context(|| {
        format!(
            "failed to write jail profile file {}",
            paths.profile_path.display()
        )
    })?;
    if !paths.record_path.exists() {
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&paths.record_path)
            .with_context(|| {
                format!(
                    "failed to create jail record file {}",
                    paths.record_path.display()
                )
            })?;
    }
    Ok(())
}

pub(crate) fn list_command(_list: ListCommand) -> Result<()> {
    for name in jail::list_named_jails()? {
        println!("{}", name.to_string_lossy());
    }
    Ok(())
}

pub(crate) fn rm_command(rm: RmCommand) -> Result<()> {
    let resolved = jail::resolve(
        rm.name.as_deref(),
        rm.profile.as_deref(),
        jail::ResolveMode::MustExist,
    )
    .context("failed to resolve jail to remove")?;
    jail::remove_jail(&resolved.paths)
}
