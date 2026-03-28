use anyhow::{Context, Result};

use crate::cli::{AddCommand, ListCommand, RmCommand};
use crate::jail;
use crate::privileges;

pub(crate) fn add_command(add: AddCommand) -> Result<()> {
    if let Some(name) = add.name.as_deref() {
        jail::validate_explicit_name(name)
            .with_context(|| format!("invalid jail name '{name}'"))?;
    }
    jail::resolve(
        add.name.as_deref(),
        add.profile.as_deref(),
        jail::ResolveMode::EnsureExists,
    )
    .context("failed to create or reuse explicit jail")?;
    Ok(())
}

pub(crate) fn list_command(_list: ListCommand) -> Result<()> {
    for name in jail::list_named_jails()? {
        println!("{}", name.to_string_lossy());
    }
    Ok(())
}

pub(crate) fn rm_command(rm: RmCommand) -> Result<()> {
    privileges::require_root_euid("cowjail rm")?;
    let resolved = jail::resolve(
        rm.name.as_deref(),
        rm.profile.as_deref(),
        jail::ResolveMode::MustExist,
    )
    .context("failed to resolve jail to remove")?;
    jail::remove_jail_with_verbose(&resolved.paths, rm.verbose)
}
