use anyhow::{Context, Result, bail};
use fs_err as fs;
use std::process::Command as ProcessCommand;

use crate::cli::{self, ProfileAction, ProfileCommand};
use crate::jail;
use crate::profile_loader;

pub(crate) fn profile_command(cmd: ProfileCommand) -> Result<()> {
    match cmd.action {
        ProfileAction::List => list_profiles(),
        ProfileAction::Show { name } => show_profile(&name),
        ProfileAction::Edit { name } => edit_profile(&name),
    }
}

fn list_profiles() -> Result<()> {
    let layout = jail::layout()?;
    let profiles_dir = layout.config_root.join("profiles");
    if !profiles_dir.exists() {
        return Ok(());
    }

    let mut names = Vec::new();
    for entry in fs::read_dir(&profiles_dir)
        .with_context(|| format!("failed to read profiles dir {}", profiles_dir.display()))?
    {
        let entry = entry.with_context(|| {
            format!(
                "failed to read entry in profiles dir {}",
                profiles_dir.display()
            )
        })?;
        let meta = entry
            .metadata()
            .with_context(|| format!("failed to stat profile {}", entry.path().display()))?;
        if !meta.is_file() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(ToOwned::to_owned) else {
            continue;
        };
        names.push(name);
    }

    names.sort();
    for name in names {
        println!("{name}");
    }
    Ok(())
}

fn edit_profile(name: &str) -> Result<()> {
    let path = resolved_profile_path(name)?;

    if std::env::var_os("EDITOR").is_none() {
        bail!("EDITOR is not set");
    }
    let status = ProcessCommand::new("sh")
        .arg("-c")
        .arg("exec $EDITOR \"$1\"")
        .arg("cowjail-profile-edit")
        .arg(&path)
        .status()
        .with_context(|| format!("failed to spawn editor for {}", path.display()))?;
    if !status.success() {
        bail!("editor exited with status {status}");
    }
    Ok(())
}

fn show_profile(name: &str) -> Result<()> {
    let path = resolved_profile_path(name)?;
    let text = fs::read_to_string(&path)
        .with_context(|| format!("failed to read profile file {}", path.display()))?;
    print!("{text}");
    if !text.ends_with('\n') {
        println!();
    }
    Ok(())
}

fn resolved_profile_path(name: &str) -> Result<std::path::PathBuf> {
    jail::validate_explicit_name(name).context("invalid profile name")?;
    let path = jail::profile_definition_path(name)?;
    if path.exists() {
        return Ok(path);
    }
    if name == cli::DEFAULT_PROFILE {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create profiles dir {}", parent.display()))?;
        }
        fs::write(&path, profile_loader::builtin_default_profile_source()).with_context(|| {
            format!("failed to initialize default profile at {}", path.display())
        })?;
        return Ok(path);
    }
    bail!("profile does not exist: {name}")
}
