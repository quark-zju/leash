use anyhow::{Context, Result, bail};
use fs_err as fs;
use std::path::Path;
use std::process::Command as ProcessCommand;

use crate::cli::{self, ProfileAction, ProfileCommand};
use crate::jail;
use crate::profile_loader;

pub(crate) fn profile_command(cmd: ProfileCommand) -> Result<()> {
    match cmd.action {
        ProfileAction::List => list_profiles(),
        ProfileAction::Show { name } => show_profile(&name),
        ProfileAction::Edit { name } => edit_profile(&name),
        ProfileAction::Rm { name } => rm_profile(&name),
    }
}

fn list_profiles() -> Result<()> {
    let layout = jail::layout()?;
    let profiles_dir = layout.config_root.join("profiles");
    let mut names = Vec::new();
    if profiles_dir.exists() {
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
    }
    names.extend(crate::profile_builtin::builtin_names().map(ToOwned::to_owned));

    names.sort();
    names.dedup();
    for name in names {
        println!("{name}");
    }
    Ok(())
}

fn edit_profile(name: &str) -> Result<()> {
    if crate::profile_builtin::is_builtin_name(name) {
        bail!("builtin profile is read-only: {name}");
    }
    let path = editable_profile_path(name)?;

    if std::env::var_os("EDITOR").is_none() {
        bail!("EDITOR is not set");
    }
    let status = ProcessCommand::new("sh")
        .arg("-c")
        .arg("exec $EDITOR \"$1\"")
        .arg("leash-profile-edit")
        .arg(&path)
        .status()
        .with_context(|| format!("failed to spawn editor for {}", path.display()))?;
    if !status.success() {
        bail!("editor exited with status {status}");
    }
    Ok(())
}

fn show_profile(name: &str) -> Result<()> {
    let home = jail::home_dir()?;
    let text = profile_loader::render_profile_source_for_show(Path::new(name), &home)
        .or_else(|_| read_profile_source_for_show(name))?;
    print!("{text}");
    if !text.ends_with('\n') {
        println!();
    }
    Ok(())
}

fn editable_profile_path(name: &str) -> Result<std::path::PathBuf> {
    jail::validate_explicit_name(name).context("invalid profile name")?;
    let path = jail::profile_definition_path(name)?;
    if path.exists() {
        return Ok(path);
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create profiles dir {}", parent.display()))?;
    }
    let content = if name == cli::DEFAULT_PROFILE {
        profile_loader::builtin_default_profile_source()
    } else {
        ""
    };
    fs::write(&path, content)
        .with_context(|| format!("failed to initialize profile at {}", path.display()))?;
    Ok(path)
}

fn rm_profile(name: &str) -> Result<()> {
    if crate::profile_builtin::is_builtin_name(name) {
        bail!("builtin profile is read-only: {name}");
    }
    jail::validate_explicit_name(name).context("invalid profile name")?;
    let path = jail::profile_definition_path(name)?;
    if !path.exists() {
        bail!("profile does not exist: {name}");
    }
    fs::remove_file(&path)
        .with_context(|| format!("failed to remove profile file {}", path.display()))?;
    Ok(())
}

fn read_profile_source_for_show(name: &str) -> Result<String> {
    if let Some(source) = crate::profile_builtin::source_for_name(name) {
        return Ok(source.to_string());
    }
    jail::validate_explicit_name(name).context("invalid profile name")?;
    let path = jail::profile_definition_path(name)?;
    read_profile_source_for_show_from_path(name, &path)
}

fn read_profile_source_for_show_from_path(name: &str, path: &Path) -> Result<String> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(text),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound && name == cli::DEFAULT_PROFILE => {
            Ok(profile_loader::builtin_default_profile_source().to_string())
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            bail!("profile does not exist: {name}")
        }
        Err(err) => {
            Err(err).with_context(|| format!("failed to read profile file {}", path.display()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn show_falls_back_to_builtin_default_without_creating_file() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("default");
        let text = read_profile_source_for_show_from_path(cli::DEFAULT_PROFILE, &path)
            .expect("default fallback source");
        assert_eq!(text, profile_loader::builtin_default_profile_source());
        assert!(!path.exists());
    }

    #[test]
    fn show_missing_non_default_profile_returns_error() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("demo");
        let err = read_profile_source_for_show_from_path("demo", &path)
            .expect_err("missing non-default should fail");
        assert!(err.to_string().contains("profile does not exist: demo"));
    }

    #[test]
    fn show_supports_builtin_profile_name() {
        let text = read_profile_source_for_show("builtin:basic").expect("builtin show");
        assert!(text.contains("/bin ro"));
    }

    #[test]
    fn edit_rejects_builtin_profile_name() {
        let err = edit_profile("builtin:basic").expect_err("builtin edit should fail");
        assert!(err.to_string().contains("read-only"));
    }

    #[test]
    fn rm_rejects_builtin_profile_name() {
        let err = rm_profile("builtin:basic").expect_err("builtin rm should fail");
        assert!(err.to_string().contains("read-only"));
    }
}
