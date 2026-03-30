use anyhow::{Context, Result, bail};
use fs_err as fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;

use crate::cli::{self, ProfileAction, ProfileCommand};
use crate::daemon_client;
use crate::jail;
use crate::profile_loader;

pub(crate) fn profile_command(cmd: ProfileCommand) -> Result<()> {
    match cmd.action {
        ProfileAction::Show => show_profile(),
        ProfileAction::Edit => edit_profile(),
    }
}

fn edit_profile() -> Result<()> {
    let path = editable_default_profile_path()?;
    let original = load_default_profile_source()?;
    let temp_path = write_temp_profile(&original)?;
    let result = (|| {
        if std::env::var_os("EDITOR").is_none() {
            bail!("EDITOR is not set");
        }
        let status = ProcessCommand::new("sh")
            .arg("-c")
            .arg("exec $EDITOR \"$1\"")
            .arg("leash-profile-edit")
            .arg(&temp_path)
            .status()
            .with_context(|| format!("failed to spawn editor for {}", temp_path.display()))?;
        if !status.success() {
            bail!("editor exited with status {status}");
        }

        let edited = fs::read_to_string(&temp_path)
            .with_context(|| format!("failed to read edited profile {}", temp_path.display()))?;
        let cwd = jail::current_pwd()?;
        let home = jail::home_dir()?;
        crate::profile::normalize_source_with_home(&edited, &cwd, &home)
            .context("edited profile is invalid")?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create profiles dir {}", parent.display()))?;
        }
        fs::write(&path, edited.as_bytes())
            .with_context(|| format!("failed to write profile file {}", path.display()))?;

        if let Some(active) = daemon_client::get_profile_if_running()? {
            let loaded = profile_loader::load_profile(Path::new(cli::DEFAULT_PROFILE))?;
            daemon_client::set_profile(&loaded.normalized_source)?;
            if active == loaded.normalized_source {
                eprintln!("daemon profile: updated (was already consistent)");
            } else {
                eprintln!("daemon profile: updated (was different from disk)");
            }
        }

        Ok(())
    })();
    let _ = fs::remove_file(&temp_path);
    result
}

fn show_profile() -> Result<()> {
    let home = jail::home_dir()?;
    let text = profile_loader::render_profile_source_for_show(Path::new(cli::DEFAULT_PROFILE), &home)
        .or_else(|_| read_profile_source_for_show())?;
    print!("{text}");
    if !text.ends_with('\n') {
        println!();
    }

    if let Some(active) = daemon_client::get_profile_if_running()? {
        let loaded = profile_loader::load_profile(Path::new(cli::DEFAULT_PROFILE))?;
        if active == loaded.normalized_source {
            println!("# daemon profile matches default profile");
        } else {
            println!("# daemon profile differs from default profile");
        }
    }
    Ok(())
}

fn editable_default_profile_path() -> Result<PathBuf> {
    let path = jail::profile_definition_path(cli::DEFAULT_PROFILE)?;
    if path.exists() {
        return Ok(path);
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create profiles dir {}", parent.display()))?;
    }
    let content = profile_loader::builtin_default_profile_source();
    fs::write(&path, content)
        .with_context(|| format!("failed to initialize profile at {}", path.display()))?;
    Ok(path)
}

fn load_default_profile_source() -> Result<String> {
    let path = jail::profile_definition_path(cli::DEFAULT_PROFILE)?;
    read_profile_source_for_show_from_path(&path)
}

fn read_profile_source_for_show() -> Result<String> {
    let path = jail::profile_definition_path(cli::DEFAULT_PROFILE)?;
    read_profile_source_for_show_from_path(&path)
}

fn read_profile_source_for_show_from_path(path: &Path) -> Result<String> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(text),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            Ok(profile_loader::builtin_default_profile_source().to_string())
        }
        Err(err) => {
            Err(err).with_context(|| format!("failed to read profile file {}", path.display()))
        }
    }
}

fn write_temp_profile(content: &str) -> Result<PathBuf> {
    let mut path = std::env::temp_dir();
    let nonce = format!(
        "leash-profile-{}-{}.tmp",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_nanos()
    );
    path.push(nonce);
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)
        .with_context(|| format!("failed to create temporary profile {}", path.display()))?;
    file.write_all(content.as_bytes())
        .with_context(|| format!("failed to seed temporary profile {}", path.display()))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn show_falls_back_to_builtin_default_without_creating_file() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("default");
        let text = read_profile_source_for_show_from_path(&path).expect("default fallback source");
        assert_eq!(text, profile_loader::builtin_default_profile_source());
        assert!(!path.exists());
    }

    #[test]
    fn show_missing_default_path_uses_builtin_source() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("default");
        let text = read_profile_source_for_show_from_path(&path).expect("missing default should fall back");
        assert_eq!(text, profile_loader::builtin_default_profile_source());
    }

    #[test]
    fn temp_profile_writer_seeds_content() {
        let path = write_temp_profile("/tmp rw\n").expect("temp profile");
        let text = fs::read_to_string(&path).expect("temp profile content");
        assert_eq!(text, "/tmp rw\n");
        fs::remove_file(path).expect("cleanup temp profile");
    }
}
