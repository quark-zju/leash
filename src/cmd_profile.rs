use std::ffi::OsStr;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use fs_err as fs;

use crate::cli::{ProfileAction, ProfileCommand};
use crate::fuse_runtime;
use crate::profile_store;

pub(crate) fn profile_command(command: ProfileCommand) -> Result<()> {
    match command.action {
        ProfileAction::Show => show_profile(),
        ProfileAction::Edit => edit_profile(),
    }
}

fn show_profile() -> Result<()> {
    let text = profile_store::render_default_profile_source_for_show()?;
    print!("{text}");
    if !text.ends_with('\n') {
        println!();
    }
    Ok(())
}

fn edit_profile() -> Result<()> {
    let original = profile_store::load_default_profile_source()?;
    let temp_path = write_temp_profile(&original)?;
    let result = edit_profile_via_temp_file(&temp_path);
    let _ = fs::remove_file(&temp_path);
    result
}

fn edit_profile_via_temp_file(temp_path: &Path) -> Result<()> {
    run_editor(temp_path)?;
    let edited = fs::read_to_string(temp_path)
        .with_context(|| format!("failed to read edited profile {}", temp_path.display()))?;
    profile_store::save_default_profile_source(&edited)?;
    if fuse_runtime::signal_global_daemon(libc::SIGHUP)? {
        eprintln!("reloaded running _fuse daemon");
    }
    Ok(())
}

fn run_editor(path: &Path) -> Result<()> {
    if std::env::var_os("EDITOR").is_none() {
        bail!("EDITOR is not set");
    }
    let status = ProcessCommand::new("sh")
        .arg("-c")
        .arg("exec $EDITOR \"$1\"")
        .arg("leash-profile-edit")
        .arg(path)
        .status()
        .with_context(|| format!("failed to spawn editor for {}", path.display()))?;
    if !status.success() {
        bail!("editor exited with status {status}");
    }
    Ok(())
}

fn write_temp_profile(content: &str) -> Result<PathBuf> {
    let path = temp_profile_path();
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)
        .with_context(|| format!("failed to create temporary profile {}", path.display()))?;
    file.write_all(content.as_bytes())
        .with_context(|| format!("failed to seed temporary profile {}", path.display()))?;
    Ok(path)
}

fn temp_profile_path() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("leash2-profile-{}-{nonce}.tmp", std::process::id()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_temp_profile_seeds_content() {
        let path = write_temp_profile("/tmp rw\n").expect("write temp profile");
        let text = fs::read_to_string(&path).expect("read temp profile");
        assert_eq!(text, "/tmp rw\n");
        fs::remove_file(path).expect("cleanup temp profile");
    }
}
