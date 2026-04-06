use std::ffi::OsStr;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use fs_err as fs;

use crate::cli::{ProfileAction, ProfileCommand};
use crate::fuse_runtime;
use crate::profile::{
    EvalContext, ExeResolver, FsCheck, PathExeResolver, RealFsCheck, RuleMatchKind, Visibility,
};
use crate::profile_store;

pub(crate) fn profile_command(command: ProfileCommand) -> Result<()> {
    match command.action {
        ProfileAction::Show => show_profile(),
        ProfileAction::Edit => edit_profile(),
        ProfileAction::Test { path, exe } => test_profile_path(&path, exe.as_deref()),
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
    if edited.trim().is_empty() {
        profile_store::remove_default_profile_source()?;
        eprintln!("removed default profile file; builtin default profile is now active");
    } else {
        profile_store::save_default_profile_source(&edited)?;
    }
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

fn test_profile_path(path: &Path, exe: Option<&str>) -> Result<()> {
    if !path.is_absolute() {
        bail!("rules test PATH must be an absolute path");
    }
    let cwd = std::env::current_dir().context("failed to read current directory")?;
    let profile = profile_store::load_default_profile(&cwd)?;
    let fs = RealFsCheck;
    let env = std::collections::HashMap::new();
    let exe_path = resolve_test_exe(exe)?;
    let ctx = EvalContext {
        exe: exe_path.as_deref(),
        env: &env,
        fs: &fs,
    };

    let report = profile.rule_match_report(path, &ctx);
    println!("path: {}", path.display());
    match exe_path.as_deref() {
        Some(exe_path) => println!("exe: {}", exe_path.display()),
        None => println!("exe: <none>"),
    }
    println!("visibility: {}", format_visibility(report.visibility));
    println!("effective_action: {}", report.effective_action);
    if fs.is_dir(path) {
        println!("readdir_cache: {}", profile.should_cache_readdir(path));
    } else {
        println!("readdir_cache: n/a (path is not a directory)");
    }

    println!("matches:");
    if report.entries.is_empty() {
        println!("  (none)");
        return Ok(());
    }
    for entry in report.entries {
        let kind = match entry.kind {
            RuleMatchKind::Explicit => "explicit",
            RuleMatchKind::ImplicitAncestor => "implicit-ancestor",
        };
        let status = if entry.conditions_matched {
            "matched"
        } else {
            "conditions-failed"
        };
        println!(
            "  [rule {}] {} {} kind={} status={} exe_condition={}",
            entry.rule_index + 1,
            entry.pattern,
            entry.action,
            kind,
            status,
            entry.has_exe_condition
        );
    }

    Ok(())
}

fn resolve_test_exe(exe: Option<&str>) -> Result<Option<PathBuf>> {
    let Some(exe) = exe else {
        return Ok(None);
    };
    if exe.starts_with('/') {
        return Ok(Some(PathBuf::from(exe)));
    }
    if exe.contains('/') {
        bail!("--exe must be a bare name or an absolute path");
    }
    let resolver = PathExeResolver;
    let resolved = resolver
        .resolve(exe)
        .ok_or_else(|| anyhow::anyhow!("--exe bare name not found in PATH: {exe}"))?;
    Ok(Some(resolved))
}

fn format_visibility(visibility: Visibility) -> &'static str {
    match visibility {
        Visibility::Action(_) => "action",
        Visibility::ImplicitAncestor => "implicit-ancestor",
        Visibility::Hidden => "hidden",
    }
}

fn temp_profile_path() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("leash-profile-{}-{nonce}.tmp", std::process::id()))
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

    #[test]
    fn rules_test_rejects_relative_path() {
        let err = test_profile_path(Path::new("relative/path"), None).expect_err("must fail");
        assert!(
            err.to_string()
                .contains("rules test PATH must be an absolute path"),
            "{err:#}"
        );
    }
}
