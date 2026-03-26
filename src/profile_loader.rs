use anyhow::{Context, Result};
use fs_err as fs;
use serde::{Deserialize, Serialize};
use std::hash::Hasher;
use std::path::{Path, PathBuf};
use twox_hash::XxHash64;

use crate::{cli, jail, profile, record};

const BUILTIN_DEFAULT_PROFILE_SOURCE: &str = "\
. rw
/tmp rw
/bin ro
/sbin ro
/usr ro
/lib ro
/lib64 ro
/etc ro
/dev ro
/proc ro
/sys ro
";

#[derive(Debug)]
pub(crate) struct LoadedProfile {
    pub(crate) profile: profile::Profile,
    pub(crate) normalized_source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ProfileHeaderFrame {
    pub(crate) normalized_profile: String,
}

pub(crate) fn append_profile_header(
    writer: &record::Writer,
    normalized_source: &str,
) -> Result<()> {
    let header = ProfileHeaderFrame {
        normalized_profile: normalized_source.to_string(),
    };
    writer
        .append_cbor(record::TAG_PROFILE_HEADER, &header)
        .map(|_| ())
        .context("failed to append profile header frame")?;
    writer
        .sync()
        .context("failed to flush profile header frame")
}

pub(crate) fn load_profile(profile_path: &Path) -> Result<LoadedProfile> {
    let cwd = jail::current_pwd()?;
    let source = if profile_path == Path::new(cli::DEFAULT_PROFILE) {
        BUILTIN_DEFAULT_PROFILE_SOURCE.to_string()
    } else {
        let resolved = resolve_profile_path(profile_path)?;
        fs::read_to_string(&resolved)
            .with_context(|| format!("failed to read profile file: {}", resolved.display()))?
    };
    let source_name = if profile_path == Path::new(cli::DEFAULT_PROFILE) {
        "built-in default profile".to_string()
    } else {
        format!("profile file: {}", resolve_profile_path(profile_path)?.display())
    };
    let profile = profile::Profile::parse(&source, &cwd)
        .with_context(|| format!("failed to parse {source_name}"))?;
    let normalized_source = profile::normalize_source(&source, &cwd)
        .with_context(|| format!("failed to normalize {source_name}"))?;
    Ok(LoadedProfile {
        profile,
        normalized_source,
    })
}

pub(crate) fn parse_profile_from_normalized_source(source: &str) -> Result<profile::Profile> {
    profile::Profile::parse(source, Path::new("/"))
        .context("failed to parse normalized profile source from record")
}

pub(crate) fn default_record_dir() -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .ok_or_else(|| anyhow::anyhow!("HOME is not set; cannot resolve default record directory"))?;
    Ok(PathBuf::from(home).join(".cache/cowjail"))
}

pub(crate) fn default_record_path(normalized_profile: &str, cwd: &Path) -> Result<PathBuf> {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before unix epoch")?
        .as_millis();
    let context_hash = record_context_hash(normalized_profile, cwd);
    Ok(default_record_dir()?.join(format!("{context_hash:016x}-{millis}.cjr")))
}

pub(crate) fn ensure_record_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create record directory: {}", parent.display()))?;
    }
    Ok(())
}

pub(crate) fn newest_record_path() -> Result<Option<PathBuf>> {
    let dir = default_record_dir()?;
    if !dir.exists() {
        return Ok(None);
    }

    let mut newest: Option<(std::time::SystemTime, PathBuf)> = None;
    for entry in fs::read_dir(&dir)
        .with_context(|| format!("failed to list record directory: {}", dir.display()))?
    {
        let entry =
            entry.with_context(|| format!("failed to read entry under {}", dir.display()))?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("cjr") {
            continue;
        }
        let metadata = entry
            .metadata()
            .with_context(|| format!("failed to stat record file: {}", path.display()))?;
        if !metadata.is_file() {
            continue;
        }
        let modified = metadata
            .modified()
            .with_context(|| format!("failed to get mtime: {}", path.display()))?;

        match &newest {
            Some((best, _)) if modified <= *best => {}
            _ => newest = Some((modified, path)),
        }
    }

    Ok(newest.map(|(_, path)| path))
}

fn record_context_hash(normalized_profile: &str, cwd: &Path) -> u64 {
    let mut hasher = XxHash64::default();
    hasher.write(cwd.as_os_str().as_encoded_bytes());
    hasher.write_u8(0);
    hasher.write(normalized_profile.as_bytes());
    hasher.finish()
}

fn resolve_profile_path(profile_path: &Path) -> Result<PathBuf> {
    if profile_path.is_absolute() || profile_path.components().count() > 1 {
        return Ok(profile_path.to_path_buf());
    }
    let name = profile_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("profile name is not valid UTF-8"))?;
    jail::profile_definition_path(name)
}
