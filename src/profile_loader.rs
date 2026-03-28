use anyhow::{Context, Result};
use fs_err as fs;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::{cli, jail, profile, record};

const BUILTIN_DEFAULT_PROFILE_SOURCE: &str = "\
/tmp rw
/bin ro
/sbin ro
/usr ro
/lib ro
/lib64 ro
/etc ro
/dev/stdin ro
/dev/stdout ro
/dev/null rw
/dev/urandom ro
/dev/random ro
/proc ro
/sys ro
. rw
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
        format!(
            "profile file: {}",
            resolve_profile_path(profile_path)?.display()
        )
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

pub(crate) fn ensure_record_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create record directory: {}", parent.display()))?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn default_record_dir_from_home(home: &Path) -> PathBuf {
    home.join(".cache/cowjail")
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
