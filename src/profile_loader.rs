use anyhow::{Context, Result};
use fs_err as fs;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::{cli, jail, profile, record};

pub(crate) const DEFAULT_RECORD_MAX_SIZE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

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
~/bin ro
~/.claude rw
~/.codex rw
~/.config/cowjail deny
~/.config/opencode rw
~/.config ro
~/.local/state/cowjail deny
~/.local/state/opencode/ rw
~/.gitconfig* ro
~/.gitignore* ro
~/.ssh deny
. cow
";

pub(crate) fn builtin_default_profile_source() -> &'static str {
    BUILTIN_DEFAULT_PROFILE_SOURCE
}

pub(crate) fn default_profile_source_for_help() -> String {
    let Ok(path) = resolve_profile_path(Path::new(cli::DEFAULT_PROFILE)) else {
        return BUILTIN_DEFAULT_PROFILE_SOURCE.to_string();
    };
    match fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(_) => BUILTIN_DEFAULT_PROFILE_SOURCE.to_string(),
    }
}

#[derive(Debug)]
pub(crate) struct LoadedProfile {
    pub(crate) profile: profile::Profile,
    pub(crate) normalized_source: String,
    pub(crate) record_max_size_bytes: Option<u64>,
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
    let resolved = resolve_profile_path(profile_path)?;
    let source = match fs::read_to_string(&resolved) {
        Ok(raw) => raw,
        Err(err)
            if err.kind() == std::io::ErrorKind::NotFound
                && profile_path == Path::new(cli::DEFAULT_PROFILE) =>
        {
            BUILTIN_DEFAULT_PROFILE_SOURCE.to_string()
        }
        Err(err) => {
            return Err(err)
                .with_context(|| format!("failed to read profile file: {}", resolved.display()));
        }
    };
    let source_name = format!("profile file: {}", resolved.display());
    let profile = profile::Profile::parse(&source, &cwd)
        .with_context(|| format!("failed to parse {source_name}"))?;
    let normalized_source = profile::normalize_source(&source, &cwd)
        .with_context(|| format!("failed to normalize {source_name}"))?;
    let record_max_size_bytes = match parse_record_max_size_override(&source)
        .with_context(|| format!("failed to parse max_size from {source_name}"))?
    {
        Some(override_value) => override_value,
        None => Some(DEFAULT_RECORD_MAX_SIZE_BYTES),
    };
    Ok(LoadedProfile {
        profile,
        normalized_source,
        record_max_size_bytes,
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
    jail::validate_explicit_name(name).context("invalid profile name")?;
    jail::profile_definition_path(name)
}

fn parse_record_max_size_override(source: &str) -> Result<Option<Option<u64>>> {
    let mut parsed = None;
    for (idx, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if !trimmed.starts_with('#') {
            continue;
        }
        let body = trimmed.trim_start_matches('#').trim();
        if !body.starts_with("set ") {
            continue;
        }
        let assignment = body["set ".len()..].trim();
        let Some((key, value)) = assignment.split_once('=') else {
            anyhow::bail!(
                "line {} has invalid set directive (expected key = value)",
                idx + 1
            );
        };
        if key.trim() != "max_size" {
            continue;
        }
        parsed = Some(parse_byte_size(value.trim()).with_context(|| {
            format!(
                "line {} has invalid max_size value '{}'",
                idx + 1,
                value.trim()
            )
        })?);
    }
    Ok(parsed)
}

fn parse_byte_size(raw: &str) -> Result<Option<u64>> {
    let lowered = raw.to_ascii_lowercase();
    if matches!(lowered.as_str(), "none" | "off" | "unlimited") {
        return Ok(None);
    }

    let mut split_idx = lowered.len();
    for (i, ch) in lowered.char_indices() {
        if ch.is_ascii_alphabetic() {
            split_idx = i;
            break;
        }
    }

    let number_part = lowered[..split_idx].trim().replace('_', "");
    let suffix = lowered[split_idx..].trim();
    if number_part.is_empty() {
        anyhow::bail!("size is missing numeric prefix");
    }

    let base = number_part
        .parse::<u64>()
        .with_context(|| format!("invalid numeric size: {number_part}"))?;
    let multiplier: u64 = match suffix {
        "" | "b" => 1,
        "k" | "kb" => 1024,
        "m" | "mb" => 1024 * 1024,
        "g" | "gb" => 1024 * 1024 * 1024,
        _ => anyhow::bail!("unsupported size suffix: {suffix}"),
    };
    let bytes = base
        .checked_mul(multiplier)
        .ok_or_else(|| anyhow::anyhow!("size overflows u64"))?;
    Ok(Some(bytes))
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_RECORD_MAX_SIZE_BYTES, parse_byte_size, parse_record_max_size_override};

    #[test]
    fn parse_max_size_directive_gb() {
        let src = "# set max_size = 3gb\n/tmp rw\n";
        let size = parse_record_max_size_override(src).expect("directive should parse");
        assert_eq!(size, Some(Some(3 * 1024 * 1024 * 1024)));
    }

    #[test]
    fn parse_max_size_directive_can_disable_limit() {
        let src = "# set max_size = none\n/tmp rw\n";
        let size = parse_record_max_size_override(src).expect("directive should parse");
        assert_eq!(size, Some(None));
    }

    #[test]
    fn parse_max_size_unknown_suffix_fails() {
        let err = parse_byte_size("1tb").expect_err("unsupported suffix should fail");
        assert!(err.to_string().contains("unsupported size suffix"));
    }

    #[test]
    fn default_record_limit_is_2gb() {
        assert_eq!(DEFAULT_RECORD_MAX_SIZE_BYTES, 2 * 1024 * 1024 * 1024);
    }
}
