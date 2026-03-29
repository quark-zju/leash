use anyhow::{Context, Result};
use fs_err as fs;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::{cli, jail, profile};

const BUILTIN_DEFAULT_PROFILE_SOURCE: &str = "\
# Deny access to cowjail state
~/.config/cowjail deny
~/.local/state/cowjail deny

# User overrides
%include default.local

# Deny access to browser states
~/.cache/mozilla hide
~/.config/google-chrome* hide
~/.config/chromium* hide

# Deny access to ssh configs
~/.ssh deny

# Temp files
/tmp rw

# Basic system
/bin ro
/sbin ro
/usr ro
/lib ro
/lib64 ro
/etc ro

# /dev, /proc
/dev/full rw
/dev/null rw
/dev/ptmx rw
/dev/pts rw
/dev/random ro
/dev/stderr rw
/dev/stdin ro
/dev/stdout rw
/dev/tty rw
/dev/urandom ro
/dev/zero rw
/proc rw

# Coding agents
~/.agents rw
~/.claude rw
~/.codex rw
~/.copilot rw
# opencode
~/.cache/opencode rw
~/.config/opencode rw
~/.local/share/opencode rw
~/.local/state/opencode rw

# User home (some used by coding agents too)
~/bin ro
~/.bun rw
~/.cargo ro
~/.gitconfig* ro
~/.gitignore* ro
~/.local/bin ro
~/.npm ro
~/.pyenv ro
~/.rustup ro

# Home git repos
~ git-rw
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
    pub(crate) normalized_rule_sources: Vec<RuleSource>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct RuleSource {
    pub(crate) source: String,
    pub(crate) line: usize,
}

#[derive(Debug, Clone)]
struct ExpandedLine {
    text: String,
    source: String,
    line_no: usize,
}

#[derive(Debug, Clone)]
struct IncludedSource {
    source_name: String,
    content: String,
}

pub(crate) fn load_profile(profile_path: &Path) -> Result<LoadedProfile> {
    let cwd = jail::current_pwd()?;
    let home = jail::home_dir()?;
    load_profile_with_context(profile_path, &cwd, &home)
}

pub(crate) fn load_profile_with_context(
    profile_path: &Path,
    cwd: &Path,
    home: &Path,
) -> Result<LoadedProfile> {
    let resolved = resolve_profile_path_with_home(profile_path, home)?;
    let (source_name, source) = match fs::read_to_string(&resolved) {
        Ok(raw) => (resolved.display().to_string(), raw),
        Err(err)
            if err.kind() == std::io::ErrorKind::NotFound
                && profile_path == Path::new(cli::DEFAULT_PROFILE) =>
        {
            (
                "builtin:default".to_string(),
                BUILTIN_DEFAULT_PROFILE_SOURCE.to_string(),
            )
        }
        Err(err) => {
            return Err(err)
                .with_context(|| format!("failed to read profile file: {}", resolved.display()));
        }
    };
    let expanded = expand_includes(&source, &source_name, home)?;
    let expanded_source = expanded_to_string(&expanded);
    let parse_source = strip_directive_lines(&expanded_source);
    let normalized_rule_sources = effective_rule_sources(&expanded);

    let source_name = format!("profile file: {}", resolved.display());
    let profile = profile::Profile::parse_with_home(&parse_source, cwd, home)
        .with_context(|| format!("failed to parse {source_name}"))?;
    let normalized_source = profile::normalize_source_with_home(&parse_source, cwd, home)
        .with_context(|| format!("failed to normalize {source_name}"))?;
    Ok(LoadedProfile {
        profile,
        normalized_source,
        normalized_rule_sources,
    })
}

fn resolve_profile_path(profile_path: &Path) -> Result<PathBuf> {
    let home = jail::home_dir()?;
    resolve_profile_path_with_home(profile_path, &home)
}

fn resolve_profile_path_with_home(profile_path: &Path, home: &Path) -> Result<PathBuf> {
    if profile_path.is_absolute() || profile_path.components().count() > 1 {
        return Ok(profile_path.to_path_buf());
    }
    let name = profile_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("profile name is not valid UTF-8"))?;
    jail::validate_explicit_name(name).context("invalid profile name")?;
    Ok(jail::profile_definition_path_in(
        &jail::layout_from_home(home),
        name,
    ))
}

fn expand_includes(source: &str, source_name: &str, home: &Path) -> Result<Vec<ExpandedLine>> {
    let mut stack = Vec::new();
    let mut resolver = |name: &str| read_named_profile_source_with_home(name, home);
    expand_includes_with(source, source_name, &mut stack, &mut resolver)
}

fn expand_includes_with<F>(
    source: &str,
    source_name: &str,
    stack: &mut Vec<String>,
    resolver: &mut F,
) -> Result<Vec<ExpandedLine>>
where
    F: FnMut(&str) -> Result<Option<IncludedSource>>,
{
    let mut out = Vec::new();
    for (idx, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        let Some(body) = trimmed.strip_prefix('%') else {
            out.push(ExpandedLine {
                text: line.to_string(),
                source: source_name.to_string(),
                line_no: idx + 1,
            });
            continue;
        };
        let directive = body.trim();
        if directive.starts_with("set ") {
            out.push(ExpandedLine {
                text: line.to_string(),
                source: source_name.to_string(),
                line_no: idx + 1,
            });
            continue;
        }
        if !directive.starts_with("include") {
            anyhow::bail!("line {} has unknown profile directive", idx + 1);
        }
        let mut parts = directive.split_whitespace();
        let Some(keyword) = parts.next() else {
            anyhow::bail!("line {} has empty profile directive", idx + 1);
        };
        if keyword != "include" {
            anyhow::bail!("line {} has unknown profile directive", idx + 1);
        }
        let Some(name) = parts.next() else {
            anyhow::bail!("line {} has invalid include directive", idx + 1);
        };
        if parts.next().is_some() {
            anyhow::bail!("line {} has invalid include directive", idx + 1);
        }
        jail::validate_explicit_name(name).context("invalid include profile name")?;
        if stack.iter().any(|in_stack| in_stack == name) {
            anyhow::bail!("cyclic profile include detected for '{name}'");
        }
        let Some(included_source) = resolver(name)? else {
            continue;
        };
        stack.push(name.to_string());
        let nested = expand_includes_with(
            &included_source.content,
            &included_source.source_name,
            stack,
            resolver,
        )
        .with_context(|| format!("failed to expand include '{name}'"))?;
        stack.pop();
        out.extend(nested);
    }
    Ok(out)
}

fn read_named_profile_source_with_home(name: &str, home: &Path) -> Result<Option<IncludedSource>> {
    let path = jail::profile_definition_path_in(&jail::layout_from_home(home), name);
    match fs::read_to_string(&path) {
        Ok(raw) => Ok(Some(IncludedSource {
            source_name: path.display().to_string(),
            content: raw,
        })),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => {
            Err(err).with_context(|| format!("failed to read included profile {}", path.display()))
        }
    }
}

fn expanded_to_string(lines: &[ExpandedLine]) -> String {
    let mut out = String::new();
    for line in lines {
        out.push_str(&line.text);
        out.push('\n');
    }
    out
}

fn effective_rule_sources(lines: &[ExpandedLine]) -> Vec<RuleSource> {
    let mut out = Vec::new();
    for line in lines {
        let trimmed = line.text.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('%') {
            continue;
        }
        out.push(RuleSource {
            source: line.source.clone(),
            line: line.line_no,
        });
    }
    out
}

fn strip_directive_lines(source: &str) -> String {
    let mut out = String::new();
    for line in source.lines() {
        if line.trim_start().starts_with('%') {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{IncludedSource, expand_includes_with, strip_directive_lines};
    use std::collections::BTreeMap;

    #[test]
    fn include_expands_named_profile_inline() {
        let mut includes = BTreeMap::new();
        includes.insert("base".to_string(), "/etc ro\n".to_string());
        let mut resolver = |name: &str| {
            Ok(includes.get(name).cloned().map(|content| IncludedSource {
                source_name: name.to_string(),
                content,
            }))
        };
        let mut stack = Vec::new();
        let expanded = expand_includes_with(
            "%include base\n/tmp rw\n",
            "root",
            &mut stack,
            &mut resolver,
        )
        .expect("include should expand");
        let joined = super::expanded_to_string(&expanded);
        assert_eq!(joined, "/etc ro\n/tmp rw\n");
    }

    #[test]
    fn include_missing_profile_is_ignored() {
        let mut resolver = |_name: &str| Ok(None::<IncludedSource>);
        let mut stack = Vec::new();
        let expanded = expand_includes_with(
            "%include missing\n/tmp rw\n",
            "root",
            &mut stack,
            &mut resolver,
        )
        .expect("missing include should be ignored");
        let joined = super::expanded_to_string(&expanded);
        assert_eq!(joined, "/tmp rw\n");
    }

    #[test]
    fn include_rejects_non_short_name() {
        let mut resolver = |_name: &str| Ok(None::<IncludedSource>);
        let mut stack = Vec::new();
        let err = expand_includes_with("%include nested/base\n", "root", &mut stack, &mut resolver)
            .expect_err("include name with slash should fail");
        assert!(err.to_string().contains("invalid include profile name"));
    }

    #[test]
    fn effective_rule_sources_track_include_origin() {
        let mut includes = BTreeMap::new();
        includes.insert("base".to_string(), "/etc ro\n".to_string());
        let mut resolver = |name: &str| {
            Ok(includes.get(name).cloned().map(|content| IncludedSource {
                source_name: "base.profile".to_string(),
                content,
            }))
        };
        let mut stack = Vec::new();
        let expanded = expand_includes_with(
            "%include base\n/tmp rw\n",
            "root.profile",
            &mut stack,
            &mut resolver,
        )
        .expect("expand");
        let sources = super::effective_rule_sources(&expanded);
        assert_eq!(sources.len(), 2);
        assert_eq!(sources[0].source, "base.profile");
        assert_eq!(sources[0].line, 1);
        assert_eq!(sources[1].source, "root.profile");
        assert_eq!(sources[1].line, 2);
    }

    #[test]
    fn strip_directives_removes_percent_lines() {
        let stripped = strip_directive_lines("%set max_size = 3gb\n/tmp rw\n");
        assert_eq!(stripped, "/tmp rw\n");
    }

}
