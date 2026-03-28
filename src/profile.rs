use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use globset::{Glob, GlobSet, GlobSetBuilder};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    ReadOnly,
    Passthrough,
    Cow,
    Deny,
}

#[derive(Debug, Clone)]
struct Rule {
    action: RuleAction,
}

#[derive(Debug, Clone)]
struct ParsedRuleLine {
    pattern: String,
    action: RuleAction,
}

#[derive(Debug)]
pub struct Profile {
    rules: Vec<Rule>,
    globset: GlobSet,
    glob_to_rule: Vec<usize>,
    implicit_visible_ancestors: BTreeSet<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    Action(RuleAction),
    ImplicitAncestor,
    Hidden,
}

impl Profile {
    pub fn parse(profile_src: &str, launch_cwd: &Path) -> Result<Self> {
        let cwd = normalize_abs(launch_cwd)
            .context("launch cwd for profile parsing must be an absolute normalized path")?;

        let parsed = parse_lines(profile_src, &cwd)?;
        let mut rules = Vec::new();
        let mut globset_builder = GlobSetBuilder::new();
        let mut glob_to_rule = Vec::new();
        let mut implicit_visible_ancestors = BTreeSet::new();

        for (idx, line) in parsed.iter().enumerate() {
            let action = line.action;
            let pattern = line.pattern.clone();
            if action != RuleAction::Deny {
                gather_implicit_ancestors(&pattern, &mut implicit_visible_ancestors);
            }

            let rule_idx = rules.len();
            rules.push(Rule { action });

            for glob_pattern in glob_patterns_for_rule(&pattern) {
                let glob = Glob::new(&glob_pattern).with_context(|| {
                    format!("line {} has invalid glob: {glob_pattern}", idx + 1)
                })?;
                globset_builder.add(glob);
                glob_to_rule.push(rule_idx);
            }
        }

        let globset = globset_builder
            .build()
            .context("failed to build globset for profile")?;

        Ok(Self {
            rules,
            globset,
            glob_to_rule,
            implicit_visible_ancestors,
        })
    }

    pub fn first_match_action(&self, abs_path: &Path) -> Option<RuleAction> {
        let normalized = normalize_abs(abs_path).ok()?;
        let matched = self.globset.matches(&normalized);

        let mut first_rule_idx: Option<usize> = None;
        for glob_idx in &matched {
            let rule_idx = self.glob_to_rule[*glob_idx];
            if first_rule_idx.is_none_or(|existing| rule_idx < existing) {
                first_rule_idx = Some(rule_idx);
            }
        }

        first_rule_idx.map(|rule_idx| self.rules[rule_idx].action)
    }

    pub fn visibility(&self, abs_path: &Path) -> Visibility {
        let Ok(normalized) = normalize_abs(abs_path) else {
            return Visibility::Hidden;
        };

        if let Some(action) = self.first_match_action(&normalized) {
            return Visibility::Action(action);
        }

        if self.implicit_visible_ancestors.contains(&normalized) {
            return Visibility::ImplicitAncestor;
        }

        Visibility::Hidden
    }
}

pub fn normalize_source(profile_src: &str, launch_cwd: &Path) -> Result<String> {
    let cwd = normalize_abs(launch_cwd)
        .context("launch cwd for profile normalization must be an absolute normalized path")?;
    let parsed = parse_lines(profile_src, &cwd)?;
    let mut out = String::new();
    for line in parsed {
        out.push_str(&line.pattern);
        out.push(' ');
        out.push_str(action_to_str(line.action));
        out.push('\n');
    }
    Ok(out)
}

fn parse_action(token: &str) -> Result<RuleAction> {
    match token {
        "ro" => Ok(RuleAction::ReadOnly),
        "rw" => Ok(RuleAction::Passthrough),
        "cow" => Ok(RuleAction::Cow),
        "deny" => Ok(RuleAction::Deny),
        _ => bail!("action must be one of ro/rw/cow/deny"),
    }
}

fn action_to_str(action: RuleAction) -> &'static str {
    match action {
        RuleAction::ReadOnly => "ro",
        RuleAction::Passthrough => "rw",
        RuleAction::Cow => "cow",
        RuleAction::Deny => "deny",
    }
}

fn parse_lines(profile_src: &str, cwd: &Path) -> Result<Vec<ParsedRuleLine>> {
    let mut out = Vec::new();
    for (idx, line) in profile_src.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let mut parts = trimmed.split_whitespace();
        let pattern_token = parts
            .next()
            .with_context(|| format!("line {} missing pattern", idx + 1))?;
        let action_token = parts
            .next()
            .with_context(|| format!("line {} missing action", idx + 1))?;
        if parts.next().is_some() {
            bail!("line {} has extra tokens", idx + 1);
        }

        let action = parse_action(action_token)
            .with_context(|| format!("line {} has invalid action", idx + 1))?;
        let pattern = normalize_pattern(pattern_token, cwd)
            .with_context(|| format!("line {} has invalid pattern", idx + 1))?;
        out.push(ParsedRuleLine { pattern, action });
    }
    Ok(out)
}

fn normalize_pattern(token: &str, cwd: &Path) -> Result<String> {
    let normalized = if token == "." {
        cwd.to_path_buf()
    } else {
        let path = Path::new(token);
        if path.is_absolute() {
            normalize_abs(path)
                .with_context(|| format!("invalid absolute path pattern: {token}"))?
        } else {
            normalize_abs(&cwd.join(path))
                .with_context(|| format!("invalid relative path pattern: {token}"))?
        }
    };

    normalized
        .to_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow::anyhow!("path pattern is not valid UTF-8"))
}

fn glob_patterns_for_rule(pattern: &str) -> Vec<String> {
    let base = normalized_base_pattern(pattern);
    let mut out = vec![base.to_string()];

    if let Some(descendant) = descendant_glob(base)
        && descendant != base
    {
        out.push(descendant);
    }

    out
}

fn normalized_base_pattern(pattern: &str) -> &str {
    if pattern == "/" {
        "/"
    } else {
        pattern.trim_end_matches('/')
    }
}

fn descendant_glob(base: &str) -> Option<String> {
    if base == "/**" || base.ends_with("/**") {
        return None;
    }
    if base == "/" {
        return Some("/**".to_string());
    }
    Some(format!("{base}/**"))
}

fn gather_implicit_ancestors(pattern: &str, output: &mut BTreeSet<PathBuf>) {
    let mut fixed_path = if has_glob_syntax(pattern) {
        fixed_prefix(pattern)
    } else {
        PathBuf::from(pattern)
    };

    while let Some(parent) = fixed_path.parent() {
        let parent = parent.to_path_buf();
        if parent.as_os_str().is_empty() {
            break;
        }
        if !output.insert(parent.clone()) {
            break;
        }
        fixed_path = parent;
    }
}

fn fixed_prefix(pattern: &str) -> PathBuf {
    let wildcard_idx = pattern.find(['*', '?', '[']).unwrap_or(pattern.len());
    let prefix = &pattern[..wildcard_idx];
    let trimmed = prefix.trim_end_matches('/');
    if trimmed.is_empty() {
        PathBuf::from("/")
    } else {
        PathBuf::from(trimmed)
    }
}

fn has_glob_syntax(value: &str) -> bool {
    value.contains('*') || value.contains('?') || value.contains('[')
}

fn normalize_abs(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() {
        bail!("path must be absolute: {}", path.display());
    }

    let mut out = PathBuf::new();
    out.push("/");

    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(seg) => out.push(seg),
            Component::Prefix(_) => bail!("unsupported path prefix in {}", path.display()),
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(src: &str) -> Profile {
        Profile::parse(src, Path::new("/work")).expect("profile should parse")
    }

    #[test]
    fn first_match_wins() {
        let profile = parse(
            r#"
            /etc rw
            /etc ro
            "#,
        );
        assert_eq!(
            profile.first_match_action(Path::new("/etc/passwd")),
            Some(RuleAction::Passthrough)
        );
    }

    #[test]
    fn unmatched_path_is_hidden() {
        let profile = parse(
            r#"
            /tmp rw
            "#,
        );
        assert_eq!(profile.visibility(Path::new("/opt")), Visibility::Hidden);
    }

    #[test]
    fn dot_expands_to_launch_cwd() {
        let profile = parse(
            r#"
            . rw
            "#,
        );
        assert_eq!(
            profile.first_match_action(Path::new("/work/foo")),
            Some(RuleAction::Passthrough)
        );
    }

    #[test]
    fn parent_dir_is_implicitly_visible() {
        let profile = parse(
            r#"
            /foo/bar rw
            "#,
        );
        assert_eq!(
            profile.visibility(Path::new("/foo")),
            Visibility::ImplicitAncestor
        );
        assert_eq!(
            profile.first_match_action(Path::new("/foo/bar/baz")),
            Some(RuleAction::Passthrough)
        );
    }

    #[test]
    fn deny_still_overrides_visibility_when_matched() {
        let profile = parse(
            r#"
            /foo/bar rw
            /foo deny
            "#,
        );
        assert_eq!(
            profile.visibility(Path::new("/foo")),
            Visibility::Action(RuleAction::Deny)
        );
    }

    #[test]
    fn glob_rule_matches_descendants() {
        let profile = parse(
            r#"
            /home/*/.ssh deny
            "#,
        );
        assert_eq!(
            profile.first_match_action(Path::new("/home/alice/.ssh/id_rsa")),
            Some(RuleAction::Deny)
        );
    }

    #[test]
    fn parse_ignores_blank_and_comment_lines() {
        let profile = parse(
            r#"
            # system base
            /etc ro

            # workspace in cow mode
            /work rw
            "#,
        );
        assert_eq!(
            profile.first_match_action(Path::new("/etc/passwd")),
            Some(RuleAction::ReadOnly)
        );
        assert_eq!(
            profile.first_match_action(Path::new("/work/file.txt")),
            Some(RuleAction::Passthrough)
        );
    }

    #[test]
    fn normalize_source_drops_blank_and_comment_lines() {
        let normalized = normalize_source(
            r#"
            # only effective rules remain
            /etc ro

            /work rw
            "#,
            Path::new("/work"),
        )
        .expect("normalize source");
        assert_eq!(normalized, "/etc ro\n/work rw\n");
    }

    #[test]
    fn parse_cow_action() {
        let profile = parse(
            r#"
            /work cow
            "#,
        );
        assert_eq!(
            profile.first_match_action(Path::new("/work/file.txt")),
            Some(RuleAction::Cow)
        );
    }
}
