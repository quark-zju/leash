use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use globset::{GlobBuilder, GlobSet, GlobSetBuilder};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    ReadOnly,
    Passthrough,
    GitRw,
    Deny,
    Hide,
}

#[derive(Debug, Clone)]
struct Rule {
    action: RuleAction,
}

#[derive(Debug, Clone)]
struct ParsedRuleLine {
    pattern: String,
    action: RuleAction,
    line_no: usize,
}

#[derive(Debug)]
pub struct Profile {
    rules: Vec<Rule>,
    globset: GlobSet,
    glob_to_rule: Vec<usize>,
    implicit_visible_ancestors: BTreeSet<PathBuf>,
    implicit_ancestor_globset: GlobSet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    Action(RuleAction),
    ImplicitAncestor,
    Hidden,
}

impl Profile {
    #[cfg(test)]
    pub fn parse(profile_src: &str, launch_cwd: &Path) -> Result<Self> {
        let home = home_dir_from_env()?;
        Self::parse_with_home(profile_src, launch_cwd, &home)
    }

    pub fn parse_with_home(profile_src: &str, launch_cwd: &Path, home: &Path) -> Result<Self> {
        let cwd = normalize_abs(launch_cwd)
            .context("launch cwd for profile parsing must be an absolute normalized path")?;
        let home = normalize_abs(home)
            .context("home for profile parsing must be an absolute normalized path")?;

        let parsed = parse_lines(profile_src, &cwd, &home)?;
        let mut rules = Vec::new();
        let mut globset_builder = GlobSetBuilder::new();
        let mut glob_to_rule = Vec::new();
        let mut implicit_visible_ancestors = BTreeSet::new();
        let mut implicit_ancestor_globset_builder = GlobSetBuilder::new();
        let mut implicit_ancestor_globs = BTreeSet::new();
        for line in &parsed {
            let action = line.action;
            let pattern = line.pattern.clone();
            if action != RuleAction::Deny {
                gather_implicit_ancestors(&pattern, &mut implicit_visible_ancestors);
                for ancestor_glob in implicit_ancestor_globs_for_rule(&pattern) {
                    implicit_ancestor_globs.insert(ancestor_glob);
                }
            }

            let rule_idx = rules.len();
            rules.push(Rule { action });

            for glob_pattern in glob_patterns_for_rule(&pattern) {
                let glob = GlobBuilder::new(&glob_pattern)
                    .literal_separator(true)
                    .build()
                    .with_context(|| {
                        format!("line {} has invalid glob: {glob_pattern}", line.line_no)
                    })?;
                globset_builder.add(glob);
                glob_to_rule.push(rule_idx);
            }
        }

        let globset = globset_builder
            .build()
            .context("failed to build globset for profile")?;
        for glob_pattern in implicit_ancestor_globs {
            let glob = GlobBuilder::new(&glob_pattern)
                .literal_separator(true)
                .build()
                .with_context(|| format!("invalid implicit ancestor glob: {glob_pattern}"))?;
            implicit_ancestor_globset_builder.add(glob);
        }
        let implicit_ancestor_globset = implicit_ancestor_globset_builder
            .build()
            .context("failed to build implicit ancestor globset for profile")?;

        Ok(Self {
            rules,
            globset,
            glob_to_rule,
            implicit_visible_ancestors,
            implicit_ancestor_globset,
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
        if self.implicit_ancestor_globset.is_match(&normalized) {
            return Visibility::ImplicitAncestor;
        }

        Visibility::Hidden
    }
}

#[allow(dead_code)]
pub fn normalize_source(profile_src: &str, launch_cwd: &Path) -> Result<String> {
    let home = home_dir_from_env()?;
    normalize_source_with_home(profile_src, launch_cwd, &home)
}

pub fn normalize_source_with_home(
    profile_src: &str,
    launch_cwd: &Path,
    home: &Path,
) -> Result<String> {
    let cwd = normalize_abs(launch_cwd)
        .context("launch cwd for profile normalization must be an absolute normalized path")?;
    let home = normalize_abs(home)
        .context("home for profile normalization must be an absolute normalized path")?;
    let parsed = parse_lines(profile_src, &cwd, &home)?;
    let mut out = String::new();
    for line in parsed {
        out.push_str(&line.pattern);
        out.push(' ');
        out.push_str(action_to_str(line.action));
        out.push('\n');
    }
    Ok(out)
}

#[derive(Debug, Clone)]
pub(crate) struct NormalizedRuleLine {
    pub(crate) path: PathBuf,
    pub(crate) action: RuleAction,
    pub(crate) line_no: usize,
}

pub(crate) fn parse_normalized_rule_lines(profile_src: &str) -> Result<Vec<NormalizedRuleLine>> {
    let parsed = parse_lines(profile_src, Path::new("/"), Path::new("/"))?;
    let mut out = Vec::with_capacity(parsed.len());
    for line in parsed {
        let path = PathBuf::from(&line.pattern);
        if !path.is_absolute() {
            bail!(
                "line {} normalized profile path must be absolute",
                line.line_no
            );
        }
        out.push(NormalizedRuleLine {
            path,
            action: line.action,
            line_no: line.line_no,
        });
    }
    Ok(out)
}

fn parse_action(token: &str) -> Result<RuleAction> {
    match token {
        "ro" => Ok(RuleAction::ReadOnly),
        "rw" => Ok(RuleAction::Passthrough),
        "git-rw" => Ok(RuleAction::GitRw),
        "deny" => Ok(RuleAction::Deny),
        "hide" => Ok(RuleAction::Hide),
        _ => bail!("action must be one of ro/rw/git-rw/deny/hide"),
    }
}

fn action_to_str(action: RuleAction) -> &'static str {
    match action {
        RuleAction::ReadOnly => "ro",
        RuleAction::Passthrough => "rw",
        RuleAction::GitRw => "git-rw",
        RuleAction::Deny => "deny",
        RuleAction::Hide => "hide",
    }
}

fn parse_lines(profile_src: &str, cwd: &Path, home: &Path) -> Result<Vec<ParsedRuleLine>> {
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
        let pattern = normalize_pattern(pattern_token, cwd, home)
            .with_context(|| format!("line {} has invalid pattern", idx + 1))?;
        out.push(ParsedRuleLine {
            pattern,
            action,
            line_no: idx + 1,
        });
    }
    Ok(out)
}

fn normalize_pattern(token: &str, cwd: &Path, home: &Path) -> Result<String> {
    let normalized = if token == "." {
        cwd.to_path_buf()
    } else if token == "~" || token.starts_with("~/") {
        let suffix = token.strip_prefix("~/").unwrap_or("");
        normalize_abs(&home.join(suffix))
            .with_context(|| format!("invalid home-expanded pattern: {token}"))?
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

fn home_dir_from_env() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("HOME is not set for '~' expansion"))
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

fn implicit_ancestor_globs_for_rule(pattern: &str) -> Vec<String> {
    let base = normalized_base_pattern(pattern);
    let path = Path::new(base);
    let mut out = Vec::new();

    if base != "/" {
        out.push("/".to_string());
    }

    let components: Vec<String> = path
        .components()
        .filter_map(|c| match c {
            Component::Normal(seg) => Some(seg.to_string_lossy().to_string()),
            _ => None,
        })
        .collect();
    if components.len() <= 1 {
        return out;
    }

    let count = components.len().saturating_sub(1);
    let mut prefix = String::new();
    for component in components.into_iter().take(count) {
        prefix.push('/');
        prefix.push_str(&component);
        out.push(prefix.clone());
    }
    out
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
        Profile::parse_with_home(src, Path::new("/work"), Path::new("/home/tester"))
            .expect("profile should parse")
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
    fn tilde_expands_to_home() {
        let home = PathBuf::from("/home/tester");
        let profile = parse(
            r#"
            ~/tmp rw
            "#,
        );
        assert_eq!(
            profile.first_match_action(&home.join("tmp/file")),
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
    fn glob_rule_makes_wildcard_ancestors_traversable() {
        let profile = parse(
            r#"
            /proc/*/exe ro
            "#,
        );
        assert_eq!(
            profile.visibility(Path::new("/proc/1234")),
            Visibility::ImplicitAncestor
        );
        assert_eq!(
            profile.first_match_action(Path::new("/proc/1234/exe")),
            Some(RuleAction::ReadOnly)
        );
    }

    #[test]
    fn double_star_matches_multi_level_and_single_star_does_not() {
        let profile = parse(
            r#"
            /foo/*/.git deny
            /foo/**/.git hide
            "#,
        );
        assert_eq!(
            profile.first_match_action(Path::new("/foo/a/.git/config")),
            Some(RuleAction::Deny)
        );
        assert_eq!(
            profile.first_match_action(Path::new("/foo/a/b/.git/config")),
            Some(RuleAction::Hide)
        );
        assert_eq!(
            profile.first_match_action(Path::new("/foo/.git/config")),
            Some(RuleAction::Hide)
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
        let normalized = normalize_source_with_home(
            r#"
            # only effective rules remain
            /etc ro

            /work rw
            "#,
            Path::new("/work"),
            Path::new("/home/tester"),
        )
        .expect("normalize source");
        assert_eq!(normalized, "/etc ro\n/work rw\n");
    }

    #[test]
    fn normalize_source_expands_tilde() {
        let home = PathBuf::from("/home/tester");
        let normalized = normalize_source_with_home("~/x ro\n", Path::new("/work"), home.as_path())
            .expect("normalize");
        let expected = format!("{}/x ro\n", home.display());
        assert_eq!(normalized, expected);
    }

    #[test]
    fn parse_git_rw_action() {
        let profile = parse(
            r#"
            /work git-rw
            "#,
        );
        assert_eq!(
            profile.first_match_action(Path::new("/work/repo/file.txt")),
            Some(RuleAction::GitRw)
        );
    }

    #[test]
    fn parse_hide_action() {
        let profile = parse(
            r#"
            /work hide
            "#,
        );
        assert_eq!(
            profile.first_match_action(Path::new("/work/file.txt")),
            Some(RuleAction::Hide)
        );
    }

    #[test]
    fn parse_normalized_rule_lines_reuses_profile_action_parser() {
        let lines = parse_normalized_rule_lines("/etc ro\n/tmp rw\n").expect("should parse");
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].path, PathBuf::from("/etc"));
        assert_eq!(lines[0].action, RuleAction::ReadOnly);
        assert_eq!(lines[0].line_no, 1);
        assert_eq!(lines[1].path, PathBuf::from("/tmp"));
        assert_eq!(lines[1].action, RuleAction::Passthrough);
        assert_eq!(lines[1].line_no, 2);
    }
}
