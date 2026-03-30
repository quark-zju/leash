use std::collections::BTreeSet;
#[cfg(test)]
use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
#[cfg(test)]
use std::sync::Mutex;

use anyhow::{Context, Result, bail};
use globset::GlobBuilder;
use globset::{GlobSet, GlobSetBuilder};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    ReadOnly,
    Passthrough,
    Deny,
    Hide,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestedAccess {
    Read,
    Write,
    Execute,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessDecision {
    AllowReadOnly,
    AllowReadWrite,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchDecision {
    pub decision: AccessDecision,
    pub rule_text: String,
}

#[derive(Debug, Clone)]
pub struct CompiledRule {
    action: RuleAction,
    conditions: Vec<CompiledCondition>,
    rule_text: String,
    implicit_visible_ancestors: BTreeSet<PathBuf>,
    implicit_ancestor_globset: GlobSet,
}

#[derive(Debug, Clone)]
enum CompiledCondition {
    Exe(Option<PathBuf>),
    AncestorHas(String),
}

#[derive(Debug, Clone)]
pub struct CompiledProfile {
    rules: Vec<CompiledRule>,
    globset: GlobSet,
    glob_to_rule: Vec<usize>,
}

#[cfg(test)]
#[derive(Debug, Clone)]
struct Rule {
    action: RuleAction,
    conditions: Vec<Condition>,
    implicit_visible_ancestors: BTreeSet<PathBuf>,
    implicit_ancestor_globset: GlobSet,
}

#[derive(Debug, Clone)]
struct ParsedRuleLine {
    pattern: String,
    action: RuleAction,
    normalized_conditions: Vec<String>,
    #[cfg_attr(not(test), allow(dead_code))]
    line_no: usize,
}

#[cfg(test)]
#[derive(Debug)]
pub struct Profile {
    rules: Vec<Rule>,
    globset: GlobSet,
    glob_to_rule: Vec<usize>,
}

pub trait ExeResolver {
    fn resolve(&self, name: &str) -> Option<PathBuf>;
}

pub(crate) fn monitor_glob_patterns_for_normalized_source(profile_src: &str) -> Result<Vec<String>> {
    let exe_resolver = PathExeResolver;
    let parsed = parse_lines(profile_src, Path::new("/"), Path::new("/"), &exe_resolver)?;
    let mut patterns = BTreeSet::new();
    for line in parsed {
        patterns.extend(monitor_glob_patterns_for_pattern(&line.pattern));
    }
    Ok(patterns.into_iter().collect())
}

pub(crate) fn monitor_glob_patterns_for_path(path: &Path) -> Result<Vec<String>> {
    let normalized = normalize_abs(path)?;
    let Some(pattern) = normalized.to_str() else {
        bail!("path pattern is not valid UTF-8")
    };
    Ok(monitor_glob_patterns_for_pattern(pattern))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProcMountPolicy {
    Unmounted,
    ReadOnly,
    ReadWrite,
}

pub(crate) fn proc_mount_policy_for_normalized_source(profile_src: &str) -> Result<ProcMountPolicy> {
    let exe_resolver = PathExeResolver;
    let parsed = parse_lines(profile_src, Path::new("/"), Path::new("/"), &exe_resolver)?;
    Ok(proc_mount_policy_for_parsed_lines(&parsed))
}

#[cfg(test)]
pub trait FsCheck {
    fn exists(&self, path: &Path) -> bool;
}

struct PathExeResolver;

impl ExeResolver for PathExeResolver {
    fn resolve(&self, name: &str) -> Option<PathBuf> {
        let path_var = std::env::var_os("PATH")?;
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        None
    }
}

impl CompiledProfile {
    pub fn compile_normalized_source(profile_src: &str) -> Result<Self> {
        let exe_resolver = PathExeResolver;
        let parsed = parse_lines(profile_src, Path::new("/"), Path::new("/"), &exe_resolver)?;
        let mut rules = Vec::new();
        let mut globset_builder = GlobSetBuilder::new();
        let mut glob_to_rule = Vec::new();

        for line in &parsed {
            let rule_idx = rules.len();
            rules.push(CompiledRule {
                action: line.action,
                conditions: compile_runtime_conditions(&line.normalized_conditions)?,
                rule_text: render_normalized_rule_text(line),
                implicit_visible_ancestors: build_implicit_ancestor_set(&line.pattern, line.action),
                implicit_ancestor_globset: build_implicit_ancestor_globset(&line.pattern, line.action)?,
            });

            for glob_pattern in glob_patterns_for_runtime_rule(&line.pattern) {
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

        Ok(Self {
            rules,
            globset: globset_builder
                .build()
                .context("failed to build globset for compiled profile")?,
            glob_to_rule,
        })
    }

    pub fn evaluate(
        &self,
        abs_path: &Path,
        exe_path: Option<&Path>,
        requested_access: RequestedAccess,
    ) -> Option<MatchDecision> {
        let normalized = normalize_abs(abs_path).ok()?;
        let first_rule_idx = self.first_matching_rule_idx(&normalized, exe_path);
        let implicit_rule_idx = self.first_implicit_ancestor_rule_idx(&normalized, exe_path);

        if let Some(rule_idx) = first_rule_idx {
            let rule = &self.rules[rule_idx];
            if rule.action == RuleAction::Hide && implicit_rule_idx.is_some() {
                let implicit_idx = implicit_rule_idx.expect("checked is_some above");
                return Some(MatchDecision {
                    decision: implicit_ancestor_decision_for(requested_access),
                    rule_text: self.rules[implicit_idx].rule_text.clone(),
                });
            }
            return Some(MatchDecision {
                decision: access_decision_for(rule.action, requested_access),
                rule_text: rule.rule_text.clone(),
            });
        }

        implicit_rule_idx.map(|rule_idx| MatchDecision {
            decision: implicit_ancestor_decision_for(requested_access),
            rule_text: self.rules[rule_idx].rule_text.clone(),
        })
    }

    fn first_matching_rule_idx(
        &self,
        normalized: &Path,
        exe_path: Option<&Path>,
    ) -> Option<usize> {
        let mut first_rule_idx: Option<usize> = None;
        let matched = self.globset.matches(normalized);
        for glob_idx in &matched {
            let rule_idx = self.glob_to_rule[*glob_idx];
            if !self.rules[rule_idx].conditions_match(normalized, exe_path) {
                continue;
            }
            if first_rule_idx.is_none_or(|existing| rule_idx < existing) {
                first_rule_idx = Some(rule_idx);
            }
        }
        first_rule_idx
    }

    fn first_implicit_ancestor_rule_idx(
        &self,
        normalized: &Path,
        exe_path: Option<&Path>,
    ) -> Option<usize> {
        self.rules.iter().enumerate().find_map(|(rule_idx, rule)| {
            (action_requires_visible_ancestors(rule.action)
                && rule.conditions_match(normalized, exe_path)
                && (rule.implicit_visible_ancestors.contains(normalized)
                    || rule.implicit_ancestor_globset.is_match(normalized)))
            .then_some(rule_idx)
        })
    }
}

impl CompiledRule {
    fn conditions_match(&self, path: &Path, exe_path: Option<&Path>) -> bool {
        self.conditions
            .iter()
            .all(|condition| condition.matches(path, exe_path))
    }
}

impl CompiledCondition {
    fn matches(&self, path: &Path, exe_path: Option<&Path>) -> bool {
        match self {
            Self::Exe(Some(expected)) => exe_path == Some(expected.as_path()),
            Self::Exe(None) => false,
            Self::AncestorHas(name) => runtime_ancestor_has(path, name),
        }
    }
}

#[cfg(test)]
pub struct RealFsCheck;

#[cfg(test)]
impl FsCheck for RealFsCheck {
    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }
}

#[cfg(test)]
pub struct CachingFsCheck<F = RealFsCheck> {
    inner: F,
    cache: Mutex<HashMap<PathBuf, bool>>,
}

#[cfg(test)]
impl Default for CachingFsCheck<RealFsCheck> {
    fn default() -> Self {
        Self::new(RealFsCheck)
    }
}

#[cfg(test)]
impl<F> CachingFsCheck<F> {
    pub fn new(inner: F) -> Self {
        Self {
            inner,
            cache: Mutex::new(HashMap::new()),
        }
    }
}

#[cfg(test)]
impl<F: FsCheck> FsCheck for CachingFsCheck<F> {
    fn exists(&self, path: &Path) -> bool {
        if let Some(cached) = self
            .cache
            .lock()
            .expect("fs cache poisoned")
            .get(path)
            .copied()
        {
            return cached;
        }
        let exists = self.inner.exists(path);
        self.cache
            .lock()
            .expect("fs cache poisoned")
            .insert(path.to_path_buf(), exists);
        exists
    }
}

#[cfg(test)]
#[derive(Debug, Clone)]
enum Condition {
    Exe(Option<PathBuf>),
    AncestorHas(String),
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    Action(RuleAction),
    ImplicitAncestor,
    Hidden,
}

#[cfg(test)]
impl Profile {
    pub fn parse_with_home(profile_src: &str, launch_cwd: &Path, home: &Path) -> Result<Self> {
        let cwd = normalize_abs(launch_cwd)
            .context("launch cwd for profile parsing must be an absolute normalized path")?;
        let home = normalize_abs(home)
            .context("home for profile parsing must be an absolute normalized path")?;

        let exe_resolver = PathExeResolver;
        let parsed = parse_lines(profile_src, &cwd, &home, &exe_resolver)?;
        let mut rules = Vec::new();
        let mut globset_builder = GlobSetBuilder::new();
        let mut glob_to_rule = Vec::new();
        for line in &parsed {
            let action = line.action;
            let pattern = line.pattern.clone();
            let conditions = compile_conditions(&line.normalized_conditions, &exe_resolver)
                .with_context(|| format!("line {} has invalid conditions", line.line_no))?;
            let (implicit_visible_ancestors, implicit_ancestor_globset) =
                build_implicit_ancestor_sets(&pattern, action)?;

            let rule_idx = rules.len();
            rules.push(Rule {
                action,
                conditions,
                implicit_visible_ancestors,
                implicit_ancestor_globset,
            });

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

        Ok(Self {
            rules,
            globset,
            glob_to_rule,
        })
    }

    pub fn first_match_action(&self, abs_path: &Path) -> Option<RuleAction> {
        self.first_match_action_for_exe(abs_path, None)
    }

    pub fn first_match_action_for_exe(
        &self,
        abs_path: &Path,
        exe_path: Option<&Path>,
    ) -> Option<RuleAction> {
        self.first_match_action_with_checks(abs_path, exe_path, &RealFsCheck)
    }

    pub fn first_match_action_with_checks(
        &self,
        abs_path: &Path,
        exe_path: Option<&Path>,
        fs_check: &dyn FsCheck,
    ) -> Option<RuleAction> {
        let normalized = normalize_abs(abs_path).ok()?;
        let matched = self.globset.matches(&normalized);

        let mut first_rule_idx: Option<usize> = None;
        for glob_idx in &matched {
            let rule_idx = self.glob_to_rule[*glob_idx];
            if !self.rules[rule_idx].conditions_match(&normalized, exe_path, fs_check) {
                continue;
            }
            if first_rule_idx.is_none_or(|existing| rule_idx < existing) {
                first_rule_idx = Some(rule_idx);
            }
        }

        first_rule_idx.map(|rule_idx| self.rules[rule_idx].action)
    }

    pub fn visibility(&self, abs_path: &Path) -> Visibility {
        self.visibility_for_exe(abs_path, None)
    }

    pub fn visibility_for_exe(&self, abs_path: &Path, exe_path: Option<&Path>) -> Visibility {
        self.visibility_with_checks(abs_path, exe_path, &RealFsCheck)
    }

    pub fn visibility_with_checks(
        &self,
        abs_path: &Path,
        exe_path: Option<&Path>,
        fs_check: &dyn FsCheck,
    ) -> Visibility {
        let Ok(normalized) = normalize_abs(abs_path) else {
            return Visibility::Hidden;
        };

        if let Some(action) = self.first_match_action_with_checks(&normalized, exe_path, fs_check) {
            if action == RuleAction::Hide
                && self.is_implicit_visible_ancestor(&normalized, exe_path, fs_check)
            {
                return Visibility::ImplicitAncestor;
            }
            return Visibility::Action(action);
        }

        if self.is_implicit_visible_ancestor(&normalized, exe_path, fs_check) {
            return Visibility::ImplicitAncestor;
        }

        Visibility::Hidden
    }

    fn is_implicit_visible_ancestor(
        &self,
        normalized: &Path,
        exe_path: Option<&Path>,
        fs_check: &dyn FsCheck,
    ) -> bool {
        self.rules.iter().any(|rule| {
            action_requires_visible_ancestors(rule.action)
                && rule.conditions_match(normalized, exe_path, fs_check)
                && (rule.implicit_visible_ancestors.contains(normalized)
                    || rule.implicit_ancestor_globset.is_match(normalized))
        })
    }
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
    let exe_resolver = PathExeResolver;
    let parsed = parse_lines(profile_src, &cwd, &home, &exe_resolver)?;
    let mut out = String::new();
    for line in parsed {
        out.push_str(&line.pattern);
        out.push(' ');
        out.push_str(action_to_str(line.action));
        if !line.normalized_conditions.is_empty() {
            out.push_str(" when ");
            out.push_str(&line.normalized_conditions.join(","));
        }
        out.push('\n');
    }
    Ok(out)
}

#[cfg(test)]
#[derive(Debug, Clone)]
pub(crate) struct NormalizedRuleLine {
    pub(crate) path: PathBuf,
    pub(crate) action: RuleAction,
    pub(crate) line_no: usize,
}

#[cfg(test)]
pub(crate) fn parse_normalized_rule_lines(profile_src: &str) -> Result<Vec<NormalizedRuleLine>> {
    let exe_resolver = PathExeResolver;
    let parsed = parse_lines(profile_src, Path::new("/"), Path::new("/"), &exe_resolver)?;
    let mut out = Vec::with_capacity(parsed.len());
    for line in parsed {
        if !line.normalized_conditions.is_empty() {
            bail!(
                "line {} conditional rules are not supported here",
                line.line_no
            );
        }
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
        "deny" => Ok(RuleAction::Deny),
        "hide" => Ok(RuleAction::Hide),
        _ => bail!("action must be one of ro/rw/deny/hide"),
    }
}

fn action_to_str(action: RuleAction) -> &'static str {
    match action {
        RuleAction::ReadOnly => "ro",
        RuleAction::Passthrough => "rw",
        RuleAction::Deny => "deny",
        RuleAction::Hide => "hide",
    }
}

fn render_normalized_rule_text(line: &ParsedRuleLine) -> String {
    let mut rendered = format!("{} {}", line.pattern, action_to_str(line.action));
    if !line.normalized_conditions.is_empty() {
        rendered.push_str(" when ");
        rendered.push_str(&line.normalized_conditions.join(","));
    }
    rendered
}

fn access_decision_for(action: RuleAction, requested_access: RequestedAccess) -> AccessDecision {
    match action {
        RuleAction::Passthrough => AccessDecision::AllowReadWrite,
        RuleAction::ReadOnly => match requested_access {
            RequestedAccess::Write => AccessDecision::Deny,
            RequestedAccess::Read | RequestedAccess::Execute => AccessDecision::AllowReadOnly,
        },
        RuleAction::Deny | RuleAction::Hide => AccessDecision::Deny,
    }
}

fn implicit_ancestor_decision_for(requested_access: RequestedAccess) -> AccessDecision {
    match requested_access {
        RequestedAccess::Write => AccessDecision::Deny,
        RequestedAccess::Read | RequestedAccess::Execute => AccessDecision::AllowReadOnly,
    }
}

fn compile_runtime_conditions(tokens: &[String]) -> Result<Vec<CompiledCondition>> {
    let mut out = Vec::with_capacity(tokens.len());
    for token in tokens {
        if let Some(rest) = token.strip_prefix("exe=") {
            out.push(CompiledCondition::Exe(parse_runtime_exe_condition(rest)?));
        } else if let Some(rest) = token.strip_prefix("ancestor-has=") {
            out.push(CompiledCondition::AncestorHas(rest.to_string()));
        } else {
            bail!("unknown condition '{token}'")
        }
    }
    Ok(out)
}

fn parse_runtime_exe_condition(value: &str) -> Result<Option<PathBuf>> {
    if value.starts_with('/') {
        return Ok(Some(PathBuf::from(value)));
    }
    if value.contains('/') {
        bail!("invalid exe= value '{value}': must be a bare name or an absolute path");
    }
    Ok(None)
}

fn glob_patterns_for_runtime_rule(pattern: &str) -> Vec<String> {
    let base = normalized_base_pattern_runtime(pattern);
    let mut out = vec![base.to_string()];
    if let Some(descendant) = descendant_glob_runtime(base)
        && descendant != base
    {
        out.push(descendant);
    }
    out
}

fn monitor_glob_patterns_for_pattern(pattern: &str) -> Vec<String> {
    let mut out = BTreeSet::new();
    out.extend(glob_patterns_for_runtime_rule(pattern));
    out.extend(implicit_ancestor_globs_for_rule(pattern));
    out.into_iter().collect()
}

fn normalized_base_pattern_runtime(pattern: &str) -> &str {
    if pattern == "/" {
        "/"
    } else {
        pattern.trim_end_matches('/')
    }
}

fn descendant_glob_runtime(base: &str) -> Option<String> {
    if base == "/**" || base.ends_with("/**") {
        return None;
    }
    if base == "/" {
        return Some("/**".to_string());
    }
    Some(format!("{base}/**"))
}

fn runtime_ancestor_has(path: &Path, name: &str) -> bool {
    let mut dir = match path.parent() {
        Some(parent) => parent.to_path_buf(),
        None => return false,
    };
    loop {
        if dir.join(name).exists() {
            return true;
        }
        match dir.parent() {
            Some(parent) if parent != dir => dir = parent.to_path_buf(),
            _ => return false,
        }
    }
}

fn action_requires_visible_ancestors(action: RuleAction) -> bool {
    matches!(action, RuleAction::ReadOnly | RuleAction::Passthrough)
}

#[cfg(test)]
fn compile_conditions(tokens: &[String], exe_resolver: &dyn ExeResolver) -> Result<Vec<Condition>> {
    let mut out = Vec::with_capacity(tokens.len());
    for token in tokens {
        if let Some(rest) = token.strip_prefix("exe=") {
            out.push(Condition::Exe(resolve_exe(rest, exe_resolver)?));
        } else if let Some(rest) = token.strip_prefix("ancestor-has=") {
            out.push(Condition::AncestorHas(rest.to_string()));
        } else {
            bail!("unknown condition '{token}'")
        }
    }
    Ok(out)
}

fn resolve_exe(value: &str, resolver: &dyn ExeResolver) -> Result<Option<PathBuf>> {
    if value.starts_with('/') {
        return Ok(Some(PathBuf::from(value)));
    }
    if value.contains('/') {
        bail!("invalid exe= value '{value}': must be a bare name or an absolute path");
    }
    Ok(resolver.resolve(value))
}

fn parse_lines(
    profile_src: &str,
    cwd: &Path,
    home: &Path,
    exe_resolver: &dyn ExeResolver,
) -> Result<Vec<ParsedRuleLine>> {
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

        let normalized_conditions = match parts.next() {
            None => Vec::new(),
            Some("when") => {
                let conds_str = parts
                    .next()
                    .with_context(|| format!("line {} missing conditions", idx + 1))?;
                if parts.next().is_some() {
                    bail!("line {} has extra tokens after conditions", idx + 1);
                }
                conds_str
                    .split(',')
                    .map(|raw| normalize_condition(raw.trim(), exe_resolver))
                    .collect::<Result<Vec<_>>>()?
            }
            Some(other) => bail!("line {} expected 'when' but got '{other}'", idx + 1),
        };

        let action = parse_action(action_token)
            .with_context(|| format!("line {} has invalid action", idx + 1))?;
        let pattern = normalize_pattern(pattern_token, cwd, home)
            .with_context(|| format!("line {} has invalid pattern", idx + 1))?;
        validate_special_rule(&pattern, action, &normalized_conditions, idx + 1)?;
        out.push(ParsedRuleLine {
            pattern,
            action,
            normalized_conditions,
            line_no: idx + 1,
        });
    }
    Ok(out)
}

fn normalize_condition(raw: &str, exe_resolver: &dyn ExeResolver) -> Result<String> {
    if let Some(rest) = raw.strip_prefix("exe=") {
        let resolved = resolve_exe(rest, exe_resolver)?;
        return Ok(match resolved {
            Some(path) => format!("exe={}", path.display()),
            None => format!("exe={rest}"),
        });
    }
    if let Some(rest) = raw.strip_prefix("ancestor-has=") {
        return Ok(format!("ancestor-has={rest}"));
    }
    bail!("unknown condition '{raw}'")
}

fn validate_special_rule(
    pattern: &str,
    action: RuleAction,
    normalized_conditions: &[String],
    line_no: usize,
) -> Result<()> {
    if pattern == "/proc" {
        if !normalized_conditions.is_empty() {
            bail!("line {line_no} /proc rule does not support conditions");
        }
        if !matches!(action, RuleAction::ReadOnly | RuleAction::Passthrough) {
            bail!("line {line_no} /proc rule must use ro or rw");
        }
        return Ok(());
    }
    if pattern.starts_with("/proc/") || fixed_prefix(pattern) == PathBuf::from("/proc") {
        bail!("line {line_no} /proc subpath rules are not supported");
    }
    Ok(())
}

fn proc_mount_policy_for_parsed_lines(lines: &[ParsedRuleLine]) -> ProcMountPolicy {
    lines.iter()
        .find(|line| line.pattern == "/proc")
        .map(|line| match line.action {
            RuleAction::ReadOnly => ProcMountPolicy::ReadOnly,
            RuleAction::Passthrough => ProcMountPolicy::ReadWrite,
            RuleAction::Deny | RuleAction::Hide => ProcMountPolicy::Unmounted,
        })
        .unwrap_or(ProcMountPolicy::Unmounted)
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

#[cfg(test)]
impl Rule {
    fn conditions_match(
        &self,
        path: &Path,
        exe_path: Option<&Path>,
        fs_check: &dyn FsCheck,
    ) -> bool {
        self.conditions
            .iter()
            .all(|cond| cond.matches(path, exe_path, fs_check))
    }
}

#[cfg(test)]
impl Condition {
    fn matches(&self, path: &Path, exe_path: Option<&Path>, fs_check: &dyn FsCheck) -> bool {
        match self {
            Condition::Exe(Some(expected)) => exe_path == Some(expected.as_path()),
            Condition::Exe(None) => false,
            Condition::AncestorHas(name) => ancestor_has(path, name, fs_check),
        }
    }
}

#[cfg(test)]
fn ancestor_has(path: &Path, name: &str, fs_check: &dyn FsCheck) -> bool {
    let mut dir = match path.parent() {
        Some(parent) => parent.to_path_buf(),
        None => return false,
    };
    loop {
        if fs_check.exists(&dir.join(name)) {
            return true;
        }
        match dir.parent() {
            Some(parent) if parent != dir => dir = parent.to_path_buf(),
            _ => return false,
        }
    }
}

fn build_implicit_ancestor_set(pattern: &str, action: RuleAction) -> BTreeSet<PathBuf> {
    let mut implicit_visible_ancestors = BTreeSet::new();
    if action_requires_visible_ancestors(action) {
        gather_implicit_ancestors(pattern, &mut implicit_visible_ancestors);
    }
    implicit_visible_ancestors
}

fn build_implicit_ancestor_globset(pattern: &str, action: RuleAction) -> Result<GlobSet> {
    let mut implicit_ancestor_globset_builder = GlobSetBuilder::new();
    if action_requires_visible_ancestors(action) {
        for ancestor_glob in implicit_ancestor_globs_for_rule(pattern) {
            let glob = GlobBuilder::new(&ancestor_glob)
                .literal_separator(true)
                .build()
                .with_context(|| format!("invalid implicit ancestor glob: {ancestor_glob}"))?;
            implicit_ancestor_globset_builder.add(glob);
        }
    }
    implicit_ancestor_globset_builder
        .build()
        .context("failed to build implicit ancestor globset for profile")
}

#[cfg(test)]
fn build_implicit_ancestor_sets(
    pattern: &str,
    action: RuleAction,
) -> Result<(BTreeSet<PathBuf>, GlobSet)> {
    Ok((
        build_implicit_ancestor_set(pattern, action),
        build_implicit_ancestor_globset(pattern, action)?,
    ))
}

#[cfg(test)]
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
    use std::cell::Cell;

    struct MockExeResolver(std::collections::HashMap<String, PathBuf>);

    impl ExeResolver for MockExeResolver {
        fn resolve(&self, name: &str) -> Option<PathBuf> {
            self.0.get(name).cloned()
        }
    }

    struct CountingFsCheck {
        hits: Cell<usize>,
        existing: std::collections::HashSet<PathBuf>,
    }

    impl CountingFsCheck {
        fn new(paths: &[&str]) -> Self {
            Self {
                hits: Cell::new(0),
                existing: paths.iter().map(PathBuf::from).collect(),
            }
        }
    }

    impl FsCheck for CountingFsCheck {
        fn exists(&self, path: &Path) -> bool {
            self.hits.set(self.hits.get() + 1);
            self.existing.contains(path)
        }
    }

    fn parse(src: &str) -> Profile {
        Profile::parse_with_home(src, Path::new("/work"), Path::new("/home/tester"))
            .expect("profile should parse")
    }

    fn parse_with_exe(src: &str, exe_pairs: &[(&str, &str)]) -> Profile {
        let resolver = MockExeResolver(
            exe_pairs
                .iter()
                .map(|(name, path)| (name.to_string(), PathBuf::from(path)))
                .collect(),
        );
        let cwd = PathBuf::from("/work");
        let home = PathBuf::from("/home/tester");
        let parsed = parse_lines(src, &cwd, &home, &resolver).expect("parse lines");
        let mut rules = Vec::new();
        let mut globset_builder = GlobSetBuilder::new();
        let mut glob_to_rule = Vec::new();
        for line in &parsed {
            let conditions = compile_conditions(&line.normalized_conditions, &resolver)
                .expect("compile conditions");
            let (implicit_visible_ancestors, implicit_ancestor_globset) =
                build_implicit_ancestor_sets(&line.pattern, line.action).expect("ancestor sets");
            let rule_idx = rules.len();
            rules.push(Rule {
                action: line.action,
                conditions,
                implicit_visible_ancestors,
                implicit_ancestor_globset,
            });
            for glob_pattern in glob_patterns_for_rule(&line.pattern) {
                let glob = GlobBuilder::new(&glob_pattern)
                    .literal_separator(true)
                    .build()
                    .expect("glob");
                globset_builder.add(glob);
                glob_to_rule.push(rule_idx);
            }
        }
        Profile {
            rules,
            globset: globset_builder.build().expect("globset"),
            glob_to_rule,
        }
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
    fn hide_is_overridden_for_visible_ancestor_of_explicit_child_rule() {
        let profile = parse(
            r#"
            ~/.config/opencode rw
            ~/.config hide
            "#,
        );
        assert_eq!(
            profile.visibility(Path::new("/home/tester/.config")),
            Visibility::ImplicitAncestor
        );
        assert_eq!(
            profile.first_match_action(Path::new("/home/tester/.config/opencode/state.json")),
            Some(RuleAction::Passthrough)
        );
    }

    #[test]
    fn hide_rule_does_not_make_its_ancestors_implicitly_visible() {
        let profile = parse(
            r#"
            /foo/bar hide
            "#,
        );
        assert_eq!(profile.visibility(Path::new("/foo")), Visibility::Hidden);
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
            /run/*/exe ro
            "#,
        );
        assert_eq!(
            profile.visibility(Path::new("/run/1234")),
            Visibility::ImplicitAncestor
        );
        assert_eq!(
            profile.first_match_action(Path::new("/run/1234/exe")),
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

    #[test]
    fn exe_condition_matches_resolved_binary() {
        let profile = parse_with_exe(
            "/tmp rw when exe=git\n/tmp ro\n",
            &[("git", "/usr/bin/git")],
        );
        assert_eq!(
            profile.first_match_action_for_exe(
                Path::new("/tmp/file"),
                Some(Path::new("/usr/bin/git"))
            ),
            Some(RuleAction::Passthrough)
        );
        assert_eq!(
            profile.first_match_action_for_exe(
                Path::new("/tmp/file"),
                Some(Path::new("/usr/bin/vim"))
            ),
            Some(RuleAction::ReadOnly)
        );
    }

    #[test]
    fn conditional_rule_does_not_make_ancestor_visible_without_matching_exe() {
        let profile = parse_with_exe("/foo/bar rw when exe=git\n", &[("git", "/usr/bin/git")]);
        assert_eq!(
            profile.visibility_for_exe(Path::new("/foo"), Some(Path::new("/usr/bin/vim"))),
            Visibility::Hidden
        );
        assert_eq!(
            profile.visibility_for_exe(Path::new("/foo"), Some(Path::new("/usr/bin/git"))),
            Visibility::ImplicitAncestor
        );
    }

    #[test]
    fn ancestor_has_condition_matches_when_marker_exists() {
        let profile = parse("/work/**/*.rs rw when ancestor-has=.git\n/work ro\n");
        let fs_check = CountingFsCheck::new(&["/work/repo/.git"]);
        assert_eq!(
            profile.first_match_action_with_checks(
                Path::new("/work/repo/src/lib.rs"),
                None,
                &fs_check,
            ),
            Some(RuleAction::Passthrough)
        );
        assert_eq!(
            profile.first_match_action_with_checks(
                Path::new("/work/loose/src/lib.rs"),
                None,
                &fs_check,
            ),
            Some(RuleAction::ReadOnly)
        );
    }

    #[test]
    fn caching_fs_check_reuses_ancestor_probe_results() {
        let inner = CountingFsCheck::new(&["/work/repo/.git"]);
        let cache = CachingFsCheck::new(inner);
        assert!(cache.exists(Path::new("/work/repo/.git")));
        assert!(cache.exists(Path::new("/work/repo/.git")));
        assert_eq!(cache.inner.hits.get(), 1);
    }

    #[test]
    fn compiled_profile_evaluates_rw_and_ro_rules() {
        let compiled = CompiledProfile::compile_normalized_source("/work rw\n/etc ro\n")
            .expect("compile profile");

        assert_eq!(
            compiled.evaluate(Path::new("/work/file.txt"), None, RequestedAccess::Write),
            Some(MatchDecision {
                decision: AccessDecision::AllowReadWrite,
                rule_text: "/work rw".to_string(),
            })
        );
        assert_eq!(
            compiled.evaluate(Path::new("/etc/hosts"), None, RequestedAccess::Write),
            Some(MatchDecision {
                decision: AccessDecision::Deny,
                rule_text: "/etc ro".to_string(),
            })
        );
        assert_eq!(
            compiled.evaluate(Path::new("/etc/hosts"), None, RequestedAccess::Read),
            Some(MatchDecision {
                decision: AccessDecision::AllowReadOnly,
                rule_text: "/etc ro".to_string(),
            })
        );
        assert_eq!(
            compiled.evaluate(Path::new("/etc/hosts"), None, RequestedAccess::Execute),
            Some(MatchDecision {
                decision: AccessDecision::AllowReadOnly,
                rule_text: "/etc ro".to_string(),
            })
        );
    }

    #[test]
    fn compiled_profile_honors_exe_and_ancestor_conditions() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo = temp.path().join("repo");
        std::fs::create_dir_all(repo.join(".git")).expect("mkdir .git");
        let compiled = CompiledProfile::compile_normalized_source(&format!(
            "{} rw when exe=/usr/bin/git\n{} rw when ancestor-has=.git\n{} ro\n",
            repo.display(),
            repo.display(),
            temp.path().display()
        ))
        .expect("compile profile");

        assert_eq!(
            compiled.evaluate(
                &repo.join("tracked.txt"),
                Some(Path::new("/usr/bin/git")),
                RequestedAccess::Write,
            ),
            Some(MatchDecision {
                decision: AccessDecision::AllowReadWrite,
                rule_text: format!("{} rw when exe=/usr/bin/git", repo.display()),
            })
        );
        std::fs::create_dir_all(repo.join("nested")).expect("mkdir nested");
        assert_eq!(
            compiled.evaluate(&repo.join("nested/file.txt"), None, RequestedAccess::Write,),
            Some(MatchDecision {
                decision: AccessDecision::AllowReadWrite,
                rule_text: format!("{} rw when ancestor-has=.git", repo.display()),
            })
        );
    }

    #[test]
    fn compiled_profile_allows_implicit_ancestor_read_only_traversal() {
        let compiled = CompiledProfile::compile_normalized_source("/foo/bar rw\n")
            .expect("compile profile");

        assert_eq!(
            compiled.evaluate(Path::new("/foo"), None, RequestedAccess::Read),
            Some(MatchDecision {
                decision: AccessDecision::AllowReadOnly,
                rule_text: "/foo/bar rw".to_string(),
            })
        );
        assert_eq!(
            compiled.evaluate(Path::new("/foo"), None, RequestedAccess::Write),
            Some(MatchDecision {
                decision: AccessDecision::Deny,
                rule_text: "/foo/bar rw".to_string(),
            })
        );
    }

    #[test]
    fn compiled_profile_hide_yields_to_explicit_child_ancestor_visibility() {
        let compiled = CompiledProfile::compile_normalized_source("/foo/bar rw\n/foo hide\n")
            .expect("compile profile");

        assert_eq!(
            compiled.evaluate(Path::new("/foo"), None, RequestedAccess::Read),
            Some(MatchDecision {
                decision: AccessDecision::AllowReadOnly,
                rule_text: "/foo/bar rw".to_string(),
            })
        );
    }

    #[test]
    fn compiled_profile_glob_rule_makes_wildcard_ancestor_traversable() {
        let compiled = CompiledProfile::compile_normalized_source("/work/**/.git rw\n")
            .expect("compile profile");

        assert_eq!(
            compiled.evaluate(Path::new("/work/foo"), None, RequestedAccess::Read),
            Some(MatchDecision {
                decision: AccessDecision::AllowReadOnly,
                rule_text: "/work/**/.git rw".to_string(),
            })
        );
    }

    #[test]
    fn monitor_glob_patterns_include_implicit_ancestor_globs() {
        let patterns = monitor_glob_patterns_for_normalized_source("/work/**/.git rw\n")
            .expect("monitor patterns");
        assert!(patterns.contains(&"/work/**/.git".to_string()));
        assert!(patterns.contains(&"/work/**/.git/**".to_string()));
        assert!(patterns.contains(&"/".to_string()));
        assert!(patterns.contains(&"/work".to_string()));
        assert!(patterns.contains(&"/work/**".to_string()));
    }

    #[test]
    fn proc_rule_defaults_to_unmounted_when_absent() {
        assert_eq!(
            proc_mount_policy_for_normalized_source("/tmp rw\n").expect("proc policy"),
            ProcMountPolicy::Unmounted
        );
    }

    #[test]
    fn proc_rule_accepts_ro_and_rw_only() {
        assert_eq!(
            proc_mount_policy_for_normalized_source("/proc ro\n").expect("proc policy"),
            ProcMountPolicy::ReadOnly
        );
        assert_eq!(
            proc_mount_policy_for_normalized_source("/proc rw\n").expect("proc policy"),
            ProcMountPolicy::ReadWrite
        );
        let err = proc_mount_policy_for_normalized_source("/proc deny\n")
            .expect_err("deny proc rule should fail");
        assert!(err.to_string().contains("/proc rule must use ro or rw"));
    }

    #[test]
    fn proc_subpath_rules_are_rejected() {
        let err = proc_mount_policy_for_normalized_source("/proc/self ro\n")
            .expect_err("proc subpath should fail");
        assert!(err.to_string().contains("/proc subpath rules are not supported"));
    }

    #[test]
    fn proc_rule_does_not_allow_conditions() {
        let err = proc_mount_policy_for_normalized_source("/proc rw when exe=/usr/bin/git\n")
            .expect_err("conditional proc rule should fail");
        assert!(err.to_string().contains("/proc rule does not support conditions"));
    }
}
