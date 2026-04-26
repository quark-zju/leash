//! Conditional profile rules.
//!
//! # Syntax
//!
//! ```text
//! pattern  action  [when condition[,condition...]]
//! ```
//!
//! **action**: `ro` | `rw` | `deny` | `hide`
//!
//! **conditions** (all must be true — AND semantics):
//! - `exe=name[|pattern...]` — calling process executable matching:
//!                           - bare names (no `/`) are resolved via PATH to an
//!                             absolute path, then matched exactly
//!                           - `/`-prefixed values are matched as glob patterns
//!                             (`*` does not cross `/`, `**` may cross `/`)
//! - `ancestor-has=name`   — some ancestor directory of the accessed path
//!                           contains an entry named `name`
//! - `env=VAR`             — environment variable `VAR` is set in the caller
//! - `os.id=name`          — current host OS ID from `/etc/os-release`
//!                           matches at profile load time; non-matching rules
//!                           are skipped before runtime
//!
//! **directives**:
//! - `%include name`       — inline another named profile
//!
//! Evaluation: top-down, first match wins.
//! A rule whose conditions are not all satisfied is skipped.
//! Paths that do not match any rule are hidden by default.

use std::collections::HashMap;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, LazyLock};
use std::time::Instant;

use arc_swap::ArcSwap;
use libc::{EACCES, ENOENT, EPERM};

use globset::{Glob, GlobBuilder, GlobSet, GlobSetBuilder};

use crate::access::{AccessController, AccessDecision, AccessRequest, CallerCondition};
use crate::ancestor_has_cache::AncestorHasCache;

// ── Actions ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    ReadOnly,
    ReadWrite,
    Deny,
    Hide,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    Action(Action),
    ImplicitAncestor,
    Hidden,
}

impl Action {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "ro" => Some(Self::ReadOnly),
            "rw" => Some(Self::ReadWrite),
            "deny" => Some(Self::Deny),
            "hide" => Some(Self::Hide),
            _ => None,
        }
    }

    pub fn access_errno(self) -> Option<i32> {
        match self {
            Self::ReadOnly | Self::ReadWrite => None,
            Self::Deny => Some(EACCES),
            Self::Hide => Some(ENOENT),
        }
    }

    pub fn mutation_errno(self) -> Option<i32> {
        match self {
            Self::ReadWrite => None,
            Self::ReadOnly | Self::Deny => Some(EACCES),
            Self::Hide => Some(EPERM),
        }
    }
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::ReadOnly => "ro",
            Self::ReadWrite => "rw",
            Self::Deny => "deny",
            Self::Hide => "hide",
        })
    }
}

// ── ExeResolver ───────────────────────────────────────────────────────────────

/// Resolves bare executable names to absolute paths at parse time.
///
/// Injected into [`parse`] so tests can supply a deterministic mock instead of
/// reading `$PATH` from the real environment.
pub trait ExeResolver {
    /// Look up `name` (a bare filename without `/`) and return its absolute
    /// path if found, or `None` otherwise.
    fn resolve(&self, name: &str) -> Option<PathBuf>;
}

/// Production [`ExeResolver`]: walks the real `$PATH`.
pub struct PathExeResolver;

impl ExeResolver for PathExeResolver {
    fn resolve(&self, name: &str) -> Option<PathBuf> {
        let path_var = std::env::var("PATH").ok()?;
        for dir in path_var.split(':') {
            let candidate = Path::new(dir).join(name);
            if candidate.is_file() {
                let candidate = candidate.canonicalize().unwrap_or(candidate);
                return Some(candidate);
            }
        }
        None
    }
}

// ── OsIdResolver ─────────────────────────────────────────────────────────────

/// Resolves host OS ID from `/etc/os-release` for `os.id=` conditions.
pub trait OsIdResolver {
    fn os_id(&self) -> Option<String>;
}

pub struct EtcOsReleaseResolver;

static HOST_OS_ID: LazyLock<Option<String>> = LazyLock::new(load_host_os_id);

impl OsIdResolver for EtcOsReleaseResolver {
    fn os_id(&self) -> Option<String> {
        (*HOST_OS_ID).clone()
    }
}

fn load_host_os_id() -> Option<String> {
    let source = fs::read_to_string("/etc/os-release").ok()?;
    parse_os_release_id(&source)
}

fn parse_os_release_id(source: &str) -> Option<String> {
    for raw_line in source.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(raw_value) = line.strip_prefix("ID=") else {
            continue;
        };
        let value = parse_os_release_value(raw_value)?;
        if !value.is_empty() {
            return Some(value);
        }
    }
    None
}

fn parse_os_release_value(raw: &str) -> Option<String> {
    let value = raw.trim();
    if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
        let inner = &value[1..value.len() - 1];
        let mut out = String::with_capacity(inner.len());
        let mut escaped = false;
        for ch in inner.chars() {
            if escaped {
                out.push(ch);
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else {
                out.push(ch);
            }
        }
        if escaped {
            return None;
        }
        return Some(out);
    }
    if value.starts_with('\'') && value.ends_with('\'') && value.len() >= 2 {
        return Some(value[1..value.len() - 1].to_owned());
    }
    Some(value.to_owned())
}

// ── FsCheck ───────────────────────────────────────────────────────────────────

/// Checks whether a filesystem path exists, used by `ancestor-has=` at eval time.
///
/// Injected into [`EvalContext`] so tests can supply a deterministic mock
/// instead of touching the real filesystem.
pub trait FsCheck {
    fn exists(&self, path: &Path) -> bool;
    fn is_dir(&self, path: &Path) -> bool;
}

/// Production [`FsCheck`]: delegates to `Path::exists`.
pub struct RealFsCheck;

impl FsCheck for RealFsCheck {
    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn is_dir(&self, path: &Path) -> bool {
        path.is_dir()
    }
}

// ── Conditions ────────────────────────────────────────────────────────────────

/// A single compiled condition in a `when` clause.
#[derive(Debug, Clone)]
pub enum Condition {
    /// Calling process executable path matches this matcher.
    Exe(ExeMatcher),

    /// An ancestor directory of the accessed path contains an entry named
    /// `name` (file or directory).  Checked at eval time via [`FsCheck`].
    AncestorHas(String),

    /// An environment variable named `var` is set in the caller's environment.
    Env(String),
}

#[derive(Clone)]
pub struct ExeMatcher {
    globset: GlobSet,
}

impl std::fmt::Debug for ExeMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExeMatcher").finish_non_exhaustive()
    }
}

impl ExeMatcher {
    fn from_patterns(patterns: &[String]) -> Result<Self, globset::Error> {
        let mut builder = GlobSetBuilder::new();
        for pattern in patterns {
            let glob = GlobBuilder::new(pattern).literal_separator(true).build()?;
            builder.add(glob);
        }
        Ok(Self {
            globset: builder.build()?,
        })
    }

    fn matches(&self, exe: &Path) -> bool {
        self.globset.is_match(exe)
    }
}

// ── RawCondition (pre-compilation) ───────────────────────────────────────────

enum CompiledCondition {
    Runtime(Condition),
    LoadTimeOnly(bool),
}

#[derive(Debug, Clone)]
enum RawCondition {
    Exe(String),
    AncestorHas(String),
    Env(String),
    OsId(String),
}

impl RawCondition {
    fn parse(token: &str) -> Result<Self, ParseError> {
        if let Some(rest) = token.strip_prefix("exe=") {
            Ok(Self::Exe(rest.to_owned()))
        } else if let Some(rest) = token.strip_prefix("ancestor-has=") {
            Ok(Self::AncestorHas(rest.to_owned()))
        } else if let Some(rest) = token.strip_prefix("env=") {
            Ok(Self::Env(rest.to_owned()))
        } else if let Some(rest) = token.strip_prefix("os.id=") {
            Ok(Self::OsId(rest.to_owned()))
        } else {
            Err(ParseError::UnknownCondition(token.to_owned()))
        }
    }

    fn compile(
        &self,
        exe_resolver: &dyn ExeResolver,
        os_id_resolver: &dyn OsIdResolver,
    ) -> Result<CompiledCondition, ParseError> {
        match self {
            RawCondition::Exe(value) => {
                let resolved = resolve_exes(value, exe_resolver)?;
                Ok(CompiledCondition::Runtime(Condition::Exe(resolved)))
            }
            RawCondition::AncestorHas(name) => Ok(CompiledCondition::Runtime(
                Condition::AncestorHas(name.clone()),
            )),
            RawCondition::Env(var) => Ok(CompiledCondition::Runtime(Condition::Env(var.clone()))),
            RawCondition::OsId(expected) => {
                if expected.is_empty() {
                    return Err(ParseError::InvalidOsId(expected.clone()));
                }
                let matched = os_id_resolver.os_id().as_deref() == Some(expected.as_str());
                Ok(CompiledCondition::LoadTimeOnly(matched))
            }
        }
    }

    fn to_source(&self) -> String {
        match self {
            Self::Exe(value) => format!("exe={value}"),
            Self::AncestorHas(name) => format!("ancestor-has={name}"),
            Self::Env(var) => format!("env={var}"),
            Self::OsId(value) => format!("os.id={value}"),
        }
    }
}

/// Resolve an `exe=` value at parse time and compile it into a [`GlobSet`].
///
/// Accepted forms (`|` means OR):
/// - Bare name (no `/`): resolved through [`ExeResolver`], then compiled as an
///   exact-path glob.
/// - `/`-prefixed value: compiled directly as a glob pattern.
///
/// Any other form (for example `../bin/sh`) is a parse error.
fn resolve_exes(value: &str, resolver: &dyn ExeResolver) -> Result<ExeMatcher, ParseError> {
    let mut patterns = Vec::new();
    for entry in value.split('|') {
        if entry.is_empty() {
            return Err(ParseError::InvalidExe(value.to_owned()));
        }
        if entry.starts_with('/') {
            patterns.push(entry.to_owned());
            continue;
        }
        if entry.contains('/') {
            return Err(ParseError::InvalidExe(value.to_owned()));
        }
        // Security motivation: bare names are resolved to absolute paths first,
        // so a caller cannot bypass policy by running a different same-name
        // binary from another directory.
        if let Some(path) = resolver.resolve(entry) {
            patterns.push(glob_escape_literal(
                path.as_os_str().to_string_lossy().as_ref(),
            ));
        }
    }
    ExeMatcher::from_patterns(&patterns).map_err(|_| ParseError::InvalidExe(value.to_owned()))
}

fn glob_escape_literal(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '*' | '?' | '[' | ']' | '{' | '}' | '!' | '\\' => {
                escaped.push('\\');
                escaped.push(ch);
            }
            _ => escaped.push(ch),
        }
    }
    escaped
}

// ── Rule ──────────────────────────────────────────────────────────────────────

/// A compiled rule ready for matching.
pub struct Rule {
    /// Original pattern string (for display).
    pub pattern: String,
    pub action: Action,
    /// All conditions (AND semantics).
    pub conditions: Vec<Condition>,
    raw_conditions: Vec<String>,
}

impl std::fmt::Debug for Rule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rule")
            .field("pattern", &self.pattern)
            .field("action", &self.action)
            .finish_non_exhaustive()
    }
}

// ── Profile ───────────────────────────────────────────────────────────────────

/// A compiled profile.
#[derive(Debug)]
pub struct Profile {
    rules: Vec<Rule>,
    match_globset: GlobSet,
    match_entries: Vec<InternalRuleMatch>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InternalRuleKind {
    ImplicitAncestor,
    Explicit,
}

#[derive(Debug, Clone, Copy)]
struct InternalRuleMatch {
    original_rule_index: usize,
    kind: InternalRuleKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleMatchKind {
    ImplicitAncestor,
    Explicit,
}

#[derive(Debug, Clone)]
pub struct RuleMatchReportEntry {
    pub rule_index: usize,
    pub pattern: String,
    pub action: Action,
    pub kind: RuleMatchKind,
    pub conditions_matched: bool,
    pub when_clause: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RuleMatchReport {
    pub visibility: Visibility,
    pub effective_action: Action,
    pub entries: Vec<RuleMatchReportEntry>,
}

impl Profile {
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Evaluate the profile for the given absolute `path`.
    ///
    /// `ctx` supplies runtime information needed to evaluate conditions.
    /// Returns `None` when no rule matches.
    #[cfg(test)]
    pub fn evaluate(&self, path: &Path, ctx: &EvalContext<'_>) -> Option<Action> {
        let mut ctx = StaticRuntimeEvalContext { ctx };
        self.evaluate_with_runtime(path, &mut ctx)
    }

    #[cfg(test)]
    fn evaluate_with_runtime(
        &self,
        path: &Path,
        ctx: &mut dyn RuntimeEvalContext,
    ) -> Option<Action> {
        let mut cached_conditions = vec![None; self.rules.len()];
        for matched_idx in self.match_globset.matches(path) {
            let matched = &self.match_entries[matched_idx];
            if matched.kind != InternalRuleKind::Explicit {
                continue;
            }
            if !self.rule_conditions_match(
                matched.original_rule_index,
                path,
                ctx,
                &mut cached_conditions,
            ) {
                continue;
            }
            return Some(self.rules[matched.original_rule_index].action);
        }
        None
    }

    #[cfg(test)]
    pub fn visibility(&self, path: &Path, ctx: &EvalContext<'_>) -> Visibility {
        let mut ctx = StaticRuntimeEvalContext { ctx };
        self.visibility_with_runtime(path, &mut ctx)
    }

    fn visibility_with_runtime(&self, path: &Path, ctx: &mut dyn RuntimeEvalContext) -> Visibility {
        let mut implicit_ancestor_visible = false;
        let mut cached_conditions = vec![None; self.rules.len()];

        // Match entries are inserted in source order, with implicit entries
        // before explicit entries for each rule.
        for matched_idx in self.match_globset.matches(path) {
            let matched = &self.match_entries[matched_idx];
            if !self.rule_conditions_match(
                matched.original_rule_index,
                path,
                ctx,
                &mut cached_conditions,
            ) {
                continue;
            }
            let rule = &self.rules[matched.original_rule_index];
            match matched.kind {
                InternalRuleKind::ImplicitAncestor => {
                    implicit_ancestor_visible = true;
                }
                InternalRuleKind::Explicit => {
                    if matches!(rule.action, Action::Hide | Action::Deny)
                        && implicit_ancestor_visible
                    {
                        return Visibility::ImplicitAncestor;
                    }
                    return Visibility::Action(rule.action);
                }
            }
        }
        if implicit_ancestor_visible {
            return Visibility::ImplicitAncestor;
        }
        Visibility::Hidden
    }

    #[cfg(test)]
    pub fn effective_action(&self, path: &Path, ctx: &EvalContext<'_>) -> Action {
        self.evaluate(path, ctx).unwrap_or(Action::Hide)
    }

    pub fn should_cache_readdir(&self, path: &Path) -> bool {
        if !self.readdir_self_visibility_is_exe_stable(path) {
            return false;
        }
        // Conservative: without a direct-child glob introspection API, treat any
        // caller-conditioned hide rule under this directory as potentially
        // changing readdir results for this directory.
        !self.rules.iter().any(|rule| {
            rule.has_caller_condition()
                && rule.action == Action::Hide
                && pattern_matches_implicit_ancestor(&rule.pattern, path)
        })
    }

    fn readdir_self_visibility_is_exe_stable(&self, path: &Path) -> bool {
        let mut has_exe_visible_rule = false;
        let mut first_non_exe_action = None;
        let mut saw_unconditional_implicit_ancestor_before_first_non_exe = false;
        let mut last_rule_index = None;
        for matched_idx in self.match_globset.matches(path) {
            let matched = &self.match_entries[matched_idx];
            let rule_index = matched.original_rule_index;
            let rule = &self.rules[rule_index];
            if matched.kind == InternalRuleKind::ImplicitAncestor {
                if first_non_exe_action.is_none() && rule.conditions.is_empty() {
                    saw_unconditional_implicit_ancestor_before_first_non_exe = true;
                }
                continue;
            }

            // For each rule, explicit match entries can repeat by matched path
            // segment; evaluate each explicit rule only once in source order.
            if last_rule_index == Some(rule_index) {
                continue;
            }
            last_rule_index = Some(rule_index);

            if rule.has_caller_condition() {
                if matches!(rule.action, Action::Hide | Action::Deny) {
                    return false;
                }
                if rule.action.allows_visible_descendants() {
                    has_exe_visible_rule = true;
                }
                continue;
            }
            first_non_exe_action = Some(rule.action);
            break;
        }

        if has_exe_visible_rule {
            return first_non_exe_action
                .map(Action::allows_visible_descendants)
                .unwrap_or(false);
        }
        if matches!(first_non_exe_action, Some(Action::Hide | Action::Deny)) {
            return saw_unconditional_implicit_ancestor_before_first_non_exe;
        }
        first_non_exe_action
            .map(Action::allows_visible_descendants)
            .unwrap_or(true)
    }

    pub fn rule_match_report(&self, path: &Path, ctx: &EvalContext<'_>) -> RuleMatchReport {
        let mut runtime = StaticRuntimeEvalContext { ctx };
        let mut implicit_ancestor_visible = false;
        let mut cached_conditions = vec![None; self.rules.len()];
        let mut entries = Vec::new();

        for matched_idx in self.match_globset.matches(path) {
            let matched = &self.match_entries[matched_idx];
            let rule_idx = matched.original_rule_index;
            let rule = &self.rules[rule_idx];
            let conditions_matched =
                self.rule_conditions_match(rule_idx, path, &mut runtime, &mut cached_conditions);

            let kind = match matched.kind {
                InternalRuleKind::ImplicitAncestor => RuleMatchKind::ImplicitAncestor,
                InternalRuleKind::Explicit => RuleMatchKind::Explicit,
            };
            entries.push(RuleMatchReportEntry {
                rule_index: rule_idx,
                pattern: rule.pattern.clone(),
                action: rule.action,
                kind,
                conditions_matched,
                when_clause: rule.when_clause(),
            });

            if !conditions_matched {
                continue;
            }
            match matched.kind {
                InternalRuleKind::ImplicitAncestor => {
                    implicit_ancestor_visible = true;
                }
                InternalRuleKind::Explicit => {
                    let visibility = if matches!(rule.action, Action::Hide | Action::Deny)
                        && implicit_ancestor_visible
                    {
                        Visibility::ImplicitAncestor
                    } else {
                        Visibility::Action(rule.action)
                    };
                    return RuleMatchReport {
                        visibility,
                        effective_action: match visibility {
                            Visibility::Action(action) => action,
                            Visibility::ImplicitAncestor | Visibility::Hidden => Action::Hide,
                        },
                        entries,
                    };
                }
            }
        }

        let visibility = if implicit_ancestor_visible {
            Visibility::ImplicitAncestor
        } else {
            Visibility::Hidden
        };
        RuleMatchReport {
            visibility,
            effective_action: match visibility {
                Visibility::Action(action) => action,
                Visibility::ImplicitAncestor | Visibility::Hidden => Action::Hide,
            },
            entries,
        }
    }

    #[cfg(test)]
    pub fn access_errno(&self, path: &Path, ctx: &EvalContext<'_>) -> Option<i32> {
        match self.visibility(path, ctx) {
            Visibility::Action(action) => action.access_errno(),
            Visibility::ImplicitAncestor if ctx.fs.is_dir(path) => None,
            Visibility::ImplicitAncestor | Visibility::Hidden => Some(ENOENT),
        }
    }

    #[cfg(test)]
    pub fn mutation_errno(&self, path: &Path, ctx: &EvalContext<'_>) -> Option<i32> {
        match self.visibility(path, ctx) {
            Visibility::Action(action) => action.mutation_errno(),
            Visibility::ImplicitAncestor if ctx.fs.is_dir(path) => None,
            Visibility::ImplicitAncestor | Visibility::Hidden => Some(EPERM),
        }
    }

    #[cfg(test)]
    #[allow(dead_code)]
    fn is_implicit_ancestor(&self, path: &Path, ctx: &EvalContext<'_>) -> bool {
        let mut ctx = StaticRuntimeEvalContext { ctx };
        self.is_implicit_ancestor_with_runtime(path, &mut ctx)
    }

    #[cfg(test)]
    #[allow(dead_code)]
    fn is_implicit_ancestor_with_runtime(
        &self,
        path: &Path,
        ctx: &mut dyn RuntimeEvalContext,
    ) -> bool {
        let mut cached_conditions = vec![None; self.rules.len()];
        for matched_idx in self.match_globset.matches(path) {
            let matched = &self.match_entries[matched_idx];
            if matched.kind != InternalRuleKind::ImplicitAncestor {
                continue;
            }
            if self.rule_conditions_match(
                matched.original_rule_index,
                path,
                ctx,
                &mut cached_conditions,
            ) {
                return true;
            }
        }
        false
    }

    fn rule_conditions_match(
        &self,
        rule_index: usize,
        path: &Path,
        ctx: &mut dyn RuntimeEvalContext,
        cache: &mut [Option<bool>],
    ) -> bool {
        if let Some(matched) = cache[rule_index] {
            return matched;
        }
        let matched = self.rules[rule_index].conditions_match(path, ctx);
        cache[rule_index] = Some(matched);
        matched
    }
}

impl Action {
    fn allows_visible_descendants(self) -> bool {
        matches!(self, Self::ReadOnly | Self::ReadWrite)
    }
}

// ── EvalContext ───────────────────────────────────────────────────────────────

/// Runtime context provided by the caller when evaluating a rule.
pub struct EvalContext<'a> {
    /// Absolute path of the calling process's executable, if known.
    pub exe: Option<&'a Path>,
    /// Environment variables of the calling process.
    pub env: &'a HashMap<String, String>,
    /// Filesystem existence checker used by `ancestor-has=` conditions.
    pub fs: &'a dyn FsCheck,
}

trait RuntimeEvalContext {
    fn exe(&mut self) -> Option<&Path>;
    fn env_match(&mut self, name: &str) -> bool;
    fn fs(&self) -> &dyn FsCheck;
    fn ancestor_has(&mut self, path: &Path, name: &str) -> bool;
}

struct StaticRuntimeEvalContext<'a, 'b> {
    ctx: &'a EvalContext<'b>,
}

impl RuntimeEvalContext for StaticRuntimeEvalContext<'_, '_> {
    fn exe(&mut self) -> Option<&Path> {
        self.ctx.exe
    }

    fn env_match(&mut self, name: &str) -> bool {
        self.ctx.env.contains_key(name)
    }

    fn fs(&self) -> &dyn FsCheck {
        self.ctx.fs
    }

    fn ancestor_has(&mut self, path: &Path, name: &str) -> bool {
        ancestor_has(path, name, self.ctx.fs)
    }
}

// ── Condition matching ────────────────────────────────────────────────────────

impl Rule {
    fn conditions_match(&self, path: &Path, ctx: &mut dyn RuntimeEvalContext) -> bool {
        self.conditions.iter().all(|c| c.matches(path, ctx))
    }

    fn has_caller_condition(&self) -> bool {
        self.conditions
            .iter()
            .any(|condition| matches!(condition, Condition::Exe(_) | Condition::Env(_)))
    }

    fn when_clause(&self) -> Option<String> {
        if self.raw_conditions.is_empty() {
            None
        } else {
            Some(self.raw_conditions.join(","))
        }
    }
}

impl Condition {
    fn matches(&self, path: &Path, ctx: &mut dyn RuntimeEvalContext) -> bool {
        match self {
            Condition::Exe(matcher) => ctx.exe().is_some_and(|exe| matcher.matches(exe)),

            Condition::AncestorHas(name) => ctx.ancestor_has(path, name),

            Condition::Env(var) => ctx.env_match(var),
        }
    }
}

/// Returns `true` if any ancestor directory of `path` contains an entry
/// named `name`, as reported by `fs`.
fn ancestor_has(path: &Path, name: &str, fs: &dyn FsCheck) -> bool {
    let mut dir = match path.parent() {
        Some(p) => p.to_path_buf(),
        None => return false,
    };
    loop {
        if fs.exists(&dir.join(name)) {
            return true;
        }
        match dir.parent() {
            Some(p) if p != dir => dir = p.to_path_buf(),
            _ => return false,
        }
    }
}

// ── Parser ────────────────────────────────────────────────────────────────────

/// Parse errors returned by [`parse`].
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("line {line}: {msg}")]
    Syntax { line: usize, msg: String },

    #[error("unknown condition '{0}'")]
    UnknownCondition(String),

    #[error("bad glob '{0}': {1}")]
    BadGlob(String, String),

    #[error(
        "invalid exe= value '{0}': must be pipe-separated bare names or /-prefixed glob patterns"
    )]
    InvalidExe(String),

    #[error("invalid os.id= value '{0}': must be a non-empty ID")]
    InvalidOsId(String),

    #[error("%include cycle: {0}")]
    IncludeCycle(String),

    #[error("include resolver error for '{0}': {1}")]
    IncludeError(String, String),
}

impl ParseError {
    fn syntax(line: usize, msg: impl Into<String>) -> Self {
        Self::Syntax {
            line,
            msg: msg.into(),
        }
    }
}

/// Trait for resolving `%include` directives.
pub trait IncludeResolver {
    /// Return the source text for the named profile, or an error string.
    /// `Ok(None)` silently skips a missing include.
    fn resolve(&self, name: &str) -> Result<Option<String>, String>;
}

/// An [`IncludeResolver`] that silently skips every include.
#[cfg(test)]
pub struct NoIncludes;

#[cfg(test)]
impl IncludeResolver for NoIncludes {
    fn resolve(&self, _name: &str) -> Result<Option<String>, String> {
        Ok(None)
    }
}

/// Parse a profile from source text.
///
/// - `home`: used to expand `~`.
/// - `cwd`: retained in the public API for now, but relative patterns are rejected
///   so daemon-side profile reload does not depend on a process working directory.
/// - `include_resolver`: handles `%include` directives.
/// - `exe_resolver`: resolves bare executable names in `exe=` conditions.
/// - `os.id=` conditions are resolved once from `/etc/os-release` and applied
///   at profile load time.
pub fn parse(
    source: &str,
    home: &Path,
    cwd: &Path,
    include_resolver: &dyn IncludeResolver,
    exe_resolver: &dyn ExeResolver,
) -> Result<Profile, ParseError> {
    parse_with_os_id_resolver(
        source,
        home,
        cwd,
        include_resolver,
        exe_resolver,
        &EtcOsReleaseResolver,
    )
}

fn parse_with_os_id_resolver(
    source: &str,
    home: &Path,
    cwd: &Path,
    include_resolver: &dyn IncludeResolver,
    exe_resolver: &dyn ExeResolver,
    os_id_resolver: &dyn OsIdResolver,
) -> Result<Profile, ParseError> {
    let mut rules = Vec::new();
    let include_stack: Vec<String> = Vec::new();
    parse_lines(
        source,
        home,
        cwd,
        include_resolver,
        exe_resolver,
        os_id_resolver,
        &include_stack,
        &mut rules,
    )?;
    let (match_globset, match_entries) = build_internal_rule_index(&rules)?;
    Ok(Profile {
        rules,
        match_globset,
        match_entries,
    })
}

fn parse_lines(
    source: &str,
    home: &Path,
    cwd: &Path,
    include_resolver: &dyn IncludeResolver,
    exe_resolver: &dyn ExeResolver,
    os_id_resolver: &dyn OsIdResolver,
    include_stack: &[String],
    out: &mut Vec<Rule>,
) -> Result<(), ParseError> {
    for (i, raw_line) in source.lines().enumerate() {
        let lineno = i + 1;
        let line = strip_line_comment(raw_line);

        if line.is_empty() {
            continue;
        }

        if let Some(rest) = line.strip_prefix('%') {
            parse_directive(
                rest,
                lineno,
                home,
                cwd,
                include_resolver,
                exe_resolver,
                os_id_resolver,
                include_stack,
                out,
            )?;
            continue;
        }

        if let Some(rule) = parse_rule_line(line, lineno, home, cwd, exe_resolver, os_id_resolver)?
        {
            out.push(rule);
        }
    }
    Ok(())
}

fn strip_line_comment(raw_line: &str) -> &str {
    let mut comment_start = None;
    for (idx, ch) in raw_line.char_indices() {
        if ch != '#' {
            continue;
        }
        let starts_comment = idx == 0
            || raw_line[..idx]
                .chars()
                .next_back()
                .is_some_and(char::is_whitespace);
        if starts_comment {
            comment_start = Some(idx);
            break;
        }
    }
    match comment_start {
        Some(idx) => raw_line[..idx].trim(),
        None => raw_line.trim(),
    }
}

fn parse_directive(
    rest: &str,
    lineno: usize,
    home: &Path,
    cwd: &Path,
    include_resolver: &dyn IncludeResolver,
    exe_resolver: &dyn ExeResolver,
    os_id_resolver: &dyn OsIdResolver,
    include_stack: &[String],
    out: &mut Vec<Rule>,
) -> Result<(), ParseError> {
    let mut tokens = rest.split_whitespace();
    match tokens.next() {
        Some("include") => {
            let name = tokens
                .next()
                .ok_or_else(|| ParseError::syntax(lineno, "%include requires a name"))?;
            if include_stack.iter().any(|n| n == name) {
                return Err(ParseError::IncludeCycle(name.to_owned()));
            }
            match include_resolver.resolve(name) {
                Ok(None) => {}
                Ok(Some(src)) => {
                    let mut new_stack = include_stack.to_vec();
                    new_stack.push(name.to_owned());
                    parse_lines(
                        &src,
                        home,
                        cwd,
                        include_resolver,
                        exe_resolver,
                        os_id_resolver,
                        &new_stack,
                        out,
                    )?;
                }
                Err(e) => return Err(ParseError::IncludeError(name.to_owned(), e)),
            }
        }
        Some(other) => {
            return Err(ParseError::syntax(
                lineno,
                format!("unknown directive '%{other}'"),
            ));
        }
        None => {
            return Err(ParseError::syntax(lineno, "empty directive"));
        }
    }
    Ok(())
}

/// Parse one rule line: `pattern action [when cond[,cond...]]`
fn parse_rule_line(
    line: &str,
    lineno: usize,
    home: &Path,
    cwd: &Path,
    exe_resolver: &dyn ExeResolver,
    os_id_resolver: &dyn OsIdResolver,
) -> Result<Option<Rule>, ParseError> {
    let mut tokens = line.split_whitespace();

    let pattern_tok = tokens
        .next()
        .ok_or_else(|| ParseError::syntax(lineno, "empty line"))?;
    let action_tok = tokens
        .next()
        .ok_or_else(|| ParseError::syntax(lineno, "missing action"))?;

    let action = Action::parse(action_tok)
        .ok_or_else(|| ParseError::syntax(lineno, format!("unknown action '{action_tok}'")))?;

    let raw_conditions: Vec<RawCondition> = match tokens.next() {
        None => vec![],
        Some("when") => {
            let conds_str = tokens.next().ok_or_else(|| {
                ParseError::syntax(lineno, "'when' requires at least one condition")
            })?;
            if tokens.next().is_some() {
                return Err(ParseError::syntax(
                    lineno,
                    "unexpected tokens after conditions",
                ));
            }
            conds_str
                .split(',')
                .map(RawCondition::parse)
                .collect::<Result<Vec<_>, _>>()?
        }
        Some(other) => {
            return Err(ParseError::syntax(
                lineno,
                format!("expected 'when' but got '{other}'"),
            ));
        }
    };

    let mut conditions = Vec::new();
    for condition in &raw_conditions {
        match condition.compile(exe_resolver, os_id_resolver)? {
            CompiledCondition::Runtime(condition) => conditions.push(condition),
            CompiledCondition::LoadTimeOnly(true) => {}
            CompiledCondition::LoadTimeOnly(false) => return Ok(None),
        }
    }
    let raw_conditions: Vec<String> = raw_conditions.iter().map(RawCondition::to_source).collect();

    let abs_pattern = expand_pattern(pattern_tok, home, cwd, lineno)?;
    validate_pattern_globs(&abs_pattern)?;
    Ok(Some(Rule {
        pattern: abs_pattern,
        action,
        conditions,
        raw_conditions,
    }))
}

// ── Pattern normalisation ─────────────────────────────────────────────────────

fn expand_pattern(
    pattern: &str,
    home: &Path,
    cwd: &Path,
    lineno: usize,
) -> Result<String, ParseError> {
    let _ = cwd;
    if pattern == "~" {
        return Ok(home.to_string_lossy().into_owned());
    }
    if let Some(rest) = pattern.strip_prefix("~/") {
        return Ok(home.join(rest).to_string_lossy().into_owned());
    }
    if pattern.starts_with('/') || pattern.starts_with("**/") {
        return Ok(pattern.to_owned());
    }
    Err(ParseError::syntax(
        lineno,
        format!("relative pattern '{pattern}' is not supported; use an absolute path or ~/path"),
    ))
}

fn explicit_globs_for_rule(pattern: &str) -> Vec<String> {
    let mut globs = vec![pattern.to_owned()];
    if !pattern.ends_with("/**") && !pattern.ends_with("**") {
        globs.push(format!("{pattern}/**"));
    }
    globs
}

fn validate_pattern_globs(pattern: &str) -> Result<(), ParseError> {
    for glob in explicit_globs_for_rule(pattern) {
        Glob::new(&glob).map_err(|e| ParseError::BadGlob(pattern.to_owned(), e.to_string()))?;
    }
    for glob in ancestor_globs_for_rule(pattern) {
        Glob::new(&glob).map_err(|e| ParseError::BadGlob(pattern.to_owned(), e.to_string()))?;
    }
    Ok(())
}

fn ancestor_globs_for_rule(pattern: &str) -> Vec<String> {
    let base = if pattern == "/" {
        "/"
    } else {
        pattern.trim_end_matches('/')
    };
    let path = Path::new(base);
    let mut out = Vec::new();
    if base != "/" {
        out.push("/".to_string());
    }

    let components: Vec<String> = path
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect();
    if components.len() <= 1 {
        return out;
    }

    let mut prefix = String::new();
    let has_double_star = base.contains("**");
    let limit = if has_double_star {
        components
            .iter()
            .position(|segment| segment.contains("**"))
            .unwrap_or(components.len())
    } else {
        components.len().saturating_sub(1)
    };
    for component in components.into_iter().take(limit) {
        prefix.push('/');
        prefix.push_str(&component);
        out.push(prefix.clone());
    }
    if has_double_star {
        let prefix = base.split("/**").next().unwrap_or("").trim_end_matches('/');
        if prefix.is_empty() {
            out.push("/**".to_owned());
        } else {
            out.push(format!("{prefix}/**"));
        }
    }
    out
}

pub(crate) fn pattern_matches_implicit_ancestor(pattern: &str, path: &Path) -> bool {
    ancestor_globs_for_rule(pattern).into_iter().any(|glob| {
        Glob::new(&glob)
            .map(|compiled| compiled.compile_matcher().is_match(path))
            .unwrap_or(false)
    })
}

fn build_internal_rule_index(
    rules: &[Rule],
) -> Result<(GlobSet, Vec<InternalRuleMatch>), ParseError> {
    let mut builder = GlobSetBuilder::new();
    let mut entries = Vec::new();

    for (rule_idx, rule) in rules.iter().enumerate() {
        if rule.action.allows_visible_descendants() {
            for ancestor in ancestor_globs_for_rule(&rule.pattern) {
                let glob = Glob::new(&ancestor)
                    .map_err(|e| ParseError::BadGlob(rule.pattern.clone(), e.to_string()))?;
                builder.add(glob);
                entries.push(InternalRuleMatch {
                    original_rule_index: rule_idx,
                    kind: InternalRuleKind::ImplicitAncestor,
                });
            }
        }

        for explicit in explicit_globs_for_rule(&rule.pattern) {
            let glob = Glob::new(&explicit)
                .map_err(|e| ParseError::BadGlob(rule.pattern.clone(), e.to_string()))?;
            builder.add(glob);
            entries.push(InternalRuleMatch {
                original_rule_index: rule_idx,
                kind: InternalRuleKind::Explicit,
            });
        }
    }

    let globset = builder
        .build()
        .map_err(|e| ParseError::BadGlob("<internal>".to_owned(), e.to_string()))?;
    Ok((globset, entries))
}

pub struct ProfileController<F = RealFsCheck> {
    profile: ArcSwap<Profile>,
    fs: F,
    ancestor_has_cache: AncestorHasCache,
}

impl ProfileController<RealFsCheck> {
    pub fn new(profile: Profile) -> Self {
        Self {
            profile: ArcSwap::from_pointee(profile),
            fs: RealFsCheck,
            ancestor_has_cache: AncestorHasCache::default(),
        }
    }
}

impl<F: FsCheck> ProfileController<F> {
    #[cfg(test)]
    pub(crate) fn with_fs(profile: Profile, fs: F) -> Self {
        Self {
            profile: ArcSwap::from_pointee(profile),
            fs,
            ancestor_has_cache: AncestorHasCache::default(),
        }
    }

    pub fn replace_profile(&self, profile: Profile) {
        self.profile.store(Arc::new(profile));
    }

    pub fn check<C: CallerCondition + ?Sized>(
        &self,
        request: &AccessRequest<'_>,
        caller_condition: &mut C,
    ) -> AccessDecision {
        let _caller_pid = request.caller.pid;
        let mut ctx = LazyRuntimeEvalContext {
            fs: &self.fs,
            caller_condition,
            ancestor_has_cache: &self.ancestor_has_cache,
        };
        let profile = self.profile.load();
        let errno = if request.operation.is_write() {
            match profile.visibility_with_runtime(request.path, &mut ctx) {
                Visibility::Action(action) => action.mutation_errno(),
                Visibility::ImplicitAncestor if ctx.fs().is_dir(request.path) => None,
                Visibility::ImplicitAncestor | Visibility::Hidden => Some(EPERM),
            }
        } else {
            match profile.visibility_with_runtime(request.path, &mut ctx) {
                Visibility::Action(action) => action.access_errno(),
                Visibility::ImplicitAncestor if ctx.fs().is_dir(request.path) => None,
                Visibility::ImplicitAncestor | Visibility::Hidden => Some(ENOENT),
            }
        };
        match errno {
            None => AccessDecision::Allow,
            Some(errno) => AccessDecision::Deny(errno),
        }
    }
}

impl<F: FsCheck + Send + Sync + 'static> AccessController for ProfileController<F> {
    fn check(
        &self,
        request: &AccessRequest<'_>,
        caller_condition: &mut dyn CallerCondition,
    ) -> AccessDecision {
        Self::check(self, request, caller_condition)
    }

    fn should_cache_readdir(&self, path: &Path) -> bool {
        let profile = self.profile.load();
        profile.should_cache_readdir(path)
    }
}

struct LazyRuntimeEvalContext<'a, F, C: ?Sized> {
    fs: &'a F,
    caller_condition: &'a mut C,
    ancestor_has_cache: &'a AncestorHasCache,
}

impl<F: FsCheck, C: CallerCondition + ?Sized> RuntimeEvalContext
    for LazyRuntimeEvalContext<'_, F, C>
{
    fn exe(&mut self) -> Option<&Path> {
        self.caller_condition.exe()
    }

    fn env_match(&mut self, name: &str) -> bool {
        self.caller_condition.env_match(name)
    }

    fn fs(&self) -> &dyn FsCheck {
        self.fs
    }

    fn ancestor_has(&mut self, path: &Path, name: &str) -> bool {
        let now = Instant::now();
        if let Some(cached) = self.ancestor_has_cache.lookup(name, path, now) {
            return cached;
        }

        let Some(start_dir) = path.parent() else {
            return false;
        };

        let mut dir = start_dir.to_path_buf();
        loop {
            if self.fs.exists(&dir.join(name)) {
                self.ancestor_has_cache.record_positive(name, &dir, now);
                return true;
            }
            match dir.parent() {
                Some(parent) if parent != dir => dir = parent.to_path_buf(),
                _ => {
                    self.ancestor_has_cache
                        .record_negative(name, start_dir, now);
                    return false;
                }
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::{Caller, Operation};
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // ── Test helpers ──────────────────────────────────────────────────────────

    fn home() -> PathBuf {
        PathBuf::from("/home/user")
    }
    fn cwd() -> PathBuf {
        PathBuf::from("/workspace/project")
    }

    /// [`ExeResolver`] backed by an explicit name→path map.
    struct MockExeResolver(HashMap<String, PathBuf>);

    impl MockExeResolver {
        fn new(pairs: &[(&str, &str)]) -> Self {
            Self(
                pairs
                    .iter()
                    .map(|(k, v)| (k.to_string(), PathBuf::from(v)))
                    .collect(),
            )
        }
        fn empty() -> Self {
            Self(HashMap::new())
        }
    }

    impl ExeResolver for MockExeResolver {
        fn resolve(&self, name: &str) -> Option<PathBuf> {
            self.0.get(name).cloned()
        }
    }

    struct MockOsIdResolver(Option<String>);

    impl MockOsIdResolver {
        fn some(value: &str) -> Self {
            Self(Some(value.to_owned()))
        }

        fn none() -> Self {
            Self(None)
        }
    }

    impl OsIdResolver for MockOsIdResolver {
        fn os_id(&self) -> Option<String> {
            self.0.clone()
        }
    }

    /// [`FsCheck`] backed by an explicit set of paths that "exist".
    struct MockFsCheck(HashSet<PathBuf>);

    impl MockFsCheck {
        fn new(paths: &[&str]) -> Self {
            Self(paths.iter().map(|p| PathBuf::from(p)).collect())
        }
        fn empty() -> Self {
            Self(HashSet::new())
        }
    }

    impl FsCheck for MockFsCheck {
        fn exists(&self, path: &Path) -> bool {
            self.0.contains(path)
        }

        fn is_dir(&self, path: &Path) -> bool {
            self.0.contains(path)
        }
    }

    struct CountingFsCheck {
        existing: HashSet<PathBuf>,
        exists_reads: Arc<AtomicUsize>,
    }

    impl CountingFsCheck {
        fn new(paths: &[&str]) -> (Self, Arc<AtomicUsize>) {
            let counter = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    existing: paths.iter().map(|p| PathBuf::from(p)).collect(),
                    exists_reads: Arc::clone(&counter),
                },
                counter,
            )
        }
    }

    impl FsCheck for CountingFsCheck {
        fn exists(&self, path: &Path) -> bool {
            self.exists_reads.fetch_add(1, Ordering::Relaxed);
            self.existing.contains(path)
        }

        fn is_dir(&self, path: &Path) -> bool {
            self.existing.contains(path)
        }
    }

    #[derive(Default)]
    struct MockCallerCondition {
        exe: Option<PathBuf>,
        env: HashMap<String, String>,
        exe_reads: AtomicUsize,
        env_reads: AtomicUsize,
    }

    impl CallerCondition for MockCallerCondition {
        fn exe(&mut self) -> Option<&Path> {
            self.exe_reads.fetch_add(1, Ordering::Relaxed);
            self.exe.as_deref()
        }

        fn env_match(&mut self, name: &str) -> bool {
            self.env_reads.fetch_add(1, Ordering::Relaxed);
            self.env.contains_key(name)
        }
    }

    /// Convenience: parse with no-op resolvers.
    fn parse_simple(src: &str) -> Profile {
        parse(src, &home(), &cwd(), &NoIncludes, &MockExeResolver::empty()).unwrap()
    }

    /// Convenience: parse with a custom ExeResolver.
    fn parse_with_exe(src: &str, exe_resolver: &dyn ExeResolver) -> Profile {
        parse(src, &home(), &cwd(), &NoIncludes, exe_resolver).unwrap()
    }

    fn parse_with_exe_and_os(
        src: &str,
        exe_resolver: &dyn ExeResolver,
        os_id_resolver: &dyn OsIdResolver,
    ) -> Profile {
        parse_with_os_id_resolver(
            src,
            &home(),
            &cwd(),
            &NoIncludes,
            exe_resolver,
            os_id_resolver,
        )
        .unwrap()
    }

    fn eval_with_fs(
        profile: &Profile,
        path: &str,
        exe: Option<&str>,
        env: &[(&str, &str)],
        fs: &dyn FsCheck,
    ) -> Option<Action> {
        let exe_path = exe.map(Path::new);
        let env_map: HashMap<String, String> = env
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let ctx = EvalContext {
            exe: exe_path,
            env: &env_map,
            fs,
        };
        profile.evaluate(Path::new(path), &ctx)
    }

    /// Convenience: evaluate without caring about `ancestor-has=` (empty fs).
    fn eval(
        profile: &Profile,
        path: &str,
        exe: Option<&str>,
        env: &[(&str, &str)],
    ) -> Option<Action> {
        eval_with_fs(profile, path, exe, env, &MockFsCheck::empty())
    }

    // ── Basic unconditional rules ─────────────────────────────────────────────

    #[test]
    fn unconditional_ro() {
        let p = parse_simple("/usr ro\n");
        assert_eq!(eval(&p, "/usr/bin/ls", None, &[]), Some(Action::ReadOnly));
    }

    #[test]
    fn unconditional_deny() {
        let p = parse_simple("~/.ssh deny\n");
        assert_eq!(
            eval(&p, "/home/user/.ssh/id_rsa", None, &[]),
            Some(Action::Deny)
        );
    }

    #[test]
    fn unconditional_hide() {
        let p = parse_simple("/secret hide\n/secret rw\n");
        let env = HashMap::new();
        let fs = MockFsCheck::empty();
        let ctx = EvalContext {
            exe: None,
            env: &env,
            fs: &fs,
        };

        assert_eq!(eval(&p, "/secret/key", None, &[]), Some(Action::Hide));
        assert_eq!(p.access_errno(Path::new("/secret/key"), &ctx), Some(ENOENT));
        assert_eq!(
            p.mutation_errno(Path::new("/secret/key"), &ctx),
            Some(EPERM)
        );
    }

    #[test]
    fn first_match_wins() {
        let p = parse_simple("/tmp rw\n/tmp ro\n");
        assert_eq!(eval(&p, "/tmp/foo", None, &[]), Some(Action::ReadWrite));
    }

    #[test]
    fn no_match_returns_none() {
        let p = parse_simple("/usr ro\n");
        assert_eq!(eval(&p, "/home/user/file", None, &[]), None);
    }

    #[test]
    fn no_match_is_hidden_by_default() {
        let p = parse_simple("/usr ro\n");
        let env = HashMap::new();
        let fs = MockFsCheck::empty();
        let ctx = EvalContext {
            exe: None,
            env: &env,
            fs: &fs,
        };

        assert_eq!(
            p.effective_action(Path::new("/home/user/file"), &ctx),
            Action::Hide
        );
        assert_eq!(
            p.access_errno(Path::new("/home/user/file"), &ctx),
            Some(ENOENT)
        );
        assert_eq!(
            p.mutation_errno(Path::new("/home/user/file"), &ctx),
            Some(EPERM)
        );
    }

    #[test]
    fn profile_controller_skips_proc_reads_for_unconditional_path_match() {
        let profile = parse_simple("/workspace/project ro\n/workspace/project rw when env=TOKEN\n");
        let controller = ProfileController::with_fs(profile, MockFsCheck::empty());
        let mut caller_condition = MockCallerCondition::default();

        assert_eq!(
            controller.check(
                &AccessRequest {
                    caller: &Caller::with_process_name(Some(123), Some("test".to_owned())),
                    path: Path::new("/workspace/project/file.txt"),
                    operation: Operation::Lookup,
                },
                &mut caller_condition
            ),
            AccessDecision::Allow
        );
        assert_eq!(caller_condition.exe_reads.load(Ordering::Relaxed), 0);
        assert_eq!(caller_condition.env_reads.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn profile_controller_reads_env_only_when_matching_rule_requires_it() {
        let profile = parse_simple("/workspace/project rw when env=TOKEN\n/workspace/project ro\n");
        let controller = ProfileController::with_fs(profile, MockFsCheck::empty());
        let mut caller_condition = MockCallerCondition::default();

        assert_eq!(
            controller.check(
                &AccessRequest {
                    caller: &Caller::with_process_name(Some(123), Some("test".to_owned())),
                    path: Path::new("/workspace/project/file.txt"),
                    operation: Operation::Lookup,
                },
                &mut caller_condition
            ),
            AccessDecision::Allow
        );
        assert_eq!(caller_condition.exe_reads.load(Ordering::Relaxed), 0);
        assert_eq!(caller_condition.env_reads.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn profile_controller_caches_positive_ancestor_has_across_checks() {
        let profile = parse_simple("/repo rw when ancestor-has=.git\n/repo ro\n");
        let (fs, exists_reads) = CountingFsCheck::new(&["/repo/.git"]);
        let controller = ProfileController::with_fs(profile, fs);
        let mut caller_condition = MockCallerCondition::default();
        let request = AccessRequest {
            caller: &Caller::with_process_name(Some(123), Some("test".to_owned())),
            path: Path::new("/repo/src/main.rs"),
            operation: Operation::Lookup,
        };

        assert_eq!(
            controller.check(&request, &mut caller_condition),
            AccessDecision::Allow
        );
        assert_eq!(
            controller.check(&request, &mut caller_condition),
            AccessDecision::Allow
        );

        // first check probes /repo/src/.git then /repo/.git; second check hits cache.
        assert_eq!(exists_reads.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn profile_controller_caches_negative_ancestor_has_across_checks() {
        let profile = parse_simple("/repo rw when ancestor-has=.git\n/repo ro\n");
        let (fs, exists_reads) = CountingFsCheck::new(&[]);
        let controller = ProfileController::with_fs(profile, fs);
        let mut caller_condition = MockCallerCondition::default();
        let request = AccessRequest {
            caller: &Caller::with_process_name(Some(123), Some("test".to_owned())),
            path: Path::new("/repo/src/main.rs"),
            operation: Operation::Lookup,
        };

        assert_eq!(
            controller.check(&request, &mut caller_condition),
            AccessDecision::Allow
        );
        assert_eq!(
            controller.check(&request, &mut caller_condition),
            AccessDecision::Allow
        );

        // first check probes /repo/src/.git, /repo/.git, /.git; second check hits negative cache.
        assert_eq!(exists_reads.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn ancestor_negative_cache_does_not_shadow_deeper_positive_ancestor() {
        let profile = parse_simple("/project rw when ancestor-has=.git\n/project ro\n");
        let (fs, exists_reads) = CountingFsCheck::new(&["/project/repo/.git"]);
        let controller = ProfileController::with_fs(profile, fs);
        let mut caller_condition = MockCallerCondition::default();
        let caller = Caller::with_process_name(Some(123), Some("test".to_owned()));

        // Prime negative cache at /project and / with a path outside the git repo.
        assert_eq!(
            controller.check(
                &AccessRequest {
                    caller: &caller,
                    path: Path::new("/project/other/file.txt"),
                    operation: Operation::Lookup,
                },
                &mut caller_condition
            ),
            AccessDecision::Allow
        );

        // A deeper path with /project/repo/.git must still be writable.
        assert_eq!(
            controller.check(
                &AccessRequest {
                    caller: &caller,
                    path: Path::new("/project/repo/src/file.txt"),
                    operation: Operation::Create,
                },
                &mut caller_condition
            ),
            AccessDecision::Allow
        );
        assert_eq!(exists_reads.load(Ordering::Relaxed), 5);
    }

    #[test]
    fn profile_controller_replace_profile_updates_access_decisions() {
        let controller = ProfileController::with_fs(
            parse_simple("/workspace/project ro\n"),
            MockFsCheck::empty(),
        );
        let mut caller_condition = MockCallerCondition::default();
        let caller = Caller::with_process_name(Some(123), Some("test".to_owned()));

        assert_eq!(
            controller.check(
                &AccessRequest {
                    caller: &caller,
                    path: Path::new("/workspace/project/file.txt"),
                    operation: Operation::Create,
                },
                &mut caller_condition
            ),
            AccessDecision::Deny(EACCES)
        );

        controller.replace_profile(parse_simple("/workspace/project rw\n"));

        assert_eq!(
            controller.check(
                &AccessRequest {
                    caller: &caller,
                    path: Path::new("/workspace/project/file.txt"),
                    operation: Operation::Create,
                },
                &mut caller_condition
            ),
            AccessDecision::Allow
        );
    }

    #[test]
    fn visible_descendant_rule_makes_hidden_parent_directory_traversable() {
        let p = parse_simple("/workspace/project/foo/**/*.txt rw\n/workspace/project/foo hide\n");
        let env = HashMap::new();
        let fs = MockFsCheck::new(&["/workspace/project/foo", "/workspace/project/foo/bar"]);
        let ctx = EvalContext {
            exe: None,
            env: &env,
            fs: &fs,
        };

        assert_eq!(
            p.visibility(Path::new("/workspace/project/foo"), &ctx),
            Visibility::ImplicitAncestor
        );
        assert_eq!(
            p.visibility(Path::new("/workspace/project/foo/bar"), &ctx),
            Visibility::ImplicitAncestor
        );
        assert_eq!(
            p.access_errno(Path::new("/workspace/project/foo"), &ctx),
            None
        );
        assert_eq!(
            p.evaluate(Path::new("/workspace/project/foo/bar/ok.txt"), &ctx),
            Some(Action::ReadWrite)
        );
        assert_eq!(
            p.access_errno(Path::new("/workspace/project/foo/bar/no.bin"), &ctx),
            Some(ENOENT)
        );
        assert_eq!(
            p.mutation_errno(Path::new("/workspace/project/foo/bar/no.bin"), &ctx),
            Some(EPERM)
        );
    }

    #[test]
    fn visible_descendant_rule_makes_denied_parent_directory_traversable() {
        let p = parse_simple(
            "/home/user/**/.git/COMMIT_EDITMSG rw\n/home/user/**/.git deny\n/home/user ro\n",
        );
        let env = HashMap::new();
        let fs = MockFsCheck::new(&["/home/user/repo/.git"]);
        let ctx = EvalContext {
            exe: None,
            env: &env,
            fs: &fs,
        };

        assert_eq!(
            p.visibility(Path::new("/home/user/repo/.git"), &ctx),
            Visibility::ImplicitAncestor
        );
        assert_eq!(
            p.access_errno(Path::new("/home/user/repo/.git"), &ctx),
            None
        );
        assert_eq!(
            p.evaluate(Path::new("/home/user/repo/.git/COMMIT_EDITMSG"), &ctx),
            Some(Action::ReadWrite)
        );
    }

    #[test]
    fn implicit_ancestor_from_descendant_rule_beats_later_deny_on_same_parent() {
        let resolver = MockExeResolver::new(&[("git", "/usr/bin/git")]);
        let p = parse_with_exe(
            "~/**/.git/COMMIT_EDITMSG rw\n~/**/.git rw when exe=git\n~/**/.git deny\n",
            &resolver,
        );
        let env = HashMap::new();
        let fs = MockFsCheck::new(&["/home/user/repo/.git"]);

        let ctx_no_git = EvalContext {
            exe: None,
            env: &env,
            fs: &fs,
        };
        assert_eq!(
            p.visibility(Path::new("/home/user/repo/.git"), &ctx_no_git),
            Visibility::ImplicitAncestor
        );
        assert_eq!(
            p.access_errno(Path::new("/home/user/repo/.git"), &ctx_no_git),
            None
        );

        let ctx_git = EvalContext {
            exe: Some(Path::new("/usr/bin/git")),
            env: &env,
            fs: &fs,
        };
        assert_eq!(
            p.visibility(Path::new("/home/user/repo/.git"), &ctx_git),
            Visibility::Action(Action::ReadWrite)
        );
    }

    #[test]
    fn descendant_rule_after_deny_does_not_override_parent_deny() {
        let p = parse_simple("~/**/.git deny\n~/**/.git/COMMIT_EDITMSG rw\n");
        let env = HashMap::new();
        let fs = MockFsCheck::new(&["/home/user/repo/.git"]);
        let ctx = EvalContext {
            exe: None,
            env: &env,
            fs: &fs,
        };

        assert_eq!(
            p.visibility(Path::new("/home/user/repo/.git"), &ctx),
            Visibility::Action(Action::Deny)
        );
        assert_eq!(
            p.access_errno(Path::new("/home/user/repo/.git"), &ctx),
            Some(EACCES)
        );
    }

    // ── condition: exe= ───────────────────────────────────────────────────────

    #[test]
    fn exe_absolute_pattern_match() {
        let p = parse_simple("~/.claude rw when exe=/usr/bin/claude\n~/.claude ro\n");
        assert_eq!(
            eval(
                &p,
                "/home/user/.claude/settings.json",
                Some("/usr/bin/claude"),
                &[]
            ),
            Some(Action::ReadWrite)
        );
        assert_eq!(
            eval(
                &p,
                "/home/user/.claude/settings.json",
                Some("/usr/bin/vim"),
                &[]
            ),
            Some(Action::ReadOnly)
        );
    }

    #[test]
    fn exe_bare_name_found_in_path_resolver() {
        // `claude` is resolved to `/usr/bin/claude` by the mock resolver.
        // Only that exact path should match.
        let resolver = MockExeResolver::new(&[("claude", "/usr/bin/claude")]);
        let p = parse_with_exe("~/.claude rw when exe=claude\n~/.claude ro\n", &resolver);

        assert_eq!(
            eval(&p, "/home/user/.claude/x", Some("/usr/bin/claude"), &[]),
            Some(Action::ReadWrite),
            "resolved path should match"
        );
        assert_eq!(
            eval(&p, "/home/user/.claude/x", Some("/opt/claude"), &[]),
            Some(Action::ReadOnly),
            "different install location should fall through to ro rule"
        );
    }

    #[test]
    fn exe_pipe_separated_names_match_any_resolved_path() {
        let resolver = MockExeResolver::new(&[
            ("claude", "/usr/bin/claude"),
            ("codex", "/usr/local/bin/codex"),
        ]);
        let p = parse_with_exe(
            "~/.agent rw when exe=claude|codex\n~/.agent ro\n",
            &resolver,
        );

        assert_eq!(
            eval(&p, "/home/user/.agent/x", Some("/usr/bin/claude"), &[]),
            Some(Action::ReadWrite)
        );
        assert_eq!(
            eval(&p, "/home/user/.agent/x", Some("/usr/local/bin/codex"), &[]),
            Some(Action::ReadWrite)
        );
        assert_eq!(
            eval(&p, "/home/user/.agent/x", Some("/opt/bin/codex"), &[]),
            Some(Action::ReadOnly),
            "bare names should still match only the resolved absolute path"
        );
    }

    #[test]
    fn exe_pipe_separated_values_can_mix_with_other_conditions() {
        let resolver = MockExeResolver::new(&[
            ("claude", "/usr/bin/claude"),
            ("codex", "/usr/local/bin/codex"),
        ]);
        let p = parse_with_exe(
            "/secret rw when exe=claude|codex,env=TOKEN\n/secret deny\n",
            &resolver,
        );

        assert_eq!(
            eval(
                &p,
                "/secret/file",
                Some("/usr/local/bin/codex"),
                &[("TOKEN", "1")]
            ),
            Some(Action::ReadWrite)
        );
        assert_eq!(
            eval(&p, "/secret/file", Some("/usr/local/bin/codex"), &[]),
            Some(Action::Deny)
        );
    }

    #[test]
    fn exe_multiple_names_are_checked_with_one_runtime_lookup() {
        let resolver = MockExeResolver::new(&[
            ("claude", "/usr/bin/claude"),
            ("codex", "/usr/local/bin/codex"),
        ]);
        let p = parse_with_exe("/data rw when exe=claude|codex\n/data ro\n", &resolver);
        let mut caller_condition = MockCallerCondition {
            exe: Some(PathBuf::from("/usr/local/bin/codex")),
            ..Default::default()
        };

        let controller = ProfileController::with_fs(p, MockFsCheck::empty());
        let decision = controller.check(
            &AccessRequest {
                caller: &Caller::with_process_name(Some(123), Some("test".to_owned())),
                path: Path::new("/data/file"),
                operation: Operation::OpenWrite,
            },
            &mut caller_condition,
        );

        assert_eq!(decision, AccessDecision::Allow);
        assert_eq!(caller_condition.exe_reads.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn exe_bare_name_not_in_path_never_matches() {
        // `myapp` not found in resolver → condition is always false.
        let resolver = MockExeResolver::empty();
        let p = parse_with_exe("/data rw when exe=myapp\n/data ro\n", &resolver);

        // No matter what exe is provided, the `rw` rule never fires.
        assert_eq!(
            eval(&p, "/data/file", Some("/usr/local/bin/myapp"), &[]),
            Some(Action::ReadOnly)
        );
        assert_eq!(
            eval(&p, "/data/file", Some("/opt/myapp"), &[]),
            Some(Action::ReadOnly)
        );
    }

    #[test]
    fn exe_bare_name_with_glob_chars_is_not_treated_as_glob() {
        let resolver = MockExeResolver::empty();
        let p = parse_with_exe("/data rw when exe=git*\n/data ro\n", &resolver);
        assert_eq!(
            eval(&p, "/data/file", Some("/usr/lib/git-core/git"), &[]),
            Some(Action::ReadOnly)
        );
    }

    #[test]
    fn exe_absolute_glob_pattern_matches() {
        let p = parse_simple("/repo rw when exe=/usr/**/git\n/repo ro\n");
        assert_eq!(
            eval(&p, "/repo/file", Some("/usr/lib/git-core/git"), &[]),
            Some(Action::ReadWrite)
        );
        assert_eq!(
            eval(&p, "/repo/file", Some("/opt/git"), &[]),
            Some(Action::ReadOnly)
        );
    }

    #[test]
    fn exe_glob_star_and_double_star_directory_behavior() {
        let p = parse_simple("/repo rw when exe=/usr/*/git|/usr/**/git\n/repo ro\n");
        assert_eq!(
            eval(&p, "/repo/file", Some("/usr/lib/git"), &[]),
            Some(Action::ReadWrite),
            "* should match one directory level"
        );
        assert_eq!(
            eval(&p, "/repo/file", Some("/usr/lib/git-core/git"), &[]),
            Some(Action::ReadWrite),
            "** should match multiple directory levels"
        );
    }

    #[test]
    fn exe_relative_path_is_parse_error() {
        let err = parse(
            "/foo rw when exe=../bin/sh\n",
            &home(),
            &cwd(),
            &NoIncludes,
            &MockExeResolver::empty(),
        )
        .unwrap_err();
        assert!(matches!(err, ParseError::InvalidExe(_)), "got: {err:?}");
    }

    #[test]
    fn exe_no_exe_in_context_never_matches() {
        let p = parse_simple("/foo rw when exe=/bin/sh\n/foo ro\n");
        assert_eq!(eval(&p, "/foo/bar", None, &[]), Some(Action::ReadOnly));
    }

    // ── condition: env= ───────────────────────────────────────────────────────

    #[test]
    fn env_condition_set_and_unset() {
        let p = parse_simple("/debug rw when env=DEBUG\n/debug ro\n");
        assert_eq!(
            eval(&p, "/debug/log", None, &[("DEBUG", "1")]),
            Some(Action::ReadWrite)
        );
        assert_eq!(eval(&p, "/debug/log", None, &[]), Some(Action::ReadOnly));
    }

    // ── condition: os.id= (load-time) ────────────────────────────────────────

    #[test]
    fn os_id_condition_keeps_rule_when_matching() {
        let p = parse_with_exe_and_os(
            "/etc rw when os.id=arch\n/etc ro\n",
            &MockExeResolver::empty(),
            &MockOsIdResolver::some("arch"),
        );
        assert_eq!(eval(&p, "/etc/hosts", None, &[]), Some(Action::ReadWrite));
    }

    #[test]
    fn os_id_condition_drops_rule_when_not_matching() {
        let p = parse_with_exe_and_os(
            "/etc rw when os.id=arch\n/etc ro\n",
            &MockExeResolver::empty(),
            &MockOsIdResolver::some("debian"),
        );
        assert_eq!(eval(&p, "/etc/hosts", None, &[]), Some(Action::ReadOnly));
        assert_eq!(p.rules().len(), 1);
    }

    #[test]
    fn os_id_condition_none_drops_rule() {
        let p = parse_with_exe_and_os(
            "/etc rw when os.id=arch\n/etc ro\n",
            &MockExeResolver::empty(),
            &MockOsIdResolver::none(),
        );
        assert_eq!(eval(&p, "/etc/hosts", None, &[]), Some(Action::ReadOnly));
    }

    #[test]
    fn os_id_condition_is_anded_with_runtime_conditions() {
        let p = parse_with_exe_and_os(
            "/workspace rw when os.id=arch,env=DEBUG\n/workspace ro\n",
            &MockExeResolver::empty(),
            &MockOsIdResolver::some("arch"),
        );
        assert_eq!(
            eval(&p, "/workspace/file", None, &[("DEBUG", "1")]),
            Some(Action::ReadWrite)
        );
        assert_eq!(
            eval(&p, "/workspace/file", None, &[]),
            Some(Action::ReadOnly)
        );
    }

    #[test]
    fn empty_os_id_value_is_parse_error() {
        let err = parse_with_os_id_resolver(
            "/workspace rw when os.id=\n",
            &home(),
            &cwd(),
            &NoIncludes,
            &MockExeResolver::empty(),
            &MockOsIdResolver::some("arch"),
        )
        .unwrap_err();
        assert!(matches!(err, ParseError::InvalidOsId(_)), "got: {err:?}");
    }

    // ── condition: ancestor-has= ──────────────────────────────────────────────

    #[test]
    fn ancestor_has_match_and_no_match() {
        // Virtual filesystem: `/repo/.git` exists.
        let fs = MockFsCheck::new(&["/repo/.git"]);

        let p = parse(
            "/repo rw when ancestor-has=.git\n/repo ro\n",
            &home(),
            &PathBuf::from("/repo"),
            &NoIncludes,
            &MockExeResolver::empty(),
        )
        .unwrap();

        // `/repo/src/main.rs` — ancestor `/repo` has `.git`
        assert_eq!(
            eval_with_fs(&p, "/repo/src/main.rs", None, &[], &fs),
            Some(Action::ReadWrite)
        );
        // `/repo/src` — ancestor `/repo` has `.git`
        assert_eq!(
            eval_with_fs(&p, "/repo/src", None, &[], &fs),
            Some(Action::ReadWrite)
        );
        // Fallback: same path but empty mock fs (nothing "exists"), so the
        // `ancestor-has` condition fails and the unconditional `ro` rule fires.
        let fs2 = MockFsCheck::empty();
        assert_eq!(
            eval_with_fs(&p, "/repo/src/main.rs", None, &[], &fs2),
            Some(Action::ReadOnly)
        );
    }

    #[test]
    fn ancestor_has_nested_directory() {
        // `.git` lives two levels up from the accessed path.
        let fs = MockFsCheck::new(&["/project/.git"]);

        let p = parse(
            "/project rw when ancestor-has=.git\n/project deny\n",
            &home(),
            &PathBuf::from("/project"),
            &NoIncludes,
            &MockExeResolver::empty(),
        )
        .unwrap();

        assert_eq!(
            eval_with_fs(&p, "/project/a/b/c.txt", None, &[], &fs),
            Some(Action::ReadWrite)
        );
    }

    // ── Multiple conditions (AND) ─────────────────────────────────────────────

    #[test]
    fn multiple_conditions_all_must_match() {
        let p = parse_simple("/secret rw when exe=/usr/bin/vault,env=VAULT_TOKEN\n/secret deny\n");

        // Both conditions met → rw
        assert_eq!(
            eval(
                &p,
                "/secret/key",
                Some("/usr/bin/vault"),
                &[("VAULT_TOKEN", "x")]
            ),
            Some(Action::ReadWrite)
        );
        // Only exe → deny
        assert_eq!(
            eval(&p, "/secret/key", Some("/usr/bin/vault"), &[]),
            Some(Action::Deny)
        );
        // Only env → deny
        assert_eq!(
            eval(
                &p,
                "/secret/key",
                Some("/usr/bin/vim"),
                &[("VAULT_TOKEN", "x")]
            ),
            Some(Action::Deny)
        );
        // Neither → deny
        assert_eq!(
            eval(&p, "/secret/key", Some("/usr/bin/vim"), &[]),
            Some(Action::Deny)
        );
    }

    // ── %include ──────────────────────────────────────────────────────────────

    #[test]
    fn include_expands_inline() {
        struct MapResolver(HashMap<String, String>);
        impl IncludeResolver for MapResolver {
            fn resolve(&self, name: &str) -> Result<Option<String>, String> {
                Ok(self.0.get(name).cloned())
            }
        }

        let mut map = HashMap::new();
        map.insert("base".to_owned(), "/usr ro\n/tmp rw\n".to_owned());
        let inc = MapResolver(map);

        let p = parse(
            "%include base\n~/.ssh deny\n",
            &home(),
            &cwd(),
            &inc,
            &MockExeResolver::empty(),
        )
        .unwrap();

        assert_eq!(eval(&p, "/usr/bin/ls", None, &[]), Some(Action::ReadOnly));
        assert_eq!(eval(&p, "/tmp/x", None, &[]), Some(Action::ReadWrite));
        assert_eq!(
            eval(&p, "/home/user/.ssh/key", None, &[]),
            Some(Action::Deny)
        );
    }

    #[test]
    fn include_missing_silently_skipped() {
        let p = parse_simple("%include nonexistent\n/usr ro\n");
        assert_eq!(eval(&p, "/usr/lib/foo", None, &[]), Some(Action::ReadOnly));
    }

    #[test]
    fn include_cycle_detected() {
        struct CycleResolver;
        impl IncludeResolver for CycleResolver {
            fn resolve(&self, name: &str) -> Result<Option<String>, String> {
                Ok(Some(format!("%include {name}\n")))
            }
        }
        let err = parse(
            "%include a\n",
            &home(),
            &cwd(),
            &CycleResolver,
            &MockExeResolver::empty(),
        )
        .unwrap_err();
        assert!(matches!(err, ParseError::IncludeCycle(_)));
    }

    // ── Pattern expansion ─────────────────────────────────────────────────────

    #[test]
    fn tilde_expansion() {
        let p = parse_simple("~ ro\n");
        assert_eq!(
            eval(&p, "/home/user/docs/readme.md", None, &[]),
            Some(Action::ReadOnly)
        );
    }

    #[test]
    fn relative_path_patterns_are_rejected() {
        let err = parse_simple_result("subdir deny\n").expect_err("relative path should fail");
        assert!(
            err.to_string()
                .contains("relative pattern 'subdir' is not supported"),
            "{err:#}"
        );

        let err = parse_simple_result(". rw\n").expect_err("dot path should fail");
        assert!(
            err.to_string()
                .contains("relative pattern '.' is not supported"),
            "{err:#}"
        );

        let err = parse_simple_result("./subdir rw\n").expect_err("dot slash path should fail");
        assert!(
            err.to_string()
                .contains("relative pattern './subdir' is not supported"),
            "{err:#}"
        );
    }

    #[test]
    fn readdir_cache_policy_examples() {
        let case1 = parse_simple("/a/foo hide when exe=bar\n/a ro\n");
        assert!(!case1.should_cache_readdir(Path::new("/a")));

        let case2 = parse_simple("/a/b deny when exe=bar\n/a ro\n");
        assert!(case2.should_cache_readdir(Path::new("/a")));
        assert!(!case2.should_cache_readdir(Path::new("/a/b")));

        let case3 = parse_simple("/a/**/foo rw when exe=bar\n/a ro\n");
        assert!(case3.should_cache_readdir(Path::new("/a")));

        let case4 = parse_simple("/**/.git rw when exe=git\n/**/.git deny\n");
        assert!(!case4.should_cache_readdir(Path::new("/a/.git")));
        // NOTE: keeping descendant behavior conservative for now; without a
        // direct-child glob introspection API we may disable caching for paths
        // such as /a/.git/objects more often than strictly necessary.

        let case5 = parse_simple("/a/foo hide when env=SECRET\n/a ro\n");
        assert!(!case5.should_cache_readdir(Path::new("/a")));

        let case6 = parse_simple("/a/b deny when env=SECRET\n/a ro\n");
        assert!(case6.should_cache_readdir(Path::new("/a")));
        assert!(!case6.should_cache_readdir(Path::new("/a/b")));

        let case7 = parse_simple("/a deny\n");
        assert!(!case7.should_cache_readdir(Path::new("/a")));

        let case8 = parse_simple("/a/b ro\n/a hide\n");
        assert!(case8.should_cache_readdir(Path::new("/a")));
    }

    #[test]
    fn rule_match_report_contains_condition_status() {
        let p = parse_simple("/repo rw when env=ALLOW\n/repo ro\n");
        let env = HashMap::new();
        let fs = MockFsCheck::empty();
        let ctx = EvalContext {
            exe: None,
            env: &env,
            fs: &fs,
        };
        let report = p.rule_match_report(Path::new("/repo/file"), &ctx);
        assert_eq!(report.visibility, Visibility::Action(Action::ReadOnly));
        let explicit: Vec<&RuleMatchReportEntry> = report
            .entries
            .iter()
            .filter(|entry| entry.kind == RuleMatchKind::Explicit)
            .collect();
        assert!(explicit.len() >= 2);
        assert!(explicit.iter().any(|entry| !entry.conditions_matched));
        assert!(explicit.iter().any(|entry| entry.conditions_matched));
    }

    // ── Parse errors ─────────────────────────────────────────────────────────

    #[test]
    fn unknown_action_is_error() {
        assert!(parse_simple_result("/foo bad-action\n").is_err());
    }

    #[test]
    fn unknown_condition_is_error() {
        assert!(parse_simple_result("/foo rw when user=root\n").is_err());
    }

    #[test]
    fn when_without_conditions_is_error() {
        assert!(parse_simple_result("/foo rw when\n").is_err());
    }

    #[test]
    fn extra_tokens_after_conditions_is_error() {
        assert!(parse_simple_result("/foo rw when exe=/bin/sh extra\n").is_err());
    }

    #[test]
    fn trailing_hash_comment_is_ignored() {
        let p = parse_simple("/foo ro # comment\n");
        assert_eq!(eval(&p, "/foo", None, &[]), Some(Action::ReadOnly));
    }

    #[test]
    fn hash_inside_token_is_not_treated_as_comment() {
        let p = parse_simple("/tmp/foo#bar ro\n");
        assert_eq!(eval(&p, "/tmp/foo#bar", None, &[]), Some(Action::ReadOnly));
    }

    fn parse_simple_result(src: &str) -> Result<Profile, ParseError> {
        parse(src, &home(), &cwd(), &NoIncludes, &MockExeResolver::empty())
    }
}
