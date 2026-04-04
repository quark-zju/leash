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
//! - `exe=name`            — calling process's executable matches: bare name
//!                           is resolved via PATH at parse time; absolute path
//!                           is used as-is.  Globs are not supported.
//! - `ancestor-has=name`   — some ancestor directory of the accessed path
//!                           contains an entry named `name`
//! - `env=VAR`             — environment variable `VAR` is set in the caller
//!
//! **directives**:
//! - `%include name`       — inline another named profile
//!
//! Evaluation: top-down, first match wins.
//! A rule whose conditions are not all satisfied is skipped.
//! Paths that do not match any rule are hidden by default.

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};

use libc::{EACCES, ENOENT, EPERM};

use globset::{Glob, GlobSet, GlobSetBuilder};

use crate::access::{AccessController, AccessDecision, AccessRequest};

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
            let candidate = PathBuf::from(dir).join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        None
    }
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
    /// Calling process executable equals this absolute path.
    ///
    /// Resolved at parse time:
    /// - Bare name (no `/`) → looked up via [`ExeResolver`]; `None` means the
    ///   name was not found in PATH and this condition will never match.
    /// - Absolute path → used as-is.
    Exe(Option<PathBuf>),

    /// An ancestor directory of the accessed path contains an entry named
    /// `name` (file or directory).  Checked at eval time via [`FsCheck`].
    AncestorHas(String),

    /// An environment variable named `var` is set in the caller's environment.
    Env(String),
}

// ── RawCondition (pre-compilation) ───────────────────────────────────────────

#[derive(Debug, Clone)]
enum RawCondition {
    Exe(String),
    AncestorHas(String),
    Env(String),
}

impl RawCondition {
    fn parse(token: &str) -> Result<Self, ParseError> {
        if let Some(rest) = token.strip_prefix("exe=") {
            Ok(Self::Exe(rest.to_owned()))
        } else if let Some(rest) = token.strip_prefix("ancestor-has=") {
            Ok(Self::AncestorHas(rest.to_owned()))
        } else if let Some(rest) = token.strip_prefix("env=") {
            Ok(Self::Env(rest.to_owned()))
        } else {
            Err(ParseError::UnknownCondition(token.to_owned()))
        }
    }

    fn compile(&self, exe_resolver: &dyn ExeResolver) -> Result<Condition, ParseError> {
        match self {
            RawCondition::Exe(value) => {
                let resolved = resolve_exe(value, exe_resolver)?;
                Ok(Condition::Exe(resolved))
            }
            RawCondition::AncestorHas(name) => Ok(Condition::AncestorHas(name.clone())),
            RawCondition::Env(var) => Ok(Condition::Env(var.clone())),
        }
    }
}

/// Resolve an `exe=` value at parse time.
///
/// Accepted forms:
/// - Absolute path (starts with `/`) — used as-is.
/// - Bare name (no `/`) — looked up via `resolver`; `None` if not found
///   (condition will never match at eval time).
///
/// Any other form (relative path, glob metacharacters) is a parse error.
fn resolve_exe(value: &str, resolver: &dyn ExeResolver) -> Result<Option<PathBuf>, ParseError> {
    if value.starts_with('/') {
        return Ok(Some(PathBuf::from(value)));
    }
    if value.contains('/') {
        // Relative path or glob — not supported.
        return Err(ParseError::InvalidExe(value.to_owned()));
    }
    // Bare name: look up in PATH.
    Ok(resolver.resolve(value))
}

// ── Rule ──────────────────────────────────────────────────────────────────────

/// A compiled rule ready for matching.
pub struct Rule {
    /// Original pattern string (for display).
    pub pattern: String,
    /// Compiled glob for path matching (includes an auto-added `<pat>/**`).
    pub(crate) glob: GlobSet,
    /// Compiled glob for ancestor paths that should stay visible for
    /// descendant traversal.
    pub(crate) ancestor_glob: GlobSet,
    pub action: Action,
    /// All conditions (AND semantics).
    pub conditions: Vec<Condition>,
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
}

impl Profile {
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Evaluate the profile for the given absolute `path`.
    ///
    /// `ctx` supplies runtime information needed to evaluate conditions.
    /// Returns `None` when no rule matches.
    pub fn evaluate(&self, path: &Path, ctx: &EvalContext<'_>) -> Option<Action> {
        let mut ctx = StaticRuntimeEvalContext { ctx };
        self.evaluate_with_runtime(path, &mut ctx)
    }

    fn evaluate_with_runtime(
        &self,
        path: &Path,
        ctx: &mut dyn RuntimeEvalContext,
    ) -> Option<Action> {
        for rule in &self.rules {
            if rule.glob.is_match(path) && rule.conditions_match(path, ctx) {
                return Some(rule.action);
            }
        }
        None
    }

    pub fn visibility(&self, path: &Path, ctx: &EvalContext<'_>) -> Visibility {
        let mut ctx = StaticRuntimeEvalContext { ctx };
        self.visibility_with_runtime(path, &mut ctx)
    }

    fn visibility_with_runtime(
        &self,
        path: &Path,
        ctx: &mut dyn RuntimeEvalContext,
    ) -> Visibility {
        if let Some(action) = self.evaluate_with_runtime(path, ctx) {
            if action == Action::Hide && self.is_implicit_ancestor_with_runtime(path, ctx) {
                return Visibility::ImplicitAncestor;
            }
            return Visibility::Action(action);
        }
        if self.is_implicit_ancestor_with_runtime(path, ctx) {
            return Visibility::ImplicitAncestor;
        }
        Visibility::Hidden
    }

    pub fn effective_action(&self, path: &Path, ctx: &EvalContext<'_>) -> Action {
        self.evaluate(path, ctx).unwrap_or(Action::Hide)
    }

    pub fn access_errno(&self, path: &Path, ctx: &EvalContext<'_>) -> Option<i32> {
        match self.visibility(path, ctx) {
            Visibility::Action(action) => action.access_errno(),
            Visibility::ImplicitAncestor if ctx.fs.is_dir(path) => None,
            Visibility::ImplicitAncestor | Visibility::Hidden => Some(ENOENT),
        }
    }

    pub fn mutation_errno(&self, path: &Path, ctx: &EvalContext<'_>) -> Option<i32> {
        match self.visibility(path, ctx) {
            Visibility::Action(action) => action.mutation_errno(),
            Visibility::ImplicitAncestor if ctx.fs.is_dir(path) => None,
            Visibility::ImplicitAncestor | Visibility::Hidden => Some(EPERM),
        }
    }

    fn is_implicit_ancestor(&self, path: &Path, ctx: &EvalContext<'_>) -> bool {
        let mut ctx = StaticRuntimeEvalContext { ctx };
        self.is_implicit_ancestor_with_runtime(path, &mut ctx)
    }

    fn is_implicit_ancestor_with_runtime(
        &self,
        path: &Path,
        ctx: &mut dyn RuntimeEvalContext,
    ) -> bool {
        self.rules.iter().any(|rule| {
            rule.action.allows_visible_descendants()
                && rule.ancestor_glob.is_match(path)
                && rule.conditions_match(path, ctx)
        })
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
    fn has_env(&mut self, name: &str) -> bool;
    fn fs(&self) -> &dyn FsCheck;
}

struct StaticRuntimeEvalContext<'a, 'b> {
    ctx: &'a EvalContext<'b>,
}

impl RuntimeEvalContext for StaticRuntimeEvalContext<'_, '_> {
    fn exe(&mut self) -> Option<&Path> {
        self.ctx.exe
    }

    fn has_env(&mut self, name: &str) -> bool {
        self.ctx.env.contains_key(name)
    }

    fn fs(&self) -> &dyn FsCheck {
        self.ctx.fs
    }
}

// ── Condition matching ────────────────────────────────────────────────────────

impl Rule {
    fn conditions_match(&self, path: &Path, ctx: &mut dyn RuntimeEvalContext) -> bool {
        self.conditions.iter().all(|c| c.matches(path, ctx))
    }
}

impl Condition {
    fn matches(&self, path: &Path, ctx: &mut dyn RuntimeEvalContext) -> bool {
        match self {
            Condition::Exe(resolved) => match (resolved.as_deref(), ctx.exe()) {
                // Name not found in PATH at parse time → never matches.
                (None, _) => false,
                (_, None) => false,
                (Some(expected), Some(exe)) => exe == expected,
            },

            Condition::AncestorHas(name) => ancestor_has(path, name, ctx.fs()),

            Condition::Env(var) => ctx.has_env(var),
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

    #[error("invalid exe= value '{0}': must be a bare name or an absolute path")]
    InvalidExe(String),

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
pub struct NoIncludes;

impl IncludeResolver for NoIncludes {
    fn resolve(&self, _name: &str) -> Result<Option<String>, String> {
        Ok(None)
    }
}

/// Parse a profile from source text.
///
/// - `home` / `cwd`: used to expand `~` and relative patterns.
/// - `include_resolver`: handles `%include` directives.
/// - `exe_resolver`: resolves bare executable names in `exe=` conditions.
pub fn parse(
    source: &str,
    home: &Path,
    cwd: &Path,
    include_resolver: &dyn IncludeResolver,
    exe_resolver: &dyn ExeResolver,
) -> Result<Profile, ParseError> {
    let mut rules = Vec::new();
    let include_stack: Vec<String> = Vec::new();
    parse_lines(
        source,
        home,
        cwd,
        include_resolver,
        exe_resolver,
        &include_stack,
        &mut rules,
    )?;
    Ok(Profile { rules })
}

fn parse_lines(
    source: &str,
    home: &Path,
    cwd: &Path,
    include_resolver: &dyn IncludeResolver,
    exe_resolver: &dyn ExeResolver,
    include_stack: &[String],
    out: &mut Vec<Rule>,
) -> Result<(), ParseError> {
    for (i, raw_line) in source.lines().enumerate() {
        let lineno = i + 1;
        let line = raw_line.trim();

        if line.is_empty() || line.starts_with('#') {
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
                include_stack,
                out,
            )?;
            continue;
        }

        let rule = parse_rule_line(line, lineno, home, cwd, exe_resolver)?;
        out.push(rule);
    }
    Ok(())
}

fn parse_directive(
    rest: &str,
    lineno: usize,
    home: &Path,
    cwd: &Path,
    include_resolver: &dyn IncludeResolver,
    exe_resolver: &dyn ExeResolver,
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
) -> Result<Rule, ParseError> {
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

    let conditions: Vec<Condition> = raw_conditions
        .iter()
        .map(|c| c.compile(exe_resolver))
        .collect::<Result<_, _>>()?;

    let abs_pattern = expand_pattern(pattern_tok, home, cwd);
    let glob = build_glob(&abs_pattern).map_err(|e| ParseError::BadGlob(abs_pattern.clone(), e))?;
    let ancestor_glob = build_ancestor_glob(&abs_pattern)
        .map_err(|e| ParseError::BadGlob(abs_pattern.clone(), e))?;

    Ok(Rule {
        pattern: abs_pattern,
        glob,
        ancestor_glob,
        action,
        conditions,
    })
}

// ── Pattern normalisation ─────────────────────────────────────────────────────

fn expand_pattern(pattern: &str, home: &Path, cwd: &Path) -> String {
    if pattern == "~" {
        return home.to_string_lossy().into_owned();
    }
    if let Some(rest) = pattern.strip_prefix("~/") {
        return home.join(rest).to_string_lossy().into_owned();
    }
    if pattern == "." {
        return cwd.to_string_lossy().into_owned();
    }
    if pattern.starts_with("./") {
        return cwd.join(&pattern[2..]).to_string_lossy().into_owned();
    }
    if pattern.starts_with('/') || pattern.starts_with("**/") {
        return pattern.to_owned();
    }
    cwd.join(pattern).to_string_lossy().into_owned()
}

/// Build a `GlobSet` that matches the pattern itself and all descendants.
fn build_glob(pattern: &str) -> Result<GlobSet, String> {
    let mut builder = GlobSetBuilder::new();

    let g = Glob::new(pattern).map_err(|e| e.to_string())?;
    builder.add(g);

    if !pattern.ends_with("/**") && !pattern.ends_with("**") {
        let descendant = format!("{pattern}/**");
        let g2 = Glob::new(&descendant).map_err(|e| e.to_string())?;
        builder.add(g2);
    }

    builder.build().map_err(|e| e.to_string())
}

fn build_ancestor_glob(pattern: &str) -> Result<GlobSet, String> {
    let mut builder = GlobSetBuilder::new();
    for ancestor in ancestor_globs_for_rule(pattern) {
        let glob = Glob::new(&ancestor).map_err(|e| e.to_string())?;
        builder.add(glob);
    }
    builder.build().map_err(|e| e.to_string())
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
        let prefix = base
            .split("/**")
            .next()
            .unwrap_or("")
            .trim_end_matches('/');
        if prefix.is_empty() {
            out.push("/**".to_owned());
        } else {
            out.push(format!("{prefix}/**"));
        }
    }
    out
}

fn parse_environ(raw: Vec<u8>) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for pair in raw.split(|byte| *byte == 0) {
        if pair.is_empty() {
            continue;
        }
        let Some(eq) = pair.iter().position(|byte| *byte == b'=') else {
            continue;
        };
        let key = String::from_utf8_lossy(&pair[..eq]).into_owned();
        let value = String::from_utf8_lossy(&pair[eq + 1..]).into_owned();
        out.insert(key, value);
    }
    out
}

pub trait CallerDataSource {
    fn exe(&self, pid: u32) -> Option<PathBuf>;
    fn env(&self, pid: u32) -> HashMap<String, String>;
}

pub struct ProcCallerDataSource;

impl CallerDataSource for ProcCallerDataSource {
    fn exe(&self, pid: u32) -> Option<PathBuf> {
        std::fs::read_link(format!("/proc/{pid}/exe")).ok()
    }

    fn env(&self, pid: u32) -> HashMap<String, String> {
        std::fs::read(format!("/proc/{pid}/environ"))
            .map(parse_environ)
            .unwrap_or_default()
    }
}

pub struct ProfileController<F = RealFsCheck, C = ProcCallerDataSource> {
    profile: Profile,
    fs: F,
    caller_data: C,
}

impl ProfileController<RealFsCheck, ProcCallerDataSource> {
    pub fn new(profile: Profile) -> Self {
        Self {
            profile,
            fs: RealFsCheck,
            caller_data: ProcCallerDataSource,
        }
    }
}

impl<F: FsCheck> ProfileController<F, ProcCallerDataSource> {
    #[allow(dead_code)]
    pub(crate) fn with_fs(profile: Profile, fs: F) -> Self {
        Self {
            profile,
            fs,
            caller_data: ProcCallerDataSource,
        }
    }
}

impl<F: FsCheck, C: CallerDataSource> ProfileController<F, C> {
    #[allow(dead_code)]
    pub(crate) fn with_sources(profile: Profile, fs: F, caller_data: C) -> Self {
        Self {
            profile,
            fs,
            caller_data,
        }
    }
}

impl<F: FsCheck + Send + Sync + 'static, C: CallerDataSource + Send + Sync + 'static>
    AccessController for ProfileController<F, C>
{
    fn check(&self, request: &AccessRequest<'_>) -> AccessDecision {
        let mut ctx = LazyRuntimeEvalContext {
            pid: request.caller.pid,
            fs: &self.fs,
            caller_data: &self.caller_data,
            exe_loaded: false,
            exe: None,
            env_loaded: false,
            env: HashMap::new(),
        };
        let errno = if request.operation.is_write() {
            match self.profile.visibility_with_runtime(request.path, &mut ctx) {
                Visibility::Action(action) => action.mutation_errno(),
                Visibility::ImplicitAncestor if ctx.fs().is_dir(request.path) => None,
                Visibility::ImplicitAncestor | Visibility::Hidden => Some(EPERM),
            }
        } else {
            match self.profile.visibility_with_runtime(request.path, &mut ctx) {
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

struct LazyRuntimeEvalContext<'a, F, C> {
    pid: Option<u32>,
    fs: &'a F,
    caller_data: &'a C,
    exe_loaded: bool,
    exe: Option<PathBuf>,
    env_loaded: bool,
    env: HashMap<String, String>,
}

impl<F: FsCheck, C: CallerDataSource> RuntimeEvalContext for LazyRuntimeEvalContext<'_, F, C> {
    fn exe(&mut self) -> Option<&Path> {
        if !self.exe_loaded {
            self.exe = self.pid.and_then(|pid| self.caller_data.exe(pid));
            self.exe_loaded = true;
        }
        self.exe.as_deref()
    }

    fn has_env(&mut self, name: &str) -> bool {
        if !self.env_loaded {
            self.env = self
                .pid
                .map(|pid| self.caller_data.env(pid))
                .unwrap_or_default();
            self.env_loaded = true;
        }
        self.env.contains_key(name)
    }

    fn fs(&self) -> &dyn FsCheck {
        self.fs
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::{Caller, Operation};
    use std::collections::{HashMap, HashSet};
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

    #[derive(Default)]
    struct MockCallerDataSource {
        exe: Option<PathBuf>,
        env: HashMap<String, String>,
        exe_reads: AtomicUsize,
        env_reads: AtomicUsize,
    }

    impl CallerDataSource for MockCallerDataSource {
        fn exe(&self, _pid: u32) -> Option<PathBuf> {
            self.exe_reads.fetch_add(1, Ordering::Relaxed);
            self.exe.clone()
        }

        fn env(&self, _pid: u32) -> HashMap<String, String> {
            self.env_reads.fetch_add(1, Ordering::Relaxed);
            self.env.clone()
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
        let caller_data = MockCallerDataSource::default();
        let controller =
            ProfileController::with_sources(profile, MockFsCheck::empty(), caller_data);

        assert_eq!(
            controller.check(&AccessRequest {
                caller: &Caller::new(Some(123), Some("test".to_owned())),
                path: Path::new("/workspace/project/file.txt"),
                operation: Operation::Lookup,
            }),
            AccessDecision::Allow
        );
        assert_eq!(controller.caller_data.exe_reads.load(Ordering::Relaxed), 0);
        assert_eq!(controller.caller_data.env_reads.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn profile_controller_reads_env_only_when_matching_rule_requires_it() {
        let profile = parse_simple("/workspace/project rw when env=TOKEN\n/workspace/project ro\n");
        let caller_data = MockCallerDataSource::default();
        let controller =
            ProfileController::with_sources(profile, MockFsCheck::empty(), caller_data);

        assert_eq!(
            controller.check(&AccessRequest {
                caller: &Caller::new(Some(123), Some("test".to_owned())),
                path: Path::new("/workspace/project/file.txt"),
                operation: Operation::Lookup,
            }),
            AccessDecision::Allow
        );
        assert_eq!(controller.caller_data.exe_reads.load(Ordering::Relaxed), 0);
        assert_eq!(controller.caller_data.env_reads.load(Ordering::Relaxed), 1);
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
    fn exe_glob_pattern_is_parse_error() {
        // Glob metacharacters in exe= are not supported.
        let err = parse(
            "**/.git rw when exe=**/git\n",
            &home(),
            &cwd(),
            &NoIncludes,
            &MockExeResolver::empty(),
        )
        .unwrap_err();
        assert!(matches!(err, ParseError::InvalidExe(_)), "got: {err:?}");
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

    // ── condition: ancestor-has= ──────────────────────────────────────────────

    #[test]
    fn ancestor_has_match_and_no_match() {
        // Virtual filesystem: `/repo/.git` exists.
        let fs = MockFsCheck::new(&["/repo/.git"]);

        let p = parse(
            ". rw when ancestor-has=.git\n. ro\n",
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
            ". rw when ancestor-has=.git\n. deny\n",
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
    fn relative_path_resolved_under_cwd() {
        let p = parse_simple("subdir deny\n");
        assert_eq!(
            eval(&p, "/workspace/project/subdir/secret", None, &[]),
            Some(Action::Deny)
        );
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

    fn parse_simple_result(src: &str) -> Result<Profile, ParseError> {
        parse(src, &home(), &cwd(), &NoIncludes, &MockExeResolver::empty())
    }
}
