pub(crate) const DEFAULT_PROFILE_SOURCE: &str = "\
%include builtin:deny-sensitive
%include builtin:basic
%include builtin:agents
~ git-rw
";

const DENY_SENSITIVE_PROFILE_SOURCE: &str = "\
~/.config/leash deny
~/.cache/mozilla hide
~/.config/google-chrome* hide
~/.config/chromium* hide
~/.ssh deny
";

const BASIC_PROFILE_SOURCE: &str = "\
/tmp rw
/bin ro
/sbin ro
/usr ro
/lib ro
/lib64 ro
/etc ro
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
";

const AGENTS_PROFILE_SOURCE: &str = "\
~/.agents rw
~/.claude rw
~/.codex rw
~/.copilot rw
~/.cache/opencode rw
~/.config/opencode rw
~/.local/share/opencode rw
~/.local/state/opencode rw
~/.bun rw
~/.cargo ro
~/.gitconfig* ro
~/.gitignore* ro
~/.local/bin ro
~/.npm ro
~/.pyenv ro
~/.rustup ro

~/.local hide
~/.cache hide
~/.config hide
";

const BUILTINS: &[(&str, &str)] = &[
    ("builtin:default", DEFAULT_PROFILE_SOURCE),
    ("builtin:deny-sensitive", DENY_SENSITIVE_PROFILE_SOURCE),
    ("builtin:basic", BASIC_PROFILE_SOURCE),
    ("builtin:agents", AGENTS_PROFILE_SOURCE),
];

pub(crate) fn source_for_name(name: &str) -> Option<&'static str> {
    BUILTINS
        .iter()
        .find_map(|(builtin_name, source)| (*builtin_name == name).then_some(*source))
}

pub(crate) fn is_builtin_name(name: &str) -> bool {
    source_for_name(name).is_some()
}

pub(crate) fn builtin_names() -> impl Iterator<Item = &'static str> {
    BUILTINS.iter().map(|(name, _)| *name)
}
