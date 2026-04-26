# Profile Guide

This document is the source of truth for profile syntax and default profile
behavior used by `leash`.

## Managing The Default Profile

`leash` currently manages one default per-user profile file:

- path: `$XDG_CONFIG_HOME/leash/profile`
- fallback: `~/.config/leash/profile`

Commands:

- `leash rules show`
  - prints the current default profile source
  - shows a leading comment describing whether the source came from the
    filesystem or the built-in default
  - expands `%include` content as indented comment lines for easier inspection
- `leash rules edit`
  - edits a temporary copy in `$EDITOR`
  - validates syntax before writing back
  - sends `SIGHUP` to a running `_fuse` daemon so the policy reloads
  - if the edited content is blank after trimming whitespace, removes the user
    profile file and falls back to the built-in default

There is no profile-name selection yet. Built-in fragments exist for inclusion
and inspection through `rules show`, but not as separate named user-facing
rules commands.

## Default Profile

The built-in default profile source is:

```text
%include builtin:deny-sensitive
%include builtin:basic
%include builtin:agents
%include builtin:home-hide
%include builtin:home-git-rw
```

That means the shipped policy is assembled from a few focused fragments:

- `builtin:deny-sensitive`
- `builtin:basic`
- `builtin:agents`
- `builtin:home-hide`
- `builtin:home-git-rw`

The normal way to customize the default policy is:

```bash
leash rules edit
```

## Syntax

Profile files are line-based and evaluated top to bottom with first-match-wins.

- Rule format: `pattern action`
- Conditional rule format: `pattern action when cond[,cond...]`
- Directive format: `%directive ...`
- Comment: lines starting with `#`

Supported directives:

- `%include <name>`
  - includes another source by short name or builtin name
  - missing include files are ignored

Pattern rules:

- absolute paths are supported
- `~` and `~/...` resolve relative to `$HOME`
- glob syntax is supported
  - `*` does not match `/`
  - `**` matches arbitrary directory depth
- relative path syntax such as `.`, `./foo`, or `foo/bar` is intentionally not
  supported

Example:

```text
/tmp rw
/dev/urandom ro
~/.codex rw
~ rw when ancestor-has=.git
~ ro
```

## Actions

- `ro`: readable but not writable
- `rw`: readable and writable
- `deny`: visible, but access fails with `EACCES`
- `hide`: behaves as non-existent for lookups/stat (`ENOENT`) and rejects
  same-name creation with a mutation error

Important behavior:

- hidden entries disappear from `readdir`
- if a deeper visible rule requires traversal through a hidden directory, the
  hidden ancestors become implicitly visible directories
- if no rule matches a path, it is hidden by default

## Conditions

Supported conditions:

- `exe=name[|name...]`
  - matches when the caller executable equals any listed entry
  - bare names are resolved through `$PATH` at parse time
  - absolute paths are accepted as-is
  - relative values and globs are rejected
- `env=VAR`
  - matches when the caller environment contains `VAR`
- `ancestor-has=name`
  - matches when some ancestor directory of the accessed path contains an entry
    named `name`
- `os.id=name`
  - matches when `/etc/os-release` has `ID=name`
  - evaluated at profile load time, not per-access at runtime
  - `/etc/os-release` is loaded lazily and cached once per process

Condition evaluation details:

- all conditions on a rule must match
- conditions are only evaluated after the path glob matches
- caller `exe` and `env` data are loaded lazily from `/proc/<pid>` only when a
  path-matching rule actually needs them
- rules gated by `os.id` are either included or skipped during profile load

## Special Mount-Related Rules

Some profile rules are compiled into namespace mounts during `leash run`.

### `/proc`

- only exact `/proc` is allowed
- action must be `ro`, `rw`, or `hide`
- conditional rules are rejected
- `ro` and `rw` become a procfs mount inside the child PID namespace
- `hide` means no special mount

### `/sys`

- only exact `/sys` is allowed
- action must be `ro`, `rw`, or `hide`
- conditional rules are rejected
- `/sys` is not mounted specially right now; access remains FUSE-controlled

### `/dev`

- rules must use exact paths; no glob syntax
- rules must be unconditional
- `ancestor-has`, `exe`, and `env` conditions are rejected
- `os.id` is resolved at profile load time; matching rules are treated as
  unconditional and non-matching rules are skipped
- actions must be `ro` or `rw`
- existing character-device and directory sources become bind mounts
- missing, symlink, and other non-bindable sources are skipped

### `/tmp`

- an exact unconditional `/tmp ro` or `/tmp rw` rule may become a bind mount
- this fast path is only allowed when no descendant rule conflicts with `/tmp`
- rules that make `/tmp` an implicit visible ancestor also block the fast path
- if the `/tmp` bind mount later fails at runtime, `leash` logs a warning and
  falls back to normal FUSE enforcement for `/tmp`
