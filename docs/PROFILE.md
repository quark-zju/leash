# Profile Guide

This document is the source of truth for profile syntax and default profile behavior used by `cowjail`.

## Managing Profiles

- `cowjail profile list`: list profile files under `~/.config/cowjail/profiles`
- `cowjail profile show [name]`: print profile source
  - `name` is optional; default is `default`
  - `name` may also be a readonly builtin such as `builtin:basic`
- `cowjail profile edit [name]`: open profile in `$EDITOR`
  - `name` is optional; default is `default`
  - short names (no `/`) are resolved under `~/.config/cowjail/profiles`
  - names follow the same validation rules as jail names
  - builtin profiles are readonly and cannot be edited
- `cowjail profile rm [name]`: remove profile file
  - `name` is optional; default is `default`
  - short names (no `/`) are resolved under `~/.config/cowjail/profiles`
  - names follow the same validation rules as jail names
  - builtin profiles are readonly and cannot be removed
  - `cowjail profile rm default` removes the user override file and falls back to the built-in default profile

The built-in `default` profile source includes:

```text
%include builtin:deny-sensitive
%include builtin:basic
%include builtin:agents
~ git-rw
```

That means the normal way to extend the shipped default policy is to edit `default` itself when you want a user override:

```bash
cowjail profile edit default
```

You can inspect the shipped fragments with `cowjail profile show builtin:deny-sensitive`, `builtin:basic`, and `builtin:agents`.

## Syntax

Profile is line-based and evaluated with first-match-wins.

- Rule format: `pattern action`
- Directive format: `%directive ...`
- `%include <name>`: inline another profile by short name or `builtin:name`; missing file is ignored
- Comment: lines starting with `#`
- Glob pattern is supported in paths
  - `*` does not match `/`
  - for arbitrary depth (including 0 levels), use `**`
  - example: use `foo/**/.git` instead of `foo/*/.git`
- Match order: top to bottom, first matched rule wins
- Relative rules:
  - `.` resolves to the current working directory at profile load time
  - relative paths like `foo` and `./foo` resolve under the current working directory at profile load time
- Home rule:
  - `~` and `~/...` resolve under `$HOME`

Example:

```text
/bin ro
/usr ro
/tmp rw
. git-rw
```

## Actions

- `ro`: read-only
- `rw`: writable passthrough; writes apply to the host immediately
- `git-rw`: writable only inside detected git working trees; non-repo paths remain read-only
- `deny`: path remains visible, access returns `EACCES`
- `hide`: path behaves as non-existent (`ENOENT`)

`git-rw` also applies special `.git` protection. Normal processes can read `.git` metadata but cannot modify it. Writes are only granted to trusted `git` commands recognized by the FUSE-side filter.

## Automatic Mount Handling

`cowjail` keeps profile syntax simple and applies special mount behavior internally during `run`:

- `/proc`:
  - only exact `/proc` is supported
  - action must be `ro` or `rw`
  - implemented as `procfs` mount in the child mount namespace
- `/sys`:
  - only exact `/sys` is supported
  - action must be `ro` or `rw`
  - implemented as `sysfs` mount in the child mount namespace
- `/dev`:
  - glob is not allowed; use explicit paths
  - for `ro` or `rw` rules that point to a host character device or directory, `cowjail` automatically plans bind mounts in the child mount namespace
  - once a path is auto-promoted to a bind mount root, descendant profile rules under that root are rejected as conflicts
- `/tmp`:
  - exact `/tmp ro` or `/tmp rw` may be planned as a bind mount in the child mount namespace when no other rule mentions `/tmp` and no other glob rule matches it

## Default Profile Resolution

When `--profile default` is used, or `run` and `add` omit `--profile`, `cowjail` resolves profile source in this order:

1. `~/.config/cowjail/profiles/default` when the file exists
2. built-in fallback source when the file is missing

The built-in fallback source is assembled from readonly builtin fragments and ends with `~ git-rw`.
If you want a user override, create or edit `~/.config/cowjail/profiles/default`.

To inspect the currently effective on-disk default profile, use:

```bash
cowjail profile show
```
