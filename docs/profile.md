# Profile Guide

This document is the single source of truth for profile syntax, size configuration, and default profile behavior used by `cowjail`.

## Managing Profiles

- `cowjail profile list`: list profile files under `~/.config/cowjail/profiles`
- `cowjail profile show [name]`: print profile source
  - `name` is optional; default is `default`
- `cowjail profile edit [name]`: open profile in `$EDITOR`
  - `name` is optional; default is `default`
  - short names (no `/`) are resolved under `~/.config/cowjail/profiles`
  - names follow the same validation rules as jail names
- `cowjail profile rm [name]`: remove profile file
  - `name` is optional; default is `default`
  - short names (no `/`) are resolved under `~/.config/cowjail/profiles`
  - names follow the same validation rules as jail names
  - `cowjail profile rm default` removes the user override file and falls back to the built-in default profile

## Syntax

Profile is line-based and evaluated with first-match-wins.

- Rule format: `pattern action`
- Directive format: `%directive ...`
- `%include <name>`: inline include another profile by short name (no `/`); missing file is ignored
- `%set max_size = <size|none>`: set record max size override
- Comment: lines starting with `#`
- Glob pattern is supported in paths
  - `*` does not match `/`
  - for arbitrary depth (including 0 levels), use `**`
  - example: use `foo/**/.git` instead of `foo/*/.git`
- Match order: top to bottom, first matched rule is used
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
/home/*/.ssh deny
. cow
```

## Actions

- `ro`: read-only
- `rw`: writable passthrough (writes apply to host immediately)
- `cow`: writable copy-on-write (writes are captured first and applied by `flush`)
- `deny`: path remains visible, access returns `EACCES`
- `hide`: path behaves as non-existent (`ENOENT`)

## Automatic Mount Handling

`cowjail` keeps profile syntax simple (`ro/rw/cow/deny/hide`) and applies special mount behavior internally during `run`:

- `/proc`:
  - only exact `/proc` is supported (no glob, no subpaths)
  - action must be `ro` or `rw`
  - implemented as `procfs` mount in the child mount namespace
- `/dev`:
  - glob is not allowed; use explicit paths
  - for `ro`/`rw` rules that point to a host character device or directory, `cowjail` automatically plans bind mounts in the child mount namespace
  - once a path is auto-promoted to bind mount root (for example `/dev/pts`), descendant profile rules under that root are rejected as conflicts

## Record Size Configuration

You can set record max size via a profile directive:

```text
%set max_size = 3gb
```

- Supported units: `b`, `kb`, `mb`, `gb` (case-insensitive)
- Numeric separators: `_` are allowed in numbers (for example `2_048mb`)
- Disable size limit: `none`, `off`, or `unlimited`
- Last `%set max_size = ...` directive in the expanded profile takes effect

Default record max size is `2gb` when no directive is provided.

## Default Profile Resolution

When `--profile default` is used (or `run/add/flush` omit `--profile`), `cowjail` resolves profile source in this order:

1. `~/.config/cowjail/profiles/default` when the file exists
2. built-in fallback source when the file is missing

To inspect the currently effective on-disk default profile, use:

```bash
cowjail profile show
```
