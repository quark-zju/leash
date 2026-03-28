# Profile Guide

This document is the single source of truth for profile syntax, size configuration, and the built-in default profile used by `cowjail`.

## Syntax

Profile is line-based and evaluated with first-match-wins.

- Rule format: `pattern action`
- Comment: lines starting with `#`
- Match order: top to bottom, first matched rule is used
- Relative dot rule: `.` resolves to the current working directory at profile load time

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

## Record Size Configuration

You can set record max size via a profile comment directive:

```text
# set max_size = 3gb
```

- Supported units: `b`, `kb`, `mb`, `gb` (case-insensitive)
- Numeric separators: `_` are allowed in numbers (for example `2_048mb`)
- Disable size limit: `none`, `off`, or `unlimited`
- Last `# set max_size = ...` directive in the file takes effect

Default record max size is `2gb` when no directive is provided.

## Built-In Default Profile

When `--profile default` is used, the following built-in profile source is loaded:

```text
/tmp rw
/bin ro
/sbin ro
/usr ro
/lib ro
/lib64 ro
/etc ro
/dev/stdin ro
/dev/stdout ro
/dev/null rw
/dev/urandom ro
/dev/random ro
/home/*/.ssh deny
. cow
```
