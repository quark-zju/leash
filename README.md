# cowjail

`cowjail` is a copy-on-write FUSE filesystem jail for running untrusted programs or coding agents with reduced blast radius.

`cowjail` 是一个基于 FUSE 的 copy-on-write 文件系统隔离层，主要用于运行不可信程序或 coding agent，降低不可修复破坏风险。

## Status

This project is under active development.

## Features

- Profile-based path visibility and access rules (`ro` / `rw` / `deny`)
- First-match-wins rule evaluation via `globset`
- In-memory overlay for write operations (host filesystem is not modified during `run`/`mount` session)
- CBOR framed record log with checksum and per-frame flushed marker
- `flush` replay with compaction and rename-boundary safety
- Optional replay policy override: `flush --profile <profile>`
- `run` supports verbose logs and drops privileges to real uid/gid before executing target command

## Commands

```bash
cowjail run [--profile <profile>] [--record <record_path>] [-v|--verbose] command ...
cowjail mount --profile <profile> --record <record_path> [-v|--verbose] <path>
cowjail flush [--record <record_path>] [--profile <profile>] [--dry-run] [-v|--verbose]
```

- `run`: requires `euid == 0` (for `chroot` path). It mounts a temporary FUSE root, `chroot`s into it, `chdir`s back to original cwd, drops to real uid/gid, then executes the command.
- `mount`: debug mode without `chroot` and command execution.
- `flush`: replays unflushed operations from record to host filesystem.

## Profile Format

Each non-empty line is:

```text
<pattern> <action>
```

Actions:

- `ro`: visible and readable, write-like operations denied
- `rw`: visible and writable in overlay
- `deny`: hidden/inaccessible

Rules are evaluated in order, first match wins. Unmatched paths are hidden.

Special rule pattern:

- `.` means current working directory when loading the profile (resolved to absolute path before recording).

Example:

```text
/bin ro
/lib ro
/lib64 ro
/tmp rw
/etc ro
/var ro
/home/*/.ssh deny
. rw
```

## Flush Replay Policy

If `flush --profile` is provided, that profile is used as replay policy.
Otherwise, `flush` uses the latest normalized profile header stored in the record.
If no profile header exists (older records), replay is permissive fallback.

### Non-`rw` Block Rule (Explicit)

Replay applies an operation only when all relevant paths are `rw` under the effective replay profile:

- `WriteFile { path, .. }`: `path` must be `rw`
- `CreateDir { path }`: `path` must be `rw`
- `RemoveDir { path }`: `path` must be `rw`
- `Truncate { path, .. }`: `path` must be `rw`
- `Rename { from, to }`: both `from` and `to` must be `rw`

Blocked operations are not marked flushed, so they can be retried with a broader profile later.

## Record Format (High Level)

Each frame is:

- `tag: u8` (high bit is flushed marker)
- `len: u64` (little-endian)
- `checksum: u64` (xxhash64 of payload)
- `payload: [u8; len]` (CBOR)

Current tags:

- `0x01`: write operation
- `0x02`: normalized profile header

Reader ignores incomplete/corrupt tail fragments.

## Build

```bash
cargo build
```

## Local Test

```bash
cargo test
```

## End-to-End Smoke Script

A manual smoke test script is provided at `docs/e2e_smoke.py`.

## License

MIT. See `LICENSE`.
