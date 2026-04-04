# Technical Overview

This document keeps implementation-level details that are intentionally kept
short in `README.md`.

## Scope

`leash2` currently focuses on a single shared mirror-style FUSE filesystem plus
profile-based access control.

Implemented areas:

- host-backed mirror filesystem operations
- `hide` / `ro` / `rw` / `deny` profile semantics
- path-conditional rules with `exe` and `env` predicates
- implicit ancestor visibility for hidden directories that contain allowed
  descendants
- host-visible `flock`
- broker-backed POSIX byte-range `fcntl` locks
- rootless `run` namespace setup with bind mounts and `pivot_root`
- profile reload on `SIGHUP`

Out of scope or incomplete:

- profile-specific per-run FUSE mounts
- full POSIX lock equivalence, especially blocking `F_SETLKW`
- network isolation
- seccomp

## Main Modules

- `src/mirrorfs.rs`: FUSE mirror filesystem, inode/path bookkeeping, host file
  operations, and lock forwarding/projection
- `src/profile.rs`: profile parser and rule evaluator
- `src/access.rs`: policy trait and request model used by FUSE
- `src/mount_plan.rs`: compile a profile into bind/proc mount actions for `run`
- `src/fuse_runtime.rs`: shared runtime directory, mountpoint liveness checks,
  and daemon pid signaling
- `src/userns_run.rs`: rootless namespace setup, mount application, pivot-root,
  PID 1 reaper, and command exec
- `src/cmd_*.rs` + `src/cli.rs`: CLI entrypoints

## Profile Semantics

Rules are evaluated in source order with first-match-wins after conditions are
checked.

Supported actions:

- `rw`
- `ro`
- `deny`
- `hide`

Important details:

- `hide` removes entries from `readdir`, returns `ENOENT` on lookup/stat, and
  rejects same-name creation with a mutation error.
- If a hidden directory has allowed descendants because of a deeper glob rule,
  ancestor directories are implicitly visible so the path remains traversable.
- `.` and relative path patterns are intentionally rejected because the shared
  daemon can reload the profile without a per-command CWD context.
- `exe` and `env` conditions are loaded lazily from `/proc/<pid>` only when a
  path-matching rule actually needs them.

## Mount Plan Rules

Profile rules under `/dev` are converted to bind mounts for exact non-glob
paths when the source exists and is a character device or directory.

Missing `/dev` bind sources are skipped so environments with a reduced `/dev`
layout, such as some `bwrap` setups, remain usable.

`/proc` is mounted inside the child PID namespace after the PID namespace fork.

`/sys` is not mounted specially anymore; access goes through the FUSE mirror
and is controlled by the profile.

## Symlink and Create Semantics

For open-like operations and setattr, policy checks are applied to both the
literal path and the canonicalized host target when the target resolves to a
different path. This prevents an allowed symlink from bypassing a denied
target.

For `mkdir` and file create, an already existing visible target returns
`EEXIST` before mutation denial so host-visible "already exists" behavior is
preserved without exposing hidden entries.

## Locking

The dedicated lock design is documented separately in
[`docs/locking.md`](locking.md).

## Known Trade-Offs

- inode/path maps in `MirrorFs` are long-lived and not aggressively compacted
- `readdir` currently collects child entries before replying
- whole-file lock kind is ambiguous because `fuser` does not expose the lock
  source flag

## See Also

- [`docs/RUNTIME_LAYOUT.md`](RUNTIME_LAYOUT.md)
- [`docs/PRIVILEGE_MODEL.md`](PRIVILEGE_MODEL.md)
- [`docs/TROUBLESHOOTING.md`](TROUBLESHOOTING.md)
- [`docs/locking.md`](locking.md)
