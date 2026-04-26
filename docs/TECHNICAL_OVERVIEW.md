# Technical Overview

This document keeps implementation-level details that are intentionally kept
short in `README.md`.

## Scope

`leash` currently focuses on a single shared mirror-style FUSE filesystem plus
profile-based access control.

Implemented areas:

- host-backed mirror filesystem operations
- `hide` / `ro` / `rw` / `deny` profile semantics
- path-conditional rules with `exe`, `env`, and load-time `os.id` predicates
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
- `os.id` conditions are resolved from `/etc/os-release` at profile load time,
  so non-matching rules are skipped before runtime evaluation.

## readdir Cache Policy

`MirrorFs::opendir` enables kernel directory-entry caching only when
`Profile::should_cache_readdir(path)` returns `true`.

The cacheability gate is intentionally conservative and models whether directory
results are caller-stable:

- if an applicable caller-conditioned `hide` or `deny` rule can directly affect
  the directory's own visibility decision, caching is disabled
- exception: an implicit-ancestor traversal case can still be cached for the
  exact directory path when all of these hold:
  - an unconditional implicit-ancestor match appears before the first
    unconditional explicit result
  - caller-conditioned visible descendants exist (for example `rw when exe=...`)
  - the first unconditional explicit result at this directory is an exact
    `hide`/`deny` match
- caller-conditioned `hide` rules affecting descendant names also disable
  caching for ancestor directories, because child lists can vary by caller

This allows patterns like `.git` to cache at the `.git` directory itself in the
implicit-visible case, while keeping deeper directories such as `.git/refs`
uncached when stability cannot be guaranteed.

## Mount Plan Rules

Profile rules under `/dev` are converted to bind mounts for exact non-glob
paths when the source exists and is a character device or directory.

Missing `/dev` bind sources are skipped so environments with a reduced `/dev`
layout, such as some `bwrap` setups, remain usable.

PTY paths are special-cased:

- `/dev/pts` is mounted as a fresh `devpts` instance in the run namespace
  instead of being bind-mounted from the host
- `/dev/ptmx` is then bind-mounted from the namespace-local `/dev/pts/ptmx`
- mount-plan ordering is normalized so `/dev/pts` is applied before `/dev/ptmx`

This avoids host/jail PTY wiring mismatches where `stat("/dev/ptmx")` succeeds
but `open("/dev/ptmx")` fails with `ENOENT` because the visible `ptmx` node is
not attached to a usable `devpts` instance for that namespace.

For compatibility in user namespaces, `devpts` mount options use the current
mapped GID first and fall back to an option set without `gid=...` if the kernel
rejects the explicit group mapping.

`/proc` is mounted inside the child PID namespace after the PID namespace fork.

`/sys` is not mounted specially anymore; access goes through the FUSE mirror
and is controlled by the profile.

`/tmp` has a bind-mount fast path when the first exact `/tmp` rule is an
unconditional `ro` or `rw` rule and no other rule conflicts with that mount.

Conflicts include:

- descendant rules such as `/tmp/cache ro`
- glob rules that make `/tmp` an implicit visible ancestor, such as
  `/**/secret.txt ro`

If those conflicts exist, mount-plan construction fails explicitly instead of
silently changing `/tmp` policy semantics.

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
[`docs/LOCKING.md`](LOCKING.md).

## Known Trade-Offs

- inode/path maps in `MirrorFs` are long-lived and not aggressively compacted
- `readdir` currently collects child entries before replying
- whole-file lock kind is ambiguous because `fuser` does not expose the lock
  source flag

## See Also

- [`docs/RULES.md`](RULES.md)
- [`docs/RUNTIME_LAYOUT.md`](RUNTIME_LAYOUT.md)
- [`docs/PRIVILEGE_MODEL.md`](PRIVILEGE_MODEL.md)
- [`docs/TROUBLESHOOTING.md`](TROUBLESHOOTING.md)
- [`docs/LOCKING.md`](LOCKING.md)
