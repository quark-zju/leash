# Technical Overview

This document keeps implementation-level details that are intentionally minimized in `README.md`.

## Scope and Boundary

`leash` focuses on filesystem-risk reduction:

- path visibility filtering via profile rules
- direct host writes for allowed paths
- git-aware write gating via `git-rw`
- IPC namespace isolation to reduce IPC-based bypass paths

Out of scope:

- network namespace isolation
- complete process sandboxing
- non-Linux platforms

## High-Level Architecture

Main components:

- `run`: resolve or select jail, ensure per-jail runtime plus FUSE server, create a fresh IPC namespace for the jailed child, execute command in jail
- `_fuse`: internal long-lived FUSE server entrypoint for a jail runtime
- `profile ...`: edit and inspect reusable profile sources
- `_rm` / `_list` / `_show`: low-level runtime inspection and cleanup
- `_suid`: ensure current binary is setuid-root

Runtime state:

- runtime-only jail state under `${XDG_RUNTIME_DIR}/leash/<name>/...` or `/run/user/<uid>/leash/<name>/...`
- normalized `profile` file and optional `profile.sources` map live beside other runtime artifacts

## Filesystem Model

The FUSE layer is now passthrough-first:

- `ro`: host reads allowed, host writes rejected
- `rw`: host reads and writes allowed
- `git-rw`: host writes allowed only for paths inside a detected git working tree
- `deny`: path remains visible but returns `EACCES`
- `hide`: path behaves as absent

There is no copy-on-write overlay and no deferred replay stage.

## Git-Aware Filtering

`git-rw` relies on a dedicated filter module:

- repo detection walks parent directories looking for a plain `.git/config` layout
- ordinary worktree paths inside a detected repo are writable
- non-repo paths remain read-only
- `.git` metadata paths are read-only by default and writable only for trusted `git` invocations

Trusted `git` checks currently inspect `/proc/<pid>/exe` and allow `.git` metadata access only when that executable resolves to the trusted system `git`.

## Runtime Execution Notes

- `run` does not persist a separate mount namespace handle for jail reuse
- `_fuse` mounts a per-jail FUSE view under the runtime directory
- `run` unshares IPC, mount, and PID namespaces before spawn, then child `pre_exec` applies mount plan plus `pivot_root(".", ".")` into the jail mount
- `_rm` unmounts runtime FUSE mountpoints and removes known runtime artifacts conservatively

## Explicit Trade-Offs and Assumptions

- FUSE privilege transition ordering:
  - `_fuse` mounts, starts background request handling, then drops to the real user
  - this relies on current Linux threading credential semantics
- `pivot_root` root switch without a separate container runtime:
  - `run` uses `pivot_root(".", ".")` followed by `umount2(".", MNT_DETACH)` to make the jail mount the real mount-namespace root
  - this reduces compatibility issues with tools that later create their own namespaces
- Userspace policy enforcement instead of kernel-only mounts:
  - `deny`, `hide`, and `git-rw` all stay in one userspace path
  - this simplifies policy behavior at the cost of some fidelity and performance
- Simple long-lived caches over tighter reclamation:
  - the FUSE inode/path maps and git repo-root cache are kept intentionally simple
  - entries may accumulate or become stale during a long-lived mount, especially across heavy temp-file churn or `git init` after an earlier negative repo lookup
  - the current operational assumption is that these mounts are session-scoped; if they stop behaving well, tear them down and rebuild with `leash _rm '*'`
- `readdir` favors simple whole-directory collection:
  - directory entries are collected into memory before they are streamed back through FUSE
  - this keeps the implementation straightforward, and the current assumption is that extremely large directories are uncommon in the intended agent workloads
- Known filesystem compatibility gaps:
  - hardlinks are not supported by the current FUSE layer
  - mmap-heavy workloads may degrade or fail depending on access pattern
  - metadata fidelity is partial compared with a full kernel filesystem stack
  - `/proc` is not fully virtualized; current behavior includes a targeted compatibility shim for `/proc/self` and a hard block on `/proc/thread-self`
  - mount-plan validation errors use normalized line numbers by default and upgrade to `source:line` when `profile.sources` is available

## fanotify Evaluation

Recent exploration added a fanotify-based daemon, a single global active profile model, pid-namespace filtering, and daemon fail-closed teardown for running pid namespaces.

Those pieces were useful and may be kept even if the execution layer returns to FUSE:

- a global privileged daemon is a good control-plane shape
- a single active profile is simpler than per-session profile registration
- pid-namespace filtering is a good boundary for attributing controlled workloads
- daemon liveness wired into pid-namespace PID 1 gives a clean fail-closed path when the daemon exits

However, fanotify has hard limits as a complete filesystem policy engine.

fanotify is a reasonable fit for observation and some open-time allow/deny decisions, but it is not a good fit for enforcing the full `leash` profile model on its own.

Major limitations discovered during the fanotify design pass:

- open-time permission events are not enough to express full `ro` semantics
- directory tree mutation coverage is incomplete for `ro` enforcement, especially for operations like rename, unlink, mkdir, rmdir, link, symlink, truncate, and metadata-only changes
- `hide` semantics do not map cleanly to fanotify permission decisions; the kernel interface is naturally closer to allow or deny than to making a path behave as absent
- write intent is much easier to observe after the fact than to classify correctly before every possible mutating operation

In practice, this means fanotify cannot safely replace the execution semantics needed for `ro` profiles.

The current conclusion is:

- fanotify can still be useful as an observer, auditor, or limited deny gate
- fanotify is not sufficient as the sole enforcement layer for `leash`
- if `leash` needs complete `ro` behavior across normal file and directory mutations, a filesystem mediation layer such as FUSE remains the more practical direction

So the main design takeaway from this exploration is not "fanotify was a mistake". The better conclusion is:

- keep the improved control-plane ideas
- keep the simplified profile model
- keep daemon fail-closed behavior for supervised workloads
- but do not depend on fanotify alone for final read-only enforcement semantics

## Lock Files

`leash` uses two lock domains:

1. Runtime root lock on `${runtime_root}/.lock`
2. Per-jail runtime lock on `.../<name>/lock`

These protect concurrent runtime creation, `_fuse` reuse-or-start logic, and runtime cleanup.

## See Also

- Runtime paths and lifecycle details: [`docs/RUNTIME_LAYOUT.md`](RUNTIME_LAYOUT.md)
- Privilege transition model: [`docs/PRIVILEGE_MODEL.md`](PRIVILEGE_MODEL.md)
