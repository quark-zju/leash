# Technical Overview

This document keeps implementation-level details that are intentionally minimized in `README.md`.

## Scope and Boundary

`cowjail` focuses on filesystem-risk reduction:

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

- runtime-only jail state under `${XDG_RUNTIME_DIR}/cowjail/<name>/...` or `/run/user/<uid>/cowjail/<name>/...`
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
- `.git` metadata paths are blocked unless the requesting process is a trusted `git` invocation

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
- Known filesystem compatibility gaps:
  - hardlinks are not supported by the current FUSE layer
  - mmap-heavy workloads may degrade or fail depending on access pattern
  - metadata fidelity is partial compared with a full kernel filesystem stack
  - `/proc` is not fully virtualized; current behavior includes a targeted compatibility shim for `/proc/self` and a hard block on `/proc/thread-self`
  - mount-plan validation errors use normalized line numbers by default and upgrade to `source:line` when `profile.sources` is available

## Lock Files

`cowjail` uses two lock domains:

1. Runtime root lock on `${runtime_root}/.lock`
2. Per-jail runtime lock on `.../<name>/lock`

These protect concurrent runtime creation, `_fuse` reuse-or-start logic, and runtime cleanup.

## See Also

- Runtime paths and lifecycle details: [`docs/RUNTIME_LAYOUT.md`](RUNTIME_LAYOUT.md)
- Privilege transition model: [`docs/PRIVILEGE_MODEL.md`](PRIVILEGE_MODEL.md)
