# Technical Overview

This document keeps implementation-level details that are intentionally minimized in `README.md`.

## Scope and Boundary

`cowjail` focuses on filesystem-risk reduction:

- path visibility filtering via profile rules
- copy-on-write overlay for write operations
- record-based replay (`flush`) with selective policy checks
- IPC namespace isolation to reduce IPC-based bypass paths

Out of scope:

- network namespace isolation
- complete process sandboxing (seccomp/capability hardening is limited)
- non-Linux platforms

## High-Level Architecture

Main components:

- `run`: resolve/select jail, ensure per-jail runtime + FUSE server, create a fresh IPC namespace for the jailed child, execute command in jail
- `_fuse` (hidden): internal long-lived FUSE server entrypoint for a jail runtime
- `flush`: replay pending record operations onto host filesystem
- `add` / `rm` / `list`: named jail lifecycle
- `_suid` (hidden): ensure current binary is setuid-root (self-reexec via `sudo` when needed)

State layout:

- persistent state: `~/.local/state/cowjail/<NAME>/...`
- runtime state: `${XDG_RUNTIME_DIR}/cowjail/<NAME>/...` if `XDG_RUNTIME_DIR` exists, otherwise `/run/user/<uid>/cowjail/<NAME>/...`
- profile source map: `state/<name>/profile.sources` (CBOR), mapping normalized rule index back to original `source:path + line` across `%include` expansion

## Record Model

Record is CBOR-framed append-only log with:

- tag byte
- payload length
- checksum
- payload

Write operations are appended during FUSE activity and marked flushed when host replay succeeds.
Reader uses best-effort behavior for incomplete/corrupt tail fragments.

Current write model caveat:

- COW regular-file writes snapshot whole-file content into in-memory overlay and into record frames.
- This favors simple replay semantics over memory/disk efficiency.
- Large-file or high-frequency rewrite workloads can consume substantial RAM and record space during a session.

## Replay Layers

There are two replay paths:

1. `record -> overlay` (mount-time)
- used by `_fuse` startup
- reconstructs in-memory overlay from unflushed write frames
- does not mutate host filesystem

2. `record -> host` (flush-time)
- used by public `flush` / hidden `_flush`
- applies operations to host filesystem if allowed by replay policy
- requires ownership checks against current euid on target paths (or nearest existing parent for create/delete-style ops)
- marks successfully handled frames as flushed

## Profiles

Profile semantics are part of the filesystem policy model (path visibility filtering and write mode decisions).  
For syntax, action semantics, size configuration, and the built-in default profile, see [`docs/profile.md`](profile.md).

## Internal vs Public CLI

Public:

- `run`
- `flush`
- `add`
- `rm`
- `list`
- `help`

Hidden low-level (debug/recovery):

- `_fuse`
- `_mount`
- `_flush`
- `_suid`

These low-level commands are intentionally separate from normal workflow docs.

## Runtime Execution Notes

- `run` does not persist a separate mount namespace handle for jail reuse.
- `_fuse` mounts a per-jail FUSE view under the runtime directory (`.../mount`).
- `run` creates fresh IPC/mount/PID namespaces (`unshare(CLONE_NEWIPC|CLONE_NEWNS|CLONE_NEWPID)`), applies mount plan and `chroot` first, then forks into a minimal PID-namespace init reaper (PID 1) plus worker branch; the worker drops privileges and executes the target command.
- `rm` unmounts runtime FUSE mountpoints and removes known runtime/state artifacts conservatively.

## Explicit Trade-Offs and Assumptions

These are intentional design choices, not accidental omissions.

- FUSE privilege transition ordering:
  - `_fuse` mounts, starts background request handling, then drops to real user.
  - On Linux NPTL, credential changes apply process-wide, so worker threads also lose root credentials after the drop.
  - This ordering is accepted, but relies on current Linux threading credential semantics.
- `chroot` instead of `pivot_root`:
  - `run` uses `chroot` for simpler setup and compatibility with current flow.
  - `cowjail` treats this as risk reduction, not a full container boundary.
  - Privilege drop plus `PR_SET_NO_NEW_PRIVS` are the main post-setup containment controls.
- Userspace COW + record log instead of kernel overlayfs:
  - Primary goal is replayability and auditability of per-operation changes.
  - Profile actions (`deny` and `hide`, in addition to `ro`/`rw`/`cow`) are enforced in one userspace path.
  - overlayfs would improve kernel-level fidelity/performance, but does not provide the same operation-log semantics.
- Record integrity trust model:
  - Replay assumes per-user state directories are owned and writable only by that same user.
  - If an attacker can directly edit `state/<name>/record`, replay trust is already broken.
  - `flush` still gates operations through profile policy checks; this limits but does not eliminate impact of state compromise.
- Known filesystem compatibility gaps:
  - hardlinks are not supported by the current FUSE layer.
  - mmap-heavy workloads may degrade or fail depending on access pattern.
  - metadata fidelity is intentionally limited compared with a full kernel filesystem stack (`setattr` supports `rw` passthrough truncate/chmod/atime/mtime, while `cow` mode only supports truncate + regular-file executable-bit updates and in-memory atime overrides).
  - host-visible atime changes are not a strict replay signal; read-side effects in FUSE/host path traversal can update atime even without `flush`.
  - `/proc` is not fully virtualized. Current behavior includes a targeted compatibility shim: `/proc/self` `readlink` is rewritten to the requesting PID, and `/proc/thread-self` is hard-blocked (`ENOENT`).
  - mount-plan validation errors use normalized line numbers by default, and upgrade to `source:line` when `profile.sources` is available.

## Lock Files

`cowjail` uses three lock domains:

1. Runtime root lock (`${runtime_root}/.lock`)
- Acquired during runtime directory creation.
- Protects concurrent creation/ownership-fix of runtime root and per-jail runtime directories.

2. Per-jail runtime lock (`.../<name>/lock`)
- Acquired before runtime state inspection/mutation and before `_fuse` reuse-or-start logic.
- Protects:
  - runtime skeleton ensure/classify transitions
  - `fuse.pid` read + mount-check + potential new `_fuse` spawn sequence
  - runtime cleanup (`rm`) ordering

3. Record file lock (on `state/<name>/record`)
- Acquired by `flush` replay path.
- Protects frame reads and `mark_flushed` tag updates from interleaving with other flushes.

## See Also

- Runtime paths and lifecycle details: [`docs/RUNTIME_LAYOUT.md`](RUNTIME_LAYOUT.md)
- Privilege transition model: [`docs/PRIVILEGE_MODEL.md`](PRIVILEGE_MODEL.md)
