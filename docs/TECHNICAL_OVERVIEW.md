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

- `run`: resolve/select jail, ensure per-jail runtime + FUSE server, join server IPC namespace, execute command in jail
- `_fuse` (hidden): internal long-lived FUSE server entrypoint for a jail runtime
- `flush`: replay pending record operations onto host filesystem
- `add` / `rm` / `list`: named jail lifecycle
- `_suid` (hidden): ensure current binary is setuid-root (self-reexec via `sudo` when needed)

State layout:

- persistent state: `~/.local/state/cowjail/<NAME>/...`
- runtime state: `${XDG_RUNTIME_DIR}/cowjail/<NAME>/...` if `XDG_RUNTIME_DIR` exists, otherwise `/run/user/<uid>/cowjail/<NAME>/...`

## Record Model

Record is CBOR-framed append-only log with:

- tag byte
- payload length
- checksum
- payload

Write operations are appended during FUSE activity and marked flushed when host replay succeeds.
Reader uses best-effort behavior for incomplete/corrupt tail fragments.

## Replay Layers

There are two replay paths:

1. `record -> overlay` (mount-time)
- used by `_fuse` startup
- reconstructs in-memory overlay from unflushed write frames
- does not mutate host filesystem

2. `record -> host` (flush-time)
- used by public `flush` / hidden `_flush`
- applies operations to host filesystem if allowed by replay policy
- marks successfully handled frames as flushed

## Profiles

Profile lines are `pattern action` with first-match-wins.

Actions:

- `ro`
- `rw` (writable passthrough; applies to host immediately)
- `cow` (writable copy-on-write; captured and applied by `flush`)
- `deny` (visible but blocked with `EACCES`)
- `hide` (hidden with `ENOENT`)

`.` resolves relative to current working directory at profile load time.

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
- `run` joins the FUSE server IPC namespace (`setns(CLONE_NEWIPC)`), then `chroot`s to that mount, then drops privileges to the real user.
- `rm` unmounts runtime FUSE mountpoints and removes known runtime/state artifacts conservatively.
