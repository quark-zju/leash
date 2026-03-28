# Runtime Layout

This document explains where jail data lives and how runtime artifacts are created and removed.

## Directory Roots

Persistent roots:

- config root: `~/.config/cowjail`
- state root: `~/.local/state/cowjail`

Runtime root:

- `${XDG_RUNTIME_DIR}/cowjail` when `XDG_RUNTIME_DIR` is set
- fallback: `/run/user/<uid>/cowjail`

Each jail uses one `<name>` directory under both state and runtime roots.

## Per-Jail State Layout

`~/.local/state/cowjail/<name>/`:

- `profile`: normalized resolved profile source
- `record`: append-only operation record (CBOR framed)

Unknown files in state/runtime directories are treated conservatively during `rm` (cleanup refuses broad recursive delete).

## Per-Jail Runtime Layout

`.../cowjail/<name>/`:

- `lock`: runtime lock file for synchronization
- `mount/`: FUSE mountpoint
- `fuse.pid`: PID of background `_fuse` server
- `ipcns` / `mntns`: reserved runtime artifacts; not used for current `run` IPC flow

## Lifecycle by Command

`add`:

- resolves jail identity
- ensures state and runtime skeleton exists
- writes normalized `profile` and initializes `record`

`run`:

- resolves jail identity
- ensures runtime directory and lock
- reuses or starts `_fuse`
- executes command inside jail mount

`flush`:

- reads `record`
- applies pending operations based on replay policy
- marks applied frames flushed

`rm`:

- unmounts runtime mountpoint (`umount2(MNT_DETACH)` path)
- removes known runtime artifacts
- removes runtime dir when clean
- removes known state artifacts and state dir

## Runtime Reuse Rules

`run` reuses existing `_fuse` server when:

- `fuse.pid` exists
- process is alive
- process is still mounted on expected mountpoint

Otherwise, it starts a new `_fuse` server.

## Common Failure Modes

- `EBUSY` when removing `mount/`: lingering mount references or live FUSE process.
- `ENOTCONN` on stale mountpoint traversal: disconnected FUSE endpoint.
- `Permission denied` on cleanup: ownership drift after privileged operations.

Use `cowjail rm -v <name>` for step-by-step cleanup logs.

## Why No Recursive Delete

`rm` intentionally removes only recognized files/dirs. This reduces blast radius and avoids deleting unrelated files accidentally placed under jail directories.
