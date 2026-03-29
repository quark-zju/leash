# Runtime Layout

This document explains where jail data lives after the runtime-only simplification.

## Directory Roots

- Config root: `~/.config/leash`
- Runtime root: `${XDG_RUNTIME_DIR}/leash`
- Fallback runtime root: `/run/user/<uid>/leash`

`leash` no longer keeps persistent jail state under `~/.local/state`. All per-jail state lives under the runtime root and is expected to disappear across reboot or runtime directory cleanup.

## Per-Jail Layout

`.../leash/<name>/`:

- `profile`: normalized resolved profile source
- `profile.sources`: optional CBOR source map for `%include` expansion
- `lock`: runtime lock file for synchronization
- `mount/`: FUSE mountpoint
- `fuse.pid`: PID of background `_fuse` server
- `fuse.log`: background `_fuse` stdout/stderr log
- `ipcns` / `mntns`: reserved runtime artifacts; not used by the current `run` flow

Unknown files in runtime directories are treated conservatively during `rm`.

## Lifecycle by Command

`add`:

- resolves jail identity
- writes normalized `profile` and optional `profile.sources` under the runtime root

`run`:

- resolves jail identity
- ensures runtime directory and lock
- reuses or starts `_fuse`
- executes command inside jail mount

`rm`:

- unmounts runtime mountpoint (`umount2(MNT_DETACH)` path)
- removes known runtime artifacts
- removes runtime dir when clean

## Runtime Reuse Rules

`run` reuses an existing `_fuse` server when:

- `fuse.pid` exists
- the process is alive
- the process is still mounted on the expected mountpoint

Otherwise, it starts a new `_fuse` server.

## Why No Recursive Delete

`rm` intentionally removes only recognized files and directories. This reduces blast radius and avoids deleting unrelated files accidentally placed under a jail runtime directory.
