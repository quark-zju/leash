# Troubleshooting

## `run` fails before the command starts

### `Transport endpoint is not connected`

This usually means the shared FUSE mountpoint is stale after a previous daemon
crash.

`run` should lazily clean stale mounts with `fusermount -u -z`. If it still
fails, manually inspect the shared mountpoint under
`${XDG_RUNTIME_DIR}/leash/mount` or `/run/user/<uid>/leash/mount`.

For manual cleanup and daemon restart during testing, use:

```bash
leash _kill
```

### `pivot_root('.', '.') failed: Invalid argument`

`pivot_root` requires the new root to be a mountpoint in the current mount
namespace. `leash` self-bind mounts the shared FUSE root before `pivot_root`
to satisfy that constraint.

If this error comes back, inspect verbose syscall logs from `run -v` around the
bind mount and pivot sequence.

### `mount proc failed ... EPERM`

Mounting `/proc` must happen in the child that is already inside the new PID
namespace. `leash` does this in the PID namespace init process, not in the
pre-fork supervisor.

If a regression appears here, check whether `/proc` mounting moved back before
the PID namespace fork.

### `/dev/...` bind mount source is missing

Some environments expose a reduced `/dev` tree. `leash` skips missing `/dev`
bind sources, but existing sources that are not a character device or directory
still fail mount-plan validation.

## FUSE/profile debugging

Run with verbose logs:

```bash
leash run -v /path/to/command
leash _fuse -v
```

When `run -v` spawns `_fuse`, the daemon's stdout/stderr go to
`${XDG_RUNTIME_DIR}/leash/fuse.log` or `/run/user/<uid>/leash/fuse.log`
instead of the terminal.

Mounted integration tests can also be run with:

```bash
RUST_LOG=debug cargo test --test integration -- --nocapture
```

## Locking and SQLite

If an agent CLI using SQLite shows lock contention or unexpected busy behavior,
read [`docs/locking.md`](locking.md) first. The current design supports
host-visible non-blocking POSIX byte-range locks, but `F_SETLKW` is still
rejected explicitly.
