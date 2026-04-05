# Runtime Layout

This document explains where `leash` keeps config and runtime artifacts.

## Config Root

Default profile path:

- `$XDG_CONFIG_HOME/leash/profile` when `XDG_CONFIG_HOME` is set
- fallback: `~/.config/leash/profile`

If the profile file does not exist, `profile show` and `_fuse` use the built-in
default profile source.

## Runtime Root

Shared runtime root:

- `${XDG_RUNTIME_DIR}/leash` when `XDG_RUNTIME_DIR` is set
- fallback: `/run/user/<uid>/leash`

If `XDG_RUNTIME_DIR` is unset and the fallback `/run/user/<uid>` directory must
be created, `leash` sets that fallback runtime directory to mode `0700`.

## Runtime Files

Under the shared runtime root:

- `mount/`: global FUSE mountpoint
- `fuse.log`: append-only stdout/stderr log for `_fuse` when started by `run -v`
- `fuse.pid`: PID file for the background `_fuse` daemon

The current design intentionally uses one shared per-user FUSE mount, not one
mount per profile.

## Lifecycle

`run`:

- ensures the shared mountpoint exists
- checks whether the mountpoint is already a live `leash` FUSE mount
- lazily unmounts stale disconnected FUSE mounts with `fusermount -u -z`
- starts `_fuse` if the mount is absent
- executes the command in a fresh namespace setup rooted at the shared mount

`_fuse`:

- writes `fuse.pid` on startup
- serves the shared mirror filesystem in the foreground
- removes `fuse.pid` on shutdown

`_kill`:

- sends `SIGTERM` to the daemon recorded in `fuse.pid`
- lazy-unmounts the shared FUSE mountpoint
- removes stale pid files so the next `run` can start a fresh daemon

`profile edit`:

- writes the validated profile back to the default profile file
- sends `SIGHUP` to the PID recorded in `fuse.pid` when a daemon is running

## Common Failure Modes

- `Transport endpoint is not connected`: stale FUSE mountpoint after a daemon
  crash; `run` is expected to clean this up before spawning a new daemon.
- stale `fuse.pid`: the recorded process no longer exists; signaling code drops
  the stale pid file.
