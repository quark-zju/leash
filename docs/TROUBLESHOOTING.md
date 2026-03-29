# Troubleshooting

## `run` fails with FUSE or permission errors

### `fusermount: option allow_other only allowed if 'user_allow_other' is set in /etc/fuse.conf`

`cowjail` may need `allow_other` for high-level `run` mounts.

Fix:

1. Edit `/etc/fuse.conf` as root.
2. Ensure this line is present and uncommented:

```text
user_allow_other
```

### `failed to spawn child command in jail: Invalid argument (os error 22)`

This is often a follow-on symptom when mount/root-switch access failed earlier.

Run with verbose logging to inspect the step that failed:

```bash
cowjail run -v --profile <profile> -- <command>
```

If `_fuse` starts but fails later, inspect the runtime log:

- `${XDG_RUNTIME_DIR}/cowjail/<derived-name>/fuse.log`
- fallback: `/run/user/<uid>/cowjail/<derived-name>/fuse.log`
- use `cowjail _list` to inspect active runtime names when needed

You can also enable vendored `fuse` crate logs for `_fuse` using:

```bash
COWJAIL_FUSE_LOG=debug cowjail run -v --profile <profile> -- <command>
```

Accepted levels follow `env_logger` filter syntax (for example: `error`, `warn`, `info`, `debug`, `trace`).

## `strace` debugging

When debugging a jailed command with `strace`, place `strace` after `cowjail run --`.

Correct:

```bash
cowjail run -- strace -ff -s 256 -yy -o /tmp/cowjail.strace <command>
```

Avoid this form:

```bash
strace cowjail run -- <command>
```

Why:

- `cowjail run` relies on the binary's setuid-root behavior for mount and root-switch setup.
- Tracing the `cowjail` binary itself changes exec/setuid behavior, so you are no longer observing the normal privileged path.
- In practice this can make failures look unrelated to the real problem because the jail setup is no longer running under the same privilege model.

For runtime crashes involving native modules or `mmap`-heavy tools, useful syscall filters include:

```bash
cowjail run -- strace -ff -s 256 -yy \
  -e trace=openat,statx,readlink,mmap,mprotect,munmap,close \
  -o /tmp/cowjail.strace \
  <command>
```

## `_suid` and setuid behavior

### `_suid` appears successful but privileged operations still fail

The binary may be on a `nosuid` mount.

Check owner/mode:

```bash
ls -l ./target/debug/cowjail
```

Expected: owner `root`, and mode containing `s` on user execute bit (for example `-rwsr-xr-x`).

If your workspace filesystem is mounted with `nosuid`, place the binary on a mount where setuid is honored.

## Semantic E2E checks

For a quick high-level regression pass over `ro`, `rw`, `hide`, `deny`, and `git-rw`, run:

```bash
python3 docs/e2e_semantics.py
```

By default the script:

1. runs `cargo build`
2. uses `cargo metadata` to locate `target/debug/cowjail`
3. runs `cargo run -- _suid` automatically when the binary is not yet usable for `run`

Use `--bin <path>` to point at another binary, `--no-build` to skip the rebuild, or `--no-bootstrap-suid` if you want to manage `_suid` manually.

## `_rm` fails with mount-related errors

### `Device or resource busy (os error 16)`

A FUSE mount may still be active. Retry with verbose logs to see unmount/cleanup steps:

```bash
cowjail _rm -v <name-or-glob>
```

### `Transport endpoint is not connected (os error 107)`

This indicates a stale/disconnected FUSE mountpoint. `cowjail _rm` includes recovery logic; rerun with `-v` for details.
