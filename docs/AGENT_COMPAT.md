# Agent Compatibility Notes

This document collects practical compatibility notes for real coding-agent workloads. It is not a complete design document. The focus is on concrete behaviors that caused failures during real use and the runtime choices that made them work reliably.

## opencode

`opencode` currently uses `bun`, but may also invoke `node` and `npm`.

### `/tmp` should stay on a real bind mount

`bun` writes temporary files under `/tmp` and performs `mmap`-heavy operations there. This is a poor fit for the current FUSE path, so keeping `/tmp` on a real bind mount improves `bun` compatibility significantly.

### `/proc` should be the real procfs mount

`bun` reads files such as `/proc/self/maps`. In practice it is better to provide a real `/proc` mount instead of trying to emulate these paths through FUSE.

### `/dev/urandom` should be a real device bind mount

`bun` also uses `/dev/urandom`. This is hard to model correctly through the normal FUSE path, so exposing the real device node is the pragmatic choice.

### `~/.npm` should be writable

When `node` or `npm` are used, blocking `~/.npm` can lead to hangs or retry loops. If you want these tools to work normally, allow `~/.npm`.

## codex

### Root switch must preserve unprivileged user namespaces

The `bwrap` sandbox used by `codex` relies on user namespaces. A plain `chroot` setup tends to break unprivileged user-namespace use, so `cowjail` needs the `pivot_root`-based approach here.

### `/proc/self/exe` must work

`codex` needs `/proc/self/exe`. Trying to special-case `/proc/self` through FUSE was not sufficient: `exe` may resolve to a long host filesystem path, but after the root switch the process needs a path that still makes sense inside the jail.

### PTY devices are required

`codex` also needs `/dev/pts` and `/dev/ptmx`. Without them, tool initialization can fail with misleading errors such as being unable to modify `PATH`, even though the real problem is missing PTY support.

## git

### `rename` plus later `fstat` needs stable inode handling

`git` may rename a file and then call `fstat` on an older file descriptor. If the runtime does not preserve the expected inode behavior for that still-open descriptor, the result can degrade into `ENOENT` or other incorrect post-rename behavior. Supporting `git` correctly requires special care around inode and open-file handling across rename.
