# Privilege Model

This document describes the current privilege and namespace transitions in
`leash`.

## Goals

- Keep the long-lived FUSE daemon as an ordinary user process.
- Use rootless namespaces for `run` instead of a setuid helper.
- Drop back to the invoking uid/gid before executing the target command.
- Keep important namespace and mount syscalls visible in verbose logs.

## Command Roles

`leash _fuse`:

- runs as the invoking user
- mounts the shared global FUSE mirror under the per-user runtime directory
- reloads the default profile on `SIGHUP`

`leash run`:

- starts `_fuse` on demand if the shared mount is not alive
- creates new user, mount, IPC, and PID namespaces
- applies bind/proc mounts derived from the current profile
- pivots into the shared FUSE mount
- executes the user command in a worker process while PID 1 remains a child
  reaper

`leash rules show|edit`:

- operates on the default profile file as the invoking user
- `edit` validates the profile before writing it back and signals `_fuse` with
  `SIGHUP`

## User Namespace Mapping

`run` currently writes a single uid/gid map entry:

```text
<uid> <uid> 1
<gid> <gid> 1
```

That keeps the namespace process mapped to the invoking host user instead of
introducing a mapped namespace root uid 0.

Before writing `gid_map`, `run` writes `deny` to `/proc/self/setgroups`.

## Runtime Setup Flow

The supervisor process created by `run` does:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWIPC | CLONE_NEWPID)`
2. write `/proc/self/setgroups`, `uid_map`, and `gid_map`
3. make `/` recursively private in the new mount namespace
4. apply non-`/proc` bind mounts under the shared FUSE root
5. fork the PID namespace init process

The PID namespace init process does:

1. mount `/proc` inside the new PID namespace
2. `pivot_root` into the shared FUSE mount
3. switch to the mapped uid/gid with `setresuid` / `setresgid`
4. `chdir` to the original working directory, or `/` as a fallback
5. set its process name to `leash-init`
6. fork the worker command
7. reap all children and exit with the worker's status

The worker process closes inherited file descriptors `>= 3` before `exec()`.

## Non-Goals

`leash` is not a full process sandbox yet. It currently does not provide:

- a network namespace
- seccomp filtering
- a capability-minimized non-root namespace profile beyond the current uid/gid
  mapping and mount setup
