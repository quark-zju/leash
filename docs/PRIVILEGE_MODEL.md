# Privilege Model

This document describes how `leash` handles privilege transitions and why.

## Goals

- Keep high-risk operations gated behind root euid checks.
- Drop privileges before running untrusted user commands.
- Make transitions observable in verbose mode.

## Entry Points Requiring Root EUID

- `leash run`
- `leash _rm`
- low-level `_fuse`

These commands fail fast when `euid != 0`.

## Entry Points That Auto-Drop Elevated EUID

When running as a setuid-root binary (`ruid != 0`, `euid == 0`), these commands
drop to the real user before doing any work:

- `leash help`
- `leash profile ...`
- `leash _list`
- `leash _show`
- low-level `_mount`

This keeps read/metadata/update workflows from accidentally executing with root
effective privileges.

## `_suid` Bootstrap

`leash _suid` ensures the current binary is setuid-root:

1. If binary is already `root` + `u+s`, it exits.
2. If caller is not root euid, it reinvokes itself with `sudo`.
3. As root, it runs `chown root:root` and sets the setuid bit.
4. It verifies final metadata before success.

This avoids requiring users to manually run separate `chown`/`chmod` commands.

## Runtime Privilege Flow (`run`)

For `leash run`, the child setup path is:

1. unshare IPC namespace (`unshare(CLONE_NEWIPC)`)
2. adjust fs credentials (`setfsuid/setfsgid`) for FUSE access checks
3. `pivot_root(".", ".")` into jail mount, detach old root, and `chdir`
4. drop to real user via `privileges::drop_to_real_user()`

After step 4, the command executes as the invoking real user.

## Drop Logic (`drop_to_real_user`)

`drop_to_real_user` is intentionally strict:

- It requires current `euid == 0`.
- It requires target real uid to be non-root (`uid != 0`).
- It rejects non-root uid transitions (for example `euid=1000 -> uid=1001`).

Actual syscall sequence:

1. `setgroups([])`
2. `setresgid(gid, gid, gid)`
3. `setresuid(uid, uid, uid)`
4. `prctl(PR_SET_NO_NEW_PRIVS, 1)`

This sets real/effective/saved IDs explicitly and closes obvious privilege-regain paths.

This same drop path is used for `run`: the outer waiter process, pidns reaper, and final worker all set `PR_SET_NO_NEW_PRIVS` before continuing as the invoking real user.

## Temporary Real-Root Escalation

`privileges::with_temporary_real_root` exists for narrow internal cases (currently `_fuse` mount path with `allow_other` handling).

`allow_other` is primarily a root-switch compatibility requirement: the jail root transition is performed while still root, and without `allow_other` a FUSE mount is generally only accessible to the mounting user, which can block root-side path traversal into the jail mount during `run` setup.

Exposure is constrained by runtime path placement and ownership checks: mounts live under `${XDG_RUNTIME_DIR}/leash` (or `/run/user/<uid>/leash` fallback), so other users are blocked by the per-user runtime directory boundary rather than by omitting `allow_other`.

It:

1. captures current uid/gid triplets
2. switches triplets to root
3. runs a closure
4. restores original triplets

If restoration fails, it returns an error.

## Verbose Observability

When `--verbose` is enabled, privilege transitions are logged via `vlog!`, including:

- temporary escalation start/restore points
- drop-to-real-user target IDs
- key credential syscalls

## Non-Goals

`leash` is not a full process sandbox. It does not currently provide:

- seccomp policy isolation
- capability-minimization beyond current uid/gid handling
- network namespace isolation
