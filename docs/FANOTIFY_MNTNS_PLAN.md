# Fanotify + Mount Namespace Plan

This document evaluates replacing the current FUSE-based path filter with a fanotify-based permission daemon, while keeping mount, IPC, and PID namespace isolation.

## Verdict

The direction is viable if we narrow the goal:

- use fanotify for open-time allow/deny decisions on real host inodes
- keep mount namespace shaping so the jailed process only sees the filesystem layout we intentionally expose
- drop `hide` support and treat path denial plus readonly structure as kernel-enforced policy where possible

Under those constraints, fanotify directly fixes the main SQLite lock concern: once the jailed process opens the real underlying file, all `fcntl`/`flock` locking and `mmap` behavior stays on the real inode instead of a FUSE inode.

The biggest design risk is trying to make fanotify replace all current FUSE semantics by itself. It cannot fully do that.

## Why This Helps

Current FUSE pain points:

- advisory locks are taken on FUSE inodes, not necessarily on the host inode seen by another FUSE session
- `mmap` and inode-lifetime behavior are harder to reason about and debug
- correctness depends on userspace inode/path bookkeeping that is easy to get subtly wrong

Fanotify changes the model:

- file access happens on the real filesystem object
- SQLite locking works across sessions because the inode is shared by the kernel VFS path
- rename, `fstat`, and open-fd lifetime semantics are naturally the host filesystem semantics

## Hard Constraints

### 1. Fanotify is not a directory virtualization layer

Fanotify can block opens, but it does not make paths disappear from `readdir`, and it is not a general replacement for lookup-time `ENOENT` behavior.

Implication:

- `deny` on open is easy
- if `hide` is removed from the product, we no longer need fake `ENOENT` behavior
- the mount namespace still needs a curated tree built from bind mounts, tmpfs, procfs, sysfs, and selected device mounts

### 2. Open-time checks are not revocation

Fanotify permission decisions happen at open time. After an fd is granted:

- later policy changes do not revoke that fd
- writes through an already-open fd continue to work
- `mmap` continues to use the granted file handle

This is usually acceptable for `leash`, but it means policies should be treated as session-static.

### 3. PID-only identification is too weak

If the daemon trusts a numeric PID alone, it is vulnerable to races and attribution mistakes.

Required mitigation:

- prefer `FAN_REPORT_PIDFD` if available
- otherwise immediately convert the reported PID to a `pidfd` during event handling and validate namespace membership from `/proc`
- never key long-lived authorization state by bare PID without another stable identity

### 4. The daemon must not police itself

A blocking fanotify daemon can deadlock if its own filesystem activity loops back into the monitored policy path.

Required mitigation:

- exempt the daemon's own process tree from policy decisions
- keep daemon logs, socket state, and runtime files on paths outside monitored trees when possible
- avoid synchronous policy lookups that need filesystem access inside the monitored namespace

### 5. fanotify does not replace mount readonly semantics

If a subtree is readonly, that should still be enforced by readonly bind mounts where possible.

Reason:

- this pushes simple invariants into the kernel
- it reduces fanotify event volume
- it avoids depending on permission events for operations that are better expressed as mount flags

## Recommended Architecture

### 1. Split responsibilities cleanly

Use the mount namespace to define the broad filesystem layout. Use fanotify to decide who may open writable handles.

Recommended mapping:

- `deny`: expose path when needed, but deny opens via fanotify or readonly mounts depending on the rule
- `ro`: expose through readonly bind mount
- `rw`: expose through writable bind mount and allow through fanotify
- `git-rw`: expose through writable bind mount, but gate write opens and sensitive `.git` metadata opens in fanotify

This means the new system is not "fanotify instead of namespaces"; it is "fanotify instead of FUSE mediation", with `deny` as the only negative access rule.

### 2. Create a curated root in a fresh mount namespace

For each `run` session:

- unshare `IPC`, `mount`, and `PID` namespaces as today
- build a minimal root from tmpfs plus bind mounts for allowed paths
- apply readonly bind remounts for `ro`
- mount real `/proc`, `/sys`, `/dev`, `/tmp` only when profile logic allows them
- `pivot_root` into that curated tree

This preserves the good parts of the current namespace model while eliminating the FUSE filesystem.

### 3. Global daemon, per-mount-namespace policy registration

The daemon design is reasonable.

Suggested model:

- one privileged daemon owns one or more fanotify groups
- `leash run` creates a new mount namespace and a small policy manifest for that session
- `leash run` sends the daemon:
  - a namespace handle or joining handle for the new mntns
  - the resolved profile/policy
  - session metadata such as uid, jail name, cwd, and launch pid/pidfd
- daemon installs `FAN_MARK_MNTNS` marks for that namespace
- daemon tracks policy by mount-namespace identity, not by path prefix alone

Key point: the daemon should think in terms of "session namespace" rather than "profile name".

### 4. Socket under XDG runtime dir is the right control plane

Using `${XDG_RUNTIME_DIR}` for a Unix socket is a good fit.

Recommendations:

- use `SO_PEERCRED` on every accepted connection
- require the connecting uid to match the profile/session owner unless caller is root
- pass handles with `SCM_RIGHTS` rather than reconstructing identity from strings when possible
- keep the protocol small: `register-session`, `unregister-session`, `query-session`, `ping`

### 5. Keep session state tied to namespace lifetime

Do not treat session registration as permanent.

Suggested cleanup rules:

- session is removed when all tracked processes in the target pid namespace are gone
- session is removed if the mount namespace handle becomes invalid
- session is removed if daemon observes explicit unregister from the launcher
- stale sessions are garbage-collected on daemon restart

## Event Handling Model

For a permission event, the daemon should evaluate in this order:

1. identify mount namespace and pid/pidfd
2. map event to the registered `leash` session
3. resolve the accessed object to a stable path or file handle representation
4. determine access class: read, write, exec, create-intent, metadata
5. apply profile decision
6. allow or deny immediately

Design notes:

- keep the decision path allocation-light and deterministic
- precompile profile rules at registration time
- cache git repo root checks per mount namespace
- avoid path re-resolution through the target namespace where possible; prefer event metadata that is already tied to the opened object

## Where Serious Problems Still Exist

### loss of `hide`

Dropping `hide` removes a major implementation headache, but it is still a product decision with user-visible consequences:

- denied paths may remain discoverable through `readdir`, error differences, or metadata observations
- profiles that relied on "looks absent" semantics will need to migrate to explicit `deny`
- documentation and defaults need to be updated so this becomes an intentional simplification, not a regression surprise

### rename/create/delete control

Open permissions are straightforward. Full pathname mutation policy is harder.

Plan around this by:

- using mount topology to restrict which directories are even writable
- treating fanotify as the fine-grained gate for write opens, especially for `git-rw`
- not relying on fanotify as the only enforcement point for directory tree mutation

### daemon restart behavior

A crash or restart needs a clear posture.

Recommended default:

- fail closed for registered sessions if the daemon cannot answer permission events
- teach `leash run` to detect daemon loss and tear down affected sessions cleanly

### policy lookup cost on hot paths

Every open may now pay an IPC/policy decision cost in the daemon.

Mitigations:

- push `ro` into mount layout as much as possible
- reserve daemon decisions mainly for ambiguous writable paths and `git-rw`
- benchmark realistic agent workloads before deleting the old FUSE path

## Minimal Migration Strategy

### Phase 0: document target semantics

Before coding, freeze which current guarantees must survive:

- real inode semantics for SQLite, git, and `mmap`
- mount namespace isolation remains mandatory
- `hide` is removed; negative policy is `deny`
- `git-rw` remains supported

### Phase 1: build non-FUSE curated root

Replace the current FUSE root with a mount-tree builder:

- tmpfs root
- readonly and writable bind mounts
- existing `/proc`, `/sys`, `/dev`, `/tmp` special handling migrated here
- no fanotify yet

Success criterion:

- a basic `leash run` works without FUSE for simple `ro`/`rw` profiles

### Phase 2: add daemon and session registration

Implement the daemon and socket protocol:

- privileged daemon start/reuse logic
- session registration keyed by mount namespace
- session teardown and garbage collection

Success criterion:

- daemon can observe a registered namespace and report open events without enforcing policy

### Phase 3: enforce writable-open policy

Start with the smallest useful scope:

- allow readonly opens unconditionally when mount layout already guarantees safety
- gate writable opens under `rw` and `git-rw` trees
- deny `.git` metadata writes except for trusted `git`

Success criterion:

- SQLite tests pass across two concurrent sessions pointing at the same database
- git operations preserve host inode semantics and lock behavior

### Phase 4: remove FUSE fallback only after compatibility tests pass

Do not delete the current implementation until these cases are stable:

- SQLite lock contention across two sessions with different profiles
- `mmap`-heavy tools such as `opencode`, `codex`, and `bun`
- git rename + `fstat` behavior
- multiple concurrent sessions with overlapping path grants
- daemon restart and cleanup flows

## Proposed Work Items

1. Define the new policy split between mount layout and fanotify.
2. Implement a mount-tree builder that can realize `ro` and coarse `rw` without FUSE.
3. Add a privileged daemon with `${XDG_RUNTIME_DIR}/leashd.sock` control plane.
4. Register sessions by mount namespace and authenticate callers with peer credentials.
5. Add permission-event logging first, then enforcement.
6. Implement `git-rw` policy evaluation inside the daemon.
7. Add integration tests for SQLite, git, `mmap`, and multi-session behavior.
8. Retire `_fuse` only after feature and compatibility parity is demonstrated.

## Test Matrix

At minimum, add end-to-end tests for:

- two sessions, same SQLite database, conflicting lock attempts
- one session `rw`, one session `ro`, same database file
- `opencode` and `codex` state directories on real filesystem paths
- `git status`, `git add`, `git commit`, branch switch, and file rename
- `bun` or another `mmap`-heavy tool using `/tmp`
- session teardown with daemon restart in the middle

## Bottom Line

The core idea is sound, and it is a better fit than FUSE for SQLite and `mmap` correctness.

The important adjustment is this: fanotify should become the permission gate for real files inside a curated mount namespace, not the sole mechanism that defines what the filesystem looks like.

If the implementation keeps that boundary clear, this redesign looks promising rather than dangerous.
