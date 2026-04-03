# Locking Semantics

This document describes the current `flock` / `fcntl` lock design in `leash2`,
why SQLite compatibility matters, and the known semantic gaps.

## Why SQLite Compatibility Matters

Many coding-agent CLIs keep local state in SQLite databases. That includes
session metadata, tool caches, and indexing state. In practice, the same agent
or helper process may access those database files through the FUSE mount, while
another process on the host accesses the backing path directly.

That means `leash2` cannot treat locks as "mount-local only" if SQLite-backed
tools are expected to work reliably. There must be at least some host-visible
synchronization between processes inside the FUSE mount and processes operating
on the backing files outside the mount.

The current implementation aims to provide that synchronization for two lock
families:

- BSD `flock`
- POSIX byte-range `fcntl` locks

## What SQLite Actually Uses

SQLite's Unix VFS uses POSIX byte-range locks on fixed offsets in the main
database file:

- `PENDING_BYTE = 0x40000000`
- `RESERVED_BYTE = PENDING_BYTE + 1`
- `SHARED_FIRST = PENDING_BYTE + 2`
- `SHARED_SIZE = 510`

The lock transitions are not whole-file `flock` semantics:

- SHARED acquires a read lock on `PENDING_BYTE`, then a read lock on
  `SHARED_FIRST..SHARED_FIRST+SHARED_SIZE-1`, then releases `PENDING_BYTE`.
- RESERVED takes a write lock on `RESERVED_BYTE`.
- EXCLUSIVE takes a write lock on the full SHARED byte range.
- PENDING takes a write lock on `PENDING_BYTE`.

Unlock behavior is also not restricted to exact-range matches:

- SHARED acquisition releases only `PENDING_BYTE`.
- Downgrading from EXCLUSIVE/RESERVED to SHARED releases
  `PENDING_BYTE..RESERVED_BYTE` as a 2-byte range.
- Fully unlocking to NO_LOCK uses `l_start = 0, l_len = 0`, which means
  "unlock to EOF".
- SQLite has an Apple/NFS workaround path that explicitly splits the SHARED
  range into subranges during EXCLUSIVE to SHARED downgrade.

So the FUSE-side POSIX lock model must support interval splitting and merging.
It cannot assume that every unlock request exactly matches a previously locked
range.

### About `F_SETLKW`

For the main database file, stock SQLite mostly uses non-blocking `F_SETLK`.

`F_SETLKW` only appears in a narrow main-db path when SQLite is compiled with
`SQLITE_ENABLE_SETLK_TIMEOUT`, `bBlockOnConnect` is enabled, and the lock
request is exactly a SHARED read lock on the SHARED byte range.

Without `SQLITE_ENABLE_SETLK_TIMEOUT`, SQLite's Unix VFS maps its normal lock
wrapper directly to `F_SETLK`.

This is why `leash2` currently prioritizes correctness for non-blocking
`F_SETLK/F_GETLK/F_UNLCK` and rejects `F_SETLKW` explicitly.

## Current Design

### `flock`

`leash2` requests `FUSE_FLOCK_LOCKS` and forwards whole-file lock requests to
host `flock` on the backing file descriptor.

For `F_GETLK`-style probing on that path, `flock` cannot report an owner PID or
a byte range, so the implementation uses a probe open and reports an
approximate whole-file conflict with `pid = 0`.

### POSIX `fcntl` Range Locks

`leash2` requests `FUSE_POSIX_LOCKS` and handles non-whole-file byte-range
locks in userspace.

The in-memory lock state is maintained per inode:

- each inode has a lock table keyed by FUSE `lock_owner`
- each owner stores a normalized list of byte ranges
- overlapping unlocks may split existing ranges
- adjacent ranges with the same mode are merged
- conflicts are checked against other owners before accepting a new lock
- `F_GETLK` is answered from the in-memory table

After every accepted state change, the inode lock table is flattened into a
host-side projection:

- if any owner holds an exclusive lock over a segment, project that segment as
  `F_WRLCK`
- otherwise, if one or more owners hold shared locks over a segment, project
  that segment as `F_RDLCK`
- adjacent projected segments with the same mode are merged

That projected state is applied to the backing file with POSIX `fcntl` locks by
a dedicated lock-broker process.

### Why A Separate Lock Broker Exists

The main FUSE daemon should not hold projected host `fcntl` locks directly.

POSIX locks are tracked by process and inode. If the daemon process itself held
those locks, then closing any unrelated file descriptor for the same inode in
the daemon could unexpectedly release the process's host locks.

To avoid that, `leash2` forks a broker process that only:

- keeps stable backing-file descriptors open for projected locks
- applies and removes host `fcntl` byte-range locks
- does not participate in normal file I/O

The parent FUSE daemon sends synchronous projection updates to the broker over
a Unix socket.

### Release Cleanup

On `flush` and `release`, the daemon drops the lock state for the corresponding
FUSE `lock_owner` and reapplies the host projection through the broker.

If an inode has no remaining POSIX range locks, the daemon asks the broker to
drop that inode and release the host locks.

## Known Limitations

### `F_SETLKW` Is Not Supported Yet

Blocking POSIX lock requests are rejected with `EINVAL`.

This avoids blocking while holding the filesystem mutex and avoids inventing a
deadlock policy that is not equivalent to the kernel's native POSIX lock
implementation. The tradeoff is that SQLite builds relying on
`SQLITE_ENABLE_SETLK_TIMEOUT` are not fully supported yet.

### Whole-File Lock Kind Is Ambiguous

`fuser` does not expose the FUSE lock-kind flag that distinguishes BSD `flock`
requests from POSIX `fcntl` requests. Because of that, whole-file lock requests
are treated as `flock`-compatible.

This is not fully equivalent to POSIX whole-file `fcntl` locks.

### Host Projection Loses Owner Identity

The broker projects the merged lock state for an inode, not each original
client owner independently. This is enough to create host-visible exclusion,
but it does not preserve the exact kernel-visible owner identity of each FUSE
client on the host side.

Consequences:

- `F_GETLK` reports `pid = 0`
- host-side deadlock detection is not delegated to the kernel
- the implementation must reject or avoid blocking lock semantics instead of
  pretending they are natively equivalent

### Broker Updates Are Not Transactional

Projection updates are applied as a sequence of host `fcntl` operations. If one
operation fails after earlier segments were changed, the broker reports an
error and the parent does not commit the new in-memory state, but the host-side
projection may still have been partially modified.

This is acceptable for the current prototype, but it is not a strong atomicity
guarantee.

### Broker Opens Files Read-Write

The broker currently opens backing files with `read(true).write(true)` before
projecting POSIX locks. That keeps lock upgrades simple, but it can fail on
read-only files even when the requested projection only needs shared locks.

### Only The Current Lock Model Is Synchronized

The design synchronizes advisory `flock` and POSIX range locks. It does not try
to provide mandatory-lock semantics, and it does not make unrelated kernel
state outside those lock APIs coherent.

## Practical Interpretation

The current target is:

- SQLite-style byte-range locking should be visible across the FUSE boundary
  for non-blocking POSIX locks.
- Whole-file `flock` should conflict with host `flock` on the same backing
  file.
- Unsupported lock forms should fail explicitly instead of being silently
  ignored.

The current non-goal is:

- exact kernel-equivalent POSIX lock semantics for every possible application,
  especially blocking locks and whole-file POSIX locks.

