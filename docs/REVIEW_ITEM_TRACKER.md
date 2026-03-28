# Review Item Tracker

This document tracks review items raised in discussion and their current disposition.

Status values:

- done: implemented
- planned: accepted for next implementation phase
- documented: intentionally kept as-is, with explicit docs
- deferred: accepted risk, not scheduled now

## Security / Architecture Items

1. FUSE background thread started before privilege drop
- status: done
- note: code and docs now document Linux process-wide credential assumption.

2. Whole binary setuid-root attack surface
- status: documented
- note: current model keeps high-risk entry points gated; helper-binary split is deferred.

3. No seccomp after drop
- status: documented
- note: listed as non-goal in current boundary docs.

4. Record file path injection via record tampering
- status: done
- note: trust boundary documented; replay now also checks ownership constraints before host apply.

5. PID reuse race in FUSE server detection
- status: deferred
- note: low probability race; start_time tuple check not scheduled yet.

6. chroot instead of pivot_root
- status: documented
- note: explicit trade-off recorded; treated as risk reduction, not container isolation.

## Correctness / Runtime Behavior

1. readdir may drop entries when reply buffer is full
- status: done
- note: fixed with buffer-full stop behavior plus regression tests.

2. Record growth from repeated full-file snapshots
- status: documented
- note: limitation and cost explicitly documented; compaction redesign deferred.

3. setattrs beyond truncate not supported
- status: planned
- note: next phase item; see Setattr Plan below.

4. Flush lock and flush semantics discussion
- status: deferred
- note: current framing/checksum approach retained; no immediate redesign scheduled.

## Compatibility / UX

1. hardlink support gaps
- status: documented

2. mmap-heavy workload gaps
- status: documented

3. run troubleshooting discoverability for profile rules
- status: done
- note: run help now points users to profile help.

4. network isolation expectation
- status: documented
- note: explicitly listed as out-of-scope.

## Setattr Plan

Goal: improve behavior for common tools without overhauling metadata model.

### Phase A (recommended minimal step)

- keep truncate path as-is
- return explicit, stable error for unsupported metadata updates
  - prefer EOPNOTSUPP instead of ENOSYS when mode uid gid atime mtime are requested without size
- add tests for chmod and touch style calls to assert current behavior intentionally
- document exact behavior in technical overview and help text

### Phase B (optional incremental support)

- support mtime and atime in COW overlay metadata
- support mode changes in COW overlay for owner-only bits
- persist these metadata deltas into record format
- teach flush replay to apply metadata safely under ownership checks

Phase B should be split into multiple atomic commits because it touches overlay state model, record schema, and replay semantics.
