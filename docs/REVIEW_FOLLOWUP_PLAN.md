# Review Follow-Up Plan

This plan captures practical follow-up work after external security and correctness review.
It is intentionally scoped to changes that improve safety/correctness without large architecture rewrites.

Detailed item-by-item disposition is tracked in `docs/REVIEW_ITEM_TRACKER.md`.

## Scope Decision

In scope for near-term:

- fix correctness issues with clear user impact and low implementation risk
- document explicit trust assumptions and known limitations
- tighten host-write ownership boundaries during `flush`

Out of scope for now:

- replacing `chroot` with `pivot_root`
- splitting into a separate setuid helper binary
- switching COW core to kernel overlayfs
- adding Landlock mode
- record compaction/rotation redesign

## Priority P0: Correctness

1. [x] Fix `readdir` pagination correctness (`src/cowfs.rs`)
- Handle `reply.add(...) == true` (buffer full), stop and return properly.
- Add regression test with enough directory entries to trigger multiple calls.

2. [x] Keep documenting large-file COW cost
- Large-file write amplification has been a repeated review finding.
- Keep this limitation visible in docs until an on-disk/block-level model exists.

## Priority P1: Safety Hardening (Low-Risk)

1. [x] Add explicit comment around `_fuse` privilege-drop ordering (`src/cmd_fuse.rs`)
- Explain why mount/background-thread-before-drop is currently safe on Linux.
- State that this depends on process-wide credential semantics.

2. [x] Tighten ownership policy for host writes during `flush`
- Before applying write/remove operations to host paths, verify ownership constraints.
- Minimum policy: do not modify files/directories not owned by the invoking real user.
- Document exceptions if specific operations must remain allowed.

3. [x] Clarify record-file trust boundary in docs
- State that record replay trusts per-user state directory ownership/permissions.
- Recommend operational checks when running on shared or unusual filesystem layouts.

## Priority P2: Compatibility Documentation

1. [x] Document unsupported/partial features prominently
- hardlink behavior
- mmap-heavy workload caveats
- metadata limitations (for example, partial `setattr` semantics)

2. [x] Improve user guidance for profile debugging
- In `run` help text, point users to `help profile` for policy troubleshooting.

## Verification Plan

For each implemented item:

1. Add or update targeted tests first when feasible.
2. Run focused test subsets (`src/tests/runtime.rs`, `src/tests/flush.rs`) relevant to changed behavior.
3. Update docs in the same commit as behavior changes.

## Tracking

Suggested execution order:

1. `readdir` correctness fix + test
2. `_fuse` ordering comment + doc sync
3. ownership enforcement in `flush` + tests
4. compatibility/help-text documentation cleanup
