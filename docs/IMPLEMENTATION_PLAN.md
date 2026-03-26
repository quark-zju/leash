# cowjail Implementation Plan

This document replaces the old single-process `run + temporary chroot` plan with a named-jail design.

The new direction is:

- jails have stable names
- a jail can outlive one process
- entering an existing jail should feel closer to `ip netns exec <name> ...`
- named jails should imply stable record file naming
- record state should survive host reboot
- replay should gradually move from "host-side flush only" toward "filesystem can materialize state from record itself"

## Design Judgment

This direction is feasible and materially better for usability.

The strongest part of the proposal is the shift from an almost-anonymous one-shot jail to a named object with lifecycle:

- easier to inspect
- easier to re-enter
- easier to associate with a record file
- easier to debug
- easier to recover after reboot

The main architectural consequence is that `cowjail` stops being only a command runner and becomes a jail manager.

That means the implementation should explicitly manage:

- jail identity
- jail metadata
- jail lifecycle
- namespace entry/exit
- persistent backing state

## Core Model

Each jail has a globally unique name.

Public commands should stay small and high-level:

- `cowjail run [--name <name> | --profile <profile>] command ...`
- `cowjail flush [--name <name> | --profile <profile>] [--dry-run]`
- `cowjail add --name <name> [--profile <profile>]`
- `cowjail rm [--name <name> | --profile <profile>]`
- `cowjail list`

### Jail Name Rules

Explicit jail names should be restricted to a simple portable character set:

- ASCII letters
- ASCII digits
- `.`
- `_`
- `-`

Additional constraints:

- must not be empty
- must not be `.` or `..`
- must not contain `/`

Implementation should use a small hand-written validator rather than a regex dependency.

The prefix `unnamed-` is reserved for auto-generated jail identities:

- explicit creation via `add --name unnamed-...` should be rejected
- selecting an already-existing jail by name may still allow `unnamed-...`
- this keeps internal auto-generated names distinct without blocking later direct inspection or removal

Each named jail should have durable metadata under a stable runtime path plus a durable record path.

Suggested split:

- runtime namespace handle and mount wiring under `/run/cowjail/<name>/`
- durable record and metadata under `~/.local/state/cowjail/` or `~/.cache/cowjail/`

The runtime path can disappear on reboot; the durable state must not.

### Concrete Path Layout

This plan now assumes the following concrete layout.

Persistent state that survives reboot:

- `~/.local/state/cowjail/NAME/profile`
- `~/.local/state/cowjail/NAME/record`

Runtime state under tmpfs:

- `/run/cowjail/NAME/ipcns`
- `/run/cowjail/NAME/mntns`

These are namespace-handle paths, not the final visible filesystem mountpoint inside the jail.

User-managed profile definitions:

- `~/.config/cowjail/profiles/NAME`

Semantics:

- `~/.config/cowjail/profiles/NAME` stores the user-facing profile definition
- `~/.local/state/cowjail/NAME/profile` stores the resolved profile content actually bound to the jail
- the stored jail profile must contain expanded cwd-sensitive paths rather than a symbolic `.` entry
- `record` is the durable write log for that jail

## Namespace Design

The proposal to use a mount namespace is correct.

Recommended behavior:

1. Create a new mount namespace for the jail.
2. Bind-mount a namespace handle into `/run/cowjail/<name>/mntns` so it can be reopened later.
3. Mount the jail FUSE filesystem inside that namespace.
4. Enter the namespace when running commands or attaching debug mounts.

This is analogous to `ip netns`, but for mount namespaces.

### IPC Isolation

Adding IPC isolation is worth doing.

Reason:

- some launchers or helpers may use IPC channels that should not bleed across jail boundaries
- it reduces accidental interaction with host session services
- it makes the jail concept more coherent when reused by multiple commands

Suggested sequence:

- start with mount namespace only
- then add IPC namespace
- evaluate whether PID namespace is needed later

PID namespace is valuable, but it is a larger behavioral change than mount+IPC and does not need to block the named-jail design.

## FUSE Server Lifecycle

The FUSE server should be treated as a long-lived per-jail process.

Key requirements:

- it must not be chrooted
- it should drop privileges after mount
- it should run inside the jail mount namespace (so the mount exists there)

Practical plan:

- `run` spawns an internal server entrypoint via hidden `_fuse`
- the parent sets up namespaces as needed, then execs the FUSE server
- after mount completes, the server drops privileges and loops

Runtime status tracking (no persistent pidfd):

- write `/run/cowjail/NAME/fuse.pid`
- validate liveness by checking `/proc/<pid>/mountinfo` for the jail mountpoint
- if the PID is gone or no longer owns the mount, restart and refresh the pid file

This avoids PID reuse confusion without requiring a persistent supervisor.

## Record and State Design

Named jails imply stable records.

Instead of "new implicit record for each run", use:

- one stable record file per jail name
- one metadata file per jail name

Suggested durable files:

- `state/<name>/record.cjr`
- `state/<name>/profile`
- `state/<name>/meta.json`

Suggested metadata contents:

- jail name
- normalized profile source
- creation time
- last attach time
- record path
- runtime namespace handle path
- status flags

## Reboot Survival

If you want the jail to survive reboot conceptually, split "jail identity" from "live namespace instance".

After reboot:

- the mount namespace handle under `/run` is gone
- the record and profile remain
- `cowjail revive <name>` or `cowjail start <name>` should recreate the namespace and remount the filesystem from durable state

This is where FUSE-internal replay becomes important.

## FUSE Internal Replay

This is the right long-term move.

Today the model is:

- host filesystem visible through profile
- overlay in memory
- write operations appended to record
- separate `flush` replays record to host

For reboot survival, the jail filesystem itself should be able to reconstruct overlay state from record on mount.

That means:

- open record at mount time
- scan valid frames
- build overlay state from unflushed operations
- present reconstructed state immediately inside the FUSE filesystem

This should be treated as "overlay replay", distinct from "host flush replay".

Two replay layers:

1. `record -> overlay`
   Used when mounting or reviving a jail. Does not mutate host filesystem.

2. `record -> host`
   Used by `cowjail flush`. Mutates host filesystem and marks frames flushed.

That split gives you reboot persistence without forcing immediate host writes.

## CLI Direction

The public CLI should optimize for "just use the jail" rather than explicit lifecycle choreography.

Suggested public shape:

```text
cowjail run [--name <name> | --profile <profile>] command ...
cowjail flush [--name <name> | --profile <profile>] [--dry-run]
cowjail add --name <name> [--profile <profile>]
cowjail rm [--name <name> | --profile <profile>]
cowjail list
```

This keeps the common path short:

- `run` ensures the jail exists, ensures the runtime is mounted, then executes inside it
- `flush` resolves the same jail identity and replays its record
- `add/rm/list` are explicit management commands

### Jail Selector Rules

`run`, `flush`, and `rm` should share one selector module with one resolution algorithm.

Proposed rules:

1. `--name <name>`
- Select that jail directly.
- For `run`, create if missing.
- For `rm`, fail if missing.

2. `--profile <profile>` with no `--name`
- Resolve to a deterministic auto-generated jail identity derived from:
  - normalized profile content with cwd already expanded
- `run` creates it if missing.
- `flush` resolves the same identity.
- `rm` resolves the same identity but must not auto-create.

3. Neither `--name` nor `--profile`
- Equivalent to `--profile default`.
- Cwd still participates indirectly through profile expansion, so separate working directories do not accidentally share the same implicit jail when `.` matters.

Auto-generated jails should be clearly distinguishable from user-named jails.

Suggested options:

- a reserved prefix such as `unnamed-<hash>`
- or a metadata flag that marks the jail as generated

The concrete rule for this plan is:

- auto-generated jail names use `unnamed-<hash>`
- the hash input is the expanded profile content, including cwd expansion

### Cwd Resolution Rule

When expanding `.` in a profile and when deriving auto-generated jail identity:

1. Prefer `$PWD` if it exists.
2. Otherwise, use the current directory reported by the Rust standard library.
3. Do not canonicalize through symlink expansion.

This preserves the path spelling the user is actually operating in, which is important both for profile meaning and for derived jail identity.

The prefix is useful for `list`; a metadata flag may still be useful later for richer UX.

### Low-Level Commands

The project should keep a low-level escape hatch for advanced users and debugging, but not expose it in the normal help output.

Suggested hidden commands:

```text
cowjail _fuse --profile <profile> --record <record_path> --pid-path <pid_path> <mountpoint>
cowjail _mount --profile <profile> --record <record_path> <path>
cowjail _flush --record <record_path> [--profile <profile>] [--dry-run]
```

Properties:

- no named-jail state writes
- explicit `--record`
- explicit `--profile` where needed
- intended for debugging, recovery, and expert workflows
- not listed in normal `--help`
- shown only in verbose help such as `-v --help`

This preserves the current debug-oriented power without forcing the main UX to expose lifecycle internals.

## Recommended Implementation Order

## Progress Snapshot

Completed:

- [x] Phase 1 (`1`..`5`) jail identity, selector, and stable record/profile binding
- [x] Phase 2 step `6` namespace runtime directory and named handle paths under `/run/cowjail`
- [x] Phase 2 step `7` enter logic (`setns`) in run execution path
- [x] Phase 2 step `8` move FUSE mount lifecycle into named namespace and runtime mountpoint
- [x] Phase 2 step `9` finish high-level run path on top of persistent runtime server
- [x] Phase 3 step `10` IPC namespace isolation baseline
- [x] Phase 3 step `11` privilege drop path with `setgroups/setgid/setuid/PR_SET_NO_NEW_PRIVS`
- [x] Phase 3 step `12` security boundary documentation update in README
- [x] Phase 4 step `13` record-to-overlay replay pass defined and implemented
- [x] Phase 4 step `14` mount-time overlay reconstruction from record
- [x] Phase 4 step `15` overlay replay kept separate from host flush replay
- [x] Phase 4 step `16` reboot-style recovery scenario tests
- [x] Phase 5 step `17` public `flush` uses selector-based UX
- [x] Phase 5 step `18` hidden low-level `_fuse` / `_mount` / `_flush` commands

### Phase 1: Jail identity and selector model

1. `state: add named jail metadata model`
- Introduce jail name validation and on-disk metadata layout.
- Make jail names globally unique.

2. `selector: implement shared jail resolution module`
- Resolve `--name`, `--profile`, and implicit default consistently.
- Distinguish "resolve or create" from "resolve only".

3. `cli: add add/rm/list commands`
- `add` is explicit creation.
- `rm` uses shared selector logic but never auto-creates.
- `list` surfaces both named and auto-generated jails clearly.

4. `record: bind jail identity to stable record path`
- Replace implicit per-run record with a stable record path derived from jail name.
- Keep existing frame format.

5. `profile: persist normalized profile into jail metadata`
- Remove ambiguity between "profile path" and "actual resolved profile content".

### Phase 2: Named mount namespace lifecycle

6. `ns: create named mount namespace handles under /run/cowjail`
- Add namespace creation and runtime directory conventions.

7. `ns: add enter logic for existing named jail`
- Implement the equivalent of "open handle and setns into it".

8. `mount: move fuse mount lifecycle into named namespace`
- Make mount placement part of jail start rather than part of a single process execution.

9. `cmd: implement high-level run`
- `run` resolves or creates the jail, ensures runtime namespace state exists, and then executes inside it.
- No separate public `start` or `exec` command.

### Phase 3: Isolation refinement

10. `ns: add ipc namespace isolation`
- Keep this separate from mount namespace work.
- Add behavioral tests for isolated IPC.

11. `run: preserve privilege dropping inside named exec path`
- Keep `setgroups([])`, `setgid`, `setuid`, `PR_SET_NO_NEW_PRIVS`.

12. `security: document current isolation boundary`
- Explicitly state that network and broader sandboxing are still out of scope.

### Phase 4: Overlay replay from record

13. `record: define overlay replay pass`
- Formalize record-to-overlay replay semantics.

14. `fuse: reconstruct overlay state from record at mount time`
- Make a newly started jail show prior unflushed writes.

15. `fuse: separate overlay replay from host flush replay`
- Do not mark frames flushed just because overlay replay consumed them.

16. `test: reboot-style recovery scenarios`
- Simulate "write in jail -> process exits -> remount jail -> state still visible".

### Phase 5: Operational polish

17. `flush: switch fully to selector-based UX`
- `flush` should use the same jail selector logic as `run`.
- Public `flush` should be high-level and state-aware.

18. `debug: preserve hidden _fuse, _mount and _flush commands`
- Keep low-level commands for recovery and advanced debugging.
- Do not write named-jail metadata from these code paths.

## Key Risks

### 1. Mount namespace handle management

The `/run` handle approach is sound, but cleanup must be explicit.

Questions to settle:

- what command owns namespace creation
- what command remounts after reboot
- how to detect stale runtime handles

### 2. Stable single record per jail

One stable record file is good for ergonomics, but it increases pressure on:

- compaction
- recovery time on mount
- concurrent writer/flush coordination

Long term, you may want:

- a compacted snapshot file
- plus an append-only active log

But this does not need to block the first named-jail version.

### 3. Overlay replay correctness

Once the filesystem rehydrates from record, replay bugs become mount-time bugs, not just flush-time bugs.

That raises the bar for:

- ordering
- rename boundaries
- symlink behavior
- type transitions

### 4. Root and setns behavior

Entering existing mount namespaces and mounting FUSE in them will likely tighten privilege requirements further.

This should be designed deliberately instead of accreting special cases.

## Definition of Done for This New Direction

Version 1 of the named-jail design is done when:

- a jail has a stable name and stable metadata
- a jail can be started, re-entered, and flushed by name
- the default record file is derived from jail identity, not per-run randomness
- mount namespace state can be recreated after reboot
- unflushed record state can be reconstructed into the FUSE overlay on jail start
- `flush` remains explicit for host filesystem mutation

## Non-Goals for This Plan

These are intentionally out of scope for now:

- network namespace support
- non-Linux platforms
- full process sandboxing
- seccomp/capability micro-hardening beyond the existing exec path
