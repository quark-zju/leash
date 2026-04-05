# leash

Experimental rewrite of `leash` focused on a single global FUSE mirror filesystem with pluggable access control.

## Current Scope

- `src/mirrorfs.rs`: mirror-style FUSE filesystem backed by the real host filesystem via `fs_err`
- `src/access.rs`: standalone access-control trait and operation model; FUSE does not depend directly on `profile`
- `src/profile.rs`: conditional profile rule engine for future policy integration
- `tests/integration.rs`: custom integration harness that mounts one FUSE instance and runs filesystem-facing tests against the real mount

The intended direction is:

- one global FUSE mount
- one global policy/profile in the future
- per-process-name access decisions instead of multiple mounts with separate profiles

## Implemented In MirrorFs

- mirror read/write behavior on top of a backing directory
- per-request access checks through `AccessController`
- process-name lookup from `/proc/<pid>/comm`
- stable handle behavior across rename
- hardlink support
- `mmap`-relevant file semantics coverage
- host-visible `flock` forwarding
- internal POSIX range-lock table with host `fcntl` projection through a dedicated broker process
- zero TTL for FUSE entry/attr replies to reduce stale kernel-side metadata caching

## Current Limitations

- `src/main.rs` is still a stub; there is no real mount CLI yet
- `F_SETLKW` is intentionally rejected with `EINVAL` to avoid daemon-side blocking and deadlock
- whole-file lock requests are treated as `flock`-compatible because `fuser` does not currently expose the FUSE lock-kind flag
- the codebase still has some `unused`/`dead_code` allowances while the binary entrypoint is unfinished

## Testing

Run everything:

```bash
cargo test -q
```

Run the mounted integration harness only:

```bash
cargo test --test integration -- --nocapture
```

The integration harness:

- creates one top-level temp directory
- creates `backing/` and `mount/` under it
- mounts one background FUSE instance on `mount/`
- creates one subdirectory per logical subtest under both trees
- runs subtests sequentially

## Integration Logging

The integration harness uses `env_logger` and reads `RUST_LOG`.

Common settings:

```bash
RUST_LOG=integration=debug cargo test --test integration -- --nocapture
RUST_LOG=integration=debug,fuser=off cargo test --test integration -- --nocapture
RUST_LOG=debug cargo test --test integration -- --nocapture
```

These are useful when investigating broker projection, lock behavior, and general FUSE request flow.

## Docs

- [docs/TECHNICAL_OVERVIEW.md](docs/TECHNICAL_OVERVIEW.md)
- [docs/PRIVILEGE_MODEL.md](docs/PRIVILEGE_MODEL.md)
- [docs/RUNTIME_LAYOUT.md](docs/RUNTIME_LAYOUT.md)
- [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)
- [docs/LOCKING.md](docs/LOCKING.md)

## Dependencies Used Intentionally

- `fs_err` for host filesystem access
- `fuser` for FUSE
- `anyhow` and `thiserror` for errors
- `log` and `env_logger` for logging
- `tempfile` and `memmap2` for tests

## Near-Term Next Steps

- replace the stub `main` with a real mount CLI
- connect `profile` to `AccessController`
- validate the broker-backed range-lock model against a real SQLite workload
