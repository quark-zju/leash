# cowjail

`cowjail` is a Linux filesystem safety layer for untrusted programs and coding agents.

`cowjail` 是一个 Linux 上的文件系统防护层，面向不可信程序和 coding agent。

It combines:

- profile-based filesystem visibility and write policy (`ro` / `rw` / `deny`)
- copy-on-write behavior (writes stay in overlay + record first)
- selective replay (`flush`) to apply only pending writes you accept
- IPC namespace isolation to reduce escapes via host IPC services (for example `systemd-run`)

Out of scope:

- network isolation
- full process/container sandboxing
- cross-platform support (Linux only)

## Quick Usage

Start from the simplest flow (default profile + current directory identity):

```bash
cowjail run -- your-command arg1 arg2  # run inside jail
cowjail flush --dry-run                # review pending changes
cowjail flush                          # apply pending changes to host
```

Use an explicit profile:

```bash
cowjail run --profile default -- your-command        # select jail by profile identity
cowjail flush --profile default --dry-run            # review pending changes for that profile
cowjail flush --profile default                      # apply pending changes for that profile
```

Use named jail management when you want stable explicit identities:

```bash
cowjail add --name agent --profile default           # create/pin explicit jail metadata
cowjail run --name agent -- your-command arg1 arg2   # run in named jail
cowjail flush --name agent --dry-run                 # review pending changes for named jail
cowjail flush --name agent                           # apply pending changes for named jail
cowjail list                                         # list known jails
cowjail rm --name agent                              # remove jail metadata/runtime state
```

## More Docs

- Technical overview: [`docs/TECHNICAL_OVERVIEW.md`](docs/TECHNICAL_OVERVIEW.md)
- Implementation plan and progress: [`docs/IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md)
- E2E smoke test: [`docs/e2e_smoke.py`](docs/e2e_smoke.py)

## License

MIT. See `LICENSE`.
