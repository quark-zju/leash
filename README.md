# cowjail

`cowjail` is a Linux filesystem safety layer for untrusted programs and coding agents.

It combines:

- profile-based filesystem visibility and write policy (`ro` / `rw` / `cow` / `deny` / `hide`)
- copy-on-write behavior (`cow`: writes stay in overlay + record first)
- selective replay (`flush`) to apply only pending writes you accept
- IPC namespace isolation to reduce escapes via host IPC services (for example `systemd-run`)

Out of scope:

- network/container isolation
- non-Linux support

---

`cowjail` 是一个 Linux 文件系统防护层，面向不可信程序和 AI 编码工具。

包含：

- 配置文件控制读写策略（`ro` / `rw` / `cow` / `deny` / `hide`）
- 写隔离（`cow` 写操作先记录，仅在隔离区可见，后可选是否写回真实系统）
- IPC 隔离，防止如 `systemd-run` 逃过文件系统隔离

不包含：

- 网络/容器隔离
- 非 Linux 系统支持

## Usage

### Simple

Use `cowjail run` to run a command. It uses the default profile - only the current directory is writable, and various parts of the filesystem like `~/.ssh` is hidden.

```bash
cowjail run -- your-command arg1 arg2  # run inside jail
```

Changes by the command won't affect the real filesystem directly. Use `cowjail flush` to view and apply changes:

```
cowjail flush --dry-run                # review pending changes
cowjail flush                          # apply pending changes to host
```

Changes are designed to survive reboots. But it's still recommended to flush early to keep changes.

### Custom profile

Create a custom profile file:

```text
# ~/my-profile
/bin ro
/lib ro
/lib64 ro
/usr ro
/etc ro
/tmp rw
/home/*/.ssh deny
. cow
```

`rw` means passthrough write (applies to host immediately), while `cow` means delayed write (visible in jail first, applied by `flush`).
`deny` means path remains visible but access returns permission denied. `hide` means path is hidden as if it does not exist.

```bash
cowjail run --profile ~/my-profile -- your-command   # select jail by profile
cowjail flush --profile ~/my-profile --dry-run       # review pending changes
cowjail flush --profile ~/my-profile                 # apply pending changes
```

### Named jails

Similar to `ip netns`, `cowjail` supports naming the jails:

```bash
cowjail add --name agent --profile default           # assign a name to a jail
cowjail run --name agent -- your-command arg1 arg2   # run in the jail
cowjail run --name agent -- another-command args     # run in the same jail
cowjail flush --name agent --dry-run                 # review pending changes
cowjail flush --name agent                           # apply pending changes
cowjail list                                         # list known jails
cowjail rm --name agent                              # remove jail
```

## More Docs

- Technical overview: [`docs/TECHNICAL_OVERVIEW.md`](docs/TECHNICAL_OVERVIEW.md)
- Troubleshooting: [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md)
- E2E smoke test: [`docs/e2e_smoke.py`](docs/e2e_smoke.py)

## License

MIT. See `LICENSE`.
