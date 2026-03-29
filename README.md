# cowjail

`cowjail` is a Linux filesystem safety layer for untrusted programs and coding agents.

I personally use it to add restrictions to [codex](https://github.com/quark-zju/codex) and [opencode](https://github.com/quark-zju/opencode) — making their file operations visible, isolated, and selectively replayable.

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

## Install

Install from GitHub:

```bash
cargo install --git https://github.com/quark-zju/cowjail cowjail
```

Then bootstrap setuid helper:

```bash
cowjail _suid
```

Shell completion: put this line in your shell rc file:

```bash
source <(cowjail completion)
```

## Usage

### Quick start

Use `cowjail run` to run a command. It uses the built-in `default` profile.

```bash
cowjail run -- codex      # or opencode, bash, ...
```

Changes by the command won't affect the real filesystem directly. Use `cowjail flush` to view and apply changes:

```bash
cowjail flush -n                       # review pending changes
cowjail flush                          # apply pending changes to host
```

Changes are designed to survive reboots. But it's still recommended to flush early to keep changes.

### Custom profile

If a tool needs access to another path, edit `default.local` and add a rule there. For example, to allow writes under `~/Downloads`:

```bash
cowjail profile edit default.local
~/Downloads rw
```

See [`docs/profile.md`](docs/profile.md) for profile syntax and more examples.

### Named jails

Similar to `ip netns`, `cowjail` supports naming the jails:

```bash
cowjail add --name agent --profile default           # assign a name to a jail
cowjail run --name agent -- your-command arg1 arg2   # run in the jail
cowjail run --name agent -- another-command args     # run in the same jail
cowjail flush --name agent -n                        # review pending changes
cowjail flush --name agent                           # apply pending changes
cowjail show agent                                   # show profile + pending write count
cowjail list                                         # list known jails
cowjail rm --name agent                              # remove jail
cowjail rm 'unnamed-*'                               # remove jails by name glob
```

## More Docs

- Technical overview: [`docs/TECHNICAL_OVERVIEW.md`](docs/TECHNICAL_OVERVIEW.md)
- Profile guide (syntax, size config, default profile): [`docs/profile.md`](docs/profile.md)
- Runtime layout: [`docs/RUNTIME_LAYOUT.md`](docs/RUNTIME_LAYOUT.md)
- Privilege model: [`docs/PRIVILEGE_MODEL.md`](docs/PRIVILEGE_MODEL.md)
- Troubleshooting: [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md)
- E2E smoke test: [`docs/e2e_smoke.py`](docs/e2e_smoke.py)

## Known Limitations

- hardlinks are not supported by the current FUSE layer
- mmap-heavy workloads may degrade or fail
- metadata behavior is partial (`setattr` supports truncate, executable-bit mode updates for regular files, and in-memory atime updates; uid/gid and full metadata persistence are not implemented)
- regular-file COW writes currently snapshot full file contents, so large-file rewrite workloads may use high RAM and record space

## License

MIT. See `LICENSE`.
