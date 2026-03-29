# cowjail

`cowjail` is a Linux filesystem safety layer for coding agents.

It combines:

- profile-based filesystem visibility and write policy (`ro` / `rw` / `git-rw` / `deny` / `hide`)
- git-aware writable working trees with `.git` metadata protection
- IPC/PID/MNT namespace isolation to reduce escapes via host IPC services (for example `systemd-run`)

Out of scope:

- network/container isolation
- non-Linux support

`cowjail` 是一个 Linux 文件系统防护层，主要面向 AI 编码工具。

包含：

- 配置文件控制读写策略（`ro` / `rw` / `git-rw` / `deny` / `hide`）
- 针对 git working tree 的可写支持，以及对 `.git` 元数据的额外保护
- IPC/PID/MNT 隔离，减少逃逸如 `systemd-run` 的可能性

不包含：

- 网络/容器隔离
- 非 Linux 系统支持

## Project status

I personally use this project with `codex` and `opencode`.

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
cowjail run codex # or opencode, bash, ...
```

The built-in `default` profile is tuned for coding-agent workflows:

- writes inside detected git working trees are allowed through `git-rw`
- writes under broad user state trees like `~/.config`, `~/.cache`, `~/.local` are still controlled by explicit rules
- writes under agent-specific directories like `~/.codex`, `~/.claude`, `~/.agents` go directly to the host
- writes under `/tmp` go directly to the host

So the default behavior is: keep most of the home directory read-only, allow direct writes where the profile explicitly permits them, and make repository worktrees writable without exposing `.git` metadata to arbitrary processes.

### Custom profile

If a tool needs access to another path, edit your `default` profile override directly. For example, to allow writes under `~/Downloads`:

```bash
cowjail profile edit default
~/Downloads rw
```

The shipped builtin fragments are also inspectable through `cowjail profile show builtin:deny-sensitive`, `builtin:basic`, and `builtin:agents`, but they are read-only.

See [`docs/PROFILE.md`](docs/PROFILE.md) for profile syntax and more examples.

## More Docs

- Agent compatibility notes: [`docs/AGENT_COMPAT.md`](docs/AGENT_COMPAT.md)
- Technical overview: [`docs/TECHNICAL_OVERVIEW.md`](docs/TECHNICAL_OVERVIEW.md)
- Profile guide (syntax, actions, default profile): [`docs/PROFILE.md`](docs/PROFILE.md)
- Runtime layout: [`docs/RUNTIME_LAYOUT.md`](docs/RUNTIME_LAYOUT.md)
- Privilege model: [`docs/PRIVILEGE_MODEL.md`](docs/PRIVILEGE_MODEL.md)
- Troubleshooting: [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md)
- Semantic E2E script: [`docs/e2e_semantics.py`](docs/e2e_semantics.py)

## Known Limitations

- hardlinks are not supported by the current FUSE layer
- mmap-heavy workloads may degrade or fail
- metadata behavior is partial (`setattr` supports truncate and common passthrough metadata updates for regular files; uid/gid persistence is not fully implemented)
- git detection currently focuses on plain `.git/config` repositories; worktree and helper-process handling is intentionally conservative

## License

MIT. See `LICENSE`.
