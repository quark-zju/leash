# leash

`leash` is a Linux filesystem safety layer for coding agents.

- blocks reads of sensitive files such as `~/.ssh` and browser profiles
- controls what can be written, such as `/tmp`, agent state, and git working
  copies
- protects `.git` metadata so normal writes do not silently corrupt a repo

`leash` 主要面向 Codex、OpenCode、Claude Code 等 AI 编码工具。

- 阻止读取敏感文件，如 `~/.ssh`、浏览器配置及部分系统密钥
- 控制写入范围，只允许 `/tmp`、agent 状态目录、git 工作区等路径可写
- 保护 `.git` 元数据，防止普通写入操作意外破坏代码仓库

## Quick Start

```bash
cargo install --path .
leash run bash
```

`leash run ...` 会按需启动一个共享 FUSE daemon，加载默认 profile，然后在
新的 user/mount/pid/ipc namespace 里运行命令。

常用例子：

```bash
leash run bash
leash run codex
leash run opencode
```

## Profiles

查看当前默认 profile：

```bash
leash profile show
```

修改默认 profile：

```bash
leash profile edit
```

`profile show` 会标明当前使用的是文件系统里的 profile，还是 builtin 默认
profile；`profile edit` 保存空白内容时会删除用户 profile 文件并回退到
builtin 默认配置。

Profile 语法和默认规则说明见
[`docs/PROFILE.md`](docs/PROFILE.md)。

## Low-Level Commands

这些命令主要用于调试：

- `leash _fuse`
  - 前台运行共享 FUSE daemon
- `leash _kill`
  - 停掉共享 FUSE daemon，并清理共享 mount

调试 `run -v` 时，`_fuse` 的日志会写到：

- `${XDG_RUNTIME_DIR}/leash/fuse.log`
- 或 fallback 的 `/run/user/<uid>/leash/fuse.log`

## More Docs

- Profile guide: [`docs/PROFILE.md`](docs/PROFILE.md)
- Locking design: [`docs/LOCKING.md`](docs/LOCKING.md)
- Technical overview: [`docs/TECHNICAL_OVERVIEW.md`](docs/TECHNICAL_OVERVIEW.md)
- Runtime layout: [`docs/RUNTIME_LAYOUT.md`](docs/RUNTIME_LAYOUT.md)
- Privilege model: [`docs/PRIVILEGE_MODEL.md`](docs/PRIVILEGE_MODEL.md)
- Troubleshooting: [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md)

## Status

The current codebase already supports:

- one shared per-user FUSE mirror mount
- profile-driven access control
- rootless `run` based on Linux namespaces
- host-visible `flock` and broker-backed POSIX range locks
- profile reload through `SIGHUP`

It is still Linux-only, and compatibility is being tuned against real coding
agent workloads.
