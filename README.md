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
leash run bash  # or codex, opencode, etc
```

## Profiles

[Profile](docs/PROFILE.md) decides what paths can be accessed.

```bash
leash profile show  # show rules
leash profile edit  # edit rules
```

## More docs

See `docs/` for more docs.
