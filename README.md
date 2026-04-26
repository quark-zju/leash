# leash

`leash` is a Linux filesystem safety layer for coding agents. Design goals:

- configurable deny rules for sensitive reads, e.g. `~/.ssh` keys
- safer recovery after accidental code deletion
  - in git repos, working files are writable so you can recover with git; `.git` metadata is writable only via `git`
  - in non-git directories, writes are blocked by default
- default policy favors practical day-to-day use, not a strict guarantee that every deletion scenario is recoverable

`leash` 提供文件系统读写保护，主要面向 AI 编码工具。设计宗旨：

- 可配置地禁止读取敏感文件（如 `~/.ssh` 密钥）
- 误删代码后尽量可恢复
  - 在 git 仓库中，工作区可写，便于用 git 恢复；`.git` 元数据仅允许 `git` 命令写入
  - 在非 git 目录中，默认不可写
- 默认配置侧重“实用可用”，并不严格保证所有误删场景都能恢复

## Quick Start

```bash
cargo install --path .
leash run bash  # or codex, opencode, etc
```

## Rules

Show, test, and edit rules:

```bash
leash rules show                # show rules
leash rules test ~/.ssh/config  # test a path against rules
leash rules edit                # edit rules
```

See [this doc](docs/RULES.md) for the syntax of rules.

## More docs

See `docs/` for more docs.
