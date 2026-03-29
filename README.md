# leash

`leash` is a Linux filesystem safety layer for coding agents - keep your AI on a leash.

- blocks reads of sensitive files (like `~/.ssh`, browser profiles, system secrets)
- controls what can be written (`/tmp`, agent state, git working copies)
- protects `.git` metadata so only `git` commands can write it

`leash` 是一个 Linux 文件系统防护层，主要面向 AI 编码工具 (codex, opencode)。

- 阻止读取敏感文件（如 `~/.ssh`、浏览器配置、系统机密）
- 控制可写路径（`/tmp`、agent 状态目录、git 工作区）
- 保护 `.git` 元数据，只允许 `git` 命令写入

## Quick start

```bash
cargo install --git https://github.com/quark-zju/leash leash
leash _suid
leash run codex # or opencode, bash, ...
```

## Profiles

Check which paths are read-only or writable:

```bash
leash profile show
```

Modify your local override (applies on the next `leash run`):

```bash
leash profile edit
```

Profile syntax and details: [`docs/PROFILE.md`](docs/PROFILE.md)

## More docs

- Agent compatibility notes: [`docs/AGENT_COMPAT.md`](docs/AGENT_COMPAT.md)
- Technical overview: [`docs/TECHNICAL_OVERVIEW.md`](docs/TECHNICAL_OVERVIEW.md)
- Profile guide (syntax, actions, default profile): [`docs/PROFILE.md`](docs/PROFILE.md)
- Runtime layout: [`docs/RUNTIME_LAYOUT.md`](docs/RUNTIME_LAYOUT.md)
- Privilege model: [`docs/PRIVILEGE_MODEL.md`](docs/PRIVILEGE_MODEL.md)
- Troubleshooting: [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md)
- Semantic E2E script: [`docs/e2e_semantics.py`](docs/e2e_semantics.py)

## License

MIT. See `LICENSE`.
