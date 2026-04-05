# Tail Event Stream

This document describes the lightweight runtime event stream used by
`leash tail`.

## Goals

- Observe selected high-value FUSE events without enabling broad debug logs.
- Keep mirrorfs request latency stable even when clients are disconnected or
  slow.
- Allow ad-hoc filtering from clients.

## Architecture

`leash _fuse` starts a per-user Unix domain socket server under:

- `${XDG_RUNTIME_DIR}/leash/tail.sock`
- fallback runtime root: `/run/user/<uid>/leash/tail.sock`

The server receives structured events from mirrorfs via an in-process bounded
queue and broadcasts matching events to subscribed clients.

## Event Kinds

Current kinds:

- `lookup-miss`: lookup returns `ENOENT`
- `open-denied`: read/open-style access denied (`open`, `stat/getattr`, `opendir/readdir`)
- `mutation-denied`: mutation denied by policy (`mkdir`, `create`, `write`, `rename`, etc.)
- `lock`: file lock operations (`getlk`/`setlk`, success or failure)

## Client Protocol

After connecting to the Unix socket, client sends one line:

- empty line: subscribe all kinds
- `kinds=lookup-miss,open-denied,mutation-denied,lock`: subscribe selected kinds

Server responds by streaming newline-delimited event lines:

`ts_ms=<epoch_ms> kind=<kind> errno=<errno|- > path=<path|- > detail=<text|- >`

## CLI

`leash tail [--kinds <comma-list>]`

Examples:

- `leash tail`
- `leash tail --kinds lookup-miss,open-denied`
- `leash tail --kinds mutation-denied`
- `leash tail --kinds lock`

## Backpressure Behavior

- Mirrorfs producers enqueue into a bounded channel.
- If the channel is full, new events are dropped.
- Client write errors or disconnects remove that client.

This is intentional: event streaming must never block filesystem operations.
