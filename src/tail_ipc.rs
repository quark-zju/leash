use std::collections::HashSet;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use log::warn;

use crate::fuse_runtime;

const EVENT_CHANNEL_CAPACITY: usize = 4096;
const CLIENT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);
const DISPATCH_POLL_TIMEOUT: Duration = Duration::from_millis(200);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventKind {
    LookupMiss,
    OpenDenied,
    MutationDenied,
    Lock,
}

impl EventKind {
    pub fn as_token(self) -> &'static str {
        match self {
            Self::LookupMiss => "lookup-miss",
            Self::OpenDenied => "open-denied",
            Self::MutationDenied => "mutation-denied",
            Self::Lock => "lock",
        }
    }

    pub fn parse_token(raw: &str) -> Option<Self> {
        match raw {
            "lookup-miss" => Some(Self::LookupMiss),
            "open-denied" => Some(Self::OpenDenied),
            "mutation-denied" => Some(Self::MutationDenied),
            "lock" => Some(Self::Lock),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Event {
    pub kind: EventKind,
    pub path: Option<PathBuf>,
    pub errno: Option<i32>,
    pub detail: Option<String>,
}

#[derive(Clone)]
pub struct Sink {
    tx: SyncSender<Event>,
}

impl Sink {
    pub fn emit(&self, event: Event) {
        let _ = self.tx.try_send(event);
    }
}

pub struct ServerGuard {
    _join: thread::JoinHandle<()>,
    socket_path: PathBuf,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

pub fn start_global_server() -> Result<(Sink, ServerGuard)> {
    let socket_path = fuse_runtime::global_tail_socket_path()?;
    start_server_at(&socket_path)
}

fn start_server_at(socket_path: &Path) -> Result<(Sink, ServerGuard)> {
    match std::fs::remove_file(socket_path) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(err)
                .with_context(|| format!("failed to remove stale {}", socket_path.display()));
        }
    }

    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("failed to bind {}", socket_path.display()))?;
    let (tx, rx) = mpsc::sync_channel(EVENT_CHANNEL_CAPACITY);
    let join = thread::Builder::new()
        .name("leash-tail-server".to_owned())
        .spawn(move || run_server(listener, rx))
        .context("failed to spawn tail server thread")?;
    Ok((
        Sink { tx },
        ServerGuard {
            _join: join,
            socket_path: socket_path.to_path_buf(),
        },
    ))
}

fn run_server(listener: UnixListener, rx: Receiver<Event>) {
    if let Err(err) = listener.set_nonblocking(true) {
        warn!("tail server failed to set listener nonblocking: {err}");
        return;
    }
    let mut clients: Vec<Client> = Vec::new();
    loop {
        accept_clients(&listener, &mut clients);
        match rx.recv_timeout(DISPATCH_POLL_TIMEOUT) {
            Ok(event) => {
                dispatch_event(&event, &mut clients);
                for event in rx.try_iter() {
                    dispatch_event(&event, &mut clients);
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
}

fn accept_clients(listener: &UnixListener, clients: &mut Vec<Client>) {
    loop {
        match listener.accept() {
            Ok((mut stream, _addr)) => {
                if let Err(err) = stream.set_write_timeout(Some(CLIENT_HANDSHAKE_TIMEOUT)) {
                    warn!("tail client setup failed: {err}");
                    continue;
                }
                match read_filter(&mut stream) {
                    Ok(filter) => clients.push(Client { stream, filter }),
                    Err(err) => warn!("tail client handshake failed: {err}"),
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(err) => {
                warn!("tail listener accept failed: {err}");
                break;
            }
        }
    }
}

fn read_filter(stream: &mut UnixStream) -> Result<Filter> {
    stream
        .set_read_timeout(Some(CLIENT_HANDSHAKE_TIMEOUT))
        .context("failed to set tail client read timeout")?;
    let mut line = String::new();
    let mut reader = BufReader::new(stream.try_clone().context("failed to clone tail stream")?);
    let _ = reader
        .read_line(&mut line)
        .context("failed to read tail filter line")?;
    parse_filter(line.trim())
}

fn parse_filter(input: &str) -> Result<Filter> {
    if input.is_empty() {
        return Ok(Filter::all());
    }
    let Some(rest) = input.strip_prefix("kinds=") else {
        anyhow::bail!("expected empty line or kinds=...");
    };
    let mut kinds = HashSet::new();
    for raw in rest.split(',') {
        let token = raw.trim();
        if token.is_empty() {
            continue;
        }
        let kind = EventKind::parse_token(token)
            .ok_or_else(|| anyhow::anyhow!("unknown event kind: {token}"))?;
        kinds.insert(kind);
    }
    Ok(Filter { kinds })
}

fn dispatch_event(event: &Event, clients: &mut Vec<Client>) {
    let line = format_event_line(event);
    clients.retain_mut(|client| {
        if !client.filter.matches(event.kind) {
            return true;
        }
        client.stream.write_all(line.as_bytes()).is_ok()
    });
}

fn format_event_line(event: &Event) -> String {
    let ts_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let path = event
        .path
        .as_ref()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "-".to_owned());
    let errno = event
        .errno
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-".to_owned());
    let detail = event.detail.as_deref().unwrap_or("-");
    format!(
        "ts_ms={ts_ms} kind={} errno={errno} path={path} detail={detail}\n",
        event.kind.as_token()
    )
}

struct Client {
    stream: UnixStream,
    filter: Filter,
}

#[derive(Clone)]
struct Filter {
    kinds: HashSet<EventKind>,
}

impl Filter {
    fn all() -> Self {
        Self {
            kinds: [
                EventKind::LookupMiss,
                EventKind::OpenDenied,
                EventKind::MutationDenied,
                EventKind::Lock,
            ]
            .into_iter()
            .collect(),
        }
    }

    fn matches(&self, kind: EventKind) -> bool {
        self.kinds.contains(&kind)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_filter_supports_empty_and_kinds_list() {
        let all = parse_filter("").expect("empty filter");
        assert!(all.matches(EventKind::LookupMiss));
        assert!(all.matches(EventKind::OpenDenied));
        assert!(all.matches(EventKind::MutationDenied));
        assert!(all.matches(EventKind::Lock));

        let filtered = parse_filter("kinds=lookup-miss,lock").expect("kind filter");
        assert!(filtered.matches(EventKind::LookupMiss));
        assert!(!filtered.matches(EventKind::OpenDenied));
        assert!(filtered.matches(EventKind::Lock));
    }
}
