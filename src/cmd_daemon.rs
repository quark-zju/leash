use anyhow::{Context, Result, bail};
use fs_err as fs;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use crate::cli::LowLevelDaemonCommand;
use crate::jail;
use crate::privileges;
use crate::run_env;

pub(crate) fn daemon_command(cmd: LowLevelDaemonCommand) -> Result<()> {
    privileges::require_root_euid("leash _daemon")?;
    run_env::set_process_name(c"leashd")?;

    let socket_path = cmd.socket.unwrap_or_else(default_socket_path);
    prepare_socket_parent(&socket_path)?;
    remove_stale_socket(&socket_path)?;

    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("failed to bind daemon socket {}", socket_path.display()))?;
    fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("failed to chmod daemon socket {}", socket_path.display()))?;
    crate::vlog!("daemon: listening on {}", socket_path.display());
    let mut state = DaemonState::default();

    loop {
        let (mut stream, _addr) = listener
            .accept()
            .context("failed to accept daemon connection")?;
        let peer = peer_credentials(&stream)?;
        authorize_peer(&peer)?;
        handle_client(&mut state, &mut stream, peer)?;
    }
}

pub(crate) fn default_socket_path() -> PathBuf {
    jail::runtime_root().join("leashd.sock")
}

fn prepare_socket_parent(socket_path: &Path) -> Result<()> {
    let parent = socket_path.parent().ok_or_else(|| {
        anyhow::anyhow!(
            "daemon socket path has no parent: {}",
            socket_path.display()
        )
    })?;
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create daemon socket parent {}", parent.display()))?;
    privileges::ensure_owned_by_real_user(parent)?;
    Ok(())
}

fn remove_stale_socket(socket_path: &Path) -> Result<()> {
    let meta = match fs::symlink_metadata(socket_path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(err).with_context(|| {
                format!("failed to inspect daemon socket {}", socket_path.display())
            });
        }
    };
    if !meta.file_type().is_socket() {
        bail!(
            "refusing to replace non-socket path at daemon socket location: {}",
            socket_path.display()
        );
    }
    fs::remove_file(socket_path).with_context(|| {
        format!(
            "failed to remove stale daemon socket {}",
            socket_path.display()
        )
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PeerCredentials {
    pid: libc::pid_t,
    uid: libc::uid_t,
    gid: libc::gid_t,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct NamespaceKey {
    dev: u64,
    ino: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RegisteredSession {
    key: NamespaceKey,
    owner_uid: libc::uid_t,
    owner_gid: libc::gid_t,
    namespace_path: PathBuf,
}

#[derive(Debug, Default)]
struct DaemonState {
    sessions: HashMap<NamespaceKey, RegisteredSession>,
}

fn peer_credentials(stream: &UnixStream) -> Result<PeerCredentials> {
    let fd = stream.as_raw_fd();
    let mut creds = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut creds as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("getsockopt(SO_PEERCRED) failed");
    }
    Ok(PeerCredentials {
        pid: creds.pid,
        uid: creds.uid,
        gid: creds.gid,
    })
}

fn authorize_peer(peer: &PeerCredentials) -> Result<()> {
    let allowed_uid = unsafe { libc::getuid() };
    if peer.uid == allowed_uid || peer.uid == 0 {
        return Ok(());
    }
    bail!(
        "daemon connection rejected: peer pid={} uid={} gid={} does not match session uid {}",
        peer.pid,
        peer.uid,
        peer.gid,
        allowed_uid
    )
}

fn handle_client(
    state: &mut DaemonState,
    stream: &mut UnixStream,
    peer: PeerCredentials,
) -> Result<()> {
    let mut request = String::new();
    {
        let mut reader = BufReader::new(
            stream
                .try_clone()
                .context("failed to clone daemon stream")?,
        );
        reader
            .read_line(&mut request)
            .context("failed to read daemon request")?;
    }

    let request = request.trim();
    crate::vlog!(
        "daemon: request='{}' from pid={} uid={}",
        request,
        peer.pid,
        peer.uid
    );
    let response = handle_request_line(state, request, peer);
    stream
        .write_all(response.as_bytes())
        .context("failed to write daemon response")
}

fn handle_request_line(state: &mut DaemonState, request: &str, peer: PeerCredentials) -> String {
    let trimmed = request.trim();
    if trimmed.is_empty() {
        return "error empty-request\n".to_string();
    }

    let mut parts = trimmed.split_whitespace();
    let command = parts.next().unwrap_or_default();
    match command {
        "ping" => "pong\n".to_string(),
        "register-session" => {
            let Some(namespace_path) = parts.next() else {
                return "error missing-namespace-path\n".to_string();
            };
            if parts.next().is_some() {
                return "error unexpected-arguments\n".to_string();
            }
            match register_session(state, Path::new(namespace_path), &peer) {
                Ok(key) => format!("ok registered {}:{}\n", key.dev, key.ino),
                Err(err) => format!("error {}\n", sanitize_error_text(&err.to_string())),
            }
        }
        "query-session" => {
            let Some(namespace_path) = parts.next() else {
                return "error missing-namespace-path\n".to_string();
            };
            if parts.next().is_some() {
                return "error unexpected-arguments\n".to_string();
            }
            match namespace_key_for_path(Path::new(namespace_path)) {
                Ok(key) => {
                    if state.sessions.contains_key(&key) {
                        format!("ok session {}:{}\n", key.dev, key.ino)
                    } else {
                        "ok missing\n".to_string()
                    }
                }
                Err(err) => format!("error {}\n", sanitize_error_text(&err.to_string())),
            }
        }
        _ => "error unknown-command\n".to_string(),
    }
}

fn register_session(
    state: &mut DaemonState,
    namespace_path: &Path,
    peer: &PeerCredentials,
) -> Result<NamespaceKey> {
    let key = namespace_key_for_path(namespace_path)?;
    state.sessions.insert(
        key,
        RegisteredSession {
            key,
            owner_uid: peer.uid,
            owner_gid: peer.gid,
            namespace_path: namespace_path.to_path_buf(),
        },
    );
    Ok(key)
}

fn namespace_key_for_path(path: &Path) -> Result<NamespaceKey> {
    let meta = fs::metadata(path)
        .with_context(|| format!("failed to stat namespace handle {}", path.display()))?;
    Ok(NamespaceKey {
        dev: meta.dev(),
        ino: meta.ino(),
    })
}

fn sanitize_error_text(text: &str) -> String {
    text.chars()
        .map(|ch| if ch.is_ascii_whitespace() { '-' } else { ch })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn default_socket_lives_under_runtime_root() {
        assert!(default_socket_path().ends_with("leashd.sock"));
    }

    #[test]
    fn authorize_peer_accepts_real_uid() {
        let peer = PeerCredentials {
            pid: 1,
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
        };
        authorize_peer(&peer).expect("real uid should be accepted");
    }

    #[test]
    fn request_handler_registers_and_queries_session() {
        let mut state = DaemonState::default();
        let peer = PeerCredentials {
            pid: 123,
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
        };
        let namespace_path = unique_test_path();
        fs::write(&namespace_path, b"placeholder").expect("write namespace placeholder");

        let register = handle_request_line(
            &mut state,
            &format!("register-session {}", namespace_path.display()),
            peer,
        );
        assert!(register.starts_with("ok registered "));

        let query = handle_request_line(
            &mut state,
            &format!("query-session {}", namespace_path.display()),
            peer,
        );
        assert!(query.starts_with("ok session "));

        fs::remove_file(&namespace_path).expect("remove namespace placeholder");
    }

    fn unique_test_path() -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should advance")
            .as_nanos();
        std::env::temp_dir().join(format!("leash-daemon-test-{stamp}"))
    }
}
