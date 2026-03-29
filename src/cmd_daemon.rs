use anyhow::{Context, Result, bail};
use fs_err as fs;
use std::io::{BufRead, BufReader, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileTypeExt;
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

    loop {
        let (mut stream, _addr) = listener
            .accept()
            .context("failed to accept daemon connection")?;
        let peer = peer_credentials(&stream)?;
        authorize_peer(&peer)?;
        handle_client(&mut stream, peer)?;
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

fn handle_client(stream: &mut UnixStream, peer: PeerCredentials) -> Result<()> {
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
    match request {
        "ping" => stream
            .write_all(b"pong\n")
            .context("failed to write daemon response"),
        "stop" => stream
            .write_all(b"unsupported\n")
            .context("failed to write daemon response"),
        "" => stream
            .write_all(b"error empty-request\n")
            .context("failed to write daemon response"),
        _ => stream
            .write_all(b"error unknown-command\n")
            .context("failed to write daemon response"),
    }
}

use std::os::unix::fs::PermissionsExt;

#[cfg(test)]
mod tests {
    use super::*;

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
}
