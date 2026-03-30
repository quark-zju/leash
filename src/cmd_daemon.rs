use anyhow::{Context, Result, bail};
use fs_err as fs;
use std::collections::HashSet;
use std::fs::File;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
#[cfg(not(test))]
use std::thread;

use crate::cli::LowLevelDaemonCommand;
use crate::jail;
use crate::privileges;
use crate::run_env;

#[cfg(not(test))]
const FAN_MARK_FILESYSTEM: libc::c_uint = 0x0000_0100;
#[cfg(not(test))]
const OBSERVE_MASK: u64 =
    libc::FAN_OPEN | libc::FAN_OPEN_EXEC | libc::FAN_ACCESS | libc::FAN_CLOSE_WRITE;

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
    let observer = FilesystemObserver::new()?;
    let host_pidns = pid_namespace_key_for_pid(1)?
        .ok_or_else(|| anyhow::anyhow!("failed to resolve host pid namespace for pid 1"))?;
    mark_common_filesystems(&observer)?;
    observer.spawn_thread(host_pidns)?;
    let mut state = DaemonState {
        sessions: HashSet::new(),
        _observer: observer,
    };

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

fn mark_common_filesystems(observer: &FilesystemObserver) -> Result<()> {
    let mut seen_devices = HashSet::new();
    for path in observed_filesystem_roots() {
        let meta = fs::metadata(&path).with_context(|| {
            format!("failed to stat observed filesystem root {}", path.display())
        })?;
        if !seen_devices.insert(meta.dev()) {
            continue;
        }
        observer.mark_filesystem(&path)?;
        crate::vlog!("daemon: observing filesystem rooted at {}", path.display());
    }
    Ok(())
}

fn observed_filesystem_roots() -> Vec<PathBuf> {
    let mut roots = vec![PathBuf::from("/"), std::env::temp_dir()];
    if let Some(runtime_dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        roots.push(PathBuf::from(runtime_dir));
    }
    roots
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

struct DaemonState {
    sessions: HashSet<NamespaceKey>,
    _observer: FilesystemObserver,
}

#[cfg(test)]
impl Default for DaemonState {
    fn default() -> Self {
        Self {
            sessions: HashSet::new(),
            _observer: FilesystemObserver::new().expect("test observer should initialize"),
        }
    }
}

struct ReceivedRequest {
    request: String,
    received_fd: Option<File>,
}

struct FilesystemObserver {
    #[cfg_attr(test, allow(dead_code))]
    fd: File,
}

impl FilesystemObserver {
    #[cfg(not(test))]
    fn new() -> Result<Self> {
        let fd = unsafe {
            libc::fanotify_init(
                (libc::FAN_CLOEXEC | libc::FAN_CLASS_NOTIF | libc::FAN_NONBLOCK) as libc::c_uint,
                (libc::O_RDONLY | libc::O_LARGEFILE) as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error()).context("fanotify_init failed");
        }
        Ok(Self {
            fd: unsafe { File::from_raw_fd(fd) },
        })
    }

    #[cfg(test)]
    fn new() -> Result<Self> {
        Ok(Self {
            fd: File::open("/dev/null").context("failed to open /dev/null for test observer")?,
        })
    }

    #[cfg(test)]
    fn spawn_thread(&self, _host_pidns: NamespaceKey) -> Result<()> {
        Ok(())
    }

    #[cfg(test)]
    fn mark_filesystem(&self, _path: &Path) -> Result<()> {
        Ok(())
    }

    #[cfg(not(test))]
    fn spawn_thread(&self, host_pidns: NamespaceKey) -> Result<()> {
        let file = self
            .fd
            .try_clone()
            .context("failed to clone fanotify fd for observer thread")?;
        thread::Builder::new()
            .name("leash-fanotify".to_string())
            .spawn(move || observe_events(file, host_pidns))
            .context("failed to spawn fanotify observer thread")?;
        Ok(())
    }

    #[cfg(not(test))]
    fn mark_filesystem(&self, path: &Path) -> Result<()> {
        let path_c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
            .context("filesystem mark path contains interior NUL byte")?;
        let rc = unsafe {
            libc::fanotify_mark(
                self.fd.as_raw_fd(),
                libc::FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
                OBSERVE_MASK,
                libc::AT_FDCWD,
                path_c.as_ptr(),
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| {
                format!(
                    "fanotify_mark(FAN_MARK_FILESYSTEM) failed for {}",
                    path.display()
                )
            });
        }
        Ok(())
    }
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
    let received = recv_request(stream)?;
    let request = received.request.trim();
    crate::vlog!(
        "daemon: request='{}' from pid={} uid={}",
        request,
        peer.pid,
        peer.uid
    );
    let response = handle_request(state, request, peer, received.received_fd);
    stream
        .write_all(response.as_bytes())
        .context("failed to write daemon response")
}

fn handle_request(
    state: &mut DaemonState,
    request: &str,
    peer: PeerCredentials,
    received_fd: Option<File>,
) -> String {
    let mut lines = request.lines();
    let Some(command) = lines.next().map(str::trim) else {
        return "error empty-request\n".to_string();
    };
    match command {
        "ping" => "pong\n".to_string(),
        "register-session" => {
            let Some(_profile_path) = lines.next() else {
                return "error missing-profile-path\n".to_string();
            };
            let Some(namespace_file) = received_fd else {
                return "error missing-mntns-fd\n".to_string();
            };
            if lines.next().is_some() {
                return "error unexpected-arguments\n".to_string();
            }
            match register_session(state, namespace_file) {
                Ok(key) => format!("ok registered {}:{}\n", key.dev, key.ino),
                Err(err) => format!("error {}\n", sanitize_error_text(&err.to_string())),
            }
        }
        "query-session" => {
            if lines.next().is_some() {
                return "error unexpected-arguments\n".to_string();
            }
            match namespace_key_for_pid(peer.pid) {
                Ok(Some(key)) if state.sessions.contains(&key) => {
                    format!("ok session {}:{}\n", key.dev, key.ino)
                }
                Ok(Some(_)) | Ok(None) => "ok missing\n".to_string(),
                Err(err) => format!("error {}\n", sanitize_error_text(&err.to_string())),
            }
        }
        _ => "error unknown-command\n".to_string(),
    }
}

fn register_session(state: &mut DaemonState, namespace_file: File) -> Result<NamespaceKey> {
    let meta = namespace_file
        .metadata()
        .context("failed to stat received mount namespace fd")?;
    let key = NamespaceKey {
        dev: meta.dev(),
        ino: meta.ino(),
    };
    state.sessions.insert(key);
    Ok(key)
}

fn recv_request(stream: &UnixStream) -> Result<ReceivedRequest> {
    let fd = stream.as_raw_fd();
    let mut data = [0u8; 1024];
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr() as *mut libc::c_void,
        iov_len: data.len(),
    };
    let mut control = [0u8; 128];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = control.len();

    let received = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if received < 0 {
        return Err(std::io::Error::last_os_error()).context("recvmsg failed for daemon request");
    }
    if received == 0 {
        bail!("daemon client disconnected before sending request")
    }

    let request = std::str::from_utf8(&data[..received as usize])
        .context("daemon request was not valid UTF-8")?
        .to_string();
    let received_fd = extract_received_fd(&msg);
    Ok(ReceivedRequest {
        request,
        received_fd,
    })
}

fn extract_received_fd(msg: &libc::msghdr) -> Option<File> {
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(msg as *const libc::msghdr as *mut libc::msghdr) };
    while !cmsg.is_null() {
        let header = unsafe { &*cmsg };
        if header.cmsg_level == libc::SOL_SOCKET && header.cmsg_type == libc::SCM_RIGHTS {
            let data_ptr = unsafe { libc::CMSG_DATA(cmsg) as *const libc::c_int };
            let raw_fd = unsafe { *data_ptr };
            return Some(unsafe { File::from_raw_fd(raw_fd) });
        }
        cmsg = unsafe { libc::CMSG_NXTHDR(msg as *const libc::msghdr as *mut libc::msghdr, cmsg) };
    }
    None
}

fn namespace_key_for_pid(pid: libc::pid_t) -> Result<Option<NamespaceKey>> {
    let path = mount_namespace_path_for_pid(pid);
    namespace_key_for_path(&path)
}

fn pid_namespace_key_for_pid(pid: libc::pid_t) -> Result<Option<NamespaceKey>> {
    let path = pid_namespace_path_for_pid(pid);
    namespace_key_for_path(&path)
}

fn namespace_key_for_path(path: &Path) -> Result<Option<NamespaceKey>> {
    let meta = match fs::metadata(&path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(err)
                .with_context(|| format!("failed to stat namespace handle {}", path.display()));
        }
    };
    Ok(Some(NamespaceKey {
        dev: meta.dev(),
        ino: meta.ino(),
    }))
}

fn mount_namespace_path_for_pid(pid: libc::pid_t) -> PathBuf {
    PathBuf::from(format!("/proc/{pid}/ns/mnt"))
}

fn pid_namespace_path_for_pid(pid: libc::pid_t) -> PathBuf {
    PathBuf::from(format!("/proc/{pid}/ns/pid"))
}

#[cfg(not(test))]
fn observe_events(file: File, host_pidns: NamespaceKey) {
    let fd = file.as_raw_fd();
    let mut buffer = [0u8; 8192];
    loop {
        let rc = unsafe { libc::read(fd, buffer.as_mut_ptr() as *mut libc::c_void, buffer.len()) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            if err.raw_os_error() == Some(libc::EAGAIN) {
                thread::sleep(std::time::Duration::from_millis(25));
                continue;
            }
            crate::vlog!("fanotify: read failed: {}", err);
            break;
        }
        if rc == 0 {
            crate::vlog!("fanotify: event stream closed");
            break;
        }

        let mut offset = 0usize;
        let total = rc as usize;
        while offset + std::mem::size_of::<libc::fanotify_event_metadata>() <= total {
            let meta =
                unsafe { &*(buffer[offset..].as_ptr() as *const libc::fanotify_event_metadata) };
            if meta.vers != libc::FANOTIFY_METADATA_VERSION {
                crate::vlog!(
                    "fanotify: metadata version mismatch got={} expected={}",
                    meta.vers,
                    libc::FANOTIFY_METADATA_VERSION
                );
                return;
            }
            if meta.event_len < std::mem::size_of::<libc::fanotify_event_metadata>() as u32 {
                crate::vlog!("fanotify: short event_len={}", meta.event_len);
                break;
            }

            let path = if meta.fd >= 0 {
                describe_event_fd(meta.fd)
            } else {
                "<no-fd>".to_string()
            };
            match pid_namespace_key_for_pid(meta.pid) {
                Ok(Some(pidns)) if pidns != host_pidns => {
                    crate::vlog!(
                        "fanotify: controlled pid={} pidns={}:{} mask={} path={}",
                        meta.pid,
                        pidns.dev,
                        pidns.ino,
                        describe_mask(meta.mask),
                        path
                    );
                }
                Ok(Some(_)) | Ok(None) => {}
                Err(err) => {
                    crate::vlog!(
                        "fanotify: failed to inspect pid namespace for {}: {}",
                        meta.pid,
                        err
                    );
                }
            }
            if meta.fd >= 0 {
                unsafe {
                    libc::close(meta.fd);
                }
            }
            offset += meta.event_len as usize;
        }
    }
}

#[cfg(test)]
fn test_register_request(profile_path: &Path) -> String {
    format!("register-session\n{}", profile_path.display())
}

#[cfg(not(test))]
fn describe_event_fd(fd: libc::c_int) -> String {
    let link = PathBuf::from(format!("/proc/self/fd/{fd}"));
    match fs::read_link(&link) {
        Ok(path) => path.display().to_string(),
        Err(_) => format!("fd:{fd}"),
    }
}

#[cfg(not(test))]
fn describe_mask(mask: u64) -> String {
    let mut parts = Vec::new();
    if mask & libc::FAN_ACCESS != 0 {
        parts.push("access");
    }
    if mask & libc::FAN_OPEN != 0 {
        parts.push("open");
    }
    if mask & libc::FAN_OPEN_EXEC != 0 {
        parts.push("open-exec");
    }
    if mask & libc::FAN_CLOSE_WRITE != 0 {
        parts.push("close-write");
    }
    if mask & libc::FAN_EVENT_ON_CHILD != 0 {
        parts.push("child");
    }
    if mask & libc::FAN_Q_OVERFLOW != 0 {
        parts.push("overflow");
    }
    if parts.is_empty() {
        return format!("0x{mask:x}");
    }
    parts.join(",")
}

fn sanitize_error_text(text: &str) -> String {
    text.chars()
        .map(|ch| if ch.is_ascii_whitespace() { '-' } else { ch })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

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
            pid: unsafe { libc::getpid() },
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
        };
        let temp = tempdir().expect("tempdir");
        let profile_path = temp.path().join("profile");
        fs::write(&profile_path, "/workspace rw\n").expect("write profile");
        let namespace_file = File::open("/proc/self/ns/mnt").expect("open current mntns");
        let register = handle_request(
            &mut state,
            &test_register_request(&profile_path),
            peer,
            Some(namespace_file),
        );
        assert!(register.starts_with("ok registered "));

        let query = handle_request(&mut state, "query-session", peer, None);
        assert!(query.starts_with("ok session "));
    }

    #[test]
    fn query_session_reports_missing_for_unknown_pid_namespace() {
        let mut state = DaemonState::default();
        let peer = PeerCredentials {
            pid: 999_999,
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
        };
        assert_eq!(
            handle_request(&mut state, "query-session", peer, None),
            "ok missing\n"
        );
    }

    #[test]
    fn register_session_requires_mntns_fd() {
        let mut state = DaemonState::default();
        let peer = PeerCredentials {
            pid: unsafe { libc::getpid() },
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
        };
        let temp = tempdir().expect("tempdir");
        let profile_path = temp.path().join("profile");
        fs::write(&profile_path, "/workspace rw\n").expect("write profile");
        assert_eq!(
            handle_request(
                &mut state,
                &test_register_request(&profile_path),
                peer,
                None,
            ),
            "error missing-mntns-fd\n"
        );
    }
}
