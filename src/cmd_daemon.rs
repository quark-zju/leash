use anyhow::{Context, Result, bail};
use fs_err as fs;
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Write;
use std::os::fd::AsRawFd;
#[cfg(not(test))]
use std::os::fd::FromRawFd;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
#[cfg(not(test))]
use std::thread;

use crate::cli::LowLevelDaemonCommand;
use crate::jail;
use crate::privileges;
use crate::proc_mounts;
#[cfg(test)]
use crate::profile::CompiledProfile;
#[cfg(not(test))]
use crate::profile::{AccessDecision, CompiledProfile, RequestedAccess};
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
    privileges::ensure_owned_by_real_user(&socket_path)?;
    crate::vlog!("daemon: listening on {}", socket_path.display());
    let observer = FilesystemObserver::new()?;
    let host_pidns = pid_namespace_key_for_pid(1)?
        .ok_or_else(|| anyhow::anyhow!("failed to resolve host pid namespace for pid 1"))?;
    let active_profile = Arc::new(RwLock::new(None));
    let observed_mount_points = mark_initial_filesystems(&observer)?;
    observer.spawn_thread(host_pidns, active_profile.clone())?;
    let mut state = DaemonState {
        active_profile,
        host_pidns,
        observer,
        observed_mount_points,
    };

    loop {
        let (mut stream, _addr) = listener
            .accept()
            .context("failed to accept daemon connection")?;
        let peer = peer_credentials(&stream)?;
        authorize_peer(&peer, state.host_pidns)?;
        if handle_client(&mut state, &mut stream, peer)? {
            crate::vlog!("daemon: shutting down");
            break;
        }
    }

    cleanup_socket(&socket_path)?;
    Ok(())
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

fn mark_initial_filesystems(observer: &FilesystemObserver) -> Result<BTreeSet<PathBuf>> {
    let mounts = proc_mounts::read_mount_table()?;
    let roots = default_monitor_mount_points(&mounts)?;
    mark_mount_points(observer, &roots)?;
    Ok(roots.into_iter().collect())
}

fn default_monitor_mount_points(mounts: &[proc_mounts::MountEntry]) -> Result<Vec<PathBuf>> {
    Ok(proc_mounts::mount_points_for_paths(
        mounts,
        &baseline_monitor_paths(),
    ))
}

fn mark_mount_points(observer: &FilesystemObserver, mount_points: &[PathBuf]) -> Result<()> {
    for path in mount_points {
        observer.mark_filesystem(path).with_context(|| {
            format!("failed to start fanotify monitoring for mount {}", path.display())
        })?;
        crate::vlog!("daemon: observing filesystem rooted at {}", path.display());
    }
    Ok(())
}

fn monitor_mount_points_for_profile(profile_source: &str) -> Result<Vec<PathBuf>> {
    let mounts = proc_mounts::read_mount_table()?;
    let mut patterns = crate::profile::monitor_glob_patterns_for_normalized_source(profile_source)?;
    patterns.retain(|pattern| pattern != "/proc" && !pattern.starts_with("/proc/"));
    for path in baseline_monitor_paths() {
        patterns.extend(crate::profile::monitor_glob_patterns_for_path(&path)?);
    }
    proc_mounts::covered_mount_points(&mounts, &patterns)
}

pub(crate) fn baseline_monitor_paths() -> Vec<PathBuf> {
    let mut paths = vec![PathBuf::from("/"), std::env::temp_dir()];
    if let Some(runtime_dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        paths.push(PathBuf::from(runtime_dir));
    }
    paths
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

fn cleanup_socket(socket_path: &Path) -> Result<()> {
    match fs::remove_file(socket_path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err)
            .with_context(|| format!("failed to remove daemon socket {}", socket_path.display())),
    }
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
    active_profile: Arc<RwLock<Option<ActiveProfile>>>,
    host_pidns: NamespaceKey,
    observer: FilesystemObserver,
    observed_mount_points: BTreeSet<PathBuf>,
}

#[derive(Debug, Clone)]
struct ActiveProfile {
    source: String,
    #[cfg_attr(test, allow(dead_code))]
    compiled: CompiledProfile,
}

#[cfg(test)]
impl Default for DaemonState {
    fn default() -> Self {
        Self {
            active_profile: Arc::new(RwLock::new(None)),
            host_pidns: NamespaceKey { dev: 1, ino: 1 },
            observer: FilesystemObserver::new().expect("test observer should initialize"),
            observed_mount_points: BTreeSet::new(),
        }
    }
}

struct ReceivedRequest {
    request: String,
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
    fn spawn_thread(
        &self,
        _host_pidns: NamespaceKey,
        _active_profile: Arc<RwLock<Option<ActiveProfile>>>,
    ) -> Result<()> {
        Ok(())
    }

    #[cfg(test)]
    fn mark_filesystem(&self, _path: &Path) -> Result<()> {
        Ok(())
    }

    #[cfg(not(test))]
    fn spawn_thread(
        &self,
        host_pidns: NamespaceKey,
        active_profile: Arc<RwLock<Option<ActiveProfile>>>,
    ) -> Result<()> {
        let file = self
            .fd
            .try_clone()
            .context("failed to clone fanotify fd for observer thread")?;
        thread::Builder::new()
            .name("leash-fanotify".to_string())
            .spawn(move || observe_events(file, host_pidns, active_profile))
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

fn authorize_peer(peer: &PeerCredentials, host_pidns: NamespaceKey) -> Result<()> {
    let allowed_uid = unsafe { libc::getuid() };
    if peer.uid != allowed_uid && peer.uid != 0 {
        bail!(
            "daemon connection rejected: peer pid={} uid={} gid={} does not match session uid {}",
            peer.pid,
            peer.uid,
            peer.gid,
            allowed_uid
        )
    }
    let peer_pidns = pid_namespace_key_for_pid(peer.pid)?.ok_or_else(|| {
        anyhow::anyhow!("failed to resolve pid namespace for peer pid={}", peer.pid)
    })?;
    if peer_pidns != host_pidns {
        bail!(
            "daemon connection rejected: peer pid={} is outside host pid namespace {}:{}",
            peer.pid,
            host_pidns.dev,
            host_pidns.ino
        )
    }
    Ok(())
}

fn handle_client(
    state: &mut DaemonState,
    stream: &mut UnixStream,
    peer: PeerCredentials,
) -> Result<bool> {
    let received = recv_request(stream)?;
    let request = received.request.trim();
    crate::vlog!(
        "daemon: request='{}' from pid={} uid={}",
        request,
        peer.pid,
        peer.uid
    );
    let response = handle_request(state, request, peer);
    stream
        .write_all(response.body.as_bytes())
        .context("failed to write daemon response")?;
    stream.flush().context("failed to flush daemon response")?;
    Ok(response.shutdown)
}

struct RequestResponse {
    body: String,
    shutdown: bool,
}

fn handle_request(state: &mut DaemonState, request: &str, _peer: PeerCredentials) -> RequestResponse {
    let mut lines = request.lines();
    let Some(command) = lines.next().map(str::trim) else {
        return RequestResponse {
            body: "error empty-request\n".to_string(),
            shutdown: false,
        };
    };
    match command {
        "ping" => RequestResponse {
            body: "pong\n".to_string(),
            shutdown: false,
        },
        "set-profile" => {
            let profile_source = lines.collect::<Vec<_>>().join("\n");
            if profile_source.trim().is_empty() {
                return RequestResponse {
                    body: "error missing-profile-source\n".to_string(),
                    shutdown: false,
                };
            }
            match CompiledProfile::compile_normalized_source(&profile_source) {
                Ok(compiled) => {
                    if let Ok(mount_points) = monitor_mount_points_for_profile(&profile_source) {
                        for mount_point in mount_points {
                            if state.observed_mount_points.insert(mount_point.clone()) {
                                if let Err(err) = state.observer.mark_filesystem(&mount_point) {
                                    crate::vlog!(
                                        "daemon: failed to add monitor for {}: {}",
                                        mount_point.display(),
                                        err
                                    );
                                } else {
                                    crate::vlog!(
                                        "daemon: added monitor for {} after profile update",
                                        mount_point.display()
                                    );
                                }
                            }
                        }
                    }
                    let mut guard = state
                        .active_profile
                        .write()
                        .expect("active profile lock poisoned");
                    *guard = Some(ActiveProfile {
                        source: profile_source,
                        compiled,
                    });
                    RequestResponse {
                        body: "ok profile-updated\n".to_string(),
                        shutdown: false,
                    }
                }
                Err(err) => RequestResponse {
                    body: format!("error invalid-profile:{}\n", err),
                    shutdown: false,
                },
            }
        }
        "get-profile" => {
            let guard = state
                .active_profile
                .read()
                .expect("active profile lock poisoned");
            match &*guard {
                Some(profile) => RequestResponse {
                    body: format!("ok\n{}\n", profile.source),
                    shutdown: false,
                },
                None => RequestResponse {
                    body: "ok\n".to_string(),
                    shutdown: false,
                },
            }
        }
        "shutdown" => RequestResponse {
            body: "ok shutting-down\n".to_string(),
            shutdown: true,
        },
        _ => RequestResponse {
            body: "error unknown-command\n".to_string(),
            shutdown: false,
        },
    }
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
    Ok(ReceivedRequest { request })
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

fn pid_namespace_path_for_pid(pid: libc::pid_t) -> PathBuf {
    PathBuf::from(format!("/proc/{pid}/ns/pid"))
}

#[cfg(not(test))]
fn observe_events(
    file: File,
    host_pidns: NamespaceKey,
    active_profile: Arc<RwLock<Option<ActiveProfile>>>,
) {
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
            let actual_path = if meta.fd >= 0 {
                path_for_event_fd(meta.fd)
            } else {
                None
            };
            match pid_namespace_key_for_pid(meta.pid) {
                Ok(Some(pidns)) if pidns != host_pidns => {
                    let exe_path = exe_path_for_pid(meta.pid);
                    let access = requested_access_from_mask(meta.mask);
                    let decision = match (actual_path.as_deref(), active_profile.read()) {
                        (Some(target_path), Ok(guard)) => guard
                            .as_ref()
                            .and_then(|profile| {
                                profile
                                    .compiled
                                    .evaluate(target_path, exe_path.as_deref(), access)
                            })
                            .map(|matched| {
                                format!(
                                    "{} rule=\"{}\"",
                                    format_access_decision(matched.decision),
                                    matched.rule_text.replace('"', "\\\"")
                                )
                            })
                            .unwrap_or_else(|| "no-match".to_string()),
                        (None, _) => "no-path".to_string(),
                        (_, Err(_)) => "profile-lock-error".to_string(),
                    };
                    crate::vlog!(
                        "fanotify: controlled pid={} pidns={}:{} mask={} access={} exe={} decision={} path={}",
                        meta.pid,
                        pidns.dev,
                        pidns.ino,
                        describe_mask(meta.mask),
                        format_requested_access(access),
                        exe_path
                            .as_deref()
                            .map(|path| path.display().to_string())
                            .unwrap_or_else(|| "<unknown>".to_string()),
                        decision,
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

#[cfg(not(test))]
fn describe_event_fd(fd: libc::c_int) -> String {
    path_for_event_fd(fd)
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| format!("fd:{fd}"))
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

#[cfg(not(test))]
fn path_for_event_fd(fd: libc::c_int) -> Option<PathBuf> {
    let link = PathBuf::from(format!("/proc/self/fd/{fd}"));
    fs::read_link(&link).ok()
}

#[cfg(not(test))]
fn exe_path_for_pid(pid: libc::pid_t) -> Option<PathBuf> {
    fs::read_link(format!("/proc/{pid}/exe")).ok()
}

#[cfg(not(test))]
fn requested_access_from_mask(mask: u64) -> RequestedAccess {
    if mask & libc::FAN_CLOSE_WRITE != 0 {
        RequestedAccess::Write
    } else if mask & libc::FAN_OPEN_EXEC != 0 {
        RequestedAccess::Execute
    } else {
        RequestedAccess::Read
    }
}

#[cfg(not(test))]
fn format_requested_access(access: RequestedAccess) -> &'static str {
    match access {
        RequestedAccess::Read => "read",
        RequestedAccess::Write => "write",
        RequestedAccess::Execute => "execute",
    }
}

#[cfg(not(test))]
fn format_access_decision(decision: AccessDecision) -> &'static str {
    match decision {
        AccessDecision::AllowReadOnly => "allow-ro",
        AccessDecision::AllowReadWrite => "allow-rw",
        AccessDecision::Deny => "deny",
    }
}

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
            pid: unsafe { libc::getpid() },
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
        };
        let host_pidns = pid_namespace_key_for_pid(peer.pid)
            .expect("peer pidns lookup")
            .expect("peer pidns");
        authorize_peer(&peer, host_pidns).expect("real uid should be accepted");
    }

    #[test]
    fn request_handler_sets_and_reads_global_profile() {
        let mut state = DaemonState::default();
        let peer = PeerCredentials {
            pid: unsafe { libc::getpid() },
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
        };
        let update = handle_request(&mut state, "set-profile\n/work rw\n/etc ro", peer);
        assert_eq!(update.body, "ok profile-updated\n");
        assert!(!update.shutdown);

        let query = handle_request(&mut state, "get-profile", peer);
        assert_eq!(query.body, "ok\n/work rw\n/etc ro\n");
        assert!(!query.shutdown);
    }

    #[test]
    fn get_profile_reports_empty_before_initialization() {
        let mut state = DaemonState::default();
        let peer = PeerCredentials {
            pid: unsafe { libc::getpid() },
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
        };
        let response = handle_request(&mut state, "get-profile", peer);
        assert_eq!(response.body, "ok\n");
        assert!(!response.shutdown);
    }

    #[test]
    fn set_profile_requires_content() {
        let mut state = DaemonState::default();
        let peer = PeerCredentials {
            pid: unsafe { libc::getpid() },
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
        };
        let response = handle_request(&mut state, "set-profile", peer);
        assert_eq!(response.body, "error missing-profile-source\n");
        assert!(!response.shutdown);
    }

    #[test]
    fn shutdown_request_requests_daemon_exit() {
        let mut state = DaemonState::default();
        let peer = PeerCredentials {
            pid: unsafe { libc::getpid() },
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
        };
        let response = handle_request(&mut state, "shutdown", peer);
        assert_eq!(response.body, "ok shutting-down\n");
        assert!(response.shutdown);
    }
}
