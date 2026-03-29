use anyhow::{Context, Result, bail};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::cmd_daemon;

pub(crate) fn ensure_daemon_running(verbose: bool) -> Result<()> {
    let socket_path = cmd_daemon::default_socket_path();
    if ping_daemon(&socket_path).is_ok() {
        return Ok(());
    }

    spawn_daemon_process(verbose)?;
    wait_for_daemon(&socket_path, Duration::from_secs(2))
}

pub(crate) fn register_session(profile_path: &Path) -> Result<()> {
    let namespace_file =
        File::open("/proc/self/ns/mnt").context("failed to open current mount namespace handle")?;
    let request = format!("register-session\n{}", profile_path.display());
    let response = send_request_with_fd(
        &cmd_daemon::default_socket_path(),
        &request,
        namespace_file.as_raw_fd(),
    )?;
    if response.starts_with("ok registered ") {
        return Ok(());
    }
    bail!("daemon refused session registration: {}", response.trim())
}

fn ping_daemon(socket_path: &Path) -> Result<()> {
    let response = send_request(socket_path, "ping")?;
    if response.trim() == "pong" {
        return Ok(());
    }
    bail!("unexpected daemon ping response: {}", response.trim())
}

fn send_request(socket_path: &Path, request: &str) -> Result<String> {
    let mut stream = UnixStream::connect(socket_path).with_context(|| {
        format!(
            "failed to connect to daemon socket {}",
            socket_path.display()
        )
    })?;
    stream.write_all(request.as_bytes()).with_context(|| {
        format!(
            "failed to write daemon request to {}",
            socket_path.display()
        )
    })?;
    stream.write_all(b"\n").with_context(|| {
        format!(
            "failed to finalize daemon request to {}",
            socket_path.display()
        )
    })?;

    let mut response = String::new();
    let mut reader = BufReader::new(stream);
    reader.read_line(&mut response).with_context(|| {
        format!(
            "failed to read daemon response from {}",
            socket_path.display()
        )
    })?;
    Ok(response)
}

fn send_request_with_fd(socket_path: &Path, request: &str, raw_fd: libc::c_int) -> Result<String> {
    let stream = UnixStream::connect(socket_path).with_context(|| {
        format!(
            "failed to connect to daemon socket {}",
            socket_path.display()
        )
    })?;
    sendmsg_with_fd(&stream, request, raw_fd)?;

    let mut response = String::new();
    let mut reader = BufReader::new(stream);
    reader.read_line(&mut response).with_context(|| {
        format!(
            "failed to read daemon response from {}",
            socket_path.display()
        )
    })?;
    Ok(response)
}

fn sendmsg_with_fd(stream: &UnixStream, request: &str, raw_fd: libc::c_int) -> Result<()> {
    let fd = stream.as_raw_fd();
    let mut payload = Vec::with_capacity(request.len() + 1);
    payload.extend_from_slice(request.as_bytes());
    payload.push(b'\n');

    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
    };
    let mut control = [0u8; 128];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = control.len();

    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg as *const libc::msghdr as *mut libc::msghdr) };
    if cmsg.is_null() {
        bail!("failed to allocate ancillary data header for daemon request")
    }
    unsafe {
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) as usize;
        let data_ptr = libc::CMSG_DATA(cmsg) as *mut libc::c_int;
        *data_ptr = raw_fd;
    }
    msg.msg_controllen =
        unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) as usize };

    let sent = unsafe { libc::sendmsg(fd, &msg, 0) };
    if sent < 0 {
        return Err(std::io::Error::last_os_error()).context("sendmsg failed for daemon request");
    }
    Ok(())
}

fn spawn_daemon_process(verbose: bool) -> Result<()> {
    let exe = std::env::current_exe().context("failed to locate current executable")?;
    let mut cmd = Command::new(exe);
    cmd.arg("_daemon")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if verbose {
        cmd.arg("-v");
    }
    cmd.spawn().context("failed to spawn daemon process")?;
    Ok(())
}

fn wait_for_daemon(socket_path: &Path, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    let mut last_err = None;
    while Instant::now() < deadline {
        match ping_daemon(socket_path) {
            Ok(()) => return Ok(()),
            Err(err) => last_err = Some(err),
        }
        thread::sleep(Duration::from_millis(50));
    }
    if let Some(err) = last_err {
        return Err(err).context("daemon did not become ready before timeout");
    }
    bail!("daemon did not become ready before timeout")
}
