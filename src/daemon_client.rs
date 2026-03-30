use anyhow::{Context, Result, bail};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::cmd_daemon;

pub(crate) fn ensure_daemon_running(verbose: bool, profile_source: &str) -> Result<()> {
    let socket_path = cmd_daemon::default_socket_path();
    if ping_daemon(&socket_path).is_ok() {
        return Ok(());
    }

    spawn_daemon_process(verbose)?;
    wait_for_daemon(&socket_path, Duration::from_secs(2))?;
    set_profile(profile_source)
}

fn ping_daemon(socket_path: &std::path::Path) -> Result<()> {
    let response = send_request(socket_path, "ping")?;
    if response.trim() == "pong" {
        return Ok(());
    }
    bail!("unexpected daemon ping response: {}", response.trim())
}

pub(crate) fn set_profile(profile_source: &str) -> Result<()> {
    let request = format!("set-profile\n{profile_source}");
    let response = send_request(&cmd_daemon::default_socket_path(), &request)?;
    if response.trim() == "ok profile-updated" {
        return Ok(());
    }
    bail!("daemon refused profile update: {}", response.trim())
}

pub(crate) fn shutdown_daemon() -> Result<()> {
    let response = send_request(&cmd_daemon::default_socket_path(), "shutdown")?;
    if response.trim() == "ok shutting-down" {
        return Ok(());
    }
    bail!("daemon refused shutdown request: {}", response.trim())
}

pub(crate) fn get_profile_if_running() -> Result<Option<String>> {
    let Some(response) = try_send_request(&cmd_daemon::default_socket_path(), "get-profile")?
    else {
        return Ok(None);
    };
    let Some(body) = response.strip_prefix("ok\n") else {
        bail!("daemon returned unexpected get-profile response: {}", response.trim());
    };
    Ok(Some(body.trim_end_matches('\n').to_string()))
}

fn send_request(socket_path: &std::path::Path, request: &str) -> Result<String> {
    let Some(response) = try_send_request(socket_path, request)? else {
        bail!(
            "failed to connect to daemon socket {}",
            socket_path.display()
        )
    };
    Ok(response)
}

fn try_send_request(socket_path: &std::path::Path, request: &str) -> Result<Option<String>> {
    let mut stream = match UnixStream::connect(socket_path) {
        Ok(stream) => stream,
        Err(err) if daemon_not_running_error(&err) => return Ok(None),
        Err(err) => {
            return Err(err).with_context(|| {
                format!(
                    "failed to connect to daemon socket {}",
                    socket_path.display()
                )
            });
        }
    };
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
    stream.read_to_string(&mut response).with_context(|| {
        format!(
            "failed to read daemon response from {}",
            socket_path.display()
        )
    })?;
    Ok(Some(response))
}

fn daemon_not_running_error(err: &std::io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(libc::ENOENT | libc::ECONNREFUSED)
    )
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

fn wait_for_daemon(socket_path: &std::path::Path, timeout: Duration) -> Result<()> {
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
