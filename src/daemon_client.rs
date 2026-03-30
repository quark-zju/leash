use anyhow::{Context, Result, bail};
use std::io::{BufRead, BufReader, Write};
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

fn send_request(socket_path: &std::path::Path, request: &str) -> Result<String> {
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
