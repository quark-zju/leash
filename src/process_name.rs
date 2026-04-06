use std::ffi::CString;

use anyhow::{Context, Result, bail};
use fs_err as fs;
use log::{debug, warn};

pub fn set_process_name(name: &str) -> Result<()> {
    let name_c = CString::new(name).context("process name contains interior NUL byte")?;
    debug!("process-name: syscall prctl(PR_SET_NAME, {name})");
    let rc = unsafe { libc::prctl(libc::PR_SET_NAME, name_c.as_ptr() as libc::c_ulong, 0, 0, 0) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("prctl(PR_SET_NAME) failed");
    }

    if let Err(err) = try_append_name_to_argv(name) {
        warn!("process-name: failed to append argv suffix for {name}: {err:#}");
    }

    Ok(())
}

fn try_append_name_to_argv(name: &str) -> Result<()> {
    let (arg_start, arg_end) = read_argv_bounds_from_proc_stat()?;
    if arg_end <= arg_start {
        bail!("invalid argv bounds in /proc/self/stat: arg_start={arg_start} arg_end={arg_end}");
    }
    let capacity = arg_end - arg_start;

    let mut cmdline = fs::read("/proc/self/cmdline").context("read /proc/self/cmdline failed")?;
    if cmdline.is_empty() {
        bail!("/proc/self/cmdline is empty");
    }
    if cmdline.last().copied() != Some(0) {
        cmdline.push(0);
    }
    let first_nul = cmdline
        .iter()
        .position(|byte| *byte == 0)
        .context("/proc/self/cmdline is missing argv[0] terminator")?;

    let mut rewritten = Vec::with_capacity(cmdline.len() + name.len() + 3);
    rewritten.extend_from_slice(&cmdline[..first_nul]);
    rewritten.extend_from_slice(b" [");
    rewritten.extend_from_slice(name.as_bytes());
    rewritten.extend_from_slice(b"]");
    rewritten.push(0);
    rewritten.extend_from_slice(&cmdline[first_nul + 1..]);

    if rewritten.len() > capacity {
        bail!(
            "argv buffer too small for suffix: need {} bytes, have {} bytes",
            rewritten.len(),
            capacity
        );
    }

    unsafe {
        let dst = arg_start as *mut u8;
        std::ptr::copy_nonoverlapping(rewritten.as_ptr(), dst, rewritten.len());
        if rewritten.len() < capacity {
            std::ptr::write_bytes(dst.add(rewritten.len()), 0, capacity - rewritten.len());
        }
    }
    Ok(())
}

fn read_argv_bounds_from_proc_stat() -> Result<(usize, usize)> {
    let stat = fs::read_to_string("/proc/self/stat").context("read /proc/self/stat failed")?;
    let comm_end = stat
        .rfind(") ")
        .context("malformed /proc/self/stat: missing comm terminator")?;
    let tail = &stat[comm_end + 2..];
    let fields: Vec<&str> = tail.split_whitespace().collect();
    if fields.len() <= 46 {
        bail!(
            "malformed /proc/self/stat: expected at least 47 fields after comm, got {}",
            fields.len()
        );
    }

    let arg_start_u64: u64 = fields[45]
        .parse()
        .context("parse arg_start from /proc/self/stat failed")?;
    let arg_end_u64: u64 = fields[46]
        .parse()
        .context("parse arg_end from /proc/self/stat failed")?;
    let arg_start = usize::try_from(arg_start_u64).context("arg_start does not fit usize")?;
    let arg_end = usize::try_from(arg_end_u64).context("arg_end does not fit usize")?;
    Ok((arg_start, arg_end))
}
