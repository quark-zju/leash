use std::ffi::CString;

use anyhow::{Context, Result, bail};
use fs_err as fs;
use log::{debug, warn};

pub fn set_process_name(short_name: &str) -> Result<()> {
    let prctl_name = format!("leash-{short_name}");
    let prctl_name_c =
        CString::new(prctl_name.as_str()).context("process name contains interior NUL byte")?;
    debug!("process-name: syscall prctl(PR_SET_NAME, {prctl_name})");
    let rc = unsafe {
        libc::prctl(
            libc::PR_SET_NAME,
            prctl_name_c.as_ptr() as libc::c_ulong,
            0,
            0,
            0,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("prctl(PR_SET_NAME) failed");
    }

    if let Err(err) = try_rewrite_argv0_in_place(short_name) {
        warn!("process-name: failed to rewrite argv[0] for {short_name}: {err:#}");
    }

    Ok(())
}

fn try_rewrite_argv0_in_place(name: &str) -> Result<()> {
    let (arg_start, arg_end) = read_argv_bounds_from_proc_stat()?;
    if arg_end <= arg_start {
        bail!("invalid argv bounds in /proc/self/stat: arg_start={arg_start} arg_end={arg_end}");
    }
    let capacity = arg_end - arg_start;

    let rewritten = format!("leash[{name}]");
    if rewritten.len() + 1 > capacity {
        bail!(
            "argv buffer too small: need {} bytes, have {} bytes",
            rewritten.len(),
            capacity.saturating_sub(1)
        );
    }

    let rewritten_bytes = rewritten.as_bytes();

    unsafe {
        let dst = arg_start as *mut u8;
        std::ptr::copy_nonoverlapping(rewritten_bytes.as_ptr(), dst, rewritten_bytes.len());
        std::ptr::write_bytes(
            dst.add(rewritten_bytes.len()),
            0,
            capacity - rewritten_bytes.len(),
        );
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
