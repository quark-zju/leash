use anyhow::{Result, bail};

pub(crate) fn require_root_euid(cmd: &str) -> Result<()> {
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        bail!(
            "{cmd} requires root euid (current euid={euid}).\nRun `cowjail _suid` once to set setuid-root on the current binary.",
            cmd = cmd,
            euid = euid
        );
    }
    Ok(())
}

pub(crate) fn drop_to_real_user() -> Result<()> {
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    drop_to_ids(uid, gid)
}

fn drop_to_ids(uid: u32, gid: u32) -> Result<()> {
    if unsafe { libc::setgroups(0, std::ptr::null()) } != 0 {
        let err = std::io::Error::last_os_error();
        return Err(anyhow::anyhow!("setgroups([]) failed: {err}"));
    }
    if unsafe { libc::setgid(gid) } != 0 {
        let err = std::io::Error::last_os_error();
        return Err(anyhow::anyhow!("setgid({gid}) failed: {err}"));
    }
    if unsafe { libc::setuid(uid) } != 0 {
        let err = std::io::Error::last_os_error();
        return Err(anyhow::anyhow!("setuid({uid}) failed: {err}"));
    }
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        let err = std::io::Error::last_os_error();
        return Err(anyhow::anyhow!("prctl(PR_SET_NO_NEW_PRIVS) failed: {err}"));
    }
    Ok(())
}
