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
    crate::vlog!("privileges: drop to real user uid={} gid={}", uid, gid);
    drop_to_ids(uid, gid)
}

pub(crate) fn with_temporary_real_root<T, F>(f: F) -> Result<T>
where
    F: FnOnce() -> Result<T>,
{
    let mut ruid: libc::uid_t = 0;
    let mut euid: libc::uid_t = 0;
    let mut suid: libc::uid_t = 0;
    let mut rgid: libc::gid_t = 0;
    let mut egid: libc::gid_t = 0;
    let mut sgid: libc::gid_t = 0;

    let get_uid_rc = unsafe { libc::getresuid(&mut ruid, &mut euid, &mut suid) };
    if get_uid_rc != 0 {
        bail!(
            "failed to read current uid triplet: {}",
            std::io::Error::last_os_error()
        );
    }
    let get_gid_rc = unsafe { libc::getresgid(&mut rgid, &mut egid, &mut sgid) };
    if get_gid_rc != 0 {
        bail!(
            "failed to read current gid triplet: {}",
            std::io::Error::last_os_error()
        );
    }

    crate::vlog!(
        "privileges: temporary escalate real ids to root (ruid/euid/suid={}/{}/{}, rgid/egid/sgid={}/{}/{})",
        ruid,
        euid,
        suid,
        rgid,
        egid,
        sgid
    );
    let set_gid_root_rc = unsafe { libc::setresgid(0, 0, 0) };
    if set_gid_root_rc != 0 {
        bail!(
            "failed to switch gid triplet to root: {}",
            std::io::Error::last_os_error()
        );
    }
    let set_uid_root_rc = unsafe { libc::setresuid(0, 0, 0) };
    if set_uid_root_rc != 0 {
        let _ = unsafe { libc::setresgid(rgid, egid, sgid) };
        bail!(
            "failed to switch uid triplet to root: {}",
            std::io::Error::last_os_error()
        );
    }

    let run_result = f();

    crate::vlog!(
        "privileges: restore uid/gid triplets to ruid/euid/suid={}/{}/{}, rgid/egid/sgid={}/{}/{}",
        ruid,
        euid,
        suid,
        rgid,
        egid,
        sgid
    );
    let restore_uid_rc = unsafe { libc::setresuid(ruid, euid, suid) };
    let restore_uid_err = std::io::Error::last_os_error();
    let restore_gid_rc = unsafe { libc::setresgid(rgid, egid, sgid) };
    let restore_gid_err = std::io::Error::last_os_error();

    if restore_uid_rc != 0 {
        bail!("failed to restore uid triplet: {}", restore_uid_err);
    }
    if restore_gid_rc != 0 {
        bail!("failed to restore gid triplet: {}", restore_gid_err);
    }

    run_result
}

fn drop_to_ids(uid: u32, gid: u32) -> Result<()> {
    crate::vlog!("privileges: setgroups([])");
    if unsafe { libc::setgroups(0, std::ptr::null()) } != 0 {
        let err = std::io::Error::last_os_error();
        return Err(anyhow::anyhow!("setgroups([]) failed: {err}"));
    }
    crate::vlog!("privileges: setgid({gid})");
    if unsafe { libc::setgid(gid) } != 0 {
        let err = std::io::Error::last_os_error();
        return Err(anyhow::anyhow!("setgid({gid}) failed: {err}"));
    }
    crate::vlog!("privileges: setuid({uid})");
    if unsafe { libc::setuid(uid) } != 0 {
        let err = std::io::Error::last_os_error();
        return Err(anyhow::anyhow!("setuid({uid}) failed: {err}"));
    }
    crate::vlog!("privileges: prctl(PR_SET_NO_NEW_PRIVS,1)");
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        let err = std::io::Error::last_os_error();
        return Err(anyhow::anyhow!("prctl(PR_SET_NO_NEW_PRIVS) failed: {err}"));
    }
    Ok(())
}
