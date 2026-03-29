use anyhow::{Context, Result, bail};
use fs_err as fs;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

pub(crate) fn require_root_euid(cmd: &str) -> Result<()> {
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        bail!(
            "{cmd} requires root euid (current euid={euid}).\nRun `leash _suid` once to set setuid-root on the current binary.",
            cmd = cmd,
            euid = euid
        );
    }
    Ok(())
}

pub(crate) fn drop_to_real_user() -> Result<()> {
    let uid = unsafe { libc::getuid() };
    let euid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getgid() };
    validate_drop_to_real_user_uids(uid, euid)?;
    crate::vlog!("privileges: drop to real user uid={} gid={}", uid, gid);
    drop_to_ids(uid, gid)
}

pub(crate) fn drop_root_euid_if_needed() -> Result<bool> {
    let uid = unsafe { libc::getuid() };
    let euid = unsafe { libc::geteuid() };
    if euid == 0 && uid != 0 {
        drop_to_real_user()?;
        return Ok(true);
    }
    Ok(false)
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
    crate::vlog!("privileges: setresgid({gid},{gid},{gid})");
    if unsafe { libc::setresgid(gid, gid, gid) } != 0 {
        let err = std::io::Error::last_os_error();
        return Err(anyhow::anyhow!(
            "setresgid({gid},{gid},{gid}) failed: {err}"
        ));
    }
    crate::vlog!("privileges: setresuid({uid},{uid},{uid})");
    if unsafe { libc::setresuid(uid, uid, uid) } != 0 {
        let err = std::io::Error::last_os_error();
        return Err(anyhow::anyhow!(
            "setresuid({uid},{uid},{uid}) failed: {err}"
        ));
    }
    crate::vlog!("privileges: prctl(PR_SET_NO_NEW_PRIVS, 1)");
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        let err = std::io::Error::last_os_error();
        return Err(anyhow::anyhow!(
            "prctl(PR_SET_NO_NEW_PRIVS, 1) failed: {err}"
        ));
    }
    Ok(())
}

fn validate_drop_to_real_user_uids(uid: u32, euid: u32) -> Result<()> {
    if euid != 0 {
        if uid != euid {
            bail!(
                "refusing uid transition from non-root euid={euid} to uid={uid}; drop_to_real_user requires root euid"
            );
        }
        bail!("drop_to_real_user requires root euid (current euid={euid})");
    }
    if uid == 0 && euid != 0 {
        bail!("drop_to_real_user requires non-root real uid target (current uid=0, euid={euid})");
    }
    Ok(())
}

/// Fix ownership of `path` to the real (non-setuid) user/group.
/// A no-op when the path is already correctly owned or the effective uid is not root.
pub(crate) fn ensure_owned_by_real_user(path: &Path) -> Result<()> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(err).with_context(|| format!("failed to stat {}", path.display()));
        }
    };

    let target_uid = unsafe { libc::getuid() };
    let target_gid = unsafe { libc::getgid() };
    if meta.uid() == target_uid && meta.gid() == target_gid {
        return Ok(());
    }

    if unsafe { libc::geteuid() } != 0 {
        return Ok(());
    }

    let c_path = CString::new(path.as_os_str().as_bytes())
        .with_context(|| format!("path contains interior NUL byte: {}", path.display()))?;
    let rc = unsafe { libc::chown(c_path.as_ptr(), target_uid, target_gid) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!(
                "failed to chown {} to {target_uid}:{target_gid}",
                path.display()
            )
        });
    }
    Ok(())
}

/// Remove `path` if it exists, retrying after a `chown` fix on `parent_dir` if the
/// first attempt fails with `PermissionDenied`.
pub(crate) fn remove_file_if_exists_with_owner_fix(parent_dir: &Path, path: &Path) -> Result<()> {
    match remove_file_if_exists(path) {
        Ok(()) => Ok(()),
        Err(err)
            if err
                .downcast_ref::<std::io::Error>()
                .is_some_and(|ioe| ioe.kind() == std::io::ErrorKind::PermissionDenied) =>
        {
            ensure_owned_by_real_user(parent_dir)?;
            remove_file_if_exists(path)
        }
        Err(err) => Err(err),
    }
}

fn remove_file_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("failed to remove file {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::{drop_root_euid_if_needed, validate_drop_to_real_user_uids};

    #[test]
    fn drop_validation_allows_root_to_non_root() {
        validate_drop_to_real_user_uids(1000, 0).expect("root to non-root should be allowed");
    }

    #[test]
    fn drop_validation_rejects_non_root_transition() {
        let err = validate_drop_to_real_user_uids(1000, 1001).expect_err("must reject non-root");
        assert!(
            err.to_string()
                .contains("refusing uid transition from non-root")
        );
    }

    #[test]
    fn drop_validation_rejects_non_root_noop() {
        let err = validate_drop_to_real_user_uids(1000, 1000).expect_err("must require root");
        assert!(err.to_string().contains("requires root euid"));
    }

    #[test]
    fn drop_validation_accepts_sudo() {
        validate_drop_to_real_user_uids(0, 0).expect("root -> root is okay (sudo)")
    }

    #[test]
    fn conditional_drop_is_noop_without_setuid_root() {
        let dropped = drop_root_euid_if_needed().expect("conditional drop should not fail");
        assert!(!dropped);
    }
}
