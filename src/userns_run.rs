use std::ffi::{CString, OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;

use anyhow::{Context, Result, bail};
use fs_err as fs;
use log::debug;

use crate::mount_plan::MountPlanEntry;

const MOUNTINFO_PATH: &str = "/proc/self/mountinfo";

#[derive(Debug, Clone)]
pub struct UsernsRunConfig {
    pub fuse_mount_root: PathBuf,
    pub cwd: PathBuf,
    pub program: OsString,
    pub args: Vec<OsString>,
    pub mount_plan: Vec<MountPlanEntry>,
}

impl UsernsRunConfig {
    pub fn new(
        fuse_mount_root: PathBuf,
        cwd: PathBuf,
        program: OsString,
        args: Vec<OsString>,
        mount_plan: Vec<MountPlanEntry>,
    ) -> Self {
        Self {
            fuse_mount_root,
            cwd,
            program,
            args,
            mount_plan,
        }
    }
}

pub fn run_in_user_namespace(config: &UsernsRunConfig) -> Result<i32> {
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    let supervisor_pid = fork_process("userns-supervisor")?;
    if supervisor_pid == 0 {
        let status = match run_namespace_supervisor(config, uid, gid) {
            Ok(status) => status,
            Err(err) => {
                eprintln!("leash2 userns run failed: {err:#}");
                125
            }
        };
        unsafe { libc::_exit(status) }
    }

    wait_for_specific_child(supervisor_pid)
}

fn run_namespace_supervisor(
    config: &UsernsRunConfig,
    uid: libc::uid_t,
    gid: libc::gid_t,
) -> Result<i32> {
    unshare_run_namespaces()?;
    write_current_user_namespace_maps(uid, gid)?;
    make_mounts_private()?;
    apply_mount_plan_before_pid_namespace_init(&config.fuse_mount_root, &config.mount_plan)?;
    run_pid_namespace_init_and_exec(config, uid, gid)
}

fn unshare_run_namespaces() -> Result<()> {
    let flags = libc::CLONE_NEWUSER | libc::CLONE_NEWNS | libc::CLONE_NEWIPC | libc::CLONE_NEWPID;
    debug!("userns-run: syscall unshare(flags={flags:#x})");
    let rc = unsafe { libc::unshare(flags) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context(
            "unshare(CLONE_NEWUSER|CLONE_NEWNS|CLONE_NEWIPC|CLONE_NEWPID) failed",
        );
    }
    Ok(())
}

fn write_current_user_namespace_maps(uid: libc::uid_t, gid: libc::gid_t) -> Result<()> {
    debug!("userns-run: write /proc/self/setgroups = deny");
    fs::write("/proc/self/setgroups", b"deny\n").context("write /proc/self/setgroups failed")?;

    let uid_map = format!("{} {} 1\n", uid, uid);
    debug!("userns-run: write /proc/self/uid_map = {}", uid_map.trim_end());
    fs::write("/proc/self/uid_map", uid_map.as_bytes())
        .context("write /proc/self/uid_map failed")?;

    let gid_map = format!("{} {} 1\n", gid, gid);
    debug!("userns-run: write /proc/self/gid_map = {}", gid_map.trim_end());
    fs::write("/proc/self/gid_map", gid_map.as_bytes())
        .context("write /proc/self/gid_map failed")?;

    Ok(())
}

fn make_mounts_private() -> Result<()> {
    let root = CString::new("/").expect("literal '/' cannot contain NUL");
    let flags = (libc::MS_REC | libc::MS_PRIVATE) as libc::c_ulong;
    debug!("userns-run: syscall mount(NULL, /, NULL, {flags:#x}, NULL)");
    let rc = unsafe {
        libc::mount(
            std::ptr::null(),
            root.as_ptr(),
            std::ptr::null(),
            flags,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("mount(MS_PRIVATE|MS_REC) failed");
    }
    Ok(())
}

fn apply_mount_plan_before_pid_namespace_init(
    fuse_mount_root: &Path,
    plan: &[MountPlanEntry],
) -> Result<()> {
    apply_mount_plan(fuse_mount_root, plan, MountPhase::BeforePidNamespaceInit)
}

fn apply_mount_plan_in_pid_namespace_init(
    fuse_mount_root: &Path,
    plan: &[MountPlanEntry],
) -> Result<()> {
    apply_mount_plan(fuse_mount_root, plan, MountPhase::InPidNamespaceInit)
}

fn apply_mount_plan(
    fuse_mount_root: &Path,
    plan: &[MountPlanEntry],
    phase: MountPhase,
) -> Result<()> {
    for entry in plan {
        if mount_phase_for_entry(entry) != phase {
            continue;
        }
        apply_mount_plan_entry(fuse_mount_root, entry)?;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MountPhase {
    BeforePidNamespaceInit,
    InPidNamespaceInit,
}

fn mount_phase_for_entry(entry: &MountPlanEntry) -> MountPhase {
    match entry {
        MountPlanEntry::Bind { .. } | MountPlanEntry::Sys { .. } => {
            MountPhase::BeforePidNamespaceInit
        }
        MountPlanEntry::Proc { .. } => MountPhase::InPidNamespaceInit,
    }
}

fn apply_mount_plan_entry(fuse_mount_root: &Path, entry: &MountPlanEntry) -> Result<()> {
    let target = mount_target_for_entry(fuse_mount_root, entry)?;
    match entry {
        MountPlanEntry::Bind { path, read_only } => {
            ensure_mount_target_type(path, &target)?;
            bind_mount(path, &target)?;
            if *read_only {
                remount_bind_read_only(&target)?;
            }
        }
        MountPlanEntry::Proc { read_only } => {
            mount_virtual_fs("proc", "proc", &target)?;
            if *read_only {
                remount_read_only(&target)?;
            }
        }
        MountPlanEntry::Sys { read_only } => {
            ensure_mount_target_type(Path::new("/sys"), &target)?;
            bind_mount(Path::new("/sys"), &target)?;
            if *read_only {
                remount_bind_read_only(&target)?;
            }
        }
    }
    Ok(())
}

fn ensure_mount_target_type(source: &Path, target: &Path) -> Result<()> {
    let source_metadata = fs::metadata(source).with_context(|| {
        format!(
            "bind source does not exist or is inaccessible: {}",
            source.display()
        )
    })?;
    let target_metadata = fs::metadata(target).with_context(|| {
        format!(
            "bind target does not exist in fuse mount: {}",
            target.display()
        )
    })?;
    if source_metadata.is_dir() != target_metadata.is_dir() {
        bail!(
            "bind source/target type mismatch: source={} target={}",
            source.display(),
            target.display()
        );
    }
    Ok(())
}

fn mount_target_for_entry(fuse_mount_root: &Path, entry: &MountPlanEntry) -> Result<PathBuf> {
    let path = entry
        .path()
        .ok_or_else(|| anyhow::anyhow!("mount plan entry does not expose a path"))?;
    let rel = path
        .strip_prefix("/")
        .with_context(|| format!("mount path must be absolute: {}", path.display()))?;
    if rel.as_os_str().is_empty() {
        Ok(fuse_mount_root.to_path_buf())
    } else {
        Ok(fuse_mount_root.join(rel))
    }
}

fn bind_mount(source: &Path, target: &Path) -> Result<()> {
    let source_c = c_path(source).context("bind source path contains interior NUL byte")?;
    let target_c = c_path(target).context("bind target path contains interior NUL byte")?;
    debug!(
        "userns-run: syscall mount({}, {}, NULL, MS_BIND, NULL)",
        source.display(),
        target.display()
    );
    let rc = unsafe {
        libc::mount(
            source_c.as_ptr(),
            target_c.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND as libc::c_ulong,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!(
                "bind mount failed: {} -> {}",
                source.display(),
                target.display()
            )
        });
    }
    Ok(())
}

fn remount_bind_read_only(target: &Path) -> Result<()> {
    let target_c = c_path(target).context("bind remount target path contains interior NUL byte")?;
    let flags = readonly_bind_remount_flags(target)?;
    debug!(
        "userns-run: syscall mount(NULL, {}, NULL, {flags:#x}, NULL)",
        target.display()
    );
    let rc = unsafe {
        libc::mount(
            std::ptr::null(),
            target_c.as_ptr(),
            std::ptr::null(),
            flags,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("bind remount read-only failed: {}", target.display()));
    }
    Ok(())
}

fn readonly_bind_remount_flags(target: &Path) -> Result<libc::c_ulong> {
    Ok((libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY) as libc::c_ulong
        | locked_mount_flags_for_target(target, Path::new(MOUNTINFO_PATH))?)
}

fn locked_mount_flags_for_target(target: &Path, mountinfo: &Path) -> Result<libc::c_ulong> {
    let content = fs::read_to_string(mountinfo)
        .with_context(|| format!("failed to read {}", mountinfo.display()))?;
    for line in content.lines() {
        let Some((mount_point, mount_flags)) = parse_mountinfo_mount_flags(line)? else {
            continue;
        };
        if mount_point == target {
            return Ok(mount_flags);
        }
    }
    bail!("failed to find mountinfo entry for {}", target.display())
}

fn parse_mountinfo_mount_flags(line: &str) -> Result<Option<(PathBuf, libc::c_ulong)>> {
    if line.trim().is_empty() {
        return Ok(None);
    }

    let fields: Vec<&str> = line.split_whitespace().collect();
    let Some(sep) = fields.iter().position(|field| *field == "-") else {
        bail!("mountinfo line missing separator: {line}");
    };
    if sep < 6 {
        bail!("mountinfo line is malformed: {line}");
    }

    let mut flags = 0;
    for option in fields[5].split(',') {
        flags |= match option {
            "nosuid" => libc::MS_NOSUID as libc::c_ulong,
            "nodev" => libc::MS_NODEV as libc::c_ulong,
            "noexec" => libc::MS_NOEXEC as libc::c_ulong,
            "noatime" => libc::MS_NOATIME as libc::c_ulong,
            "nodiratime" => libc::MS_NODIRATIME as libc::c_ulong,
            "relatime" => libc::MS_RELATIME as libc::c_ulong,
            "strictatime" => libc::MS_STRICTATIME as libc::c_ulong,
            _ => 0,
        };
    }

    Ok(Some((
        PathBuf::from(unescape_mount_field(fields[4])),
        flags,
    )))
}

fn mount_virtual_fs(source: &str, fstype: &str, target: &Path) -> Result<()> {
    let source_c = CString::new(source).expect("literal source does not contain NUL");
    let fstype_c = CString::new(fstype).expect("literal fstype does not contain NUL");
    let target_c = c_path(target).context("virtual fs target path contains interior NUL byte")?;
    debug!(
        "userns-run: syscall mount({}, {}, {}, 0, NULL)",
        source,
        target.display(),
        fstype
    );
    let rc = unsafe {
        libc::mount(
            source_c.as_ptr(),
            target_c.as_ptr(),
            fstype_c.as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!("mount {fstype} failed at {}", target.display())
        });
    }
    Ok(())
}

fn remount_read_only(target: &Path) -> Result<()> {
    let target_c = c_path(target).context("remount target path contains interior NUL byte")?;
    let flags = (libc::MS_REMOUNT | libc::MS_RDONLY) as libc::c_ulong;
    debug!(
        "userns-run: syscall mount(NULL, {}, NULL, {flags:#x}, NULL)",
        target.display()
    );
    let rc = unsafe {
        libc::mount(
            std::ptr::null(),
            target_c.as_ptr(),
            std::ptr::null(),
            flags,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("remount read-only failed: {}", target.display()));
    }
    Ok(())
}

fn pivot_root_into(new_root: &Path) -> Result<()> {
    let new_root_c = c_path(new_root).context("pivot_root path contains interior NUL byte")?;
    let dot = CString::new(".").expect("literal '.' cannot contain NUL");
    let root = CString::new("/").expect("literal '/' cannot contain NUL");

    debug!("userns-run: syscall chdir({})", new_root.display());
    if unsafe { libc::chdir(new_root_c.as_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("chdir into fuse mount root failed before pivot_root");
    }

    debug!("userns-run: syscall pivot_root(., .)");
    let rc = unsafe { libc::syscall(libc::SYS_pivot_root, dot.as_ptr(), dot.as_ptr()) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("pivot_root('.', '.') failed");
    }

    debug!("userns-run: syscall umount2(., MNT_DETACH)");
    if unsafe { libc::umount2(dot.as_ptr(), libc::MNT_DETACH) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("umount2('.', MNT_DETACH) failed after pivot_root");
    }

    debug!("userns-run: syscall chdir(/)");
    if unsafe { libc::chdir(root.as_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error()).context("chdir('/') failed after pivot_root");
    }
    Ok(())
}

fn drop_to_target_ids(uid: libc::uid_t, gid: libc::gid_t) -> Result<()> {
    debug!("userns-run: syscall setresgid({gid}, {gid}, {gid})");
    if unsafe { libc::setresgid(gid, gid, gid) } != 0 {
        return Err(std::io::Error::last_os_error()).context("setresgid failed");
    }
    debug!("userns-run: syscall setresuid({uid}, {uid}, {uid})");
    if unsafe { libc::setresuid(uid, uid, uid) } != 0 {
        return Err(std::io::Error::last_os_error()).context("setresuid failed");
    }
    Ok(())
}

fn chdir_or_root(cwd: &Path) -> Result<()> {
    let cwd_c = c_path(cwd).context("cwd contains interior NUL byte")?;
    debug!("userns-run: syscall chdir({})", cwd.display());
    if unsafe { libc::chdir(cwd_c.as_ptr()) } == 0 {
        return Ok(());
    }

    let err = std::io::Error::last_os_error();
    if !matches!(
        err.raw_os_error(),
        Some(libc::ENOENT | libc::ENOTDIR | libc::EACCES)
    ) {
        return Err(err).with_context(|| format!("chdir to {} failed", cwd.display()));
    }

    let root = CString::new("/").expect("literal '/' cannot contain NUL");
    debug!("userns-run: syscall chdir(/) fallback after {err}");
    if unsafe { libc::chdir(root.as_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("fallback chdir('/') failed after {err}"));
    }
    Ok(())
}

fn run_pid_namespace_init_and_exec(
    config: &UsernsRunConfig,
    uid: libc::uid_t,
    gid: libc::gid_t,
) -> Result<i32> {
    let init_pid = fork_process("pidns-init")?;
    if init_pid > 0 {
        return wait_for_specific_child(init_pid);
    }

    apply_mount_plan_in_pid_namespace_init(&config.fuse_mount_root, &config.mount_plan)?;
    pivot_root_into(&config.fuse_mount_root)?;
    drop_to_target_ids(uid, gid)?;
    chdir_or_root(&config.cwd)?;

    let worker_pid = fork_process("pidns-worker")?;
    if worker_pid == 0 {
        let err = ProcessCommand::new(&config.program)
            .args(&config.args)
            .exec();
        eprintln!("leash2 exec failed: {err}");
        unsafe { libc::_exit(127) }
    }

    reap_pid_namespace(worker_pid)
}

fn reap_pid_namespace(worker_pid: libc::pid_t) -> Result<i32> {
    let mut worker_status = None;
    loop {
        let mut status: libc::c_int = 0;
        let rc = unsafe { libc::waitpid(-1, &mut status, 0) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::ECHILD) => break,
                _ => return Err(err).context("waitpid(-1) failed in pidns init"),
            }
        }
        if rc == worker_pid {
            worker_status = Some(status);
        }
    }
    Ok(worker_status.map(wait_status_to_exit_code).unwrap_or(1))
}

fn fork_process(label: &str) -> Result<libc::pid_t> {
    debug!("userns-run: syscall fork() for {label}");
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| format!("fork failed for {label}"));
    }
    Ok(pid)
}

fn wait_for_specific_child(pid: libc::pid_t) -> Result<i32> {
    loop {
        let mut status: libc::c_int = 0;
        let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err).with_context(|| format!("waitpid({pid}) failed"));
        }
        return Ok(wait_status_to_exit_code(status));
    }
}

fn wait_status_to_exit_code(status: libc::c_int) -> i32 {
    if libc::WIFEXITED(status) {
        return libc::WEXITSTATUS(status);
    }
    if libc::WIFSIGNALED(status) {
        return 128 + libc::WTERMSIG(status);
    }
    1
}

fn c_path(path: &Path) -> Result<CString, std::ffi::NulError> {
    CString::new(path.as_os_str().as_bytes())
}

fn unescape_mount_field(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut idx = 0usize;
    while idx < bytes.len() {
        if bytes[idx] == b'\\'
            && idx + 3 < bytes.len()
            && bytes[idx + 1..idx + 4]
                .iter()
                .all(|byte| matches!(byte, b'0'..=b'7'))
            && let Ok(value) = u8::from_str_radix(&input[idx + 1..idx + 4], 8)
        {
            out.push(value as char);
            idx += 4;
            continue;
        }
        out.push(bytes[idx] as char);
        idx += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_target_for_entry_maps_proc_sys_and_bind_paths_under_fuse_root() {
        let mount_root = Path::new("/run/user/1000/leash2/mount");

        assert_eq!(
            mount_target_for_entry(mount_root, &MountPlanEntry::Proc { read_only: true })
                .expect("proc target"),
            mount_root.join("proc")
        );
        assert_eq!(
            mount_target_for_entry(mount_root, &MountPlanEntry::Sys { read_only: false })
                .expect("sys target"),
            mount_root.join("sys")
        );
        assert_eq!(
            mount_target_for_entry(
                mount_root,
                &MountPlanEntry::Bind {
                    path: PathBuf::from("/dev/null"),
                    read_only: false,
                },
            )
            .expect("bind target"),
            mount_root.join("dev/null")
        );
    }

    #[test]
    fn wait_status_to_exit_code_handles_normal_exit_and_signal() {
        assert_eq!(wait_status_to_exit_code(7 << 8), 7);
        assert_eq!(wait_status_to_exit_code(libc::SIGTERM), 128 + libc::SIGTERM);
    }

    #[test]
    fn parse_mountinfo_mount_flags_preserves_locked_mount_attrs() {
        let line = "41 29 0:45 / /tmp/My\\040Mount rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw";

        let parsed = parse_mountinfo_mount_flags(line)
            .expect("parse mountinfo")
            .expect("mount entry");

        assert_eq!(parsed.0, PathBuf::from("/tmp/My Mount"));
        assert_eq!(
            parsed.1,
            (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC | libc::MS_RELATIME)
                as libc::c_ulong
        );
    }
}
