#![allow(unused)]
#[path = "../src/access.rs"]
mod access;
#[path = "../src/fuse_runtime.rs"]
mod fuse_runtime;
#[path = "../src/mirrorfs.rs"]
mod mirrorfs;
#[path = "../src/process_name.rs"]
mod process_name;
#[path = "../src/profile.rs"]
mod profile;
#[path = "../src/tail_ipc.rs"]
mod tail_ipc;

use std::collections::HashSet;
use std::ffi::OsStr;
use std::io::{ErrorKind, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use env_logger::Env;
use fs_err as fs;
use memmap2::{Mmap, MmapMut};
use tempfile::TempDir;

use access::{AccessController, AccessDecision, AccessRequest, Operation};
use mirrorfs::MirrorFs;
use profile::{NoIncludes, PathExeResolver, ProfileController};

type TestFn = fn(&TestContext) -> Result<()>;

struct TestCase {
    name: &'static str,
    func: TestFn,
}

macro_rules! test_case {
    ($name:ident) => {
        TestCase {
            name: stringify!($name),
            func: $name,
        }
    };
}

#[derive(Debug)]
struct IntegrationPolicy {
    allowed_writer: String,
}

impl IntegrationPolicy {
    fn new(allowed_writer: String) -> Self {
        Self { allowed_writer }
    }
}

impl AccessController for IntegrationPolicy {
    fn check(&self, request: &AccessRequest<'_>) -> AccessDecision {
        if request.operation.is_write()
            && request.caller.process_name.as_deref() != Some(self.allowed_writer.as_str())
        {
            return AccessDecision::Deny(libc::EACCES);
        }
        if request.operation.is_write() && path_has_component(request.path, "deny_writes") {
            return AccessDecision::Deny(libc::EACCES);
        }
        if request.operation == Operation::SetWriteLock
            && path_has_component(request.path, "write_lock_denied")
        {
            return AccessDecision::Deny(libc::EACCES);
        }
        AccessDecision::Allow
    }
}

struct MountedSuite {
    _tempdir: TempDir,
    backing_root: PathBuf,
    mount_root: PathBuf,
    session: Option<fuser::BackgroundSession>,
}

impl MountedSuite {
    fn new() -> Result<Self> {
        let process_name = current_process_name()?;
        Self::with_policy(IntegrationPolicy::new(process_name))
    }

    fn with_policy<P: AccessController>(policy: P) -> Result<Self> {
        Self::with_policy_factory(|_| Ok(policy))
    }

    fn with_policy_factory<P, F>(policy_factory: F) -> Result<Self>
    where
        P: AccessController,
        F: FnOnce(&Path) -> Result<P>,
    {
        let tempdir = tempfile::tempdir()?;
        let backing_root = tempdir.path().join("backing");
        let mount_root = tempdir.path().join("mount");
        fs::create_dir(&backing_root)?;
        fs::create_dir(&mount_root)?;

        let policy = policy_factory(&backing_root)?;
        let mirror = MirrorFs::new(backing_root.clone(), policy);
        let session = unsafe { mirror.mount_background(&mount_root)? };
        wait_for_directory(&mount_root)?;

        Ok(Self {
            _tempdir: tempdir,
            backing_root,
            mount_root,
            session: Some(session),
        })
    }

    fn context(&self, name: &str) -> Result<TestContext> {
        let backing_path = self.backing_root.join(name);
        fs::create_dir(&backing_path)?;
        let fuse_path = self.mount_root.join(name);
        wait_for_path(&fuse_path)?;
        Ok(TestContext {
            backing_path,
            fuse_path,
        })
    }
}

impl Drop for MountedSuite {
    fn drop(&mut self) {
        if let Some(session) = self.session.take() {
            drop(session);
        }
    }
}

struct TestContext {
    backing_path: PathBuf,
    fuse_path: PathBuf,
}

fn main() -> ExitCode {
    // Common `RUST_LOG` settings for this harness:
    // - `RUST_LOG=integration=debug` enables only this test crate's logs.
    // - `RUST_LOG=integration=debug,fuser=off` enables this crate and silences fuser.
    // - `RUST_LOG=debug` enables all logs, including fuser internals.
    let _ = env_logger::Builder::from_env(Env::default().default_filter_or("info")).try_init();
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("integration test run failed: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    if !Path::new("/dev/fuse").exists() {
        eprintln!("skipping integration tests: /dev/fuse not found");
        return Ok(());
    }

    let suite = MountedSuite::new()?;
    let mut failures = Vec::new();

    for case in test_cases() {
        let ctx = suite.context(case.name)?;
        eprintln!("test {} ...", case.name);
        match catch_unwind(AssertUnwindSafe(|| (case.func)(&ctx))) {
            Ok(Ok(())) => eprintln!("test {} ... ok", case.name),
            Ok(Err(err)) => {
                eprintln!("test {} ... FAILED\n{err:#}", case.name);
                failures.push(case.name);
            }
            Err(_) => {
                eprintln!("test {} ... FAILED\npanic during test execution", case.name);
                failures.push(case.name);
            }
        }
    }

    if failures.is_empty() {
        run_profile_policy_tests()
    } else {
        bail!(
            "{} integration subtests failed: {}",
            failures.len(),
            failures.join(", ")
        );
    }
}

fn run_profile_policy_tests() -> Result<()> {
    eprintln!("test profile_policy_hide_and_implicit_ancestor_visibility ...");
    profile_policy_hide_and_implicit_ancestor_visibility()?;
    eprintln!("test profile_policy_hide_and_implicit_ancestor_visibility ... ok");

    eprintln!("test profile_mkdir_prefers_eexist_for_visible_existing_directory ...");
    profile_mkdir_prefers_eexist_for_visible_existing_directory()?;
    eprintln!("test profile_mkdir_prefers_eexist_for_visible_existing_directory ... ok");

    eprintln!("test profile_symlink_target_policy_blocks_open_and_setattr ...");
    profile_symlink_target_policy_blocks_open_and_setattr()?;
    eprintln!("test profile_symlink_target_policy_blocks_open_and_setattr ... ok");
    Ok(())
}

fn test_cases() -> Vec<TestCase> {
    vec![
        test_case!(process_name_policy_controls_writes),
        test_case!(rename_keeps_open_handle_stat_working),
        test_case!(mmap_observes_mirrored_writes),
        test_case!(mmaps_survive_close_and_rename_and_stay_coherent),
        test_case!(hardlink_shares_inode_and_content),
        test_case!(hardlink_alias_survives_original_unlink),
        test_case!(lock_round_trip_succeeds),
        test_case!(posix_lock_reopen_after_rename_is_same_process_noop),
        test_case!(posix_partial_unlock_updates_backing_range_conflicts),
        test_case!(posix_range_lock_conflicts_with_backing_path_open),
        test_case!(posix_getlk_reports_backing_path_conflict),
        test_case!(blocking_posix_lock_requests_are_rejected),
        test_case!(flock_dup_is_noop_but_reopen_after_rename_conflicts),
        test_case!(flock_on_mirror_handle_conflicts_with_backing_path_open),
        test_case!(read_lock_and_getlk_are_not_treated_as_writes),
        test_case!(setattr_updates_file_mode),
        test_case!(readdir_lists_real_children),
        test_case!(create_makes_real_file),
    ]
}

fn current_process_name() -> Result<String> {
    let raw = fs::read_to_string("/proc/self/comm")?;
    let name = raw.trim().to_owned();
    if name.is_empty() {
        bail!("current process name is empty");
    }
    Ok(name)
}

fn path_has_component(path: &Path, needle: &str) -> bool {
    path.components()
        .any(|component| component.as_os_str() == OsStr::new(needle))
}

fn wait_for_directory(path: &Path) -> Result<()> {
    wait_for_path(path)?;
    if !fs::metadata(path)?.is_dir() {
        bail!("{} is not a directory", path.display());
    }
    Ok(())
}

fn wait_for_path(path: &Path) -> Result<()> {
    let mut last_err = None;
    for _ in 0..100 {
        match fs::metadata(path) {
            Ok(_) => return Ok(()),
            Err(err) => last_err = Some(err),
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    match last_err {
        Some(err) => Err(err.into()),
        None => Err(anyhow!("{} did not appear", path.display())),
    }
}

fn wait_for_symlink_path(path: &Path) -> Result<()> {
    let mut last_err = None;
    for _ in 0..100 {
        match fs::symlink_metadata(path) {
            Ok(_) => return Ok(()),
            Err(err) => last_err = Some(err),
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    match last_err {
        Some(err) => Err(err.into()),
        None => Err(anyhow!("{} did not appear", path.display())),
    }
}

fn flock_exclusive_nonblocking(file: &fs::File) -> std::io::Result<()> {
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn flock_unlock(file: &fs::File) -> std::io::Result<()> {
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn setlk(file: &fs::File, start: u64, end: u64, typ: i32, wait: bool) -> std::io::Result<()> {
    let mut flock = libc::flock {
        l_type: typ as libc::c_short,
        l_whence: libc::SEEK_SET as libc::c_short,
        l_start: start as libc::off_t,
        l_len: if end == u64::MAX {
            0
        } else {
            end.saturating_sub(start).saturating_add(1) as libc::off_t
        },
        l_pid: 0,
    };
    let cmd = if wait { libc::F_SETLKW } else { libc::F_SETLK };
    let rc = unsafe { libc::fcntl(file.as_raw_fd(), cmd, &mut flock) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn getlk(file: &fs::File, start: u64, end: u64, typ: i32) -> std::io::Result<(u64, u64, i32)> {
    let mut flock = libc::flock {
        l_type: typ as libc::c_short,
        l_whence: libc::SEEK_SET as libc::c_short,
        l_start: start as libc::off_t,
        l_len: if end == u64::MAX {
            0
        } else {
            end.saturating_sub(start).saturating_add(1) as libc::off_t
        },
        l_pid: 0,
    };
    let rc = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETLK, &mut flock) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let out_start = flock.l_start.max(0) as u64;
    let out_end = if flock.l_len == 0 {
        u64::MAX
    } else {
        out_start
            .saturating_add(flock.l_len as u64)
            .saturating_sub(1)
    };
    Ok((out_start, out_end, flock.l_type as i32))
}

fn process_name_policy_controls_writes(ctx: &TestContext) -> Result<()> {
    let allowed = ctx.fuse_path.join("allowed.db");
    let denied_dir = ctx.backing_path.join("deny_writes");
    let denied = ctx.fuse_path.join("deny_writes/denied.db");
    fs::create_dir(&denied_dir)?;
    fs::write(ctx.backing_path.join("allowed.db"), b"hello")?;
    fs::write(denied_dir.join("denied.db"), b"hello")?;

    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&allowed)?;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(b"HELLO")?;
    file.sync_data()?;

    let err = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&denied)
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    assert_eq!(fs::read(ctx.backing_path.join("allowed.db"))?, b"HELLO");
    Ok(())
}

fn rename_keeps_open_handle_stat_working(ctx: &TestContext) -> Result<()> {
    let from = ctx.fuse_path.join("from.txt");
    let to = ctx.fuse_path.join("to.txt");
    fs::write(&from, b"payload")?;

    let file = fs::OpenOptions::new().read(true).write(true).open(&from)?;
    let before = file.metadata()?;
    fs::rename(&from, &to)?;
    let after = file.metadata()?;

    assert_eq!(before.ino(), after.ino());
    assert!(!from.exists());
    assert!(to.exists());
    Ok(())
}

fn mmap_observes_mirrored_writes(ctx: &TestContext) -> Result<()> {
    let fuse_path = ctx.fuse_path.join("mapped.bin");
    let backing_path = ctx.backing_path.join("mapped.bin");
    fs::write(&fuse_path, b"abcdef")?;

    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&fuse_path)?;
    file.seek(SeekFrom::Start(2))?;
    file.write_all(b"ZZ")?;
    file.sync_data()?;

    let backing = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&backing_path)?;
    let mmap = unsafe { MmapMut::map_mut(&backing)? };
    assert_eq!(&mmap[..], b"abZZef");
    Ok(())
}

fn mmaps_survive_close_and_rename_and_stay_coherent(ctx: &TestContext) -> Result<()> {
    let from = ctx.fuse_path.join("mapped.bin");
    let to = ctx.fuse_path.join("renamed.bin");
    let backing_from = ctx.backing_path.join("mapped.bin");
    fs::write(&from, b"abcdef")?;

    let read_file = fs::OpenOptions::new().read(true).open(&from)?;
    let write_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&backing_from)?;
    let read_map = unsafe { Mmap::map(&read_file)? };
    let mut write_map = unsafe { MmapMut::map_mut(&write_file)? };

    drop(read_file);
    drop(write_file);
    fs::rename(&from, &to)?;

    write_map[1..5].copy_from_slice(b"WXYZ");
    write_map.flush()?;
    assert_eq!(&read_map[..], b"aWXYZf");

    drop(write_map);
    drop(read_map);

    assert_eq!(fs::read(&to)?, b"aWXYZf");
    assert_eq!(fs::read(ctx.backing_path.join("renamed.bin"))?, b"aWXYZf");
    Ok(())
}

fn hardlink_shares_inode_and_content(ctx: &TestContext) -> Result<()> {
    let original = ctx.fuse_path.join("original.db");
    let alias = ctx.fuse_path.join("alias.db");
    fs::write(&original, b"abcdef")?;
    fs::hard_link(&original, &alias)?;

    assert_eq!(fs::metadata(&original)?.ino(), fs::metadata(&alias)?.ino());

    let mut file = fs::OpenOptions::new().read(true).write(true).open(&alias)?;
    file.seek(SeekFrom::Start(2))?;
    file.write_all(b"ZZ")?;
    file.sync_data()?;

    assert_eq!(fs::read(&original)?, b"abZZef");
    assert_eq!(fs::read(&alias)?, b"abZZef");
    Ok(())
}

fn hardlink_alias_survives_original_unlink(ctx: &TestContext) -> Result<()> {
    let original = ctx.fuse_path.join("original.db");
    let alias = ctx.fuse_path.join("alias.db");
    fs::write(&original, b"abcdef")?;
    fs::hard_link(&original, &alias)?;
    fs::remove_file(&original)?;

    assert_eq!(fs::read(&alias)?, b"abcdef");
    assert_eq!(fs::metadata(&alias)?.nlink(), 1);
    Ok(())
}

fn lock_round_trip_succeeds(ctx: &TestContext) -> Result<()> {
    let path = ctx.fuse_path.join("locked.db");
    fs::write(&path, b"123456")?;
    let file = fs::OpenOptions::new().read(true).write(true).open(&path)?;

    setlk(&file, 0, 3, libc::F_WRLCK, false)?;
    let lock = getlk(&file, 0, u64::MAX, libc::F_WRLCK)?;
    setlk(&file, 0, 3, libc::F_UNLCK, false)?;

    assert_eq!(lock.0, 0);
    assert!(matches!(
        lock.2,
        libc::F_WRLCK | libc::F_UNLCK | libc::F_RDLCK
    ));
    Ok(())
}

fn posix_lock_reopen_after_rename_is_same_process_noop(ctx: &TestContext) -> Result<()> {
    let from = ctx.fuse_path.join("locked.db");
    let to = ctx.fuse_path.join("renamed.db");
    fs::write(&from, b"123456")?;

    let file = fs::OpenOptions::new().read(true).write(true).open(&from)?;
    setlk(&file, 0, 3, libc::F_WRLCK, false)?;
    fs::rename(&from, &to)?;

    let reopened = fs::OpenOptions::new().read(true).write(true).open(&to)?;
    setlk(&reopened, 0, 3, libc::F_WRLCK, false)?;

    setlk(&file, 0, 3, libc::F_UNLCK, false)?;
    Ok(())
}

fn posix_partial_unlock_updates_backing_range_conflicts(ctx: &TestContext) -> Result<()> {
    let fuse_path = ctx.fuse_path.join("locked.db");
    let backing_path = ctx.backing_path.join("locked.db");
    fs::write(&fuse_path, b"123456")?;

    let mirror_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&fuse_path)?;
    let backing_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&backing_path)?;

    setlk(&mirror_file, 10, 20, libc::F_WRLCK, false)?;

    let err = setlk(&backing_file, 15, 18, libc::F_WRLCK, false).unwrap_err();
    assert!(matches!(
        err.raw_os_error(),
        Some(code) if code == libc::EACCES || code == libc::EAGAIN
    ));

    setlk(&mirror_file, 15, 20, libc::F_UNLCK, false)?;
    setlk(&backing_file, 15, 18, libc::F_WRLCK, false)?;
    setlk(&backing_file, 15, 18, libc::F_UNLCK, false)?;

    let err = setlk(&backing_file, 10, 14, libc::F_WRLCK, false).unwrap_err();
    assert!(matches!(
        err.raw_os_error(),
        Some(code) if code == libc::EACCES || code == libc::EAGAIN
    ));

    setlk(&mirror_file, 10, 14, libc::F_UNLCK, false)?;
    Ok(())
}

fn posix_range_lock_conflicts_with_backing_path_open(ctx: &TestContext) -> Result<()> {
    let fuse_path = ctx.fuse_path.join("locked.db");
    let backing_path = ctx.backing_path.join("locked.db");
    fs::write(&fuse_path, b"123456")?;

    let mirror_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&fuse_path)?;
    let backing_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&backing_path)?;

    setlk(&mirror_file, 0x40000001, 0x40000001, libc::F_WRLCK, false)?;
    let err = setlk(&backing_file, 0x40000001, 0x40000001, libc::F_WRLCK, false).unwrap_err();
    assert!(matches!(
        err.raw_os_error(),
        Some(code) if code == libc::EACCES || code == libc::EAGAIN
    ));

    setlk(&mirror_file, 0x40000001, 0x40000001, libc::F_UNLCK, false)?;
    setlk(&backing_file, 0x40000001, 0x40000001, libc::F_WRLCK, false)?;
    setlk(&backing_file, 0x40000001, 0x40000001, libc::F_UNLCK, false)?;
    Ok(())
}

fn posix_getlk_reports_backing_path_conflict(ctx: &TestContext) -> Result<()> {
    let fuse_path = ctx.fuse_path.join("locked.db");
    let backing_path = ctx.backing_path.join("locked.db");
    fs::write(&fuse_path, b"123456")?;

    let mut ready_pipe = [0; 2];
    let mut done_pipe = [0; 2];
    if unsafe { libc::pipe(ready_pipe.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if unsafe { libc::pipe(done_pipe.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if pid == 0 {
        unsafe {
            libc::close(ready_pipe[0]);
            libc::close(done_pipe[1]);
        }
        let result = (|| -> std::io::Result<()> {
            let backing_file = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&backing_path)?;
            setlk(&backing_file, 0x40000001, 0x40000001, libc::F_WRLCK, false)?;
            let signal = [1u8];
            if unsafe { libc::write(ready_pipe[1], signal.as_ptr().cast(), 1) } != 1 {
                return Err(std::io::Error::last_os_error());
            }
            let mut wait = [0u8; 1];
            if unsafe { libc::read(done_pipe[0], wait.as_mut_ptr().cast(), 1) } < 0 {
                return Err(std::io::Error::last_os_error());
            }
            setlk(&backing_file, 0x40000001, 0x40000001, libc::F_UNLCK, false)?;
            Ok(())
        })();
        unsafe {
            libc::close(ready_pipe[1]);
            libc::close(done_pipe[0]);
            libc::_exit(if result.is_ok() { 0 } else { 1 });
        }
    }

    unsafe {
        libc::close(ready_pipe[1]);
        libc::close(done_pipe[0]);
    }
    let mut ready = [0u8; 1];
    if unsafe { libc::read(ready_pipe[0], ready.as_mut_ptr().cast(), 1) } != 1 {
        return Err(std::io::Error::last_os_error().into());
    }

    let mirror_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&fuse_path)?;
    let (_start, _end, typ) = getlk(&mirror_file, 0x40000001, 0x40000001, libc::F_WRLCK)?;
    assert_ne!(
        typ,
        libc::F_UNLCK,
        "expected getlk to report external conflict"
    );

    let done = [1u8];
    if unsafe { libc::write(done_pipe[1], done.as_ptr().cast(), 1) } != 1 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut status = 0;
    if unsafe { libc::waitpid(pid, &mut status, 0) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
        bail!("child lock holder exited abnormally: status={status}");
    }

    let (_start, _end, typ) = getlk(&mirror_file, 0x40000001, 0x40000001, libc::F_WRLCK)?;
    assert_eq!(
        typ,
        libc::F_UNLCK,
        "expected getlk to clear after child unlock"
    );
    Ok(())
}

fn blocking_posix_lock_requests_are_rejected(ctx: &TestContext) -> Result<()> {
    let path = ctx.fuse_path.join("locked.db");
    fs::write(&path, b"123456")?;

    let file = fs::OpenOptions::new().read(true).write(true).open(&path)?;
    let err = setlk(&file, 0, 3, libc::F_WRLCK, true).unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::EINVAL));
    Ok(())
}

fn flock_dup_is_noop_but_reopen_after_rename_conflicts(ctx: &TestContext) -> Result<()> {
    let from = ctx.fuse_path.join("locked.db");
    let to = ctx.fuse_path.join("renamed.db");
    fs::write(&from, b"123456")?;

    let original = fs::OpenOptions::new().read(true).write(true).open(&from)?;
    let duplicated = original.try_clone()?;
    flock_exclusive_nonblocking(&original)?;
    flock_exclusive_nonblocking(&duplicated)?;

    fs::rename(&from, &to)?;
    let reopened = fs::OpenOptions::new().read(true).write(true).open(&to)?;
    let err = flock_exclusive_nonblocking(&reopened).unwrap_err();
    assert!(
        matches!(err.raw_os_error(), Some(code) if code == libc::EWOULDBLOCK || code == libc::EAGAIN)
    );

    flock_unlock(&duplicated)?;
    flock_exclusive_nonblocking(&reopened)?;
    flock_unlock(&reopened)?;
    Ok(())
}

fn flock_on_mirror_handle_conflicts_with_backing_path_open(ctx: &TestContext) -> Result<()> {
    let fuse_path = ctx.fuse_path.join("locked.db");
    let backing_path = ctx.backing_path.join("locked.db");
    fs::write(&fuse_path, b"123456")?;

    let mirror_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&fuse_path)?;
    let backing_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&backing_path)?;
    flock_exclusive_nonblocking(&mirror_file)?;

    match flock_exclusive_nonblocking(&backing_file) {
        Err(err) if matches!(err.raw_os_error(), Some(code) if code == libc::EWOULDBLOCK || code == libc::EAGAIN) =>
            {}
        Ok(()) => panic!("expected mounted flock to conflict with a separate backing-path open"),
        Err(err) => return Err(err.into()),
    }

    flock_unlock(&mirror_file)?;
    flock_exclusive_nonblocking(&backing_file)?;
    flock_unlock(&backing_file)?;
    Ok(())
}

fn read_lock_and_getlk_are_not_treated_as_writes(ctx: &TestContext) -> Result<()> {
    let deny_dir = ctx.backing_path.join("write_lock_denied");
    fs::create_dir(&deny_dir)?;
    let path = ctx.fuse_path.join("write_lock_denied/locked.db");
    fs::write(deny_dir.join("locked.db"), b"123456")?;

    let file = fs::OpenOptions::new().read(true).write(true).open(&path)?;
    setlk(&file, 0, 3, libc::F_RDLCK, false)?;
    let _ = getlk(&file, 0, u64::MAX, libc::F_RDLCK)?;

    let err = setlk(&file, 0, 3, libc::F_WRLCK, false).unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::EACCES));

    setlk(&file, 0, 3, libc::F_UNLCK, false)?;
    Ok(())
}

fn setattr_updates_file_mode(ctx: &TestContext) -> Result<()> {
    let path = ctx.fuse_path.join("mode.txt");
    fs::write(&path, b"hi")?;
    fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    let mode = fs::metadata(ctx.backing_path.join("mode.txt"))?
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
    Ok(())
}

fn readdir_lists_real_children(ctx: &TestContext) -> Result<()> {
    fs::create_dir(ctx.fuse_path.join("nested"))?;
    fs::write(ctx.fuse_path.join("note.txt"), b"x")?;

    let names: HashSet<PathBuf> = fs::read_dir(&ctx.fuse_path)?
        .map(|entry| entry.map(|entry| Path::new(&entry.file_name()).to_path_buf()))
        .collect::<std::io::Result<_>>()?;

    assert!(names.contains(Path::new("nested")));
    assert!(names.contains(Path::new("note.txt")));
    Ok(())
}

fn create_makes_real_file(ctx: &TestContext) -> Result<()> {
    let path = ctx.fuse_path.join("created.db");
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    file.write_all(b"db")?;
    file.sync_data()?;

    assert_eq!(fs::read(ctx.backing_path.join("created.db"))?, b"db");
    Ok(())
}

fn profile_policy_hide_and_implicit_ancestor_visibility() -> Result<()> {
    let suite = MountedSuite::with_policy_factory(|backing_root| {
        let profile_src = format!(
            r#"
            {root}/visible.txt rw
            {root}/foo/**/*.txt rw
            {root}/foo hide
            "#,
            root = backing_root.display()
        );
        let profile = profile::parse(
            &profile_src,
            Path::new("/tmp"),
            Path::new("/tmp"),
            &NoIncludes,
            &PathExeResolver,
        )?;
        Ok(ProfileController::new(profile))
    })?;

    fs::write(suite.backing_root.join("visible.txt"), b"visible")?;
    fs::write(suite.backing_root.join("hidden.txt"), b"hidden")?;
    fs::create_dir_all(suite.backing_root.join("foo/sub/deeper"))?;
    fs::write(suite.backing_root.join("foo/sub/ok.txt"), b"ok")?;
    fs::write(suite.backing_root.join("foo/sub/no.bin"), b"no")?;
    fs::write(
        suite.backing_root.join("foo/sub/deeper/nested.txt"),
        b"nested",
    )?;
    fs::write(
        suite.backing_root.join("foo/sub/deeper/nested.bin"),
        b"nested-bin",
    )?;

    wait_for_path(&suite.mount_root.join("visible.txt"))?;
    wait_for_path(&suite.mount_root.join("foo"))?;

    let root_entries = read_dir_names(&suite.mount_root)?;
    assert!(root_entries.contains(Path::new("visible.txt")));
    assert!(root_entries.contains(Path::new("foo")));
    assert!(!root_entries.contains(Path::new("hidden.txt")));
    let hidden_stat_err = fs::symlink_metadata(suite.mount_root.join("hidden.txt")).unwrap_err();
    assert_eq!(hidden_stat_err.kind(), ErrorKind::NotFound);

    let create_hidden = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(suite.mount_root.join("hidden.txt"))
        .unwrap_err();
    assert_eq!(create_hidden.kind(), ErrorKind::PermissionDenied);

    let foo_metadata = fs::symlink_metadata(suite.mount_root.join("foo"))?;
    assert!(foo_metadata.is_dir());

    let foo_entries = read_dir_names(&suite.mount_root.join("foo"))?;
    assert!(foo_entries.contains(Path::new("sub")));

    let sub_entries = read_dir_names(&suite.mount_root.join("foo/sub"))?;
    assert!(sub_entries.contains(Path::new("ok.txt")));
    assert!(sub_entries.contains(Path::new("deeper")));
    assert!(!sub_entries.contains(Path::new("no.bin")));

    let nested_entries = read_dir_names(&suite.mount_root.join("foo/sub/deeper"))?;
    assert!(nested_entries.contains(Path::new("nested.txt")));
    assert!(!nested_entries.contains(Path::new("nested.bin")));

    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(suite.mount_root.join("foo/sub/new.txt"))?;
    file.write_all(b"new")?;
    file.sync_data()?;
    assert_eq!(
        fs::read(suite.backing_root.join("foo/sub/new.txt"))?,
        b"new"
    );

    let create_bin = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(suite.mount_root.join("foo/sub/new.bin"))
        .unwrap_err();
    assert_eq!(create_bin.kind(), ErrorKind::PermissionDenied);
    Ok(())
}

fn profile_mkdir_prefers_eexist_for_visible_existing_directory() -> Result<()> {
    let suite = MountedSuite::with_policy_factory(|backing_root| {
        let profile_src = format!("{} ro\n", backing_root.display());
        let profile = profile::parse(
            &profile_src,
            Path::new("/tmp"),
            Path::new("/tmp"),
            &NoIncludes,
            &PathExeResolver,
        )?;
        Ok(ProfileController::new(profile))
    })?;

    fs::create_dir(suite.backing_root.join("existing"))?;
    wait_for_path(&suite.mount_root.join("existing"))?;

    let err = fs::create_dir(suite.mount_root.join("existing")).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::AlreadyExists);
    Ok(())
}

fn profile_symlink_target_policy_blocks_open_and_setattr() -> Result<()> {
    let suite = MountedSuite::with_policy_factory(|backing_root| {
        let profile_src = format!(
            "{} rw\n{} deny\n",
            backing_root.join("allowed").display(),
            backing_root.join("denied").display()
        );
        let profile = profile::parse(
            &profile_src,
            Path::new("/tmp"),
            Path::new("/tmp"),
            &NoIncludes,
            &PathExeResolver,
        )?;
        Ok(ProfileController::new(profile))
    })?;

    fs::create_dir_all(suite.backing_root.join("allowed"))?;
    fs::create_dir_all(suite.backing_root.join("denied"))?;
    fs::write(suite.backing_root.join("denied/secret.txt"), b"secret")?;
    std::os::unix::fs::symlink(
        "../denied/secret.txt",
        suite.backing_root.join("allowed/secret-link"),
    )?;
    wait_for_symlink_path(&suite.mount_root.join("allowed/secret-link"))?;

    let read_err = fs::read(suite.mount_root.join("allowed/secret-link")).unwrap_err();
    assert_eq!(read_err.kind(), ErrorKind::PermissionDenied);

    let chmod_err = fs::set_permissions(
        suite.mount_root.join("allowed/secret-link"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap_err();
    assert_eq!(chmod_err.kind(), ErrorKind::PermissionDenied);
    Ok(())
}

fn read_dir_names(path: &Path) -> Result<HashSet<PathBuf>> {
    Ok(fs::read_dir(path)?
        .map(|entry| entry.map(|entry| Path::new(&entry.file_name()).to_path_buf()))
        .collect::<std::io::Result<_>>()?)
}
