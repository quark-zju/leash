use std::collections::HashSet;
use std::ffi::OsStr;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::Result;
use fs_err as fs;
use memmap2::{Mmap, MmapMut};
use tempfile::tempdir;

use crate::access::{AccessController, AccessDecision, AccessRequest, AllowAll};
use crate::mirrorfs::MirrorFs;

#[derive(Debug, Default)]
struct ProcessNamePolicy {
    writers: HashSet<String>,
}

impl ProcessNamePolicy {
    fn new(writers: &[&str]) -> Self {
        Self {
            writers: writers.iter().map(|name| (*name).to_owned()).collect(),
        }
    }
}

impl AccessController for ProcessNamePolicy {
    fn check(&self, request: &AccessRequest<'_>) -> AccessDecision {
        if !request.operation.is_write() {
            return AccessDecision::Allow;
        }
        match request.caller.process_name.as_deref() {
            Some(name) if self.writers.contains(name) => AccessDecision::Allow,
            _ => AccessDecision::Deny(libc::EACCES),
        }
    }
}

#[derive(Debug, Default)]
struct WriteLockOnlyPolicy;

impl AccessController for WriteLockOnlyPolicy {
    fn check(&self, request: &AccessRequest<'_>) -> AccessDecision {
        match request.operation {
            crate::access::Operation::SetWriteLock => AccessDecision::Deny(libc::EACCES),
            _ => AccessDecision::Allow,
        }
    }
}

fn test_caller(name: &str) -> crate::access::Caller {
    MirrorFs::<AllowAll>::caller_for_test(name)
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

#[test]
fn process_name_policy_controls_writes() -> Result<()> {
    let dir = tempdir()?;
    let path = dir.path().join("db.sqlite");
    fs::write(&path, b"hello")?;

    let mut mirror = MirrorFs::new(
        dir.path().to_path_buf(),
        ProcessNamePolicy::new(&["sqlite"]),
    );
    let sqlite = test_caller("sqlite");
    let cat = test_caller("cat");

    let write_fh = mirror.open_for_test(&sqlite, &path, libc::O_RDWR)?;
    mirror.write_for_test(&sqlite, write_fh, 0, b"HELLO")?;
    mirror.release_for_test(write_fh);

    let denied = mirror.open_for_test(&cat, &path, libc::O_RDWR).unwrap_err();
    assert_eq!(
        denied
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::raw_os_error),
        Some(libc::EACCES)
    );
    assert_eq!(fs::read(&path)?, b"HELLO");
    Ok(())
}

#[test]
fn rename_keeps_open_handle_stat_working() -> Result<()> {
    let dir = tempdir()?;
    let from = dir.path().join("from.txt");
    let to = dir.path().join("to.txt");
    fs::write(&from, b"payload")?;

    let mut mirror = MirrorFs::new(dir.path().to_path_buf(), AllowAll);
    let caller = test_caller("sqlite");
    let fh = mirror.open_for_test(&caller, &from, libc::O_RDWR)?;
    let ino = mirror.ensure_ino(&from);

    mirror.rename_for_test(&caller, &from, &to)?;
    let attr = mirror.getattr_handle_for_test(&caller, fh)?;

    assert_eq!(attr.ino, ino);
    assert_eq!(mirror.host_path_for_ino(ino), Some(to.as_path()));
    assert!(!from.exists());
    assert!(to.exists());
    Ok(())
}

#[test]
fn mmap_observes_mirrored_writes() -> Result<()> {
    let dir = tempdir()?;
    let path = dir.path().join("mapped.bin");
    fs::write(&path, b"abcdef")?;

    let mut mirror = MirrorFs::new(dir.path().to_path_buf(), AllowAll);
    let caller = test_caller("sqlite");
    let fh = mirror.open_for_test(&caller, &path, libc::O_RDWR)?;
    mirror.write_for_test(&caller, fh, 2, b"ZZ")?;
    mirror.flush_for_test(&caller, fh)?;

    let file = fs::OpenOptions::new().read(true).write(true).open(&path)?;
    let mmap = unsafe { MmapMut::map_mut(&file)? };
    assert_eq!(&mmap[..], b"abZZef");
    Ok(())
}

#[test]
fn mmaps_survive_close_and_rename_and_stay_coherent() -> Result<()> {
    let dir = tempdir()?;
    let from = dir.path().join("mapped.bin");
    let to = dir.path().join("renamed.bin");
    fs::write(&from, b"abcdef")?;

    let mut mirror = MirrorFs::new(dir.path().to_path_buf(), AllowAll);
    let caller = test_caller("sqlite");
    let read_fh = mirror.open_for_test(&caller, &from, libc::O_RDONLY)?;
    let write_fh = mirror.open_for_test(&caller, &from, libc::O_RDWR)?;
    let read_file = mirror.dup_handle_for_test(read_fh)?;
    let write_file = mirror.dup_handle_for_test(write_fh)?;

    let read_map = unsafe { Mmap::map(&read_file)? };
    let mut write_map = unsafe { MmapMut::map_mut(&write_file)? };

    mirror.release_for_test(read_fh);
    mirror.release_for_test(write_fh);
    drop(read_file);
    drop(write_file);

    mirror.rename_for_test(&caller, &from, &to)?;

    write_map[1..5].copy_from_slice(b"WXYZ");
    write_map.flush()?;

    assert_eq!(&read_map[..], b"aWXYZf");

    drop(write_map);
    drop(read_map);

    let reopened = fs::read(&to)?;
    assert_eq!(reopened, b"aWXYZf");
    Ok(())
}

#[test]
fn lock_round_trip_succeeds() -> Result<()> {
    let dir = tempdir()?;
    let path = dir.path().join("locked.db");
    fs::write(&path, b"123456")?;

    let mut mirror = MirrorFs::new(dir.path().to_path_buf(), AllowAll);
    let caller = test_caller("sqlite");
    let fh = mirror.open_for_test(&caller, &path, libc::O_RDWR)?;

    mirror.setlk_for_test(&caller, fh, 0, 3, libc::F_WRLCK, false)?;
    let lock = mirror.getlk_for_test(&caller, fh, 0, u64::MAX, libc::F_WRLCK)?;
    mirror.setlk_for_test(&caller, fh, 0, 3, libc::F_UNLCK, false)?;

    assert_eq!(lock.0, 0);
    assert!(matches!(
        lock.2,
        libc::F_WRLCK | libc::F_UNLCK | libc::F_RDLCK
    ));
    Ok(())
}

#[test]
fn posix_lock_reopen_after_rename_is_same_process_noop() -> Result<()> {
    let dir = tempdir()?;
    let from = dir.path().join("locked.db");
    let to = dir.path().join("renamed.db");
    fs::write(&from, b"123456")?;

    let mut mirror = MirrorFs::new(dir.path().to_path_buf(), AllowAll);
    let caller = test_caller("sqlite");
    let fh = mirror.open_for_test(&caller, &from, libc::O_RDWR)?;

    mirror.setlk_for_test(&caller, fh, 0, 3, libc::F_WRLCK, false)?;
    mirror.rename_for_test(&caller, &from, &to)?;

    let reopened = mirror.open_for_test(&caller, &to, libc::O_RDWR)?;
    mirror.setlk_for_test(&caller, reopened, 0, 3, libc::F_WRLCK, false)?;

    mirror.setlk_for_test(&caller, fh, 0, 3, libc::F_UNLCK, false)?;
    mirror.release_for_test(reopened);
    mirror.release_for_test(fh);
    Ok(())
}

#[test]
fn flock_dup_is_noop_but_reopen_after_rename_conflicts() -> Result<()> {
    let dir = tempdir()?;
    let from = dir.path().join("locked.db");
    let to = dir.path().join("renamed.db");
    fs::write(&from, b"123456")?;

    let mut mirror = MirrorFs::new(dir.path().to_path_buf(), AllowAll);
    let caller = test_caller("sqlite");
    let fh = mirror.open_for_test(&caller, &from, libc::O_RDWR)?;
    let original = mirror.dup_handle_for_test(fh)?;
    let duplicated = original.try_clone()?;

    flock_exclusive_nonblocking(&original)?;
    flock_exclusive_nonblocking(&duplicated)?;

    mirror.rename_for_test(&caller, &from, &to)?;

    let reopened = fs::OpenOptions::new().read(true).write(true).open(&to)?;
    let err = flock_exclusive_nonblocking(&reopened).unwrap_err();
    assert!(
        matches!(err.raw_os_error(), Some(code) if code == libc::EWOULDBLOCK || code == libc::EAGAIN)
    );

    flock_unlock(&duplicated)?;
    flock_exclusive_nonblocking(&reopened)?;

    flock_unlock(&reopened)?;
    mirror.release_for_test(fh);
    Ok(())
}

#[test]
fn read_lock_and_getlk_are_not_treated_as_writes() -> Result<()> {
    let dir = tempdir()?;
    let path = dir.path().join("locked.db");
    fs::write(&path, b"123456")?;

    let mut mirror = MirrorFs::new(dir.path().to_path_buf(), WriteLockOnlyPolicy);
    let caller = test_caller("reader");
    let fh = mirror.open_for_test(&caller, &path, libc::O_RDWR)?;

    mirror.setlk_for_test(&caller, fh, 0, 3, libc::F_RDLCK, false)?;
    let _ = mirror.getlk_for_test(&caller, fh, 0, u64::MAX, libc::F_RDLCK)?;

    let denied = mirror
        .setlk_for_test(&caller, fh, 0, 3, libc::F_WRLCK, false)
        .unwrap_err();
    assert_eq!(
        denied
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::raw_os_error),
        Some(libc::EACCES)
    );

    mirror.setlk_for_test(&caller, fh, 0, 3, libc::F_UNLCK, false)?;
    Ok(())
}

#[test]
fn setattr_updates_file_mode() -> Result<()> {
    let dir = tempdir()?;
    let path = dir.path().join("mode.txt");
    fs::write(&path, b"hi")?;

    let mut mirror = MirrorFs::new(dir.path().to_path_buf(), AllowAll);
    let caller = test_caller("sqlite");
    mirror.setattr_for_test(&caller, &path, None, Some(0o600), None, None)?;

    let mode = fs::metadata(&path)?.permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    Ok(())
}

#[test]
fn readdir_lists_real_children() -> Result<()> {
    let dir = tempdir()?;
    fs::create_dir(dir.path().join("nested"))?;
    fs::write(dir.path().join("note.txt"), b"x")?;

    let mut mirror = MirrorFs::new(dir.path().to_path_buf(), AllowAll);
    let caller = test_caller("ls");
    let entries = mirror.list_children_for_test(&caller, dir.path())?;
    let names: HashSet<PathBuf> = entries
        .into_iter()
        .map(|(_, _, name)| Path::new(&name).to_path_buf())
        .collect();

    assert!(names.contains(Path::new("nested")));
    assert!(names.contains(Path::new("note.txt")));
    Ok(())
}

#[test]
fn create_makes_real_file() -> Result<()> {
    let dir = tempdir()?;
    let mut mirror = MirrorFs::new(dir.path().to_path_buf(), AllowAll);
    let caller = test_caller("sqlite");

    let (attr, fh) = mirror.create_for_test(
        &caller,
        dir.path(),
        OsStr::new("created.db"),
        0o640,
        0,
        libc::O_RDWR,
    )?;
    mirror.write_for_test(&caller, fh, 0, b"db")?;

    assert_eq!(attr.kind, fuser::FileType::RegularFile);
    assert_eq!(fs::read(dir.path().join("created.db"))?, b"db");
    Ok(())
}
