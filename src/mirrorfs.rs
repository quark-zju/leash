use parking_lot::RwLock;
use std::collections::{BTreeMap, HashMap};
use std::ffi::{CString, OsStr};
use std::fs::Metadata;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use fs_err as fs;
use fs_err::os::unix::fs::OpenOptionsExt as FsOpenOptionsExt;
use fuser::{
    AccessFlags, Config, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation,
    INodeNo, InitFlags, KernelConfig, LockOwner, MountOption, OpenFlags, RenameFlags, ReplyAttr,
    ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyLock, ReplyOpen,
    ReplyStatfs, ReplyWrite, ReplyXattr, Request, TimeOrNow, WriteFlags,
};
use libc::{EACCES, EEXIST, EINVAL, EIO, EISDIR, ENOENT, ENOSYS, ENOTDIR};
use log::{debug, warn};

use crate::access::{
    AccessController, AccessDecision, AccessRequest, Caller, Operation, ProcCallerCondition,
};
use crate::process_name::set_process_name;
use crate::tail_ipc::{self, EventKind};

const TTL: Duration = Duration::from_secs(60);
const ROOT_INO: u64 = 1;

pub struct MirrorFs<P> {
    root: PathBuf,
    policy: P,
    tail_sink: Option<tail_ipc::Sink>,
    broker: LockBroker,
    next_ino: u64,
    next_fh: u64,
    ino_to_paths: HashMap<u64, Vec<PathBuf>>,
    path_to_ino: HashMap<PathBuf, u64>,
    lookup_counts: HashMap<u64, u64>,
    handles: HashMap<u64, OpenHandle>,
    lock_states: HashMap<u64, InodeLockState>,
}

struct OpenHandle {
    ino: u64,
    file: fs::File,
    writable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum LockMode {
    Shared,
    Exclusive,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OwnedRange {
    start: u64,
    end: u64,
    mode: LockMode,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct OwnerLockState {
    ranges: Vec<OwnedRange>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct InodeLockState {
    owners: BTreeMap<u64, OwnerLockState>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProjectedRange {
    start: u64,
    end: u64,
    mode: LockMode,
}

#[derive(Debug)]
struct LockBroker {
    stream: UnixStream,
    child_pid: libc::pid_t,
}

#[derive(Debug)]
struct BrokerFileState {
    file: fs::File,
    projection: Vec<ProjectedRange>,
}

struct FuseMirrorFs<P> {
    inner: RwLock<MirrorFs<P>>,
}

impl<P> FuseMirrorFs<P> {
    fn new(inner: MirrorFs<P>) -> Self {
        Self {
            inner: RwLock::new(inner),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatFs {
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub files: u64,
    pub ffree: u64,
    pub bsize: u32,
    pub namelen: u32,
    pub frsize: u32,
}

impl<P: AccessController> MirrorFs<P> {
    pub fn new(root: PathBuf, policy: P) -> Self {
        Self::new_with_tail(root, policy, None)
    }

    pub fn new_with_tail(root: PathBuf, policy: P, tail_sink: Option<tail_ipc::Sink>) -> Self {
        let mut ino_to_paths = HashMap::new();
        let mut path_to_ino = HashMap::new();
        ino_to_paths.insert(ROOT_INO, vec![root.clone()]);
        path_to_ino.insert(root.clone(), ROOT_INO);

        Self {
            root,
            policy,
            tail_sink,
            broker: LockBroker::spawn().expect("failed to spawn lock broker"),
            next_ino: ROOT_INO + 1,
            next_fh: 1,
            ino_to_paths,
            path_to_ino,
            lookup_counts: HashMap::new(),
            handles: HashMap::new(),
            lock_states: HashMap::new(),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn emit_tail_event(
        &self,
        kind: EventKind,
        path: Option<PathBuf>,
        errno: Option<i32>,
        detail: Option<String>,
    ) {
        self.emit_tail_event_lazy(kind, || (path, errno, detail));
    }

    fn emit_tail_event_lazy<F>(&self, kind: EventKind, build: F)
    where
        F: FnOnce() -> (Option<PathBuf>, Option<i32>, Option<String>),
    {
        if let Some(sink) = &self.tail_sink {
            let (path, errno, detail) = build();
            sink.emit(tail_ipc::Event {
                kind,
                path,
                errno,
                detail,
            });
        }
    }

    pub fn mount(self, mountpoint: &Path) -> Result<()> {
        let options = fuse_mount_options();
        let mut config = Config::default();
        config.mount_options = options;
        config.n_threads = Some(fuse_worker_threads());
        fuser::mount2(FuseMirrorFs::new(self), mountpoint, &config).with_context(|| {
            format!(
                "failed to mount mirror filesystem at {}",
                mountpoint.display()
            )
        })
    }

    pub unsafe fn mount_background(self, mountpoint: &Path) -> Result<fuser::BackgroundSession> {
        let options = fuse_mount_options();
        let mut config = Config::default();
        config.mount_options = options;
        config.n_threads = Some(fuse_worker_threads());
        fuser::spawn_mount2(FuseMirrorFs::new(self), mountpoint, &config).with_context(|| {
            format!(
                "failed to mount mirror filesystem in background at {}",
                mountpoint.display()
            )
        })
    }

    #[allow(dead_code)]
    pub(crate) fn caller_for_test(process_name: &str) -> Caller {
        Caller::with_process_name(None, Some(process_name.to_owned()))
    }

    pub(crate) fn ensure_ino(&mut self, path: &Path) -> u64 {
        if let Some(ino) = self.path_to_ino.get(path) {
            return *ino;
        }
        let ino = self.next_ino;
        self.next_ino += 1;
        self.register_path(ino, path.to_path_buf());
        ino
    }

    fn path_for_ino(&self, ino: u64) -> Option<&Path> {
        self.ino_to_paths
            .get(&ino)
            .and_then(|paths| {
                paths
                    .iter()
                    .find(|path| self.path_to_ino.contains_key(*path))
                    .or_else(|| paths.first())
            })
            .map(PathBuf::as_path)
    }

    #[allow(dead_code)]
    pub(crate) fn host_path_for_ino(&self, ino: u64) -> Option<&Path> {
        self.path_for_ino(ino)
    }

    #[allow(dead_code)]
    pub(crate) fn link_for_test(
        &mut self,
        caller: &Caller,
        ino: u64,
        newparent: &Path,
        newname: &OsStr,
    ) -> Result<FileAttr> {
        let source = self
            .path_for_ino(ino)
            .ok_or_else(|| std::io::Error::from_raw_os_error(ENOENT))?
            .to_path_buf();
        let target = newparent.join(newname);
        self.authorize(caller, &source, Operation::Link)?;
        self.authorize(caller, &target, Operation::Link)?;
        fs::hard_link(&source, &target)?;
        self.register_path(ino, target.clone());
        let metadata = fs::symlink_metadata(&target)?;
        Ok(self.attr_for_path(&target, &metadata))
    }

    fn resolve_child(&self, parent: u64, name: &OsStr) -> Option<PathBuf> {
        self.path_for_ino(parent).map(|path| path.join(name))
    }

    fn register_path(&mut self, ino: u64, path: PathBuf) {
        if self.path_to_ino.contains_key(&path) {
            return;
        }
        self.path_to_ino.insert(path.clone(), ino);
        self.ino_to_paths.entry(ino).or_default().push(path);
    }

    fn unregister_path(&mut self, path: &Path) {
        let Some(ino) = self.path_to_ino.remove(path) else {
            return;
        };
        if let Some(paths) = self.ino_to_paths.get_mut(&ino) {
            paths.retain(|candidate| candidate != path);
            if paths.is_empty() {
                self.ino_to_paths.remove(&ino);
            }
        }
    }

    fn note_lookup(&mut self, ino: u64, nlookup: u64) {
        if ino == ROOT_INO || nlookup == 0 {
            return;
        }
        self.lookup_counts
            .entry(ino)
            .and_modify(|count| *count = count.saturating_add(nlookup))
            .or_insert(nlookup);
    }

    fn forget_ino(&mut self, ino: u64, nlookup: u64) {
        if ino == ROOT_INO || nlookup == 0 {
            return;
        }
        if let Some(count) = self.lookup_counts.get_mut(&ino) {
            *count = count.saturating_sub(nlookup);
            if *count == 0 {
                self.lookup_counts.remove(&ino);
            }
        }
        self.cleanup_inode_if_forgettable(ino);
    }

    fn cleanup_inode_if_forgettable(&mut self, ino: u64) {
        if ino == ROOT_INO {
            return;
        }
        if self.lookup_counts.contains_key(&ino) {
            return;
        }
        if self.handles.values().any(|handle| handle.ino == ino) {
            return;
        }
        if self.lock_states.contains_key(&ino) {
            match self.broker.drop_inode(ino) {
                Ok(()) => {
                    self.lock_states.remove(&ino);
                }
                Err(err) => {
                    debug!("mirrorfs forget cleanup skipped lock drop for ino={ino}: {err}");
                    return;
                }
            }
        }
        let Some(paths) = self.ino_to_paths.remove(&ino) else {
            return;
        };
        for path in paths {
            if self.path_to_ino.get(&path) == Some(&ino) {
                self.path_to_ino.remove(&path);
            }
        }
    }

    #[allow(dead_code)]
    pub(crate) fn unregister_path_for_test(&mut self, path: &Path) {
        self.unregister_path(path);
    }

    fn authorize(&self, caller: &Caller, path: &Path, operation: Operation) -> Result<()> {
        let mut caller_condition = ProcCallerCondition::from_pid(caller.pid);
        match self.policy.check(
            &AccessRequest {
                caller,
                path,
                operation,
            },
            &mut caller_condition,
        ) {
            AccessDecision::Allow => Ok(()),
            AccessDecision::Deny(errno) => Err(std::io::Error::from_raw_os_error(errno).into()),
        }
    }

    fn authorize_errno(&self, caller: &Caller, path: &Path, operation: Operation) -> Option<i32> {
        let mut caller_condition = ProcCallerCondition::from_pid(caller.pid);
        match self.policy.check(
            &AccessRequest {
                caller,
                path,
                operation,
            },
            &mut caller_condition,
        ) {
            AccessDecision::Allow => None,
            AccessDecision::Deny(errno) => Some(errno),
        }
    }

    fn create_errno(&self, caller: &Caller, path: &Path, operation: Operation) -> Option<i32> {
        if self
            .authorize_errno(caller, path, Operation::Lookup)
            .is_none()
            && fs::symlink_metadata(path).is_ok()
        {
            return Some(EEXIST);
        }
        self.authorize_errno(caller, path, operation)
    }

    fn authorize_open_path(
        &self,
        caller: &Caller,
        path: &Path,
        operation: Operation,
    ) -> Result<()> {
        self.authorize(caller, path, operation)?;
        let Some(target) = resolved_host_target(path) else {
            return Ok(());
        };
        self.authorize(caller, &target, operation)
    }

    fn attr_for_path(&mut self, path: &Path, metadata: &Metadata) -> FileAttr {
        FileAttr {
            ino: INodeNo(self.ensure_ino(path)),
            size: metadata.len(),
            blocks: metadata.blocks(),
            atime: system_time_from_unix(metadata.atime(), metadata.atime_nsec()),
            mtime: system_time_from_unix(metadata.mtime(), metadata.mtime_nsec()),
            ctime: system_time_from_unix(metadata.ctime(), metadata.ctime_nsec()),
            crtime: system_time_from_unix(metadata.ctime(), metadata.ctime_nsec()),
            kind: filetype_from_metadata(metadata),
            perm: (metadata.mode() & 0o7777) as u16,
            nlink: metadata.nlink() as u32,
            uid: metadata.uid(),
            gid: metadata.gid(),
            rdev: metadata.rdev() as u32,
            blksize: 4096,
            flags: 0,
        }
    }

    pub(crate) fn getattr_path(&mut self, caller: &Caller, path: &Path) -> Result<FileAttr> {
        self.authorize(caller, path, Operation::GetAttr)?;
        let metadata = fs::symlink_metadata(path)?;
        Ok(self.attr_for_path(path, &metadata))
    }

    fn getattr_handle(&mut self, caller: &Caller, ino: u64, fh: u64) -> Result<FileAttr> {
        let path = self
            .path_for_ino(ino)
            .ok_or_else(|| std::io::Error::from_raw_os_error(ENOENT))?
            .to_path_buf();
        self.authorize(caller, &path, Operation::GetAttr)?;
        let metadata = self
            .handles
            .get(&fh)
            .ok_or_else(|| std::io::Error::from_raw_os_error(ENOENT))?
            .file
            .metadata()?;
        Ok(self.attr_for_path(&path, &metadata))
    }

    #[allow(dead_code)]
    pub(crate) fn getattr_handle_for_test(&mut self, caller: &Caller, fh: u64) -> Result<FileAttr> {
        let ino = self
            .handles
            .get(&fh)
            .map(|handle| handle.ino)
            .ok_or_else(|| std::io::Error::from_raw_os_error(ENOENT))?;
        self.getattr_handle(caller, ino, fh)
    }

    pub(crate) fn lookup_child(
        &mut self,
        caller: &Caller,
        parent: u64,
        name: &OsStr,
    ) -> Result<FileAttr> {
        let path = self
            .resolve_child(parent, name)
            .ok_or_else(|| std::io::Error::from_raw_os_error(ENOENT))?;
        self.authorize(caller, &path, Operation::Lookup)?;
        let metadata = fs::symlink_metadata(&path)?;
        Ok(self.attr_for_path(&path, &metadata))
    }

    #[allow(dead_code)]
    pub(crate) fn list_children_for_test(
        &mut self,
        caller: &Caller,
        path: &Path,
    ) -> Result<Vec<(u64, FileType, std::ffi::OsString)>> {
        self.authorize(caller, path, Operation::ReadDir)?;
        self.list_children(caller, path)
    }

    fn list_children(
        &mut self,
        caller: &Caller,
        parent: &Path,
    ) -> Result<Vec<(u64, FileType, std::ffi::OsString)>> {
        let mut out = Vec::new();
        let entries = fs::read_dir(parent)?;
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if self.authorize_errno(caller, &path, Operation::Lookup) == Some(ENOENT) {
                continue;
            }
            let file_type = entry.file_type()?;
            let ino = self.ensure_ino(&path);
            out.push((ino, filetype_from_std(file_type), entry.file_name()));
        }
        Ok(out)
    }

    #[allow(dead_code)]
    pub(crate) fn open_for_test(
        &mut self,
        caller: &Caller,
        path: &Path,
        flags: i32,
    ) -> Result<u64> {
        let ino = self.ensure_ino(path);
        self.open_path(caller, ino, flags)
    }

    fn open_path(&mut self, caller: &Caller, ino: u64, flags: i32) -> Result<u64> {
        let path = self
            .path_for_ino(ino)
            .ok_or_else(|| std::io::Error::from_raw_os_error(ENOENT))?;
        let operation = if flags & libc::O_ACCMODE == libc::O_RDONLY {
            Operation::OpenRead
        } else {
            Operation::OpenWrite
        };
        self.authorize_open_path(caller, path, operation)?;
        ensure_openable_node(path)?;
        let file = open_host_file(path, flags, false)?;
        Ok(self.allocate_handle(ino, file, operation.is_write()))
    }

    #[allow(dead_code)]
    pub(crate) fn read_for_test(
        &mut self,
        caller: &Caller,
        fh: u64,
        offset: i64,
        size: u32,
    ) -> Result<Vec<u8>> {
        let ino = self
            .handles
            .get(&fh)
            .map(|handle| handle.ino)
            .ok_or_else(|| std::io::Error::from_raw_os_error(ENOENT))?;
        self.read_handle(caller, ino, fh, offset, size)
    }

    fn read_handle(
        &mut self,
        caller: &Caller,
        ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
    ) -> Result<Vec<u8>> {
        if offset < 0 {
            return Err(std::io::Error::from_raw_os_error(EIO).into());
        }
        let path = self
            .path_for_ino(ino)
            .ok_or_else(|| std::io::Error::from_raw_os_error(ENOENT))?;
        self.authorize(caller, path, Operation::Read)?;
        let mut buf = vec![0u8; size as usize];
        let file = self
            .handles
            .get_mut(&fh)
            .ok_or_else(|| std::io::Error::from_raw_os_error(ENOENT))?;
        file.file.seek(SeekFrom::Start(offset as u64))?;
        let len = file.file.read(&mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }

    #[allow(dead_code)]
    pub(crate) fn dup_handle_for_test(&self, fh: u64) -> Result<fs::File> {
        let handle = self
            .handles
            .get(&fh)
            .ok_or_else(|| std::io::Error::from_raw_os_error(ENOENT))?;
        Ok(handle.file.try_clone()?)
    }

    #[allow(dead_code)]
    pub(crate) fn write_for_test(
        &mut self,
        caller: &Caller,
        fh: u64,
        offset: i64,
        data: &[u8],
    ) -> Result<u32> {
        let ino = self
            .handles
            .get(&fh)
            .map(|handle| handle.ino)
            .ok_or_else(|| std::io::Error::from_raw_os_error(ENOENT))?;
        self.write_handle(caller, ino, fh, offset, data)
    }

    fn write_handle(
        &mut self,
        caller: &Caller,
        ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
    ) -> Result<u32> {
        if offset < 0 {
            return Err(std::io::Error::from_raw_os_error(EIO).into());
        }
        let path = self
            .path_for_ino(ino)
            .ok_or_else(|| std::io::Error::from_raw_os_error(ENOENT))?;
        self.authorize(caller, path, Operation::Write)?;
        let file = self
            .handles
            .get_mut(&fh)
            .ok_or_else(|| std::io::Error::from_raw_os_error(ENOENT))?;
        file.file.seek(SeekFrom::Start(offset as u64))?;
        file.file.write_all(data)?;
        Ok(data.len() as u32)
    }

    pub(crate) fn create_for_test(
        &mut self,
        caller: &Caller,
        parent: &Path,
        name: &OsStr,
        mode: u32,
        umask: u32,
        flags: i32,
    ) -> Result<(FileAttr, u64)> {
        let path = parent.join(name);
        if let Some(errno) = self.create_errno(caller, &path, Operation::Create) {
            return Err(std::io::Error::from_raw_os_error(errno).into());
        }
        let file = open_host_file(&path, flags | libc::O_CREAT, true)?;
        let created_mode = normalize_create_mode(mode, umask) as u32;
        file.set_permissions(std::fs::Permissions::from_mode(created_mode))?;
        let metadata = file.metadata()?;
        let ino = self.ensure_ino(&path);
        let fh = self.allocate_handle(ino, file, true);
        Ok((self.attr_for_path(&path, &metadata), fh))
    }

    pub(crate) fn rename_for_test(
        &mut self,
        caller: &Caller,
        from: &Path,
        to: &Path,
    ) -> Result<()> {
        self.authorize(caller, from, Operation::Rename)?;
        self.authorize(caller, to, Operation::Rename)?;
        self.apply_host_rename(from, to)
    }

    pub(crate) fn flush_for_test(&mut self, caller: &Caller, fh: u64) -> Result<()> {
        let Some((ino, writable)) = self
            .handles
            .get(&fh)
            .map(|handle| (handle.ino, handle.writable))
        else {
            return Err(std::io::Error::from_raw_os_error(ENOENT).into());
        };
        if !writable {
            return Ok(());
        }
        let path = self
            .path_for_ino(ino)
            .ok_or_else(|| std::io::Error::from_raw_os_error(ENOENT))?;
        self.authorize(caller, path, Operation::Fsync)?;
        let handle = self
            .handles
            .get_mut(&fh)
            .ok_or_else(|| std::io::Error::from_raw_os_error(ENOENT))?;
        handle.file.sync_data()?;
        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) fn release_for_test(&mut self, fh: u64) {
        let Some(handle) = self.handles.remove(&fh) else {
            return;
        };
        self.cleanup_inode_if_forgettable(handle.ino);
    }

    pub(crate) fn setlk_for_test(
        &mut self,
        caller: &Caller,
        fh: u64,
        start: u64,
        end: u64,
        typ: i32,
        sleep: bool,
    ) -> Result<()> {
        let ino = self
            .handles
            .get(&fh)
            .map(|handle| handle.ino)
            .ok_or_else(|| std::io::Error::from_raw_os_error(ENOENT))?;
        let path = self
            .path_for_ino(ino)
            .ok_or_else(|| std::io::Error::from_raw_os_error(ENOENT))?;
        self.authorize(caller, path, lock_operation(typ))?;
        let handle = self
            .handles
            .get(&fh)
            .ok_or_else(|| std::io::Error::from_raw_os_error(ENOENT))?;
        apply_setlk(&handle.file, start, end, typ, sleep)?;
        Ok(())
    }

    pub(crate) fn getlk_for_test(
        &mut self,
        caller: &Caller,
        fh: u64,
        start: u64,
        end: u64,
        typ: i32,
    ) -> Result<(u64, u64, i32, u32)> {
        let ino = self
            .handles
            .get(&fh)
            .map(|handle| handle.ino)
            .ok_or_else(|| std::io::Error::from_raw_os_error(ENOENT))?;
        let path = self
            .path_for_ino(ino)
            .ok_or_else(|| std::io::Error::from_raw_os_error(ENOENT))?;
        self.authorize(caller, path, Operation::GetLock)?;
        let handle = self
            .handles
            .get(&fh)
            .ok_or_else(|| std::io::Error::from_raw_os_error(ENOENT))?;
        getlk(&handle.file, start, end, typ)
    }

    fn setlk_for_fuse(
        &mut self,
        caller: &Caller,
        ino: u64,
        fh: u64,
        lock_owner: LockOwner,
        start: u64,
        end: u64,
        typ: i32,
        sleep: bool,
    ) -> Result<()> {
        let Some(path) = self.path_for_ino(ino).map(Path::to_path_buf) else {
            return Err(std::io::Error::from_raw_os_error(ENOENT).into());
        };
        self.authorize(caller, &path, lock_operation(typ))?;
        let end = normalize_lock_end(end)?;
        if is_whole_file_lock(start, end) {
            // fuser does not expose fuse_lk_in.lk_flags, so a whole-file lock
            // request is treated as BSD flock-compatible here.
            let handle = self
                .handles
                .get(&fh)
                .ok_or_else(|| std::io::Error::from_raw_os_error(ENOENT))?;
            return apply_flock(&handle.file, typ, sleep);
        }
        if sleep {
            return Err(std::io::Error::from_raw_os_error(EINVAL).into());
        }

        let owner = lock_owner.0;
        let mut next_state = self.lock_states.get(&ino).cloned().unwrap_or_default();
        if typ == libc::F_UNLCK {
            next_state.unlock_owner_range(owner, start, end);
        } else {
            let mode = lock_mode_from_fcntl(typ)?;
            if let Some(conflict) = next_state.find_conflict(owner, start, end, mode) {
                debug!(
                    "mirrorfs posix lock conflict ino={} owner={} range={}..={} conflict={}..={}",
                    ino, owner, start, end, conflict.start, conflict.end
                );
                return Err(std::io::Error::from_raw_os_error(libc::EAGAIN).into());
            }
            next_state.apply_owner_lock(owner, start, end, mode);
        }

        self.apply_inode_lock_state(ino, &path, next_state)
    }

    fn getlk_for_fuse(
        &mut self,
        caller: &Caller,
        ino: u64,
        fh: u64,
        lock_owner: LockOwner,
        start: u64,
        end: u64,
        typ: i32,
    ) -> Result<(u64, u64, i32, u32)> {
        let Some(path) = self.path_for_ino(ino).map(Path::to_path_buf) else {
            return Err(std::io::Error::from_raw_os_error(ENOENT).into());
        };
        self.authorize(caller, &path, Operation::GetLock)?;
        let handle = self
            .handles
            .get(&fh)
            .ok_or_else(|| std::io::Error::from_raw_os_error(ENOENT))?;
        let end = normalize_lock_end(end)?;
        if is_whole_file_lock(start, end) {
            // Match the whole-file flock-compatible path used by setlk().
            return getlk_via_flock_probe(&path, typ);
        }

        let mode = lock_mode_from_fcntl(typ)?;
        let owner = lock_owner.0;
        let local_conflict = self
            .lock_states
            .get(&ino)
            .and_then(|state| state.find_conflict(owner, start, end, mode))
            .map(|conflict| conflict.as_reply());
        if let Some(conflict) = local_conflict {
            return Ok(conflict);
        }

        getlk(&handle.file, start, end, typ)
    }

    fn release_lock_owner_for_fuse(&mut self, ino: u64, lock_owner: LockOwner) -> Result<()> {
        let Some(path) = self.path_for_ino(ino).map(Path::to_path_buf) else {
            return Ok(());
        };
        let Some(mut next_state) = self.lock_states.get(&ino).cloned() else {
            return Ok(());
        };
        next_state.remove_owner(lock_owner.0);
        self.apply_inode_lock_state(ino, &path, next_state)
    }

    fn apply_inode_lock_state(
        &mut self,
        ino: u64,
        path: &Path,
        next_state: InodeLockState,
    ) -> Result<()> {
        if next_state.is_empty() {
            self.broker.drop_inode(ino)?;
            self.lock_states.remove(&ino);
            return Ok(());
        }

        let projection = next_state.to_projection();
        self.broker.apply_projection(ino, path, &projection)?;
        self.lock_states.insert(ino, next_state);
        Ok(())
    }

    pub(crate) fn setattr_for_test(
        &mut self,
        caller: &Caller,
        path: &Path,
        size: Option<u64>,
        mode: Option<u32>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
    ) -> Result<FileAttr> {
        self.authorize_open_path(caller, path, Operation::SetAttr)?;
        self.apply_setattr(path, size, mode, atime, mtime)
    }

    pub(crate) fn statfs_for_test(&self, caller: &Caller, path: &Path) -> Result<StatFs> {
        self.authorize(caller, path, Operation::StatFs)?;
        statfs(path)
    }

    fn apply_setattr(
        &mut self,
        path: &Path,
        size: Option<u64>,
        mode: Option<u32>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
    ) -> Result<FileAttr> {
        if size.is_none() && mode.is_none() && atime.is_none() && mtime.is_none() {
            return Err(std::io::Error::from_raw_os_error(ENOSYS).into());
        }

        if let Some(size) = size {
            let file = fs::OpenOptions::new().write(true).open(path)?;
            file.set_len(size)?;
        }
        if let Some(mode) = mode {
            fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
        }
        if atime.is_some() || mtime.is_some() {
            apply_times(path, atime, mtime)?;
        }

        let metadata = fs::symlink_metadata(path)?;
        Ok(self.attr_for_path(path, &metadata))
    }

    fn allocate_handle(&mut self, ino: u64, file: fs::File, writable: bool) -> u64 {
        let fh = self.next_fh;
        self.next_fh += 1;
        self.handles.insert(
            fh,
            OpenHandle {
                ino,
                file,
                writable,
            },
        );
        fh
    }

    fn remap_paths_after_rename(&mut self, from: &Path, to: &Path) {
        let stale_paths: Vec<PathBuf> = self
            .path_to_ino
            .keys()
            .filter(|path| path.as_path() == to || path.starts_with(to))
            .cloned()
            .collect();
        for stale_path in stale_paths {
            self.unregister_path(&stale_path);
        }

        let moved_paths: Vec<(u64, PathBuf)> = self
            .path_to_ino
            .iter()
            .filter_map(|(path, ino)| {
                if path.as_path() == from || path.starts_with(from) {
                    Some((*ino, path.clone()))
                } else {
                    None
                }
            })
            .collect();

        for (ino, old_path) in moved_paths {
            let suffix = old_path
                .strip_prefix(from)
                .expect("renamed path keeps source prefix");
            let new_path = if suffix.as_os_str().is_empty() {
                to.to_path_buf()
            } else {
                to.join(suffix)
            };
            self.unregister_path(&old_path);
            self.register_path(ino, new_path);
        }
    }

    fn apply_host_rename(&mut self, from: &Path, to: &Path) -> Result<()> {
        fs::rename(from, to)?;
        self.remap_paths_after_rename(from, to);
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
struct LockConflict {
    start: u64,
    end: u64,
    mode: LockMode,
}

impl LockConflict {
    fn as_reply(self) -> (u64, u64, i32, u32) {
        (self.start, self.end, self.mode.to_fcntl(), 0)
    }
}

impl InodeLockState {
    fn is_empty(&self) -> bool {
        self.owners.is_empty()
    }

    fn remove_owner(&mut self, owner: u64) {
        self.owners.remove(&owner);
    }

    fn apply_owner_lock(&mut self, owner: u64, start: u64, end: u64, mode: LockMode) {
        let state = self.owners.entry(owner).or_default();
        state.unlock_range(start, end);
        state.ranges.push(OwnedRange { start, end, mode });
        state.normalize();
    }

    fn unlock_owner_range(&mut self, owner: u64, start: u64, end: u64) {
        let should_remove = match self.owners.get_mut(&owner) {
            Some(state) => {
                state.unlock_range(start, end);
                state.ranges.is_empty()
            }
            None => false,
        };
        if should_remove {
            self.owners.remove(&owner);
        }
    }

    fn find_conflict(
        &self,
        owner: u64,
        start: u64,
        end: u64,
        requested: LockMode,
    ) -> Option<LockConflict> {
        let mut best = None;
        for (&other_owner, state) in &self.owners {
            if other_owner == owner {
                continue;
            }
            for range in &state.ranges {
                if !requested.conflicts_with(range.mode) {
                    continue;
                }
                let Some((start, end)) = overlap(start, end, range.start, range.end) else {
                    continue;
                };
                let candidate = LockConflict {
                    start,
                    end,
                    mode: range.mode,
                };
                if best
                    .map(|current: LockConflict| candidate.start < current.start)
                    .unwrap_or(true)
                {
                    best = Some(candidate);
                }
            }
        }
        best
    }

    fn to_projection(&self) -> Vec<ProjectedRange> {
        let mut boundaries = Vec::new();
        for state in self.owners.values() {
            for range in &state.ranges {
                boundaries.push(range.start);
                boundaries.push(range.end.saturating_add(1));
            }
        }
        boundaries.sort_unstable();
        boundaries.dedup();

        let mut projection: Vec<ProjectedRange> = Vec::new();
        for window in boundaries.windows(2) {
            let start = window[0];
            let next = window[1];
            if next == 0 || next <= start {
                continue;
            }
            let end = next - 1;
            let mut mode = None;
            for state in self.owners.values() {
                for range in &state.ranges {
                    if range.start <= start && range.end >= end {
                        mode = Some(match (mode, range.mode) {
                            (Some(LockMode::Exclusive), _) => LockMode::Exclusive,
                            (_, LockMode::Exclusive) => LockMode::Exclusive,
                            _ => LockMode::Shared,
                        });
                    }
                }
            }
            let Some(mode) = mode else { continue };
            if let Some(last) = projection.last_mut() {
                if last.mode == mode && last.end.saturating_add(1) == start {
                    last.end = end;
                    continue;
                }
            }
            projection.push(ProjectedRange { start, end, mode });
        }
        projection
    }
}

impl OwnerLockState {
    fn unlock_range(&mut self, start: u64, end: u64) {
        let mut next = Vec::new();
        for range in self.ranges.drain(..) {
            let Some((overlap_start, overlap_end)) = overlap(range.start, range.end, start, end)
            else {
                next.push(range);
                continue;
            };
            if range.start < overlap_start {
                next.push(OwnedRange {
                    start: range.start,
                    end: overlap_start - 1,
                    mode: range.mode,
                });
            }
            if overlap_end < range.end {
                next.push(OwnedRange {
                    start: overlap_end + 1,
                    end: range.end,
                    mode: range.mode,
                });
            }
        }
        self.ranges = next;
        self.normalize();
    }

    fn normalize(&mut self) {
        self.ranges.sort_by_key(|range| range.start);
        let mut normalized: Vec<OwnedRange> = Vec::new();
        for range in self.ranges.drain(..) {
            if let Some(last) = normalized.last_mut() {
                if last.mode == range.mode && last.end.saturating_add(1) >= range.start {
                    last.end = last.end.max(range.end);
                    continue;
                }
            }
            normalized.push(range);
        }
        self.ranges = normalized;
    }
}

impl LockMode {
    fn to_fcntl(self) -> i32 {
        match self {
            Self::Shared => libc::F_RDLCK,
            Self::Exclusive => libc::F_WRLCK,
        }
    }

    fn conflicts_with(self, other: Self) -> bool {
        matches!((self, other), (Self::Exclusive, _) | (_, Self::Exclusive))
    }
}

fn fuse_mount_options() -> Vec<MountOption> {
    vec![MountOption::FSName("leash-mirror".to_owned())]
}

fn fuse_worker_threads() -> usize {
    std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
        .clamp(1, 2)
}

impl<P: AccessController> Filesystem for FuseMirrorFs<P> {
    fn init(&mut self, _req: &Request, config: &mut KernelConfig) -> std::io::Result<()> {
        config
            .add_capabilities(InitFlags::FUSE_FLOCK_LOCKS | InitFlags::FUSE_POSIX_LOCKS)
            .map_err(|unsupported| {
                std::io::Error::other(format!("unsupported init flags: {unsupported:?}"))
            })?;
        Ok(())
    }

    fn lookup(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let caller = caller_from_request(req);
        let mut fs = self.inner.write();
        match fs.lookup_child(&caller, parent.0, name) {
            Ok(attr) => {
                fs.note_lookup(attr.ino.0, 1);
                reply.entry(&TTL, &attr, Generation(0));
            }
            Err(err) => {
                let errno = io_errno(&err);
                if errno == ENOENT {
                    fs.emit_tail_event_lazy(EventKind::LookupMiss, || {
                        let lookup_path = fs
                            .path_for_ino(parent.0)
                            .map(Path::to_path_buf)
                            .map(|parent_path| parent_path.join(name));
                        (lookup_path, Some(errno), None)
                    });
                }
                reply.error(Errno::from_i32(errno));
            }
        }
    }

    fn forget(&self, _req: &Request, ino: INodeNo, nlookup: u64) {
        let mut fs = self.inner.write();
        fs.forget_ino(ino.0, nlookup);
    }

    fn getattr(&self, req: &Request, ino: INodeNo, fh: Option<FileHandle>, reply: ReplyAttr) {
        let caller = caller_from_request(req);
        let mut fs = self.inner.write();
        let result = match fh {
            Some(fh) => fs.getattr_handle(&caller, ino.0, fh.0),
            None => match fs.path_for_ino(ino.0).map(Path::to_path_buf) {
                Some(path) => fs.getattr_path(&caller, &path),
                None => Err(std::io::Error::from_raw_os_error(ENOENT).into()),
            },
        };
        match result {
            Ok(attr) => reply.attr(&TTL, &attr),
            Err(err) => {
                let errno = io_errno(&err);
                if is_access_denied_errno(errno) {
                    fs.emit_tail_event_lazy(EventKind::OpenDenied, || {
                        (
                            fs.path_for_ino(ino.0).map(Path::to_path_buf),
                            Some(errno),
                            None,
                        )
                    });
                }
                reply.error(Errno::from_i32(errno));
            }
        }
    }

    fn readdir(
        &self,
        req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let caller = caller_from_request(req);
        let mut fs = self.inner.write();
        let Some(path) = fs.path_for_ino(ino.0).map(Path::to_path_buf) else {
            reply.error(Errno::ENOENT);
            return;
        };
        if let Some(errno) = fs.authorize_errno(&caller, &path, Operation::ReadDir) {
            if is_access_denied_errno(errno) {
                fs.emit_tail_event(
                    EventKind::OpenDenied,
                    Some(path),
                    Some(errno),
                    Some("op=opendir".to_owned()),
                );
            }
            reply.error(Errno::from_i32(errno));
            return;
        }
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(err) => {
                reply.error(Errno::from(err));
                return;
            }
        };
        if !metadata.file_type().is_dir() {
            reply.error(Errno::ENOTDIR);
            return;
        }

        let mut entries = vec![
            (ino.0, FileType::Directory, std::ffi::OsString::from(".")),
            (
                fs.ensure_ino(path.parent().unwrap_or(&path)),
                FileType::Directory,
                std::ffi::OsString::from(".."),
            ),
        ];
        match fs.list_children(&caller, &path) {
            Ok(mut children) => entries.append(&mut children),
            Err(err) => {
                reply.error(Errno::from_i32(io_errno(&err)));
                return;
            }
        }

        append_readdir_entries(
            &entries,
            offset as i64,
            |child_ino, next_offset, kind, name| {
                reply.add(INodeNo(child_ino), next_offset as u64, kind, name)
            },
        );
        reply.ok();
    }

    fn opendir(&self, req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        let caller = caller_from_request(req);
        let mut fs = self.inner.write();
        let Some(path) = fs.path_for_ino(ino.0).map(Path::to_path_buf) else {
            reply.error(Errno::ENOENT);
            return;
        };
        if let Some(errno) = fs.authorize_errno(&caller, &path, Operation::ReadDir) {
            if is_access_denied_errno(errno) {
                fs.emit_tail_event(
                    EventKind::OpenDenied,
                    Some(path),
                    Some(errno),
                    Some("op=opendir".to_owned()),
                );
            }
            reply.error(Errno::from_i32(errno));
            return;
        }

        let flags = if fs.policy.should_cache_readdir(&path) {
            FopenFlags::FOPEN_KEEP_CACHE | FopenFlags::FOPEN_CACHE_DIR
        } else {
            FopenFlags::empty()
        };
        reply.opened(FileHandle(0), flags);
    }

    fn open(&self, req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        let caller = caller_from_request(req);
        let mut fs = self.inner.write();
        let result = (|| -> Result<u64> {
            let path = fs
                .path_for_ino(ino.0)
                .map(Path::to_path_buf)
                .ok_or_else(|| std::io::Error::from_raw_os_error(ENOENT))?;
            let raw_flags = flags.0;
            let operation = if raw_flags & libc::O_ACCMODE == libc::O_RDONLY {
                Operation::OpenRead
            } else {
                Operation::OpenWrite
            };
            fs.authorize_open_path(&caller, &path, operation)?;
            ensure_openable_node(&path)?;
            let file = open_host_file(&path, raw_flags, false)?;
            Ok(fs.allocate_handle(ino.0, file, operation.is_write()))
        })();
        match result {
            Ok(fh) => reply.opened(FileHandle(fh), FopenFlags::empty()),
            Err(err) => {
                let errno = io_errno(&err);
                if matches!(errno, libc::EACCES | libc::EPERM) {
                    fs.emit_tail_event_lazy(EventKind::OpenDenied, || {
                        (
                            fs.path_for_ino(ino.0).map(Path::to_path_buf),
                            Some(errno),
                            None,
                        )
                    });
                }
                reply.error(Errno::from_i32(errno));
            }
        }
    }

    fn read(
        &self,
        req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        let caller = caller_from_request(req);
        let mut fs = self.inner.write();
        match fs.read_handle(&caller, ino.0, fh.0, offset as i64, size) {
            Ok(data) => reply.data(&data),
            Err(err) => reply.error(Errno::from_i32(io_errno(&err))),
        }
    }

    fn readlink(&self, req: &Request, ino: INodeNo, reply: ReplyData) {
        let caller = caller_from_request(req);
        let fs = self.inner.read();
        let Some(path) = fs.path_for_ino(ino.0).map(Path::to_path_buf) else {
            reply.error(Errno::ENOENT);
            return;
        };
        if let Some(errno) = fs.authorize_errno(&caller, &path, Operation::ReadLink) {
            reply.error(Errno::from_i32(errno));
            return;
        }
        match fs::read_link(&path) {
            Ok(target) => reply.data(target.as_os_str().as_bytes()),
            Err(err) => reply.error(Errno::from(err)),
        }
    }

    fn create(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        let caller = caller_from_request(req);
        let mut fs = self.inner.write();
        let Some(parent_path) = fs.path_for_ino(parent.0).map(Path::to_path_buf) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let result = (|| -> Result<(FileAttr, u64)> {
            let path = parent_path.join(name);
            if let Some(errno) = fs.create_errno(&caller, &path, Operation::Create) {
                return Err(std::io::Error::from_raw_os_error(errno).into());
            }
            let file = open_host_file(&path, flags | libc::O_CREAT, true)?;
            let created_mode = normalize_create_mode(mode, umask) as u32;
            file.set_permissions(std::fs::Permissions::from_mode(created_mode))?;
            let metadata = file.metadata()?;
            let ino = fs.ensure_ino(&path);
            let fh = fs.allocate_handle(ino, file, true);
            let attr = fs.attr_for_path(&path, &metadata);
            Ok((attr, fh))
        })();
        match result {
            Ok((attr, fh)) => {
                fs.note_lookup(attr.ino.0, 1);
                reply.created(
                    &TTL,
                    &attr,
                    Generation(0),
                    FileHandle(fh),
                    FopenFlags::empty(),
                );
            }
            Err(err) => {
                let errno = io_errno(&err);
                if is_access_denied_errno(errno) {
                    fs.emit_tail_event(
                        EventKind::MutationDenied,
                        Some(parent_path.join(name)),
                        Some(errno),
                        Some("op=create".to_owned()),
                    );
                }
                reply.error(Errno::from_i32(errno));
            }
        }
    }

    fn write(
        &self,
        req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        let caller = caller_from_request(req);
        let mut fs = self.inner.write();
        match fs.write_handle(&caller, ino.0, fh.0, offset as i64, data) {
            Ok(len) => reply.written(len),
            Err(err) => {
                let errno = io_errno(&err);
                if is_access_denied_errno(errno) {
                    fs.emit_tail_event_lazy(EventKind::MutationDenied, || {
                        (
                            fs.path_for_ino(ino.0).map(Path::to_path_buf),
                            Some(errno),
                            Some("op=write".to_owned()),
                        )
                    });
                }
                reply.error(Errno::from_i32(errno));
            }
        }
    }

    fn flush(
        &self,
        req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        lock_owner: LockOwner,
        reply: ReplyEmpty,
    ) {
        let caller = caller_from_request(req);
        let mut fs = self.inner.write();
        match fs.flush_for_test(&caller, fh.0) {
            Ok(()) => match fs.release_lock_owner_for_fuse(ino.0, lock_owner) {
                Ok(()) => reply.ok(),
                Err(err) => reply.error(Errno::from_i32(io_errno(&err))),
            },
            Err(err) => reply.error(Errno::from_i32(io_errno(&err))),
        }
    }

    fn release(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        let mut fs = self.inner.write();
        fs.release_for_test(fh.0);
        match lock_owner {
            Some(lock_owner) => match fs.release_lock_owner_for_fuse(ino.0, lock_owner) {
                Ok(()) => reply.ok(),
                Err(err) => reply.error(Errno::from_i32(io_errno(&err))),
            },
            None => reply.ok(),
        }
    }

    fn fsync(
        &self,
        req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        datasync: bool,
        reply: ReplyEmpty,
    ) {
        let caller = caller_from_request(req);
        let mut fs = self.inner.write();
        let result = (|| -> std::io::Result<()> {
            let ino = fs
                .handles
                .get(&fh.0)
                .map(|handle| handle.ino)
                .ok_or_else(|| std::io::Error::from_raw_os_error(ENOENT))?;
            let path = fs.path_for_ino(ino).unwrap_or(fs.root()).to_path_buf();
            if let Some(errno) = fs.authorize_errno(&caller, &path, Operation::Fsync) {
                return Err(std::io::Error::from_raw_os_error(errno));
            }
            let handle = fs
                .handles
                .get_mut(&fh.0)
                .ok_or_else(|| std::io::Error::from_raw_os_error(ENOENT))?;
            if datasync {
                handle.file.sync_data()
            } else {
                handle.file.sync_all()
            }
        })();
        match result {
            Ok(()) => reply.ok(),
            Err(err) => reply.error(Errno::from(err)),
        }
    }

    fn mkdir(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        reply: ReplyEntry,
    ) {
        let caller = caller_from_request(req);
        let mut fs = self.inner.write();
        let Some(parent_path) = fs.path_for_ino(parent.0).map(Path::to_path_buf) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let path = parent_path.join(name);
        if let Some(errno) = fs.create_errno(&caller, &path, Operation::Mkdir) {
            if is_access_denied_errno(errno) {
                fs.emit_tail_event(
                    EventKind::MutationDenied,
                    Some(path),
                    Some(errno),
                    Some("op=mkdir".to_owned()),
                );
            }
            reply.error(Errno::from_i32(errno));
            return;
        }
        let result = create_dir_with_mode(&path, normalize_create_mode(mode, umask))
            .and_then(|_| fs::symlink_metadata(&path));
        match result {
            Ok(metadata) => {
                let attr = fs.attr_for_path(&path, &metadata);
                fs.note_lookup(attr.ino.0, 1);
                reply.entry(&TTL, &attr, Generation(0));
            }
            Err(err) => reply.error(Errno::from(err)),
        }
    }

    fn unlink(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let caller = caller_from_request(req);
        let mut fs = self.inner.write();
        let Some(path) = fs.resolve_child(parent.0, name) else {
            reply.error(Errno::ENOENT);
            return;
        };
        if let Some(errno) = fs.authorize_errno(&caller, &path, Operation::Unlink) {
            if is_access_denied_errno(errno) {
                fs.emit_tail_event(
                    EventKind::MutationDenied,
                    Some(path),
                    Some(errno),
                    Some("op=unlink".to_owned()),
                );
            }
            reply.error(Errno::from_i32(errno));
            return;
        }
        match fs::remove_file(&path) {
            Ok(()) => {
                fs.unregister_path(&path);
                reply.ok();
            }
            Err(err) => reply.error(Errno::from(err)),
        }
    }

    fn rmdir(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let caller = caller_from_request(req);
        let mut fs = self.inner.write();
        let Some(path) = fs.resolve_child(parent.0, name) else {
            reply.error(Errno::ENOENT);
            return;
        };
        if let Some(errno) = fs.authorize_errno(&caller, &path, Operation::Rmdir) {
            if is_access_denied_errno(errno) {
                fs.emit_tail_event(
                    EventKind::MutationDenied,
                    Some(path),
                    Some(errno),
                    Some("op=rmdir".to_owned()),
                );
            }
            reply.error(Errno::from_i32(errno));
            return;
        }
        match fs::remove_dir(&path) {
            Ok(()) => reply.ok(),
            Err(err) => reply.error(Errno::from(err)),
        }
    }

    fn symlink(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        link: &Path,
        reply: ReplyEntry,
    ) {
        let caller = caller_from_request(req);
        let mut fs = self.inner.write();
        let Some(path) = fs.resolve_child(parent.0, name) else {
            reply.error(Errno::ENOENT);
            return;
        };
        if let Some(errno) = fs.authorize_errno(&caller, &path, Operation::Symlink) {
            if is_access_denied_errno(errno) {
                fs.emit_tail_event(
                    EventKind::MutationDenied,
                    Some(path),
                    Some(errno),
                    Some("op=symlink".to_owned()),
                );
            }
            reply.error(Errno::from_i32(errno));
            return;
        }
        match std::os::unix::fs::symlink(link, &path).and_then(|_| fs::symlink_metadata(&path)) {
            Ok(metadata) => {
                let attr = fs.attr_for_path(&path, &metadata);
                fs.note_lookup(attr.ino.0, 1);
                reply.entry(&TTL, &attr, Generation(0));
            }
            Err(err) => reply.error(Errno::from(err)),
        }
    }

    fn link(
        &self,
        req: &Request,
        ino: INodeNo,
        newparent: INodeNo,
        newname: &OsStr,
        reply: ReplyEntry,
    ) {
        let caller = caller_from_request(req);
        let mut fs = self.inner.write();
        let Some(newparent_path) = fs.path_for_ino(newparent.0).map(Path::to_path_buf) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let target = newparent_path.join(newname);
        match fs.link_for_test(&caller, ino.0, &newparent_path, newname) {
            Ok(attr) => {
                fs.note_lookup(attr.ino.0, 1);
                reply.entry(&TTL, &attr, Generation(0));
            }
            Err(err) => {
                let errno = io_errno(&err);
                if is_access_denied_errno(errno) {
                    fs.emit_tail_event(
                        EventKind::MutationDenied,
                        Some(target),
                        Some(errno),
                        Some("op=link".to_owned()),
                    );
                }
                reply.error(Errno::from_i32(errno));
            }
        }
    }

    fn rename(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        _flags: RenameFlags,
        reply: ReplyEmpty,
    ) {
        let caller = caller_from_request(req);
        let mut fs = self.inner.write();
        let Some(from) = fs.resolve_child(parent.0, name) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let Some(to) = fs.resolve_child(newparent.0, newname) else {
            reply.error(Errno::ENOENT);
            return;
        };
        match fs.rename_for_test(&caller, &from, &to) {
            Ok(()) => reply.ok(),
            Err(err) => {
                let errno = io_errno(&err);
                if is_access_denied_errno(errno) {
                    fs.emit_tail_event_lazy(EventKind::MutationDenied, move || {
                        (
                            Some(from),
                            Some(errno),
                            Some(format!("op=rename to={}", to.display())),
                        )
                    });
                }
                reply.error(Errno::from_i32(errno));
            }
        }
    }

    fn setattr(
        &self,
        req: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<fuser::BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        if uid.is_some() || gid.is_some() {
            reply.error(Errno::from_i32(libc::EOPNOTSUPP));
            return;
        }
        let caller = caller_from_request(req);
        let mut fs = self.inner.write();
        let Some(path) = fs.path_for_ino(ino.0).map(Path::to_path_buf) else {
            reply.error(Errno::ENOENT);
            return;
        };
        match fs.setattr_for_test(&caller, &path, size, mode, atime, mtime) {
            Ok(attr) => reply.attr(&TTL, &attr),
            Err(err) => {
                let errno = io_errno(&err);
                if is_access_denied_errno(errno) {
                    fs.emit_tail_event(
                        EventKind::MutationDenied,
                        Some(path),
                        Some(errno),
                        Some("op=setattr".to_owned()),
                    );
                }
                reply.error(Errno::from_i32(errno));
            }
        }
    }

    fn access(&self, req: &Request, ino: INodeNo, _mask: AccessFlags, reply: ReplyEmpty) {
        let caller = caller_from_request(req);
        let fs = self.inner.read();
        let Some(path) = fs.path_for_ino(ino.0).map(Path::to_path_buf) else {
            reply.error(Errno::ENOENT);
            return;
        };
        match fs.authorize_errno(&caller, &path, Operation::Access) {
            Some(errno) => reply.error(Errno::from_i32(errno)),
            None => reply.ok(),
        }
    }

    fn statfs(&self, req: &Request, ino: INodeNo, reply: ReplyStatfs) {
        let caller = caller_from_request(req);
        let fs = self.inner.read();
        let Some(path) = fs.path_for_ino(ino.0).map(Path::to_path_buf) else {
            reply.error(Errno::ENOENT);
            return;
        };
        match fs.statfs_for_test(&caller, &path) {
            Ok(stats) => reply.statfs(
                stats.blocks,
                stats.bfree,
                stats.bavail,
                stats.files,
                stats.ffree,
                stats.bsize,
                stats.namelen,
                stats.frsize,
            ),
            Err(err) => reply.error(Errno::from_i32(io_errno(&err))),
        }
    }

    fn listxattr(&self, req: &Request, ino: INodeNo, size: u32, reply: ReplyXattr) {
        let caller = caller_from_request(req);
        let fs = self.inner.read();
        let Some(path) = fs.path_for_ino(ino.0).map(Path::to_path_buf) else {
            reply.error(Errno::ENOENT);
            return;
        };
        if let Some(errno) = fs.authorize_errno(&caller, &path, Operation::GetAttr) {
            reply.error(Errno::from_i32(errno));
            return;
        }

        let path_c = match CString::new(path.as_os_str().as_bytes()) {
            Ok(path_c) => path_c,
            Err(_) => {
                reply.error(Errno::EINVAL);
                return;
            }
        };

        if size == 0 {
            let required = unsafe { libc::llistxattr(path_c.as_ptr(), std::ptr::null_mut(), 0) };
            if required < 0 {
                let err = std::io::Error::last_os_error();
                reply.error(Errno::from(err));
                return;
            }
            reply.size(required as u32);
            return;
        }

        let mut buf = vec![0u8; size as usize];
        let len = unsafe { libc::llistxattr(path_c.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
        if len < 0 {
            let err = std::io::Error::last_os_error();
            reply.error(Errno::from(err));
            return;
        }
        reply.data(&buf[..len as usize]);
    }

    fn fsyncdir(
        &self,
        req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        datasync: bool,
        reply: ReplyEmpty,
    ) {
        let caller = caller_from_request(req);
        let fs = self.inner.read();
        let Some(path) = fs.path_for_ino(ino.0).map(Path::to_path_buf) else {
            reply.error(Errno::ENOENT);
            return;
        };
        if let Some(errno) = fs.authorize_errno(&caller, &path, Operation::FsyncDir) {
            reply.error(Errno::from_i32(errno));
            return;
        }
        let result = fs::File::open(&path).and_then(|file| {
            if datasync {
                file.sync_data()
            } else {
                file.sync_all()
            }
        });
        match result {
            Ok(()) => reply.ok(),
            Err(err) => reply.error(Errno::from(err)),
        }
    }

    fn getlk(
        &self,
        req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        lock_owner: LockOwner,
        start: u64,
        end: u64,
        typ: i32,
        _pid: u32,
        reply: ReplyLock,
    ) {
        let caller = caller_from_request(req);
        let mut fs = self.inner.write();
        match fs.getlk_for_fuse(&caller, ino.0, fh.0, lock_owner, start, end, typ) {
            Ok((start, end, typ, pid)) => {
                fs.emit_tail_event_lazy(EventKind::Lock, || {
                    (
                        fs.path_for_ino(ino.0).map(Path::to_path_buf),
                        None,
                        Some(format!(
                            "op=getlk start={start} end={end} typ={typ} owner={} pid={pid}",
                            lock_owner.0
                        )),
                    )
                });
                reply.locked(start, end, typ, pid)
            }
            Err(err) => {
                let errno = io_errno(&err);
                fs.emit_tail_event_lazy(EventKind::Lock, || {
                    (
                        fs.path_for_ino(ino.0).map(Path::to_path_buf),
                        Some(errno),
                        Some(format!(
                            "op=getlk start={start} end={end} typ={typ} owner={}",
                            lock_owner.0
                        )),
                    )
                });
                reply.error(Errno::from_i32(errno))
            }
        }
    }

    fn setlk(
        &self,
        req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        lock_owner: LockOwner,
        start: u64,
        end: u64,
        typ: i32,
        _pid: u32,
        sleep: bool,
        reply: ReplyEmpty,
    ) {
        let caller = caller_from_request(req);
        let mut fs = self.inner.write();
        match fs.setlk_for_fuse(&caller, ino.0, fh.0, lock_owner, start, end, typ, sleep) {
            Ok(()) => {
                fs.emit_tail_event_lazy(EventKind::Lock, || {
                    (
                        fs.path_for_ino(ino.0).map(Path::to_path_buf),
                        None,
                        Some(format!(
                            "op=setlk start={start} end={end} typ={typ} owner={} sleep={sleep}",
                            lock_owner.0
                        )),
                    )
                });
                reply.ok()
            }
            Err(err) => {
                let errno = io_errno(&err);
                fs.emit_tail_event_lazy(EventKind::Lock, || {
                    (
                        fs.path_for_ino(ino.0).map(Path::to_path_buf),
                        Some(errno),
                        Some(format!(
                            "op=setlk start={start} end={end} typ={typ} owner={} sleep={sleep}",
                            lock_owner.0
                        )),
                    )
                });
                reply.error(Errno::from_i32(errno))
            }
        }
    }
}

fn caller_from_request(req: &Request) -> Caller {
    let pid = req.pid();
    debug!("mirrorfs request pid={}", pid);
    Caller::new(Some(pid), read_process_name)
}

fn read_process_name(pid: u32) -> Option<String> {
    let path = PathBuf::from(format!("/proc/{pid}/exe"));
    let target = fs::read_link(path).ok()?;
    let exe = target.to_string_lossy().into_owned();
    if exe.is_empty() { None } else { Some(exe) }
}

fn filetype_from_metadata(metadata: &Metadata) -> FileType {
    filetype_from_std(metadata.file_type())
}

fn filetype_from_std(kind: std::fs::FileType) -> FileType {
    if kind.is_dir() {
        FileType::Directory
    } else if kind.is_symlink() {
        FileType::Symlink
    } else if kind.is_file() {
        FileType::RegularFile
    } else if kind.is_block_device() {
        FileType::BlockDevice
    } else if kind.is_char_device() {
        FileType::CharDevice
    } else if kind.is_fifo() {
        FileType::NamedPipe
    } else if kind.is_socket() {
        FileType::Socket
    } else {
        FileType::RegularFile
    }
}

fn system_time_from_unix(sec: i64, nsec: i64) -> SystemTime {
    if sec < 0 || nsec < 0 {
        return SystemTime::UNIX_EPOCH;
    }
    SystemTime::UNIX_EPOCH + Duration::new(sec as u64, nsec as u32)
}

fn ensure_openable_node(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_dir() {
        return Err(std::io::Error::from_raw_os_error(EISDIR).into());
    }
    Ok(())
}

fn open_host_file(path: &Path, flags: i32, create_new: bool) -> Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    match flags & libc::O_ACCMODE {
        libc::O_RDONLY => {
            options.read(true);
        }
        libc::O_WRONLY => {
            options.write(true);
        }
        libc::O_RDWR => {
            options.read(true).write(true);
        }
        _ => return Err(std::io::Error::from_raw_os_error(EINVAL).into()),
    }
    if flags & libc::O_APPEND != 0 {
        options.append(true);
    }
    if flags & libc::O_TRUNC != 0 {
        options.truncate(true);
    }
    if create_new {
        options.create_new(true);
    }
    let custom_flags = flags
        & !(libc::O_ACCMODE
            | libc::O_APPEND
            | libc::O_CREAT
            | libc::O_EXCL
            | libc::O_NOCTTY
            | libc::O_TRUNC);
    options.custom_flags(custom_flags);
    Ok(options.open(path)?)
}

fn normalize_create_mode(mode: u32, umask: u32) -> u16 {
    (mode & !umask & 0o7777) as u16
}

fn create_dir_with_mode(path: &Path, mode: u16) -> std::io::Result<()> {
    fs::create_dir(path)?;
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_mode(mode as u32);
    fs::set_permissions(path, permissions)
}

fn append_readdir_entries<F>(
    entries: &[(u64, FileType, std::ffi::OsString)],
    offset: i64,
    mut add: F,
) where
    F: FnMut(u64, i64, FileType, &OsStr) -> bool,
{
    let start = if offset <= 0 { 0 } else { offset as usize };
    for (index, entry) in entries.iter().enumerate().skip(start) {
        if add(entry.0, (index + 1) as i64, entry.1, entry.2.as_os_str()) {
            break;
        }
    }
}

fn apply_times(path: &Path, atime: Option<TimeOrNow>, mtime: Option<TimeOrNow>) -> Result<()> {
    let c_path = CString::new(path.as_os_str().as_bytes())?;
    let times = [to_timespec_or_omit(atime), to_timespec_or_omit(mtime)];
    let rc = unsafe { libc::utimensat(libc::AT_FDCWD, c_path.as_ptr(), times.as_ptr(), 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().into())
    }
}

fn to_timespec_or_omit(value: Option<TimeOrNow>) -> libc::timespec {
    match value {
        Some(TimeOrNow::SpecificTime(ts)) => match ts.duration_since(SystemTime::UNIX_EPOCH) {
            Ok(duration) => libc::timespec {
                tv_sec: duration.as_secs() as libc::time_t,
                tv_nsec: duration.subsec_nanos() as libc::c_long,
            },
            Err(_) => libc::timespec {
                tv_sec: 0,
                tv_nsec: libc::UTIME_OMIT,
            },
        },
        Some(TimeOrNow::Now) => libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_NOW,
        },
        None => libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_OMIT,
        },
    }
}

fn lock_operation(typ: i32) -> Operation {
    match typ {
        libc::F_RDLCK => Operation::SetReadLock,
        libc::F_WRLCK => Operation::SetWriteLock,
        libc::F_UNLCK => Operation::Unlock,
        _ => Operation::SetWriteLock,
    }
}

fn lock_len(start: u64, end: u64) -> libc::off_t {
    if end == lock_range_end_to_eof() {
        0
    } else {
        end.saturating_sub(start).saturating_add(1) as libc::off_t
    }
}

fn lock_range_end_to_eof() -> u64 {
    i64::MAX as u64
}

fn make_flock(start: u64, end: u64, typ: i32) -> libc::flock {
    libc::flock {
        l_type: typ as libc::c_short,
        l_whence: libc::SEEK_SET as libc::c_short,
        l_start: start as libc::off_t,
        l_len: lock_len(start, end),
        l_pid: 0,
    }
}

fn flock_operation(typ: i32, sleep: bool) -> Result<libc::c_int> {
    let base = match typ {
        libc::F_RDLCK => libc::LOCK_SH,
        libc::F_WRLCK => libc::LOCK_EX,
        libc::F_UNLCK => libc::LOCK_UN,
        _ => return Err(std::io::Error::from_raw_os_error(EINVAL).into()),
    };
    if typ == libc::F_UNLCK || sleep {
        Ok(base)
    } else {
        Ok(base | libc::LOCK_NB)
    }
}

fn apply_flock(file: &fs::File, typ: i32, sleep: bool) -> Result<()> {
    let rc = unsafe { libc::flock(file.as_raw_fd(), flock_operation(typ, sleep)?) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().into())
    }
}

fn getlk_via_flock_probe(path: &Path, typ: i32) -> Result<(u64, u64, i32, u32)> {
    let probe = fs::OpenOptions::new().read(true).write(true).open(path)?;
    match apply_flock(&probe, typ, false) {
        Ok(()) => {
            apply_flock(&probe, libc::F_UNLCK, false)?;
            Ok((0, lock_range_end_to_eof(), libc::F_UNLCK, 0))
        }
        Err(err) => {
            let errno = io_errno(&err);
            if errno == libc::EWOULDBLOCK || errno == libc::EAGAIN {
                // flock cannot report an owning pid or byte range. Return a
                // whole-file conflict of the requested type as an
                // approximation for F_GETLK.
                Ok((0, lock_range_end_to_eof(), typ, 0))
            } else {
                Err(err)
            }
        }
    }
}

fn normalize_lock_end(end: u64) -> Result<u64> {
    if end == u64::MAX || end > lock_range_end_to_eof() {
        Ok(lock_range_end_to_eof())
    } else {
        Ok(end)
    }
}

fn is_whole_file_lock(start: u64, end: u64) -> bool {
    start == 0 && end == lock_range_end_to_eof()
}

fn lock_mode_from_fcntl(typ: i32) -> Result<LockMode> {
    match typ {
        libc::F_RDLCK => Ok(LockMode::Shared),
        libc::F_WRLCK => Ok(LockMode::Exclusive),
        _ => Err(std::io::Error::from_raw_os_error(EINVAL).into()),
    }
}

fn overlap(left_start: u64, left_end: u64, right_start: u64, right_end: u64) -> Option<(u64, u64)> {
    let start = left_start.max(right_start);
    let end = left_end.min(right_end);
    (start <= end).then_some((start, end))
}

fn apply_host_range_lock(
    file: &fs::File,
    start: u64,
    end: u64,
    mode: LockMode,
    wait: bool,
) -> Result<()> {
    apply_setlk(file, start, end, mode.to_fcntl(), wait)
}

fn apply_host_range_unlock(file: &fs::File, start: u64, end: u64) -> Result<()> {
    apply_setlk(file, start, end, libc::F_UNLCK, false)
}

fn ranges_not_covered(current: &[ProjectedRange], target: &[ProjectedRange]) -> Vec<(u64, u64)> {
    let mut gaps = Vec::new();
    for current_range in current {
        let mut cursor = current_range.start;
        for target_range in target {
            let Some((overlap_start, overlap_end)) = overlap(
                cursor,
                current_range.end,
                target_range.start,
                target_range.end,
            ) else {
                continue;
            };
            if cursor < overlap_start {
                gaps.push((cursor, overlap_start - 1));
            }
            cursor = overlap_end.saturating_add(1);
            if cursor == 0 || cursor > current_range.end {
                break;
            }
        }
        if cursor <= current_range.end {
            gaps.push((cursor, current_range.end));
        }
    }
    gaps
}

fn write_u8(stream: &mut UnixStream, value: u8) -> Result<()> {
    stream.write_all(&[value])?;
    Ok(())
}

fn read_u8(stream: &mut UnixStream) -> Result<u8> {
    let mut buf = [0u8; 1];
    stream.read_exact(&mut buf)?;
    Ok(buf[0])
}

fn write_u32(stream: &mut UnixStream, value: u32) -> Result<()> {
    stream.write_all(&value.to_le_bytes())?;
    Ok(())
}

fn read_u32(stream: &mut UnixStream) -> Result<u32> {
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn write_i32(stream: &mut UnixStream, value: i32) -> Result<()> {
    stream.write_all(&value.to_le_bytes())?;
    Ok(())
}

fn read_i32(stream: &mut UnixStream) -> Result<i32> {
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf)?;
    Ok(i32::from_le_bytes(buf))
}

fn write_u64(stream: &mut UnixStream, value: u64) -> Result<()> {
    stream.write_all(&value.to_le_bytes())?;
    Ok(())
}

fn read_u64(stream: &mut UnixStream) -> Result<u64> {
    let mut buf = [0u8; 8];
    stream.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

fn write_bytes(stream: &mut UnixStream, value: &[u8]) -> Result<()> {
    write_u32(stream, value.len() as u32)?;
    stream.write_all(value)?;
    Ok(())
}

fn read_bytes(stream: &mut UnixStream) -> Result<Vec<u8>> {
    let len = read_u32(stream)? as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

impl LockBroker {
    fn spawn() -> std::io::Result<Self> {
        let (parent, child) = UnixStream::pair()?;
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if pid == 0 {
            drop(parent);
            if let Err(err) = set_process_name("lock-broker") {
                warn!("lock broker failed to set process name: {err:#}");
            }
            if let Err(err) = arm_broker_parent_death_signal() {
                eprintln!("lock broker failed to arm parent-death signal: {err}");
                unsafe { libc::_exit(1) }
            }
            let code = match broker_main_loop(child) {
                Ok(()) => 0,
                Err(err) => {
                    eprintln!("lock broker failed: {err}");
                    1
                }
            };
            unsafe { libc::_exit(code) }
        }
        drop(child);
        Ok(Self {
            stream: parent,
            child_pid: pid,
        })
    }

    fn apply_projection(
        &mut self,
        ino: u64,
        path: &Path,
        projection: &[ProjectedRange],
    ) -> Result<()> {
        write_broker_request(
            &mut self.stream,
            &BrokerRequest::ApplyProjection {
                ino,
                path: path.to_path_buf(),
                projection: projection.to_vec(),
            },
        )?;
        read_broker_response(&mut self.stream)?;
        Ok(())
    }

    fn drop_inode(&mut self, ino: u64) -> Result<()> {
        write_broker_request(&mut self.stream, &BrokerRequest::DropInode { ino })?;
        read_broker_response(&mut self.stream)?;
        Ok(())
    }
}

impl Drop for LockBroker {
    fn drop(&mut self) {
        let _ = write_broker_request(&mut self.stream, &BrokerRequest::Shutdown);
        let _ = read_broker_response(&mut self.stream);
        let _ = unsafe { libc::waitpid(self.child_pid, std::ptr::null_mut(), 0) };
    }
}

enum BrokerRequest {
    ApplyProjection {
        ino: u64,
        path: PathBuf,
        projection: Vec<ProjectedRange>,
    },
    DropInode {
        ino: u64,
    },
    Shutdown,
}

fn broker_main_loop(mut stream: UnixStream) -> Result<()> {
    let mut files: HashMap<u64, BrokerFileState> = HashMap::new();
    loop {
        match read_broker_request(&mut stream)? {
            BrokerRequest::ApplyProjection {
                ino,
                path,
                projection,
            } => {
                if !files.contains_key(&ino) {
                    let file = match fs::OpenOptions::new().read(true).write(true).open(&path) {
                        Ok(file) => file,
                        Err(err) => {
                            write_broker_response(&mut stream, err.raw_os_error().unwrap_or(EIO))?;
                            continue;
                        }
                    };
                    files.insert(
                        ino,
                        BrokerFileState {
                            file,
                            projection: Vec::new(),
                        },
                    );
                }
                let state = files.get_mut(&ino).expect("broker state inserted");
                match broker_apply_projection(&state.file, &state.projection, &projection) {
                    Ok(()) => {
                        state.projection = projection;
                        write_broker_response(&mut stream, 0)?;
                    }
                    Err(err) => {
                        write_broker_response(&mut stream, io_errno(&err))?;
                    }
                }
            }
            BrokerRequest::DropInode { ino } => {
                if let Some(state) = files.remove(&ino) {
                    let _ = broker_apply_projection(&state.file, &state.projection, &[]);
                }
                write_broker_response(&mut stream, 0)?;
            }
            BrokerRequest::Shutdown => {
                for (_, state) in files.drain() {
                    let _ = broker_apply_projection(&state.file, &state.projection, &[]);
                }
                write_broker_response(&mut stream, 0)?;
                return Ok(());
            }
        }
    }
}

fn arm_broker_parent_death_signal() -> std::io::Result<()> {
    let rc = unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::getppid() } == 1 {
        unsafe { libc::_exit(0) }
    }
    Ok(())
}

fn resolved_host_target(path: &Path) -> Option<PathBuf> {
    let resolved = fs::canonicalize(path).ok()?;
    if resolved == path {
        None
    } else {
        Some(resolved)
    }
}

fn broker_apply_projection(
    file: &fs::File,
    current: &[ProjectedRange],
    target: &[ProjectedRange],
) -> Result<()> {
    for segment in target {
        apply_host_range_lock(file, segment.start, segment.end, segment.mode, false)?;
    }
    for stale in ranges_not_covered(current, target) {
        apply_host_range_unlock(file, stale.0, stale.1)?;
    }
    Ok(())
}

fn write_broker_request(stream: &mut UnixStream, request: &BrokerRequest) -> Result<()> {
    match request {
        BrokerRequest::ApplyProjection {
            ino,
            path,
            projection,
        } => {
            write_u8(stream, 1)?;
            write_u64(stream, *ino)?;
            write_bytes(stream, path.as_os_str().as_bytes())?;
            write_u32(stream, projection.len() as u32)?;
            for segment in projection {
                write_u64(stream, segment.start)?;
                write_u64(stream, segment.end)?;
                write_u8(
                    stream,
                    match segment.mode {
                        LockMode::Shared => 1,
                        LockMode::Exclusive => 2,
                    },
                )?;
            }
        }
        BrokerRequest::DropInode { ino } => {
            write_u8(stream, 2)?;
            write_u64(stream, *ino)?;
        }
        BrokerRequest::Shutdown => {
            write_u8(stream, 3)?;
        }
    }
    stream.flush()?;
    Ok(())
}

fn read_broker_request(stream: &mut UnixStream) -> Result<BrokerRequest> {
    let kind = read_u8(stream)?;
    Ok(match kind {
        1 => {
            let ino = read_u64(stream)?;
            let path = PathBuf::from(std::ffi::OsString::from_vec(read_bytes(stream)?));
            let len = read_u32(stream)? as usize;
            let mut projection = Vec::with_capacity(len);
            for _ in 0..len {
                let start = read_u64(stream)?;
                let end = read_u64(stream)?;
                let mode = match read_u8(stream)? {
                    1 => LockMode::Shared,
                    2 => LockMode::Exclusive,
                    _ => return Err(std::io::Error::from_raw_os_error(EIO).into()),
                };
                projection.push(ProjectedRange { start, end, mode });
            }
            BrokerRequest::ApplyProjection {
                ino,
                path,
                projection,
            }
        }
        2 => BrokerRequest::DropInode {
            ino: read_u64(stream)?,
        },
        3 => BrokerRequest::Shutdown,
        _ => return Err(std::io::Error::from_raw_os_error(EIO).into()),
    })
}

fn write_broker_response(stream: &mut UnixStream, errno: i32) -> Result<()> {
    write_i32(stream, errno)?;
    stream.flush()?;
    Ok(())
}

fn read_broker_response(stream: &mut UnixStream) -> Result<()> {
    match read_i32(stream)? {
        0 => Ok(()),
        errno => Err(std::io::Error::from_raw_os_error(errno).into()),
    }
}

fn apply_setlk(file: &fs::File, start: u64, end: u64, typ: i32, sleep: bool) -> Result<()> {
    let cmd = if sleep { libc::F_SETLKW } else { libc::F_SETLK };
    let flock = make_flock(start, end, typ);
    let rc = unsafe { libc::fcntl(file.as_raw_fd(), cmd, &flock) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().into())
    }
}

fn getlk(file: &fs::File, start: u64, end: u64, typ: i32) -> Result<(u64, u64, i32, u32)> {
    let mut flock = make_flock(start, end, typ);
    let rc = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETLK, &mut flock) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let out_start = flock.l_start.max(0) as u64;
    let out_end = if flock.l_len == 0 {
        u64::MAX
    } else {
        out_start
            .saturating_add(flock.l_len as u64)
            .saturating_sub(1)
    };
    Ok((out_start, out_end, flock.l_type as i32, flock.l_pid as u32))
}

fn statfs(path: &Path) -> Result<StatFs> {
    let c_path = CString::new(path.as_os_str().as_bytes())?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(StatFs {
        blocks: stat.f_blocks,
        bfree: stat.f_bfree,
        bavail: stat.f_bavail,
        files: stat.f_files,
        ffree: stat.f_ffree,
        bsize: stat.f_bsize as u32,
        namelen: stat.f_namemax as u32,
        frsize: stat.f_frsize as u32,
    })
}

fn io_errno(err: &anyhow::Error) -> i32 {
    if let Some(io) = err.downcast_ref::<std::io::Error>() {
        if let Some(code) = io.raw_os_error() {
            return code;
        }
        return match io.kind() {
            std::io::ErrorKind::NotFound => ENOENT,
            std::io::ErrorKind::PermissionDenied => EACCES,
            std::io::ErrorKind::AlreadyExists => libc::EEXIST,
            std::io::ErrorKind::InvalidInput => EINVAL,
            std::io::ErrorKind::IsADirectory => EISDIR,
            std::io::ErrorKind::NotADirectory => ENOTDIR,
            _ => EIO,
        };
    }
    EIO
}

fn is_access_denied_errno(errno: i32) -> bool {
    matches!(errno, libc::EACCES | libc::EPERM)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::AllowAll;

    #[test]
    fn forget_drops_inode_path_mapping_when_no_longer_referenced() {
        let root = tempfile::tempdir().expect("tempdir");
        let path = root.path().join("a.txt");
        fs::write(&path, b"data").expect("seed file");

        let mut mirror = MirrorFs::new(root.path().to_path_buf(), AllowAll);
        let ino = mirror.ensure_ino(&path);
        mirror.note_lookup(ino, 1);

        assert_eq!(mirror.path_for_ino(ino), Some(path.as_path()));
        mirror.forget_ino(ino, 1);
        assert!(mirror.path_for_ino(ino).is_none());
        assert!(!mirror.path_to_ino.contains_key(&path));
    }

    #[test]
    fn forget_keeps_mapping_until_open_handle_is_released() {
        let root = tempfile::tempdir().expect("tempdir");
        let path = root.path().join("b.txt");
        fs::write(&path, b"data").expect("seed file");

        let mut mirror = MirrorFs::new(root.path().to_path_buf(), AllowAll);
        let ino = mirror.ensure_ino(&path);
        mirror.note_lookup(ino, 1);
        let caller = MirrorFs::<AllowAll>::caller_for_test("test");
        let fh = mirror
            .open_for_test(&caller, &path, libc::O_RDONLY)
            .expect("open");

        mirror.forget_ino(ino, 1);
        assert_eq!(mirror.path_for_ino(ino), Some(path.as_path()));

        mirror.release_for_test(fh);
        assert!(mirror.path_for_ino(ino).is_none());
    }
}
