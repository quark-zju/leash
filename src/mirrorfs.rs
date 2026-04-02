use std::collections::HashMap;
use std::ffi::{CString, OsStr};
use std::fs::Metadata;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use fs_err as fs;
use fs_err::os::unix::fs::OpenOptionsExt as FsOpenOptionsExt;
use fuser::{
    AccessFlags, Config, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags,
    Generation, INodeNo, InitFlags, KernelConfig, LockOwner, MountOption, OpenFlags, RenameFlags,
    ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyLock,
    ReplyOpen, ReplyStatfs, ReplyWrite, Request, TimeOrNow, WriteFlags,
};
use libc::{EACCES, EINVAL, EIO, EISDIR, ENOENT, ENOSYS, ENOTDIR};
use log::debug;

use crate::access::{AccessController, AccessDecision, AccessRequest, Caller, Operation};

const TTL: Duration = Duration::ZERO;
const ROOT_INO: u64 = 1;

pub struct MirrorFs<P> {
    root: PathBuf,
    policy: P,
    next_ino: u64,
    next_fh: u64,
    ino_to_paths: HashMap<u64, Vec<PathBuf>>,
    path_to_ino: HashMap<PathBuf, u64>,
    handles: HashMap<u64, OpenHandle>,
}

struct OpenHandle {
    ino: u64,
    file: fs::File,
}

struct FuseMirrorFs<P> {
    inner: Mutex<MirrorFs<P>>,
}

impl<P> FuseMirrorFs<P> {
    fn new(inner: MirrorFs<P>) -> Self {
        Self {
            inner: Mutex::new(inner),
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
        let mut ino_to_paths = HashMap::new();
        let mut path_to_ino = HashMap::new();
        ino_to_paths.insert(ROOT_INO, vec![root.clone()]);
        path_to_ino.insert(root.clone(), ROOT_INO);

        Self {
            root,
            policy,
            next_ino: ROOT_INO + 1,
            next_fh: 1,
            ino_to_paths,
            path_to_ino,
            handles: HashMap::new(),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn mount(self, mountpoint: &Path) -> Result<()> {
        let options = fuse_mount_options();
        let mut config = Config::default();
        config.mount_options = options;
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
        fuser::spawn_mount2(FuseMirrorFs::new(self), mountpoint, &config).with_context(|| {
            format!(
                "failed to mount mirror filesystem in background at {}",
                mountpoint.display()
            )
        })
    }

    #[allow(dead_code)]
    pub(crate) fn caller_for_test(process_name: &str) -> Caller {
        Caller::new(None, Some(process_name.to_owned()))
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

    #[allow(dead_code)]
    pub(crate) fn unregister_path_for_test(&mut self, path: &Path) {
        self.unregister_path(path);
    }

    fn authorize(&self, caller: &Caller, path: &Path, operation: Operation) -> Result<()> {
        match self.policy.check(&AccessRequest {
            caller,
            path,
            operation,
        }) {
            AccessDecision::Allow => Ok(()),
            AccessDecision::Deny(errno) => Err(std::io::Error::from_raw_os_error(errno).into()),
        }
    }

    fn authorize_errno(&self, caller: &Caller, path: &Path, operation: Operation) -> Option<i32> {
        match self.policy.check(&AccessRequest {
            caller,
            path,
            operation,
        }) {
            AccessDecision::Allow => None,
            AccessDecision::Deny(errno) => Some(errno),
        }
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
        self.list_children(path)
    }

    fn list_children(&mut self, parent: &Path) -> Result<Vec<(u64, FileType, std::ffi::OsString)>> {
        let mut out = Vec::new();
        let entries = fs::read_dir(parent)?;
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            let metadata = entry.metadata()?;
            let ino = self.ensure_ino(&path);
            out.push((ino, filetype_from_metadata(&metadata), entry.file_name()));
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
        self.authorize(caller, path, operation)?;
        ensure_openable_node(path)?;
        let file = open_host_file(path, flags, false)?;
        Ok(self.allocate_handle(ino, file))
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
        self.authorize(caller, parent, Operation::Create)?;
        let path = parent.join(name);
        let file = open_host_file(&path, flags | libc::O_CREAT, true)?;
        let created_mode = normalize_create_mode(mode, umask) as u32;
        file.set_permissions(std::fs::Permissions::from_mode(created_mode))?;
        let metadata = file.metadata()?;
        let ino = self.ensure_ino(&path);
        let fh = self.allocate_handle(ino, file);
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
        let ino = self
            .handles
            .get(&fh)
            .map(|handle| handle.ino)
            .ok_or_else(|| std::io::Error::from_raw_os_error(ENOENT))?;
        let path = self
            .path_for_ino(ino)
            .ok_or_else(|| std::io::Error::from_raw_os_error(ENOENT))?;
        self.authorize(caller, path, Operation::Fsync)?;
        self.handles
            .get_mut(&fh)
            .ok_or_else(|| std::io::Error::from_raw_os_error(ENOENT))?
            .file
            .sync_data()?;
        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) fn release_for_test(&mut self, fh: u64) {
        self.handles.remove(&fh);
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

    fn setlk_flock_for_fuse(
        &mut self,
        caller: &Caller,
        ino: u64,
        fh: u64,
        typ: i32,
        sleep: bool,
    ) -> Result<()> {
        let path = self
            .path_for_ino(ino)
            .ok_or_else(|| std::io::Error::from_raw_os_error(ENOENT))?;
        self.authorize(caller, path, lock_operation(typ))?;
        let handle = self
            .handles
            .get(&fh)
            .ok_or_else(|| std::io::Error::from_raw_os_error(ENOENT))?;
        // fuser does not currently expose fuse_lk_in.lk_flags, so with both
        // FUSE_FLOCK_LOCKS and FUSE_POSIX_LOCKS enabled we cannot distinguish
        // BSD flock requests from POSIX fcntl lock requests here. We
        // intentionally translate every incoming lock request onto host flock.
        // That preserves host-visible exclusion, but it changes semantics:
        // byte ranges are ignored, ownership becomes open-file-description
        // based, and blocking requests may deadlock if the waiter depends on
        // another request the daemon has not yet serviced.
        apply_flock(&handle.file, typ, sleep)
    }

    fn getlk_flock_for_fuse(
        &mut self,
        caller: &Caller,
        ino: u64,
        _fh: u64,
        typ: i32,
    ) -> Result<(u64, u64, i32, u32)> {
        let path = self
            .path_for_ino(ino)
            .ok_or_else(|| std::io::Error::from_raw_os_error(ENOENT))?
            .to_path_buf();
        self.authorize(caller, &path, Operation::GetLock)?;
        getlk_via_flock_probe(&path, typ)
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
        self.authorize(caller, path, Operation::SetAttr)?;
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

    fn allocate_handle(&mut self, ino: u64, file: fs::File) -> u64 {
        let fh = self.next_fh;
        self.next_fh += 1;
        self.handles.insert(fh, OpenHandle { ino, file });
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

fn fuse_mount_options() -> Vec<MountOption> {
    vec![MountOption::FSName("leash2-mirror".to_owned())]
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
        let mut fs = self.inner.lock().unwrap();
        match fs.lookup_child(&caller, parent.0, name) {
            Ok(attr) => reply.entry(&TTL, &attr, Generation(0)),
            Err(err) => reply.error(Errno::from_i32(io_errno(&err))),
        }
    }

    fn getattr(&self, req: &Request, ino: INodeNo, fh: Option<FileHandle>, reply: ReplyAttr) {
        let caller = caller_from_request(req);
        let mut fs = self.inner.lock().unwrap();
        let result = match fh {
            Some(fh) => fs.getattr_handle(&caller, ino.0, fh.0),
            None => match fs.path_for_ino(ino.0).map(Path::to_path_buf) {
                Some(path) => fs.getattr_path(&caller, &path),
                None => Err(std::io::Error::from_raw_os_error(ENOENT).into()),
            },
        };
        match result {
            Ok(attr) => reply.attr(&TTL, &attr),
            Err(err) => reply.error(Errno::from_i32(io_errno(&err))),
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
        let mut fs = self.inner.lock().unwrap();
        let Some(path) = fs.path_for_ino(ino.0).map(Path::to_path_buf) else {
            reply.error(Errno::ENOENT);
            return;
        };
        if let Some(errno) = fs.authorize_errno(&caller, &path, Operation::ReadDir) {
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
        match fs.list_children(&path) {
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

    fn open(&self, req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        let caller = caller_from_request(req);
        let mut fs = self.inner.lock().unwrap();
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
            fs.authorize(&caller, &path, operation)?;
            ensure_openable_node(&path)?;
            let file = open_host_file(&path, raw_flags, false)?;
            Ok(fs.allocate_handle(ino.0, file))
        })();
        match result {
            Ok(fh) => reply.opened(FileHandle(fh), FopenFlags::empty()),
            Err(err) => reply.error(Errno::from_i32(io_errno(&err))),
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
        let mut fs = self.inner.lock().unwrap();
        match fs.read_handle(&caller, ino.0, fh.0, offset as i64, size) {
            Ok(data) => reply.data(&data),
            Err(err) => reply.error(Errno::from_i32(io_errno(&err))),
        }
    }

    fn readlink(&self, req: &Request, ino: INodeNo, reply: ReplyData) {
        let caller = caller_from_request(req);
        let fs = self.inner.lock().unwrap();
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
        let mut fs = self.inner.lock().unwrap();
        let Some(parent_path) = fs.path_for_ino(parent.0).map(Path::to_path_buf) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let result = (|| -> Result<(FileAttr, u64)> {
            fs.authorize(&caller, &parent_path, Operation::Create)?;
            let path = parent_path.join(name);
            let file = open_host_file(&path, flags | libc::O_CREAT, true)?;
            let created_mode = normalize_create_mode(mode, umask) as u32;
            file.set_permissions(std::fs::Permissions::from_mode(created_mode))?;
            let metadata = file.metadata()?;
            let ino = fs.ensure_ino(&path);
            let fh = fs.allocate_handle(ino, file);
            let attr = fs.attr_for_path(&path, &metadata);
            Ok((attr, fh))
        })();
        match result {
            Ok((attr, fh)) => reply.created(
                &TTL,
                &attr,
                Generation(0),
                FileHandle(fh),
                FopenFlags::empty(),
            ),
            Err(err) => reply.error(Errno::from_i32(io_errno(&err))),
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
        let mut fs = self.inner.lock().unwrap();
        match fs.write_handle(&caller, ino.0, fh.0, offset as i64, data) {
            Ok(len) => reply.written(len),
            Err(err) => reply.error(Errno::from_i32(io_errno(&err))),
        }
    }

    fn flush(
        &self,
        req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _lock_owner: LockOwner,
        reply: ReplyEmpty,
    ) {
        let caller = caller_from_request(req);
        let mut fs = self.inner.lock().unwrap();
        match fs.flush_for_test(&caller, fh.0) {
            Ok(()) => reply.ok(),
            Err(err) => reply.error(Errno::from_i32(io_errno(&err))),
        }
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        let mut fs = self.inner.lock().unwrap();
        fs.release_for_test(fh.0);
        reply.ok();
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
        let mut fs = self.inner.lock().unwrap();
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
        let mut fs = self.inner.lock().unwrap();
        let Some(parent_path) = fs.path_for_ino(parent.0).map(Path::to_path_buf) else {
            reply.error(Errno::ENOENT);
            return;
        };
        if let Some(errno) = fs.authorize_errno(&caller, &parent_path, Operation::Mkdir) {
            reply.error(Errno::from_i32(errno));
            return;
        }
        let path = parent_path.join(name);
        let result = create_dir_with_mode(&path, normalize_create_mode(mode, umask))
            .and_then(|_| fs::symlink_metadata(&path));
        match result {
            Ok(metadata) => {
                let attr = fs.attr_for_path(&path, &metadata);
                reply.entry(&TTL, &attr, Generation(0));
            }
            Err(err) => reply.error(Errno::from(err)),
        }
    }

    fn unlink(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let caller = caller_from_request(req);
        let mut fs = self.inner.lock().unwrap();
        let Some(path) = fs.resolve_child(parent.0, name) else {
            reply.error(Errno::ENOENT);
            return;
        };
        if let Some(errno) = fs.authorize_errno(&caller, &path, Operation::Unlink) {
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
        let mut fs = self.inner.lock().unwrap();
        let Some(path) = fs.resolve_child(parent.0, name) else {
            reply.error(Errno::ENOENT);
            return;
        };
        if let Some(errno) = fs.authorize_errno(&caller, &path, Operation::Rmdir) {
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
        let mut fs = self.inner.lock().unwrap();
        let Some(path) = fs.resolve_child(parent.0, name) else {
            reply.error(Errno::ENOENT);
            return;
        };
        if let Some(errno) = fs.authorize_errno(&caller, &path, Operation::Symlink) {
            reply.error(Errno::from_i32(errno));
            return;
        }
        match std::os::unix::fs::symlink(link, &path).and_then(|_| fs::symlink_metadata(&path)) {
            Ok(metadata) => {
                let attr = fs.attr_for_path(&path, &metadata);
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
        let mut fs = self.inner.lock().unwrap();
        let Some(newparent_path) = fs.path_for_ino(newparent.0).map(Path::to_path_buf) else {
            reply.error(Errno::ENOENT);
            return;
        };
        match fs.link_for_test(&caller, ino.0, &newparent_path, newname) {
            Ok(attr) => reply.entry(&TTL, &attr, Generation(0)),
            Err(err) => reply.error(Errno::from_i32(io_errno(&err))),
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
        let mut fs = self.inner.lock().unwrap();
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
            Err(err) => reply.error(Errno::from_i32(io_errno(&err))),
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
        let mut fs = self.inner.lock().unwrap();
        let Some(path) = fs.path_for_ino(ino.0).map(Path::to_path_buf) else {
            reply.error(Errno::ENOENT);
            return;
        };
        match fs.setattr_for_test(&caller, &path, size, mode, atime, mtime) {
            Ok(attr) => reply.attr(&TTL, &attr),
            Err(err) => reply.error(Errno::from_i32(io_errno(&err))),
        }
    }

    fn access(&self, req: &Request, ino: INodeNo, _mask: AccessFlags, reply: ReplyEmpty) {
        let caller = caller_from_request(req);
        let fs = self.inner.lock().unwrap();
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
        let fs = self.inner.lock().unwrap();
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

    fn fsyncdir(
        &self,
        req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        datasync: bool,
        reply: ReplyEmpty,
    ) {
        let caller = caller_from_request(req);
        let fs = self.inner.lock().unwrap();
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
        _lock_owner: LockOwner,
        _start: u64,
        _end: u64,
        typ: i32,
        _pid: u32,
        reply: ReplyLock,
    ) {
        let caller = caller_from_request(req);
        let mut fs = self.inner.lock().unwrap();
        match fs.getlk_flock_for_fuse(&caller, ino.0, fh.0, typ) {
            Ok((start, end, typ, pid)) => reply.locked(start, end, typ, pid),
            Err(err) => reply.error(Errno::from_i32(io_errno(&err))),
        }
    }

    fn setlk(
        &self,
        req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        _lock_owner: LockOwner,
        _start: u64,
        _end: u64,
        typ: i32,
        _pid: u32,
        sleep: bool,
        reply: ReplyEmpty,
    ) {
        let caller = caller_from_request(req);
        let mut fs = self.inner.lock().unwrap();
        match fs.setlk_flock_for_fuse(&caller, ino.0, fh.0, typ, sleep) {
            Ok(()) => reply.ok(),
            Err(err) => reply.error(Errno::from_i32(io_errno(&err))),
        }
    }
}

fn caller_from_request(req: &Request) -> Caller {
    let pid = req.pid();
    let process_name = read_process_name(pid);
    debug!("mirrorfs request pid={} comm={:?}", pid, process_name);
    Caller::new(Some(pid), process_name)
}

fn read_process_name(pid: u32) -> Option<String> {
    let path = PathBuf::from(format!("/proc/{pid}/comm"));
    let raw = fs::read_to_string(path).ok()?;
    let name = raw.trim().to_owned();
    if name.is_empty() { None } else { Some(name) }
}

fn filetype_from_metadata(metadata: &Metadata) -> FileType {
    let kind = metadata.file_type();
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
