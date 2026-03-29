use fs_err::os::unix::fs::OpenOptionsExt as FsOpenOptionsExt;
use log::debug;
use std::ffi::{CString, OsStr};
use std::fs::Metadata;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use fs_err as fs;
use fuser::{
    self, FileAttr, FileType, Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory,
    ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, Request, TimeOrNow,
};
use libc::{
    EACCES, EINVAL, EIO, EISDIR, ENOENT, ENOSYS, ENOTDIR, EPERM,
};

use crate::git_rw_filter::GitRwFilter;
use crate::profile::{Profile, RuleAction, Visibility};

const TTL: Duration = Duration::from_secs(1);
const ROOT_INO: u64 = 1;

pub struct CowFs {
    profile: Profile,
    git_rw_filter: GitRwFilter,
    mount_root: Option<PathBuf>,
    next_ino: u64,
    next_fh: u64,
    ino_to_path: std::collections::HashMap<u64, PathBuf>,
    path_to_ino: std::collections::HashMap<PathBuf, u64>,
    handles: std::collections::HashMap<u64, OpenHandle>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteMode {
    Forbidden,
    Passthrough,
}

enum OpenHandle {
    Passthrough { ino: u64, file: fs::File },
}

impl CowFs {
    pub fn new(profile: Profile) -> Self {
        let mut ino_to_path = std::collections::HashMap::new();
        let mut path_to_ino = std::collections::HashMap::new();
        ino_to_path.insert(ROOT_INO, PathBuf::from("/"));
        path_to_ino.insert(PathBuf::from("/"), ROOT_INO);

        Self {
            profile,
            git_rw_filter: GitRwFilter::new(),
            mount_root: None,
            next_ino: ROOT_INO + 1,
            next_fh: 1,
            ino_to_path,
            path_to_ino,
            handles: std::collections::HashMap::new(),
        }
    }

    pub fn with_mount_root(mut self, mount_root: PathBuf) -> Self {
        self.mount_root = Some(mount_root);
        self
    }

    pub fn mount(self, mountpoint: &Path, allow_other: bool) -> Result<()> {
        let options = fuse_mount_options(allow_other);
        fuser::mount2(self, mountpoint, &options).with_context(|| {
            format!(
                "failed to mount fuse filesystem at {}",
                mountpoint.display()
            )
        })
    }

    pub unsafe fn mount_background(
        self,
        mountpoint: &Path,
        allow_other: bool,
    ) -> Result<fuser::BackgroundSession> {
        let options = fuse_mount_options(allow_other);
        fuser::spawn_mount2(self, mountpoint, &options).with_context(|| {
            format!(
                "failed to mount fuse filesystem in background at {}",
                mountpoint.display()
            )
        })
    }

    fn ensure_ino(&mut self, path: &Path) -> u64 {
        if let Some(ino) = self.path_to_ino.get(path) {
            return *ino;
        }
        let ino = self.next_ino;
        self.next_ino += 1;
        let owned = path.to_path_buf();
        self.path_to_ino.insert(owned.clone(), ino);
        self.ino_to_path.insert(ino, owned);
        ino
    }

    fn path_for_ino(&self, ino: u64) -> Option<&Path> {
        self.ino_to_path.get(&ino).map(|p| p.as_path())
    }

    fn is_visible(&self, path: &Path) -> bool {
        if self.is_hard_blocked_runtime_path(path) {
            return true;
        }
        match self.dynamic_visibility(path) {
            Visibility::Hidden | Visibility::Action(RuleAction::Hide) => false,
            Visibility::ImplicitAncestor => self.path_is_directory(path),
            Visibility::Action(_) => true,
        }
    }

    fn access_errno_for_pid(&self, path: &Path, requester_pid: Option<u32>) -> Option<i32> {
        if is_blocked_proc_thread_self(path) {
            return Some(ENOENT);
        }
        if self.is_hard_blocked_runtime_path(path) {
            return Some(EACCES);
        }
        if self.git_rw_filter.is_git_metadata_path(path)
            && !requester_pid.is_some_and(|pid| {
                self.git_rw_filter
                    .allow_git_metadata_for_pid(pid, self.mount_root.as_deref())
            })
        {
            return Some(EACCES);
        }
        match self.dynamic_visibility(path) {
            Visibility::Hidden | Visibility::Action(RuleAction::Hide) => Some(ENOENT),
            Visibility::Action(RuleAction::Deny) => Some(EACCES),
            Visibility::ImplicitAncestor if !self.path_is_directory(path) => Some(ENOENT),
            _ => None,
        }
    }

    #[cfg(test)]
    fn access_errno(&self, path: &Path) -> Option<i32> {
        self.access_errno_for_pid(path, None)
    }

    fn mutation_errno_for_pid(&self, path: &Path, requester_pid: Option<u32>) -> Option<i32> {
        if is_blocked_proc_thread_self(path) {
            return Some(ENOENT);
        }
        if self.is_hard_blocked_runtime_path(path) {
            return Some(EACCES);
        }
        if self.git_rw_filter.is_git_metadata_path(path)
            && !requester_pid.is_some_and(|pid| {
                self.git_rw_filter
                    .allow_git_metadata_for_pid(pid, self.mount_root.as_deref())
            })
        {
            return Some(EACCES);
        }
        match self.dynamic_visibility(path) {
            Visibility::Hidden | Visibility::Action(RuleAction::Hide) => Some(EPERM),
            Visibility::Action(RuleAction::Deny) => Some(EACCES),
            Visibility::ImplicitAncestor if !self.path_is_directory(path) => Some(ENOENT),
            _ => None,
        }
    }

    #[cfg(test)]
    fn mutation_errno(&self, path: &Path) -> Option<i32> {
        self.mutation_errno_for_pid(path, None)
    }

    fn path_is_directory(&self, path: &Path) -> bool {
        match fs::symlink_metadata(path) {
            Ok(meta) => meta.file_type().is_dir(),
            Err(_) => false,
        }
    }

    fn runtime_guard_root(&self) -> Option<&Path> {
        let mount_root = self.mount_root.as_deref()?;
        if mount_root.file_name() != Some(OsStr::new(crate::ns_runtime::MOUNT_DIR_NAME)) {
            return None;
        }
        let runtime_dir = mount_root.parent()?;
        let runtime_root = runtime_dir.parent()?;
        if runtime_root != crate::jail::runtime_root() {
            return None;
        }
        Some(runtime_root)
    }

    fn is_hard_blocked_runtime_path(&self, path: &Path) -> bool {
        let Some(root) = self.runtime_guard_root() else {
            return false;
        };
        path == root || path.starts_with(root)
    }

    fn dynamic_visibility(&self, path: &Path) -> Visibility {
        match self.profile.visibility(path) {
            Visibility::Action(RuleAction::GitRw) => {
                if self.git_rw_filter.path_is_git_repo_member(path) {
                    Visibility::Action(RuleAction::Passthrough)
                } else {
                    Visibility::Action(RuleAction::ReadOnly)
                }
            }
            other => other,
        }
    }

    fn write_mode_for_pid(&self, path: &Path, requester_pid: Option<u32>) -> WriteMode {
        if self.git_rw_filter.is_git_metadata_path(path) {
            return if requester_pid.is_some_and(|pid| {
                self.git_rw_filter
                    .allow_git_metadata_for_pid(pid, self.mount_root.as_deref())
            }) {
                WriteMode::Passthrough
            } else {
                WriteMode::Forbidden
            };
        }
        match self.dynamic_visibility(path) {
            Visibility::Action(RuleAction::Passthrough) => WriteMode::Passthrough,
            _ => WriteMode::Forbidden,
        }
    }

    #[cfg(test)]
    fn write_mode(&self, path: &Path) -> WriteMode {
        self.write_mode_for_pid(path, None)
    }

    fn attr_for_path(&mut self, path: &Path, metadata: &Metadata) -> FileAttr {
        FileAttr {
            ino: self.ensure_ino(path),
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

    fn host_attr(&mut self, path: &Path) -> Result<FileAttr, i32> {
        let meta = fs::symlink_metadata(path).map_err(|err| io_errno(&err))?;
        Ok(self.attr_for_path(path, &meta))
    }

    fn host_attr_for_handle(&mut self, path: &Path, fh: u64) -> Result<FileAttr, i32> {
        let meta = self
            .handles
            .get(&fh)
            .and_then(|handle| match handle {
                OpenHandle::Passthrough { file, .. } => Some(file),
            })
            .ok_or(ENOENT)?
            .metadata()
            .map_err(|err| io_errno(&err))?;
        Ok(self.attr_for_path(path, &meta))
    }

    fn allocate_passthrough_handle(&mut self, ino: u64, file: fs::File) -> u64 {
        let fh = self.next_fh;
        self.next_fh += 1;
        self.handles
            .insert(fh, OpenHandle::Passthrough { ino, file });
        fh
    }

    fn handle_ino(&self, fh: u64) -> Option<u64> {
        self.handles.get(&fh).map(|handle| match handle {
            OpenHandle::Passthrough { ino, .. } => *ino,
        })
    }

    fn passthrough_file_mut(&mut self, fh: u64) -> Option<&mut fs::File> {
        self.handles.get_mut(&fh).map(|handle| match handle {
            OpenHandle::Passthrough { file, .. } => file,
        })
    }

    fn remove_handle(&mut self, fh: u64) {
        self.handles.remove(&fh);
    }

    fn ensure_openable_node(&self, path: &Path) -> Result<(), i32> {
        let meta = fs::symlink_metadata(path).map_err(|err| io_errno(&err))?;
        if meta.file_type().is_dir() {
            Err(EISDIR)
        } else {
            Ok(())
        }
    }

    fn list_children(
        &mut self,
        parent: &Path,
    ) -> Result<Vec<(u64, FileType, std::ffi::OsString)>, i32> {
        let mut out = Vec::new();
        let rd = fs::read_dir(parent).map_err(|err| io_errno(&err))?;
        for child in rd {
            let child = child.map_err(|err| io_errno(&err))?;
            let name = child.file_name();
            let child_path = parent.join(&name);
            if !self.is_visible(&child_path) {
                continue;
            }
            let meta = child.metadata().map_err(|err| io_errno(&err))?;
            let child_type = filetype_from_metadata(&meta);
            let child_ino = self.ensure_ino(&child_path);
            out.push((child_ino, child_type, name));
        }
        Ok(out)
    }

    fn open_passthrough_file(path: &Path, flags: i32, create_new: bool) -> Result<fs::File, i32> {
        let mut opts = fs::OpenOptions::new();
        match flags & libc::O_ACCMODE {
            libc::O_RDONLY => {
                opts.read(true);
            }
            libc::O_WRONLY => {
                opts.write(true);
            }
            libc::O_RDWR => {
                opts.read(true).write(true);
            }
            _ => return Err(EINVAL),
        }
        if flags & libc::O_APPEND != 0 {
            opts.append(true);
        }
        if create_new {
            opts.create_new(true);
        }
        let custom_flags = flags
            & !(libc::O_ACCMODE
                | libc::O_APPEND
                | libc::O_CREAT
                | libc::O_EXCL
                | libc::O_NOCTTY
                | libc::O_TRUNC);
        opts.custom_flags(custom_flags);
        opts.open(path).map_err(|err| io_errno(&err))
    }

    fn apply_passthrough_setattr(
        &mut self,
        path: &Path,
        size: Option<u64>,
        mode: Option<u32>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
    ) -> Result<FileAttr, i32> {
        if size.is_none() && mode.is_none() && atime.is_none() && mtime.is_none() {
            return Err(ENOSYS);
        }

        if let Some(size) = size {
            let file = fs::OpenOptions::new()
                .write(true)
                .open(path)
                .map_err(|err| io_errno(&err))?;
            file.set_len(size).map_err(|err| io_errno(&err))?;
        }

        if let Some(mode) = mode {
            let perm = std::fs::Permissions::from_mode(mode);
            fs::set_permissions(path, perm).map_err(|err| io_errno(&err))?;
        }

        if atime.is_some() || mtime.is_some() {
            let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|_| EINVAL)?;
            let times = [to_timespec_or_omit(atime), to_timespec_or_omit(mtime)];
            let rc = unsafe { libc::utimensat(libc::AT_FDCWD, c_path.as_ptr(), times.as_ptr(), 0) };
            if rc != 0 {
                return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(EIO));
            }
        }

        let meta = fs::symlink_metadata(path).map_err(|err| io_errno(&err))?;
        Ok(self.attr_for_path(path, &meta))
    }

    #[cfg(test)]
    fn apply_passthrough_setattr_for_test(
        &mut self,
        path: &Path,
        size: Option<u64>,
        mode: Option<u32>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
    ) -> Result<FileAttr, i32> {
        self.apply_passthrough_setattr(path, size, mode, atime, mtime)
    }
}

fn fuse_mount_options(allow_other: bool) -> Vec<fuser::MountOption> {
    let mut options = Vec::with_capacity(3);
    options.push(fuser::MountOption::DefaultPermissions);
    if allow_other {
        options.push(fuser::MountOption::AllowOther);
    }
    options.push(fuser::MountOption::FSName("cowjail".to_string()));
    options
}

pub(crate) fn allow_other_enabled_in_fuse_conf() -> bool {
    let Ok(raw) = fs::read_to_string("/etc/fuse.conf") else {
        return false;
    };
    raw.lines()
        .map(|line| line.split('#').next().unwrap_or("").trim())
        .any(|line| line == "user_allow_other")
}

impl Filesystem for CowFs {
    fn lookup(&mut self, req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let Some(parent_path) = self.path_for_ino(parent).map(ToOwned::to_owned) else {
            debug!("lookup: pid={} parent_ino={} name={:?} -> ENOENT (unknown parent inode)", req.pid(), parent, name);
            reply.error(ENOENT);
            return;
        };
        let path = parent_path.join(name);
        if let Some(errno) = self.access_errno_for_pid(&path, Some(req.pid())) {
            debug!(
                "lookup: pid={} path={} -> errno {} (policy)",
                req.pid(),
                path.display(),
                errno
            );
            reply.error(errno);
            return;
        }
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                let attr = self.attr_for_path(&path, &metadata);
                debug!(
                    "lookup: pid={} path={} -> ino={} kind={:?}",
                    req.pid(),
                    path.display(),
                    attr.ino,
                    attr.kind
                );
                reply.entry(&TTL, &attr, 0);
            }
            Err(err) => {
                let errno = io_errno(&err);
                debug!(
                    "lookup: pid={} path={} -> errno {} ({err})",
                    req.pid(),
                    path.display(),
                    errno
                );
                reply.error(errno);
            }
        }
    }

    fn getattr(&mut self, req: &Request<'_>, ino: u64, fh: Option<u64>, reply: ReplyAttr) {
        let resolved_ino = fh.and_then(|fh| self.handle_ino(fh)).unwrap_or(ino);
        let Some(path) = self.path_for_ino(resolved_ino).map(ToOwned::to_owned) else {
            debug!(
                "getattr: pid={} ino={} fh={:?} -> ENOENT (unknown inode)",
                req.pid(),
                ino,
                fh
            );
            reply.error(ENOENT);
            return;
        };
        if let Some(errno) = self.access_errno_for_pid(&path, Some(req.pid())) {
            debug!(
                "getattr: pid={} path={} ino={} fh={:?} -> errno {} (policy)",
                req.pid(),
                path.display(),
                ino,
                fh,
                errno
            );
            reply.error(errno);
            return;
        }
        if let Some(fh) = fh
            && let Ok(attr) = self.host_attr_for_handle(&path, fh)
        {
            debug!(
                "getattr: pid={} path={} ino={} fh={} -> handle attr",
                req.pid(),
                path.display(),
                ino,
                fh
            );
            reply.attr(&TTL, &attr);
            return;
        }
        match self.host_attr(&path) {
            Ok(attr) => {
                debug!(
                    "getattr: pid={} path={} ino={} fh={:?} -> host attr",
                    req.pid(),
                    path.display(),
                    ino,
                    fh
                );
                reply.attr(&TTL, &attr)
            }
            Err(code) => {
                debug!(
                    "getattr: pid={} path={} ino={} fh={:?} -> errno {}",
                    req.pid(),
                    path.display(),
                    ino,
                    fh,
                    code
                );
                reply.error(code)
            }
        }
    }

    fn readdir(
        &mut self,
        req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let Some(path) = self.path_for_ino(ino).map(ToOwned::to_owned) else {
            reply.error(ENOENT);
            return;
        };
        if let Some(errno) = self.access_errno_for_pid(&path, Some(req.pid())) {
            reply.error(errno);
            return;
        }
        let meta = match fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(err) => {
                reply.error(io_errno(&err));
                return;
            }
        };
        if !meta.file_type().is_dir() {
            reply.error(ENOTDIR);
            return;
        }

        let mut entries = Vec::new();
        let self_ino = self.ensure_ino(&path);
        let parent_path = if path == Path::new("/") {
            Path::new("/").to_path_buf()
        } else {
            path.parent().unwrap_or(Path::new("/")).to_path_buf()
        };
        let parent_ino = self.ensure_ino(&parent_path);
        entries.push((self_ino, FileType::Directory, std::ffi::OsString::from(".")));
        entries.push((parent_ino, FileType::Directory, std::ffi::OsString::from("..")));
        let host_entries = match self.list_children(&path) {
            Ok(entries) => entries,
            Err(code) => {
                reply.error(code);
                return;
            }
        };
        entries.extend(host_entries);

        append_readdir_entries(&entries, offset, |ino, next_offset, kind, name| {
            reply.add(ino, next_offset, kind, name)
        });
        reply.ok();
    }

    fn open(&mut self, req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
        let Some(path) = self.path_for_ino(ino).map(ToOwned::to_owned) else {
            reply.error(ENOENT);
            return;
        };
        if flags & libc::O_ACCMODE != libc::O_RDONLY {
            if let Some(errno) = self.mutation_errno_for_pid(&path, Some(req.pid())) {
                reply.error(errno);
                return;
            }
            if self.write_mode_for_pid(&path, Some(req.pid())) == WriteMode::Forbidden {
                reply.error(EACCES);
                return;
            }
        } else if let Some(errno) = self.access_errno_for_pid(&path, Some(req.pid())) {
            reply.error(errno);
            return;
        }
        if let Err(code) = self.ensure_openable_node(&path) {
            reply.error(code);
            return;
        }
        let file = match Self::open_passthrough_file(&path, flags, false) {
            Ok(file) => file,
            Err(code) => {
                reply.error(code);
                return;
            }
        };
        let fh = self.allocate_passthrough_handle(ino, file);
        reply.opened(fh, 0);
    }

    fn read(
        &mut self,
        req: &Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        let resolved_ino = self.handle_ino(fh).unwrap_or(ino);
        let Some(path) = self.path_for_ino(resolved_ino).map(ToOwned::to_owned) else {
            reply.error(ENOENT);
            return;
        };
        if let Some(errno) = self.access_errno_for_pid(&path, Some(req.pid())) {
            reply.error(errno);
            return;
        }
        if offset < 0 {
            reply.error(EIO);
            return;
        }

        let mut buf = vec![0u8; size as usize];
        let n = if let Some(file) = self.passthrough_file_mut(fh) {
            if file.seek(SeekFrom::Start(offset as u64)).is_err() {
                reply.error(EIO);
                return;
            }
            match file.read(&mut buf) {
                Ok(n) => n,
                Err(err) => {
                    reply.error(io_errno(&err));
                    return;
                }
            }
        } else {
            let mut file = match fs::File::open(&path) {
                Ok(file) => file,
                Err(err) => {
                    reply.error(io_errno(&err));
                    return;
                }
            };
            if file.seek(SeekFrom::Start(offset as u64)).is_err() {
                reply.error(EIO);
                return;
            }
            match file.read(&mut buf) {
                Ok(n) => n,
                Err(err) => {
                    reply.error(io_errno(&err));
                    return;
                }
            }
        };
        reply.data(&buf[..n]);
    }

    fn readlink(&mut self, req: &Request<'_>, ino: u64, reply: ReplyData) {
        let Some(path) = self.path_for_ino(ino).map(ToOwned::to_owned) else {
            reply.error(ENOENT);
            return;
        };
        if let Some(errno) = self.access_errno_for_pid(&path, Some(req.pid())) {
            reply.error(errno);
            return;
        }
        if let Some(rewritten) = rewrite_proc_self_readlink_target(&path, req.pid()) {
            reply.data(rewritten.as_bytes());
            return;
        }
        match fs::read_link(&path) {
            Ok(target) => {
                let rewritten =
                    rewrite_proc_exe_readlink_target(&path, &target, self.mount_root.as_deref());
                reply.data(rewritten.as_os_str().as_bytes());
            }
            Err(err) => reply.error(io_errno(&err)),
        }
    }

    fn create(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        let Some(parent_path) = self.path_for_ino(parent).map(ToOwned::to_owned) else {
            reply.error(ENOENT);
            return;
        };
        let path = parent_path.join(name);
        if let Some(errno) = self.mutation_errno_for_pid(&path, Some(req.pid())) {
            reply.error(errno);
            return;
        }
        if self.write_mode_for_pid(&path, Some(req.pid())) == WriteMode::Forbidden {
            reply.error(EACCES);
            return;
        }
        let file = match Self::open_passthrough_file(&path, flags, true) {
            Ok(file) => file,
            Err(code) => {
                reply.error(code);
                return;
            }
        };
        let created_mode = (normalize_create_mode(mode, umask) as u32) & 0o7777;
        if let Err(err) = file.set_permissions(std::fs::Permissions::from_mode(created_mode)) {
            reply.error(io_errno(&err));
            return;
        }
        let attr = match self.host_attr(&path) {
            Ok(attr) => attr,
            Err(code) => {
                reply.error(code);
                return;
            }
        };
        let fh = self.allocate_passthrough_handle(attr.ino, file);
        reply.created(&TTL, &attr, 0, fh, 0);
    }

    fn write(
        &mut self,
        req: &Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        let resolved_ino = self.handle_ino(fh).unwrap_or(ino);
        let Some(path) = self.path_for_ino(resolved_ino).map(ToOwned::to_owned) else {
            reply.error(ENOENT);
            return;
        };
        if self.write_mode_for_pid(&path, Some(req.pid())) == WriteMode::Forbidden {
            reply.error(EACCES);
            return;
        }
        if offset < 0 {
            reply.error(EIO);
            return;
        }
        let Some(file) = self.passthrough_file_mut(fh) else {
            reply.error(ENOENT);
            return;
        };
        if let Err(err) = file.seek(SeekFrom::Start(offset as u64)) {
            reply.error(io_errno(&err));
            return;
        }
        if let Err(err) = file.write_all(data) {
            reply.error(io_errno(&err));
            return;
        }
        reply.written(data.len() as u32);
    }

    fn flush(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        _lock_owner: u64,
        reply: ReplyEmpty,
    ) {
        if let Some(file) = self.passthrough_file_mut(fh)
            && let Err(err) = file.sync_data()
        {
            reply.error(io_errno(&err));
            return;
        }
        reply.ok();
    }

    fn release(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        self.remove_handle(fh);
        reply.ok();
    }

    fn unlink(&mut self, req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let Some(parent_path) = self.path_for_ino(parent).map(ToOwned::to_owned) else {
            reply.error(ENOENT);
            return;
        };
        let path = parent_path.join(name);
        if let Some(errno) = self.mutation_errno_for_pid(&path, Some(req.pid())) {
            reply.error(errno);
            return;
        }
        if self.write_mode_for_pid(&path, Some(req.pid())) == WriteMode::Forbidden {
            reply.error(EACCES);
            return;
        }
        if let Err(err) = fs::remove_file(&path) {
            reply.error(io_errno(&err));
            return;
        }
        reply.ok();
    }

    fn mkdir(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        umask: u32,
        reply: ReplyEntry,
    ) {
        let Some(parent_path) = self.path_for_ino(parent).map(ToOwned::to_owned) else {
            reply.error(ENOENT);
            return;
        };
        let path = parent_path.join(name);
        if let Some(errno) = self.mutation_errno_for_pid(&path, Some(req.pid())) {
            reply.error(errno);
            return;
        }
        if self.write_mode_for_pid(&path, Some(req.pid())) == WriteMode::Forbidden {
            reply.error(EACCES);
            return;
        }
        if let Err(err) = create_dir_with_mode(&path, normalize_create_mode(mode, umask)) {
            reply.error(io_errno(&err));
            return;
        }
        let attr = match self.host_attr(&path) {
            Ok(attr) => attr,
            Err(code) => {
                reply.error(code);
                return;
            }
        };
        reply.entry(&TTL, &attr, 0);
    }

    fn rmdir(&mut self, req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let Some(parent_path) = self.path_for_ino(parent).map(ToOwned::to_owned) else {
            reply.error(ENOENT);
            return;
        };
        let path = parent_path.join(name);
        if let Some(errno) = self.mutation_errno_for_pid(&path, Some(req.pid())) {
            reply.error(errno);
            return;
        }
        if self.write_mode_for_pid(&path, Some(req.pid())) == WriteMode::Forbidden {
            reply.error(EACCES);
            return;
        }
        if let Err(err) = fs::remove_dir(&path) {
            reply.error(io_errno(&err));
            return;
        }
        reply.ok();
    }

    fn symlink(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        link: &Path,
        reply: ReplyEntry,
    ) {
        let Some(parent_path) = self.path_for_ino(parent).map(ToOwned::to_owned) else {
            reply.error(ENOENT);
            return;
        };
        let path = parent_path.join(name);
        if let Some(errno) = self.mutation_errno_for_pid(&path, Some(req.pid())) {
            reply.error(errno);
            return;
        }
        if self.write_mode_for_pid(&path, Some(req.pid())) == WriteMode::Forbidden {
            reply.error(EACCES);
            return;
        }
        if let Err(err) = std::os::unix::fs::symlink(link, &path) {
            reply.error(io_errno(&err));
            return;
        }
        let attr = match self.host_attr(&path) {
            Ok(attr) => attr,
            Err(code) => {
                reply.error(code);
                return;
            }
        };
        reply.entry(&TTL, &attr, 0);
    }

    fn rename(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        _flags: u32,
        reply: ReplyEmpty,
    ) {
        let Some(parent_path) = self.path_for_ino(parent).map(ToOwned::to_owned) else {
            reply.error(ENOENT);
            return;
        };
        let Some(newparent_path) = self.path_for_ino(newparent).map(ToOwned::to_owned) else {
            reply.error(ENOENT);
            return;
        };
        let from = parent_path.join(name);
        let to = newparent_path.join(newname);
        if let Some(errno) = self.mutation_errno_for_pid(&from, Some(req.pid())) {
            reply.error(errno);
            return;
        }
        if let Some(errno) = self.mutation_errno_for_pid(&to, Some(req.pid())) {
            reply.error(errno);
            return;
        }
        if self.write_mode_for_pid(&from, Some(req.pid())) == WriteMode::Forbidden
            || self.write_mode_for_pid(&to, Some(req.pid())) == WriteMode::Forbidden
        {
            reply.error(EACCES);
            return;
        }
        if let Err(err) = fs::rename(&from, &to) {
            reply.error(io_errno(&err));
            return;
        }
        reply.ok();
    }

    fn setattr(
        &mut self,
        req: &Request<'_>,
        ino: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        if uid.is_some() || gid.is_some() {
            reply.error(libc::EOPNOTSUPP);
            return;
        }
        let Some(path) = self.path_for_ino(ino).map(ToOwned::to_owned) else {
            reply.error(ENOENT);
            return;
        };
        if let Some(errno) = self.mutation_errno_for_pid(&path, Some(req.pid())) {
            reply.error(errno);
            return;
        }
        if self.write_mode_for_pid(&path, Some(req.pid())) == WriteMode::Forbidden {
            reply.error(EACCES);
            return;
        }
        match self.apply_passthrough_setattr(&path, size, mode, atime, mtime) {
            Ok(attr) => reply.attr(&TTL, &attr),
            Err(code) => reply.error(code),
        }
    }
}

fn filetype_from_metadata(metadata: &Metadata) -> FileType {
    let ft = metadata.file_type();
    if ft.is_dir() {
        FileType::Directory
    } else if ft.is_symlink() {
        FileType::Symlink
    } else if ft.is_file() {
        FileType::RegularFile
    } else if ft.is_block_device() {
        FileType::BlockDevice
    } else if ft.is_char_device() {
        FileType::CharDevice
    } else if ft.is_fifo() {
        FileType::NamedPipe
    } else if ft.is_socket() {
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

fn io_errno(err: &std::io::Error) -> i32 {
    err.raw_os_error().unwrap_or(EIO)
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
    for (i, entry) in entries.iter().enumerate().skip(start) {
        if add(entry.0, (i + 1) as i64, entry.1, entry.2.as_os_str()) {
            break;
        }
    }
}

fn to_timespec_or_omit(value: Option<TimeOrNow>) -> libc::timespec {
    match value {
        Some(TimeOrNow::SpecificTime(ts)) => match ts.duration_since(SystemTime::UNIX_EPOCH) {
            Ok(dur) => libc::timespec {
                tv_sec: dur.as_secs() as libc::time_t,
                tv_nsec: dur.subsec_nanos() as libc::c_long,
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

fn is_blocked_proc_thread_self(path: &Path) -> bool {
    let blocked = Path::new("/proc/thread-self");
    path == blocked || path.starts_with(blocked)
}

fn rewrite_proc_self_readlink_target(path: &Path, requester_pid: u32) -> Option<String> {
    if path == Path::new("/proc/self") {
        return Some(requester_pid.to_string());
    }
    None
}

fn rewrite_proc_exe_readlink_target(
    path: &Path,
    target: &Path,
    mount_root: Option<&Path>,
) -> PathBuf {
    if !is_proc_exe_path(path) {
        return target.to_path_buf();
    }
    let Some(root) = mount_root else {
        return target.to_path_buf();
    };
    let Ok(suffix) = target.strip_prefix(root) else {
        return target.to_path_buf();
    };
    if suffix.as_os_str().is_empty() {
        PathBuf::from("/")
    } else {
        Path::new("/").join(suffix)
    }
}

fn is_proc_exe_path(path: &Path) -> bool {
    let Ok(without_proc) = path.strip_prefix("/proc") else {
        return false;
    };
    let mut parts = without_proc.components();
    let first = parts.next();
    let second = parts.next();
    matches!(
        (first, second, parts.next()),
        (Some(Component::Normal(_)), Some(Component::Normal(name)), None)
            if name == OsStr::new("exe")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn parse_profile(src: &str) -> Profile {
        Profile::parse(src, Path::new("/")).expect("profile parse")
    }

    fn test_fs(profile_src: &str) -> CowFs {
        CowFs::new(parse_profile(profile_src))
    }

    #[test]
    fn runtime_root_is_hard_denied_even_if_profile_allows_it() {
        let fs = test_fs("/run/** rw\n");
        let guarded = fs.with_mount_root(PathBuf::from("/run/user/1000/cowjail/demo/mount"));
        let runtime_root = Path::new("/run/user/1000/cowjail");
        let runtime_child = Path::new("/run/user/1000/cowjail/demo/fuse.pid");

        assert_eq!(guarded.access_errno(runtime_root), Some(EACCES));
        assert_eq!(guarded.access_errno(runtime_child), Some(EACCES));
        assert_eq!(guarded.mutation_errno(runtime_root), Some(EACCES));
        assert_eq!(guarded.mutation_errno(runtime_child), Some(EACCES));
    }

    #[test]
    fn arbitrary_mount_root_does_not_hard_block_parent_tree() {
        let fs = test_fs("/var/tmp/** rw\n");
        let guarded = fs.with_mount_root(PathBuf::from("/var/tmp/demo/mnt"));
        let allowed = Path::new("/var/tmp/demo/file.txt");

        assert_eq!(guarded.access_errno(allowed), None);
        assert_eq!(guarded.mutation_errno(allowed), None);
    }

    #[test]
    fn deny_path_returns_eacces() {
        let fs = test_fs("/tmp/deny-me deny");
        assert_eq!(fs.access_errno(Path::new("/tmp/deny-me")), Some(EACCES));
        assert_eq!(fs.mutation_errno(Path::new("/tmp/deny-me")), Some(EACCES));
    }

    #[test]
    fn hide_path_returns_enoent() {
        let fs = test_fs("/tmp/hide-me hide");
        assert_eq!(fs.access_errno(Path::new("/tmp/hide-me")), Some(ENOENT));
    }

    #[test]
    fn hide_path_returns_eperm_for_mutation() {
        let fs = test_fs("/tmp/hide-me hide");
        assert_eq!(fs.mutation_errno(Path::new("/tmp/hide-me")), Some(EPERM));
    }

    #[test]
    fn implicit_ancestor_allows_directory_but_not_file() {
        let dir = tempdir().expect("tempdir");
        let base = dir.path();
        let profile_src = format!("{}/*/leaf ro\n", base.display());
        let fs = test_fs(&profile_src);

        let as_dir = base.join("as-dir");
        let as_file = base.join("as-file");
        fs::create_dir_all(&as_dir).expect("mkdir");
        fs::write(&as_file, b"x").expect("write file");

        assert_eq!(fs.access_errno(&as_dir), None);
        assert_eq!(fs.access_errno(&as_file), Some(ENOENT));
    }

    #[test]
    fn git_rw_allows_writes_inside_detected_repo() {
        let dir = tempdir().expect("tempdir");
        let repo = dir.path().join("repo");
        fs::create_dir_all(repo.join(".git")).expect("mkdir .git");
        fs::create_dir_all(repo.join("src")).expect("mkdir src");
        fs::write(repo.join(".git/config"), b"[core]\n").expect("write config");

        let profile_src = format!("{} git-rw\n", dir.path().display());
        let fs = test_fs(&profile_src);
        assert_eq!(
            fs.write_mode(&repo.join("src/lib.rs")),
            WriteMode::Passthrough
        );
        assert_eq!(fs.write_mode(&dir.path().join("notes.txt")), WriteMode::Forbidden);
    }

    #[test]
    fn git_rw_makes_non_repo_paths_read_only() {
        let dir = tempdir().expect("tempdir");
        let repo = dir.path().join("repo");
        let outside = dir.path().join("notes.txt");
        fs::create_dir_all(repo.join(".git")).expect("mkdir .git");
        fs::write(repo.join(".git/config"), b"[core]\n").expect("write config");
        fs::write(&outside, b"note").expect("write outside file");

        let profile_src = format!("{} git-rw\n", dir.path().display());
        let fs = test_fs(&profile_src);
        assert_eq!(fs.access_errno(&outside), None);
        assert_eq!(fs.mutation_errno(&outside), None);
        assert!(fs.is_visible(&outside));
        assert_eq!(fs.write_mode(&outside), WriteMode::Forbidden);
    }

    #[test]
    fn git_metadata_is_denied_without_trusted_git_process() {
        let dir = tempdir().expect("tempdir");
        let repo = dir.path().join("repo");
        fs::create_dir_all(repo.join(".git")).expect("mkdir .git");
        fs::write(repo.join(".git/config"), b"[core]\n").expect("write config");

        let profile_src = format!("{} git-rw\n", dir.path().display());
        let fs = test_fs(&profile_src);
        assert_eq!(fs.access_errno(&repo.join(".git/config")), Some(EACCES));
        assert_eq!(fs.mutation_errno(&repo.join(".git/config")), Some(EACCES));
    }

    #[test]
    fn proc_thread_self_is_hard_blocked() {
        assert!(is_blocked_proc_thread_self(Path::new("/proc/thread-self")));
        assert!(is_blocked_proc_thread_self(Path::new("/proc/thread-self/fd/0")));
        assert!(!is_blocked_proc_thread_self(Path::new("/proc/self")));
    }

    #[test]
    fn proc_self_readlink_target_is_rewritten_to_request_pid() {
        assert_eq!(
            rewrite_proc_self_readlink_target(Path::new("/proc/self"), 4242),
            Some("4242".to_string())
        );
        assert_eq!(
            rewrite_proc_self_readlink_target(Path::new("/proc/1"), 4242),
            None
        );
    }

    #[test]
    fn proc_exe_readlink_target_strips_mount_prefix() {
        let rewritten = rewrite_proc_exe_readlink_target(
            Path::new("/proc/self/exe"),
            Path::new("/run/user/1000/cowjail/demo/mount/usr/bin/readlink"),
            Some(Path::new("/run/user/1000/cowjail/demo/mount")),
        );
        assert_eq!(rewritten, Path::new("/usr/bin/readlink"));
    }

    #[test]
    fn proc_exe_readlink_target_keeps_non_matching_target() {
        let target = Path::new("/usr/bin/readlink");
        let rewritten = rewrite_proc_exe_readlink_target(
            Path::new("/proc/123/exe"),
            target,
            Some(Path::new("/run/user/1000/cowjail/demo/mount")),
        );
        assert_eq!(rewritten, target);
    }

    #[cfg(unix)]
    #[test]
    fn passthrough_setattr_mode_updates_host_permissions() {
        let dir = tempdir().expect("tempdir");
        let mut fs = test_fs("/tmp/** rw");
        let path = dir.path().join("rw-mode-target");
        fs::write(&path, b"abc").expect("seed file");
        fs.apply_passthrough_setattr_for_test(&path, None, Some(0o700), None, None)
            .expect("set mode on rw path");

        let mode = fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[cfg(unix)]
    #[test]
    fn passthrough_setattr_time_updates_host_timestamps() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempdir().expect("tempdir");
        let mut fs = test_fs("/tmp/** rw");
        let path = dir.path().join("rw-time-target");
        fs::write(&path, b"abc").expect("seed file");
        let ts = SystemTime::UNIX_EPOCH + Duration::from_secs(56_789);

        fs.apply_passthrough_setattr_for_test(
            &path,
            None,
            None,
            Some(TimeOrNow::SpecificTime(ts)),
            Some(TimeOrNow::SpecificTime(ts)),
        )
        .expect("set times on rw path");

        let meta = fs::metadata(&path).expect("metadata");
        assert_eq!(meta.atime(), 56_789);
        assert_eq!(meta.mtime(), 56_789);
    }

    #[test]
    fn readdir_append_stops_when_buffer_is_full() {
        let entries = vec![
            (1, FileType::Directory, std::ffi::OsString::from(".")),
            (2, FileType::Directory, std::ffi::OsString::from("..")),
            (3, FileType::RegularFile, std::ffi::OsString::from("a")),
            (4, FileType::RegularFile, std::ffi::OsString::from("b")),
        ];
        let mut seen = Vec::new();
        let mut calls = 0usize;
        append_readdir_entries(&entries, 0, |ino, next_offset, _kind, name| {
            calls += 1;
            seen.push((ino, next_offset, name.to_os_string()));
            calls >= 2
        });
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].0, 1);
        assert_eq!(seen[1].0, 2);
    }
}
