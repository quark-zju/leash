use std::ffi::OsStr;
use std::fs::Metadata;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use fs_err as fs;
use fuse::{
    self, FileAttr, FileType, Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory,
    ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, Request,
};
use libc::{EACCES, EEXIST, EINVAL, EIO, EISDIR, ENOENT, ENOSYS, ENOTDIR, ENOTEMPTY};

use crate::op::{FileState, Operation};
use crate::profile::{Profile, RuleAction, Visibility};
use crate::record;

const TTL: Duration = Duration::from_secs(1);
const ROOT_INO: u64 = 1;

pub struct CowFs {
    profile: Profile,
    record: record::Writer,
    next_ino: u64,
    ino_to_path: std::collections::HashMap<u64, PathBuf>,
    path_to_ino: std::collections::HashMap<PathBuf, u64>,
    overlay: std::collections::HashMap<PathBuf, OverlayNode>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReplayStats {
    pub total_frames: usize,
    pub pending_ops: usize,
    pub applied_ops: usize,
    pub skipped_frames: usize,
    pub skipped_ops: usize,
}

#[derive(Debug, Clone)]
enum OverlayNode {
    Deleted,
    Dir,
    Regular { data: Vec<u8>, executable: bool },
    Symlink { target: PathBuf },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteMode {
    Forbidden,
    Passthrough,
    Cow,
}

impl CowFs {
    pub fn new(profile: Profile, record: record::Writer) -> Self {
        let mut ino_to_path = std::collections::HashMap::new();
        let mut path_to_ino = std::collections::HashMap::new();
        ino_to_path.insert(ROOT_INO, std::path::PathBuf::from("/"));
        path_to_ino.insert(std::path::PathBuf::from("/"), ROOT_INO);

        Self {
            profile,
            record,
            next_ino: ROOT_INO + 1,
            ino_to_path,
            path_to_ino,
            overlay: std::collections::HashMap::new(),
        }
    }

    pub fn mount(self, mountpoint: &Path, allow_other: bool) -> Result<()> {
        let options = fuse_mount_options(allow_other);
        fuse::mount(self, mountpoint, &options).with_context(|| {
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
    ) -> Result<fuse::BackgroundSession<'static>> {
        let options = fuse_mount_options(allow_other);
        // SAFETY: We keep the returned BackgroundSession alive for the entire mounted lifetime.
        unsafe { fuse::spawn_mount(self, mountpoint, &options) }.with_context(|| {
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
        !matches!(
            self.profile.visibility(path),
            Visibility::Hidden | Visibility::Action(RuleAction::Deny)
        )
    }

    fn write_mode(&self, path: &Path) -> WriteMode {
        match self.profile.first_match_action(path) {
            Some(RuleAction::Cow) => WriteMode::Cow,
            Some(RuleAction::Passthrough) => WriteMode::Passthrough,
            _ => WriteMode::Forbidden,
        }
    }

    fn attr_for_path(&mut self, path: &Path, metadata: &Metadata) -> FileAttr {
        let kind = filetype_from_metadata(metadata);
        let ino = self.ensure_ino(path);
        let atime = system_time_from_unix(metadata.atime(), metadata.atime_nsec());
        let mtime = system_time_from_unix(metadata.mtime(), metadata.mtime_nsec());
        let ctime = system_time_from_unix(metadata.ctime(), metadata.ctime_nsec());

        FileAttr {
            ino,
            size: metadata.len(),
            blocks: metadata.blocks(),
            atime,
            mtime,
            ctime,
            crtime: ctime,
            kind,
            perm: (metadata.mode() & 0o7777) as u16,
            nlink: metadata.nlink() as u32,
            uid: metadata.uid(),
            gid: metadata.gid(),
            rdev: metadata.rdev() as u32,
            flags: 0,
        }
    }

    fn attr_for_overlay(&mut self, path: &Path, node: &OverlayNode) -> FileAttr {
        let now = SystemTime::now();
        let ino = self.ensure_ino(path);
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        let (kind, perm, size) = match node {
            OverlayNode::Deleted => (FileType::RegularFile, 0o000, 0),
            OverlayNode::Dir => (FileType::Directory, 0o755, 0),
            OverlayNode::Regular { data, executable } => {
                let perm = if *executable { 0o755 } else { 0o644 };
                (FileType::RegularFile, perm, data.len() as u64)
            }
            OverlayNode::Symlink { target } => {
                (FileType::Symlink, 0o777, target.as_os_str().len() as u64)
            }
        };

        FileAttr {
            ino,
            size,
            blocks: 1,
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
            kind,
            perm,
            nlink: 1,
            uid,
            gid,
            rdev: 0,
            flags: 0,
        }
    }

    fn effective_node(&self, path: &Path) -> Result<Option<NodeRef>, i32> {
        if let Some(node) = self.overlay.get(path) {
            return match node {
                OverlayNode::Deleted => Ok(None),
                _ => Ok(Some(NodeRef::Overlay(node.clone()))),
            };
        }
        match fs::symlink_metadata(path) {
            Ok(meta) => Ok(Some(NodeRef::Host(meta))),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(EIO),
        }
    }

    fn list_children(
        &mut self,
        parent: &Path,
    ) -> Result<Vec<(u64, FileType, std::ffi::OsString)>, i32> {
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();

        if let Ok(rd) = fs::read_dir(parent) {
            for child in rd {
                let Ok(child) = child else { continue };
                let name = child.file_name();
                let child_path = parent.join(&name);
                if !self.is_visible(&child_path) {
                    continue;
                }
                if matches!(self.overlay.get(&child_path), Some(OverlayNode::Deleted)) {
                    continue;
                }
                let child_type = if let Some(node) = self.overlay.get(&child_path) {
                    overlay_filetype(node)
                } else {
                    match child.metadata() {
                        Ok(meta) => filetype_from_metadata(&meta),
                        Err(_) => continue,
                    }
                };
                let child_ino = self.ensure_ino(&child_path);
                out.push((child_ino, child_type, name.clone()));
                seen.insert(name);
            }
        }

        let snapshot: Vec<(PathBuf, OverlayNode)> = self
            .overlay
            .iter()
            .map(|(p, n)| (p.clone(), n.clone()))
            .collect();
        for (path, node) in snapshot {
            if matches!(node, OverlayNode::Deleted) {
                continue;
            }
            if path.parent() != Some(parent) {
                continue;
            }
            if !self.is_visible(&path) {
                continue;
            }
            let Some(name) = path.file_name() else {
                continue;
            };
            let name = name.to_os_string();
            if seen.contains(&name) {
                continue;
            }
            let child_type = overlay_filetype(&node);
            let child_ino = self.ensure_ino(&path);
            out.push((child_ino, child_type, name));
        }

        Ok(out)
    }

    #[cfg(test)]
    fn overlay_set(&mut self, path: PathBuf, node: OverlayNode) {
        self.overlay.insert(path, node);
    }

    fn append_record(&self, op: &Operation) -> Result<(), i32> {
        self.record
            .append_cbor(record::TAG_WRITE_OP, op)
            .map(|_| ())
            .map_err(|_| EIO)
    }

    pub fn replay_from_record_frames(&mut self, frames: &[record::Frame]) -> ReplayStats {
        let mut stats = ReplayStats {
            total_frames: frames.len(),
            ..ReplayStats::default()
        };
        for frame in frames {
            if frame.flushed || frame.tag != record::TAG_WRITE_OP {
                stats.skipped_frames += 1;
                continue;
            }
            stats.pending_ops += 1;
            let op: Operation = match record::decode_cbor(frame) {
                Ok(op) => op,
                Err(_) => {
                    stats.skipped_ops += 1;
                    continue;
                }
            };
            if self.apply_replayed_operation(&op).is_ok() {
                stats.applied_ops += 1;
            } else {
                stats.skipped_ops += 1;
            }
        }
        stats
    }

    fn apply_replayed_operation(&mut self, op: &Operation) -> Result<(), ()> {
        match op {
            Operation::WriteFile { path, state } => {
                let node = match state {
                    FileState::Deleted => OverlayNode::Deleted,
                    FileState::Regular(data) => OverlayNode::Regular {
                        data: data.clone(),
                        executable: false,
                    },
                    FileState::Executable(data) => OverlayNode::Regular {
                        data: data.clone(),
                        executable: true,
                    },
                    FileState::Symlink(target) => OverlayNode::Symlink {
                        target: target.clone(),
                    },
                };
                self.overlay.insert(path.clone(), node);
                Ok(())
            }
            Operation::CreateDir { path } => {
                self.overlay.insert(path.clone(), OverlayNode::Dir);
                Ok(())
            }
            Operation::RemoveDir { path } => {
                self.overlay.insert(path.clone(), OverlayNode::Deleted);
                Ok(())
            }
            Operation::Rename { from, to } => self.apply_rename_paths(from, to).map_err(|_| ()),
            Operation::Truncate { path, size } => {
                let (mut data, executable) =
                    self.current_regular(path).map_err(|_| ())?.ok_or(())?;
                data.resize(*size as usize, 0);
                self.overlay
                    .insert(path.clone(), OverlayNode::Regular { data, executable });
                Ok(())
            }
        }
    }

    fn snapshot_node(&self, path: &Path) -> Result<Option<OverlayNode>, i32> {
        if let Some(node) = self.overlay.get(path) {
            return Ok(match node {
                OverlayNode::Deleted => None,
                other => Some(other.clone()),
            });
        }
        let meta = match fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(EIO),
        };
        if meta.file_type().is_dir() {
            return Ok(Some(OverlayNode::Dir));
        }
        if meta.file_type().is_symlink() {
            let target = fs::read_link(path).map_err(|_| EIO)?;
            return Ok(Some(OverlayNode::Symlink { target }));
        }
        if meta.file_type().is_file() {
            let data = fs::read(path).map_err(|_| EIO)?;
            let executable = meta.permissions().mode() & 0o111 != 0;
            return Ok(Some(OverlayNode::Regular { data, executable }));
        }
        Ok(None)
    }

    fn current_regular(&self, path: &Path) -> Result<Option<(Vec<u8>, bool)>, i32> {
        match self.snapshot_node(path)? {
            Some(OverlayNode::Regular { data, executable }) => Ok(Some((data, executable))),
            Some(OverlayNode::Deleted) | None => Ok(None),
            _ => Err(EIO),
        }
    }

    fn apply_rename_paths(&mut self, from: &Path, to: &Path) -> Result<(), i32> {
        if from == to {
            return Ok(());
        }
        let Some(src_node) = self.snapshot_node(from)? else {
            return Err(ENOENT);
        };
        let src_is_dir = matches!(src_node, OverlayNode::Dir);
        if src_is_dir && is_strict_descendant(from, to) {
            return Err(EINVAL);
        }

        if let Some(dst_node) = self.snapshot_node(to)? {
            let dst_is_dir = matches!(dst_node, OverlayNode::Dir);
            if src_is_dir && !dst_is_dir {
                return Err(ENOTDIR);
            }
            if !src_is_dir && dst_is_dir {
                return Err(EISDIR);
            }
            if dst_is_dir && !self.list_children(to)?.is_empty() {
                return Err(ENOTEMPTY);
            }
            self.clear_overlay_subtree(to);
            self.overlay.insert(to.to_path_buf(), OverlayNode::Deleted);
        }

        if src_is_dir {
            let moved = self.move_overlay_subtree(from, to);
            if !moved {
                self.overlay.insert(to.to_path_buf(), OverlayNode::Dir);
            }
        } else {
            self.overlay.insert(to.to_path_buf(), src_node);
        }
        self.overlay
            .insert(from.to_path_buf(), OverlayNode::Deleted);
        Ok(())
    }

    fn clear_overlay_subtree(&mut self, root: &Path) {
        let keys: Vec<PathBuf> = self
            .overlay
            .keys()
            .filter(|k| **k == root || is_strict_descendant(root, k))
            .cloned()
            .collect();
        for key in keys {
            self.overlay.remove(&key);
        }
    }

    fn move_overlay_subtree(&mut self, from: &Path, to: &Path) -> bool {
        let entries: Vec<(PathBuf, OverlayNode)> = self
            .overlay
            .iter()
            .filter_map(|(p, n)| {
                if *p == from || is_strict_descendant(from, p) {
                    Some((p.clone(), n.clone()))
                } else {
                    None
                }
            })
            .collect();
        if entries.is_empty() {
            return false;
        }
        for (old, _) in &entries {
            self.overlay.remove(old);
        }
        for (old, node) in entries {
            let suffix = old.strip_prefix(from).unwrap_or(Path::new(""));
            let new_path = if suffix.as_os_str().is_empty() {
                to.to_path_buf()
            } else {
                to.join(suffix)
            };
            self.overlay.insert(new_path, node);
        }
        true
    }
}

fn fuse_mount_options(allow_other: bool) -> Vec<&'static OsStr> {
    let mut options = Vec::with_capacity(8);
    options.push(OsStr::new("-o"));
    options.push(OsStr::new("default_permissions"));
    if allow_other {
        options.push(OsStr::new("-o"));
        options.push(OsStr::new("allow_other"));
    }
    options.push(OsStr::new("-o"));
    options.push(OsStr::new("fsname=cowjail"));
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

enum NodeRef {
    Host(Metadata),
    Overlay(OverlayNode),
}

impl Filesystem for CowFs {
    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let Some(parent_path) = self.path_for_ino(parent).map(ToOwned::to_owned) else {
            reply.error(ENOENT);
            return;
        };

        let path = parent_path.join(name);
        if !self.is_visible(&path) {
            reply.error(ENOENT);
            return;
        }

        match self.effective_node(&path) {
            Ok(Some(NodeRef::Host(metadata))) => {
                let attr = self.attr_for_path(&path, &metadata);
                reply.entry(&TTL, &attr, 0);
            }
            Ok(Some(NodeRef::Overlay(node))) => {
                let attr = self.attr_for_overlay(&path, &node);
                reply.entry(&TTL, &attr, 0);
            }
            Ok(None) => reply.error(ENOENT),
            Err(code) => reply.error(code),
        }
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyAttr) {
        let Some(path) = self.path_for_ino(ino).map(ToOwned::to_owned) else {
            reply.error(ENOENT);
            return;
        };
        if !self.is_visible(&path) {
            reply.error(ENOENT);
            return;
        }
        match self.effective_node(&path) {
            Ok(Some(NodeRef::Host(metadata))) => {
                let attr = self.attr_for_path(&path, &metadata);
                reply.attr(&TTL, &attr);
            }
            Ok(Some(NodeRef::Overlay(node))) => {
                let attr = self.attr_for_overlay(&path, &node);
                reply.attr(&TTL, &attr);
            }
            Ok(None) => reply.error(ENOENT),
            Err(code) => reply.error(code),
        }
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let Some(path) = self.path_for_ino(ino).map(ToOwned::to_owned) else {
            reply.error(ENOENT);
            return;
        };
        if !self.is_visible(&path) {
            reply.error(ENOENT);
            return;
        }

        match self.effective_node(&path) {
            Ok(Some(NodeRef::Host(meta))) => {
                if !meta.file_type().is_dir() {
                    reply.error(ENOENT);
                    return;
                }
            }
            Ok(Some(NodeRef::Overlay(node))) => {
                if !matches!(node, OverlayNode::Dir) {
                    reply.error(ENOENT);
                    return;
                }
            }
            Ok(None) => {
                reply.error(ENOENT);
                return;
            }
            Err(code) => {
                reply.error(code);
                return;
            }
        }

        let mut entries: Vec<(u64, FileType, std::ffi::OsString)> = Vec::new();
        let self_ino = self.ensure_ino(&path);
        let parent_path = if path == Path::new("/") {
            Path::new("/").to_path_buf()
        } else {
            path.parent().unwrap_or(Path::new("/")).to_path_buf()
        };
        let parent_ino = self.ensure_ino(&parent_path);
        entries.push((self_ino, FileType::Directory, std::ffi::OsString::from(".")));
        entries.push((
            parent_ino,
            FileType::Directory,
            std::ffi::OsString::from(".."),
        ));

        let overlay_entries = match self.list_children(&path) {
            Ok(entries) => entries,
            Err(code) => {
                reply.error(code);
                return;
            }
        };
        for entry in overlay_entries {
            entries.push(entry);
        }

        for (i, entry) in entries.iter().enumerate().skip(offset as usize) {
            reply.add(entry.0, (i + 1) as i64, entry.1, entry.2.as_os_str());
        }
        reply.ok();
    }

    fn open(&mut self, _req: &Request<'_>, ino: u64, flags: u32, reply: ReplyOpen) {
        let Some(path) = self.path_for_ino(ino) else {
            reply.error(ENOENT);
            return;
        };
        if !self.is_visible(path) {
            reply.error(ENOENT);
            return;
        }
        // allow write open only for writable rules.
        if flags & libc::O_ACCMODE as u32 != libc::O_RDONLY as u32
            && self.write_mode(path) == WriteMode::Forbidden
        {
            reply.error(EACCES);
            return;
        }
        reply.opened(0, 0);
    }

    fn read(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        reply: ReplyData,
    ) {
        let Some(path) = self.path_for_ino(ino).map(ToOwned::to_owned) else {
            reply.error(ENOENT);
            return;
        };
        if !self.is_visible(&path) {
            reply.error(ENOENT);
            return;
        }

        if let Some(node) = self.overlay.get(&path) {
            match node {
                OverlayNode::Deleted | OverlayNode::Dir => {
                    reply.error(ENOENT);
                    return;
                }
                OverlayNode::Symlink { .. } => {
                    reply.error(EIO);
                    return;
                }
                OverlayNode::Regular { data, .. } => {
                    if offset < 0 {
                        reply.error(EIO);
                        return;
                    }
                    let off = offset as usize;
                    if off >= data.len() {
                        reply.data(&[]);
                        return;
                    }
                    let end = std::cmp::min(data.len(), off + size as usize);
                    reply.data(&data[off..end]);
                    return;
                }
            }
        }

        let mut file = match fs::File::open(&path) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                reply.error(ENOENT);
                return;
            }
            Err(_) => {
                reply.error(EIO);
                return;
            }
        };
        if offset < 0 {
            reply.error(EIO);
            return;
        }
        if file.seek(SeekFrom::Start(offset as u64)).is_err() {
            reply.error(EIO);
            return;
        }

        let mut buf = vec![0u8; size as usize];
        let n = match file.read(&mut buf) {
            Ok(n) => n,
            Err(_) => {
                reply.error(EIO);
                return;
            }
        };
        reply.data(&buf[..n]);
    }

    fn readlink(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyData) {
        let Some(path) = self.path_for_ino(ino).map(ToOwned::to_owned) else {
            reply.error(ENOENT);
            return;
        };
        if !self.is_visible(&path) {
            reply.error(ENOENT);
            return;
        }
        if let Some(node) = self.overlay.get(&path) {
            match node {
                OverlayNode::Symlink { target } => {
                    reply.data(target.as_os_str().as_bytes());
                }
                OverlayNode::Deleted => reply.error(ENOENT),
                _ => reply.error(EIO),
            }
            return;
        }
        match fs::read_link(&path) {
            Ok(target) => reply.data(target.as_os_str().as_bytes()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => reply.error(ENOENT),
            Err(_) => reply.error(EIO),
        }
    }

    fn create(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        _mode: u32,
        _flags: u32,
        reply: ReplyCreate,
    ) {
        let Some(parent_path) = self.path_for_ino(parent).map(ToOwned::to_owned) else {
            reply.error(ENOENT);
            return;
        };
        let path = parent_path.join(name);
        if !self.is_visible(&path) {
            reply.error(ENOENT);
            return;
        }
        match self.write_mode(&path) {
            WriteMode::Forbidden => {
                reply.error(EACCES);
            }
            WriteMode::Cow => {
                match self.snapshot_node(&path) {
                    Ok(Some(_)) => {
                        reply.error(EEXIST);
                        return;
                    }
                    Ok(None) => {}
                    Err(code) => {
                        reply.error(code);
                        return;
                    }
                }
                let node = OverlayNode::Regular {
                    data: Vec::new(),
                    executable: false,
                };
                self.overlay.insert(path.clone(), node.clone());
                if self
                    .append_record(&Operation::WriteFile {
                        path: path.clone(),
                        state: FileState::Regular(Vec::new()),
                    })
                    .is_err()
                {
                    reply.error(EIO);
                    return;
                }
                let attr = self.attr_for_overlay(&path, &node);
                reply.created(&TTL, &attr, 0, 0, 0);
            }
            WriteMode::Passthrough => {
                match fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&path)
                {
                    Ok(_) => {}
                    Err(err) => {
                        reply.error(io_errno(&err));
                        return;
                    }
                }
                let meta = match fs::symlink_metadata(&path) {
                    Ok(meta) => meta,
                    Err(err) => {
                        reply.error(io_errno(&err));
                        return;
                    }
                };
                let attr = self.attr_for_path(&path, &meta);
                reply.created(&TTL, &attr, 0, 0, 0);
            }
        }
    }

    fn write(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        data: &[u8],
        _flags: u32,
        reply: ReplyWrite,
    ) {
        let Some(path) = self.path_for_ino(ino).map(ToOwned::to_owned) else {
            reply.error(ENOENT);
            return;
        };
        match self.write_mode(&path) {
            WriteMode::Forbidden => {
                reply.error(EACCES);
            }
            WriteMode::Cow => {
                if offset < 0 {
                    reply.error(EIO);
                    return;
                }
                let (mut content, executable) = match self.current_regular(&path) {
                    Ok(Some(v)) => v,
                    Ok(None) => {
                        reply.error(ENOENT);
                        return;
                    }
                    Err(code) => {
                        reply.error(code);
                        return;
                    }
                };
                let off = offset as usize;
                if content.len() < off {
                    content.resize(off, 0);
                }
                if content.len() < off + data.len() {
                    content.resize(off + data.len(), 0);
                }
                content[off..off + data.len()].copy_from_slice(data);

                self.overlay.insert(
                    path.clone(),
                    OverlayNode::Regular {
                        data: content.clone(),
                        executable,
                    },
                );
                if self
                    .append_record(&Operation::WriteFile {
                        path,
                        state: if executable {
                            FileState::Executable(content)
                        } else {
                            FileState::Regular(content)
                        },
                    })
                    .is_err()
                {
                    reply.error(EIO);
                    return;
                }
                reply.written(data.len() as u32);
            }
            WriteMode::Passthrough => {
                if offset < 0 {
                    reply.error(EIO);
                    return;
                }
                let mut file = match fs::OpenOptions::new().write(true).open(&path) {
                    Ok(file) => file,
                    Err(err) => {
                        reply.error(io_errno(&err));
                        return;
                    }
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
        }
    }

    fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let Some(parent_path) = self.path_for_ino(parent).map(ToOwned::to_owned) else {
            reply.error(ENOENT);
            return;
        };
        let path = parent_path.join(name);
        if !self.is_visible(&path) {
            reply.error(ENOENT);
            return;
        }
        match self.write_mode(&path) {
            WriteMode::Forbidden => {
                reply.error(EACCES);
                return;
            }
            WriteMode::Cow => {
                self.overlay.insert(path.clone(), OverlayNode::Deleted);
                if self
                    .append_record(&Operation::WriteFile {
                        path,
                        state: FileState::Deleted,
                    })
                    .is_err()
                {
                    reply.error(EIO);
                    return;
                }
            }
            WriteMode::Passthrough => {
                if let Err(err) = fs::remove_file(&path) {
                    reply.error(io_errno(&err));
                    return;
                }
            }
        }
        reply.ok();
    }

    fn mkdir(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        _mode: u32,
        reply: ReplyEntry,
    ) {
        let Some(parent_path) = self.path_for_ino(parent).map(ToOwned::to_owned) else {
            reply.error(ENOENT);
            return;
        };
        let path = parent_path.join(name);
        if !self.is_visible(&path) {
            reply.error(ENOENT);
            return;
        }
        match self.write_mode(&path) {
            WriteMode::Forbidden => {
                reply.error(EACCES);
            }
            WriteMode::Cow => {
                match self.snapshot_node(&path) {
                    Ok(Some(_)) => {
                        reply.error(EEXIST);
                        return;
                    }
                    Ok(None) => {}
                    Err(code) => {
                        reply.error(code);
                        return;
                    }
                }
                let node = OverlayNode::Dir;
                self.overlay.insert(path.clone(), node.clone());
                if self
                    .append_record(&Operation::CreateDir { path: path.clone() })
                    .is_err()
                {
                    reply.error(EIO);
                    return;
                }
                let attr = self.attr_for_overlay(&path, &node);
                reply.entry(&TTL, &attr, 0);
            }
            WriteMode::Passthrough => {
                if let Err(err) = fs::create_dir(&path) {
                    reply.error(io_errno(&err));
                    return;
                }
                let meta = match fs::symlink_metadata(&path) {
                    Ok(meta) => meta,
                    Err(err) => {
                        reply.error(io_errno(&err));
                        return;
                    }
                };
                let attr = self.attr_for_path(&path, &meta);
                reply.entry(&TTL, &attr, 0);
            }
        }
    }

    fn rmdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let Some(parent_path) = self.path_for_ino(parent).map(ToOwned::to_owned) else {
            reply.error(ENOENT);
            return;
        };
        let path = parent_path.join(name);
        if !self.is_visible(&path) {
            reply.error(ENOENT);
            return;
        }
        match self.write_mode(&path) {
            WriteMode::Forbidden => {
                reply.error(EACCES);
                return;
            }
            WriteMode::Cow => {
                self.overlay.insert(path.clone(), OverlayNode::Deleted);
                if self.append_record(&Operation::RemoveDir { path }).is_err() {
                    reply.error(EIO);
                    return;
                }
            }
            WriteMode::Passthrough => {
                if let Err(err) = fs::remove_dir(&path) {
                    reply.error(io_errno(&err));
                    return;
                }
            }
        }
        reply.ok();
    }

    fn symlink(
        &mut self,
        _req: &Request<'_>,
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
        if !self.is_visible(&path) {
            reply.error(ENOENT);
            return;
        }
        match self.write_mode(&path) {
            WriteMode::Forbidden => {
                reply.error(EACCES);
            }
            WriteMode::Cow => {
                match self.snapshot_node(&path) {
                    Ok(Some(_)) => {
                        reply.error(EEXIST);
                        return;
                    }
                    Ok(None) => {}
                    Err(code) => {
                        reply.error(code);
                        return;
                    }
                }
                let node = OverlayNode::Symlink {
                    target: link.to_path_buf(),
                };
                self.overlay.insert(path.clone(), node.clone());
                if self
                    .append_record(&Operation::WriteFile {
                        path: path.clone(),
                        state: FileState::Symlink(link.to_path_buf()),
                    })
                    .is_err()
                {
                    reply.error(EIO);
                    return;
                }
                let attr = self.attr_for_overlay(&path, &node);
                reply.entry(&TTL, &attr, 0);
            }
            WriteMode::Passthrough => {
                if let Err(err) = std::os::unix::fs::symlink(link, &path) {
                    reply.error(io_errno(&err));
                    return;
                }
                let meta = match fs::symlink_metadata(&path) {
                    Ok(meta) => meta,
                    Err(err) => {
                        reply.error(io_errno(&err));
                        return;
                    }
                };
                let attr = self.attr_for_path(&path, &meta);
                reply.entry(&TTL, &attr, 0);
            }
        }
    }

    fn rename(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
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
        if !self.is_visible(&from) || !self.is_visible(&to) {
            reply.error(ENOENT);
            return;
        }
        match (self.write_mode(&from), self.write_mode(&to)) {
            (WriteMode::Cow, WriteMode::Cow) => {
                if let Err(code) = self.apply_rename_paths(&from, &to) {
                    reply.error(code);
                    return;
                }
                if self.append_record(&Operation::Rename { from, to }).is_err() {
                    reply.error(EIO);
                    return;
                }
            }
            (WriteMode::Passthrough, WriteMode::Passthrough) => {
                if let Err(err) = fs::rename(&from, &to) {
                    reply.error(io_errno(&err));
                    return;
                }
            }
            _ => {
                reply.error(EACCES);
                return;
            }
        }
        reply.ok();
    }

    fn setattr(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<SystemTime>,
        _mtime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        let Some(size) = size else {
            reply.error(ENOSYS);
            return;
        };
        let Some(path) = self.path_for_ino(ino).map(ToOwned::to_owned) else {
            reply.error(ENOENT);
            return;
        };
        match self.write_mode(&path) {
            WriteMode::Forbidden => {
                reply.error(EACCES);
            }
            WriteMode::Cow => {
                let (mut data, executable) = match self.current_regular(&path) {
                    Ok(Some(v)) => v,
                    Ok(None) => {
                        reply.error(ENOENT);
                        return;
                    }
                    Err(code) => {
                        reply.error(code);
                        return;
                    }
                };
                data.resize(size as usize, 0);
                let node = OverlayNode::Regular {
                    data: data.clone(),
                    executable,
                };
                self.overlay.insert(path.clone(), node.clone());
                if self
                    .append_record(&Operation::WriteFile {
                        path: path.clone(),
                        state: if executable {
                            FileState::Executable(data)
                        } else {
                            FileState::Regular(data)
                        },
                    })
                    .is_err()
                {
                    reply.error(EIO);
                    return;
                }
                let attr = self.attr_for_overlay(&path, &node);
                reply.attr(&TTL, &attr);
            }
            WriteMode::Passthrough => {
                let file = match fs::OpenOptions::new().write(true).open(&path) {
                    Ok(file) => file,
                    Err(err) => {
                        reply.error(io_errno(&err));
                        return;
                    }
                };
                if let Err(err) = file.set_len(size) {
                    reply.error(io_errno(&err));
                    return;
                }
                let meta = match fs::symlink_metadata(&path) {
                    Ok(meta) => meta,
                    Err(err) => {
                        reply.error(io_errno(&err));
                        return;
                    }
                };
                let attr = self.attr_for_path(&path, &meta);
                reply.attr(&TTL, &attr);
            }
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

fn overlay_filetype(node: &OverlayNode) -> FileType {
    match node {
        OverlayNode::Deleted => FileType::RegularFile,
        OverlayNode::Dir => FileType::Directory,
        OverlayNode::Regular { .. } => FileType::RegularFile,
        OverlayNode::Symlink { .. } => FileType::Symlink,
    }
}

fn system_time_from_unix(sec: i64, nsec: i64) -> SystemTime {
    if sec < 0 || nsec < 0 {
        return SystemTime::UNIX_EPOCH;
    }
    SystemTime::UNIX_EPOCH + Duration::new(sec as u64, nsec as u32)
}

fn is_strict_descendant(parent: &Path, child: &Path) -> bool {
    child != parent && child.starts_with(parent)
}

fn io_errno(err: &std::io::Error) -> i32 {
    err.raw_os_error().unwrap_or(EIO)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn parse_profile(src: &str) -> Profile {
        Profile::parse(src, Path::new("/")).expect("profile parse")
    }

    fn test_fs(profile_src: &str) -> (tempfile::TempDir, std::path::PathBuf, CowFs) {
        let dir = tempdir().expect("tempdir");
        let record_path = dir.path().join("cowjail-cowfs-test.cjr");
        let writer = record::Writer::open_append(&record_path).expect("open record writer");
        (
            dir,
            record_path,
            CowFs::new(parse_profile(profile_src), writer),
        )
    }

    #[test]
    fn overlay_deleted_hides_host_file() {
        let (_dir, _record_path, mut fs) = test_fs("/tmp/** cow");
        let path = PathBuf::from("/tmp/cowjail-overlay-deleted");
        std::fs::write(&path, b"host").expect("seed host");
        fs.overlay_set(path.clone(), OverlayNode::Deleted);
        let got = fs.effective_node(&path).expect("effective node");
        assert!(got.is_none());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn overlay_regular_overrides_host_file() {
        let (_dir, _record_path, mut fs) = test_fs("/tmp/** cow");
        let path = PathBuf::from("/tmp/cowjail-overlay-regular");
        std::fs::write(&path, b"host").expect("seed host");
        fs.overlay_set(
            path.clone(),
            OverlayNode::Regular {
                data: b"overlay".to_vec(),
                executable: false,
            },
        );
        let got = fs.effective_node(&path).expect("effective node");
        match got {
            Some(NodeRef::Overlay(OverlayNode::Regular { data, .. })) => {
                assert_eq!(data, b"overlay")
            }
            _ => panic!("expected overlay regular node"),
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn overlay_readdir_includes_new_children() {
        let (_dir, _record_path, mut fs) = test_fs("/tmp/** cow");
        let dir = PathBuf::from("/tmp/cowjail-overlay-dir");
        let _ = std::fs::create_dir_all(&dir);
        let new_file = dir.join("from-overlay");
        let new_dir = dir.join("overlay-subdir");
        let new_link = dir.join("overlay-link");
        fs.overlay_set(
            new_file.clone(),
            OverlayNode::Regular {
                data: b"x".to_vec(),
                executable: false,
            },
        );
        fs.overlay_set(new_dir, OverlayNode::Dir);
        fs.overlay_set(
            new_link,
            OverlayNode::Symlink {
                target: PathBuf::from("/tmp/target"),
            },
        );
        let entries = fs.list_children(&dir).expect("list children");
        assert!(
            entries
                .iter()
                .any(|(_, _, name)| name == &std::ffi::OsString::from("from-overlay"))
        );
        assert!(
            entries
                .iter()
                .any(|(_, _, name)| name == &std::ffi::OsString::from("overlay-subdir"))
        );
        assert!(
            entries
                .iter()
                .any(|(_, _, name)| name == &std::ffi::OsString::from("overlay-link"))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rename_moves_overlay_subtree() {
        let (_dir, _record_path, mut fs) = test_fs("/tmp/** cow");
        let from = PathBuf::from("/tmp/cowjail-rename-from");
        let to = PathBuf::from("/tmp/cowjail-rename-to");
        let child = from.join("child.txt");
        fs.overlay_set(from.clone(), OverlayNode::Dir);
        fs.overlay_set(
            child.clone(),
            OverlayNode::Regular {
                data: b"x".to_vec(),
                executable: false,
            },
        );

        fs.apply_rename_paths(&from, &to)
            .expect("rename should succeed");
        assert!(matches!(fs.overlay.get(&from), Some(OverlayNode::Deleted)));
        assert!(matches!(fs.overlay.get(&to), Some(OverlayNode::Dir)));
        assert!(matches!(
            fs.overlay.get(&to.join("child.txt")),
            Some(OverlayNode::Regular { .. })
        ));
    }

    #[test]
    fn rename_dir_into_own_subpath_fails() {
        let (_dir, _record_path, mut fs) = test_fs("/tmp/** cow");
        let from = PathBuf::from("/tmp/cowjail-self-rename");
        let to = from.join("sub");
        fs.overlay_set(from.clone(), OverlayNode::Dir);
        let err = fs
            .apply_rename_paths(&from, &to)
            .expect_err("rename to own subpath should fail");
        assert_eq!(err, EINVAL);
    }

    #[test]
    fn replay_restores_pending_writes_and_rename() {
        let dir = tempdir().expect("tempdir");
        let record_path = dir.path().join("cowjail-replay-test.cjr");
        let writer = record::Writer::open_append(&record_path).expect("open record writer");

        writer
            .append_cbor(
                record::TAG_WRITE_OP,
                &Operation::WriteFile {
                    path: PathBuf::from("/tmp/replay-a"),
                    state: FileState::Regular(b"one".to_vec()),
                },
            )
            .expect("append write a");
        writer
            .append_cbor(
                record::TAG_WRITE_OP,
                &Operation::Rename {
                    from: PathBuf::from("/tmp/replay-a"),
                    to: PathBuf::from("/tmp/replay-b"),
                },
            )
            .expect("append rename");
        writer
            .append_cbor(
                record::TAG_WRITE_OP,
                &Operation::WriteFile {
                    path: PathBuf::from("/tmp/replay-b"),
                    state: FileState::Executable(b"two".to_vec()),
                },
            )
            .expect("append write b");
        writer.sync().expect("sync record");

        let frames = record::read_frames(&record_path).expect("read frames");
        let mut fs = CowFs::new(parse_profile("/tmp/** cow"), writer);
        let stats = fs.replay_from_record_frames(&frames);
        assert_eq!(stats.pending_ops, 3);
        assert_eq!(stats.applied_ops, 3);
        assert!(matches!(
            fs.overlay.get(Path::new("/tmp/replay-a")),
            Some(OverlayNode::Deleted)
        ));
        assert!(matches!(
            fs.overlay.get(Path::new("/tmp/replay-b")),
            Some(OverlayNode::Regular {
                data,
                executable: true
            }) if data == b"two"
        ));
    }

    #[test]
    fn replay_skips_flushed_frames() {
        let dir = tempdir().expect("tempdir");
        let record_path = dir.path().join("cowjail-replay-flushed-test.cjr");
        let writer = record::Writer::open_append(&record_path).expect("open record writer");

        let flushed_offset = writer
            .append_cbor(
                record::TAG_WRITE_OP,
                &Operation::WriteFile {
                    path: PathBuf::from("/tmp/replay-flushed"),
                    state: FileState::Regular(b"old".to_vec()),
                },
            )
            .expect("append flushed op");
        writer
            .append_cbor(
                record::TAG_WRITE_OP,
                &Operation::WriteFile {
                    path: PathBuf::from("/tmp/replay-flushed"),
                    state: FileState::Regular(b"new".to_vec()),
                },
            )
            .expect("append pending op");
        writer.sync().expect("sync record");
        record::mark_flushed(&record_path, flushed_offset).expect("mark flushed");

        let frames = record::read_frames(&record_path).expect("read frames");
        let mut fs = CowFs::new(parse_profile("/tmp/** cow"), writer);
        let stats = fs.replay_from_record_frames(&frames);
        assert_eq!(stats.pending_ops, 1);
        assert_eq!(stats.applied_ops, 1);
        assert_eq!(stats.skipped_frames, 1);
        assert!(matches!(
            fs.overlay.get(Path::new("/tmp/replay-flushed")),
            Some(OverlayNode::Regular {
                data,
                executable: false
            }) if data == b"new"
        ));
    }

    #[test]
    fn replay_persists_pending_overlay_across_remount_like_restart() {
        let dir = tempdir().expect("tempdir");
        let record_path = dir.path().join("cowjail-replay-restart-test.cjr");
        let mount1_writer = record::Writer::open_append(&record_path).expect("open first writer");

        mount1_writer
            .append_cbor(
                record::TAG_WRITE_OP,
                &Operation::WriteFile {
                    path: PathBuf::from("/tmp/reboot-visible-a"),
                    state: FileState::Regular(b"first".to_vec()),
                },
            )
            .expect("append first write");
        mount1_writer
            .append_cbor(
                record::TAG_WRITE_OP,
                &Operation::Rename {
                    from: PathBuf::from("/tmp/reboot-visible-a"),
                    to: PathBuf::from("/tmp/reboot-visible-b"),
                },
            )
            .expect("append rename");
        mount1_writer
            .append_cbor(
                record::TAG_WRITE_OP,
                &Operation::Truncate {
                    path: PathBuf::from("/tmp/reboot-visible-b"),
                    size: 3,
                },
            )
            .expect("append truncate");
        mount1_writer.sync().expect("sync first writer");

        let mount1_frames = record::read_frames(&record_path).expect("read first mount frames");
        let mut mount1_fs = CowFs::new(parse_profile("/tmp/** cow"), mount1_writer);
        let mount1_stats = mount1_fs.replay_from_record_frames(&mount1_frames);
        assert_eq!(mount1_stats.pending_ops, 3);
        assert_eq!(mount1_stats.applied_ops, 3);
        assert!(matches!(
            mount1_fs.overlay.get(Path::new("/tmp/reboot-visible-a")),
            Some(OverlayNode::Deleted)
        ));
        assert!(matches!(
            mount1_fs.overlay.get(Path::new("/tmp/reboot-visible-b")),
            Some(OverlayNode::Regular {
                data,
                executable: false
            }) if data == b"fir"
        ));
        drop(mount1_fs);

        let mount2_writer = record::Writer::open_append(&record_path).expect("open second writer");
        let mount2_frames = record::read_frames(&record_path).expect("read second mount frames");
        let mut mount2_fs = CowFs::new(parse_profile("/tmp/** cow"), mount2_writer);
        let mount2_stats = mount2_fs.replay_from_record_frames(&mount2_frames);
        assert_eq!(mount2_stats.pending_ops, 3);
        assert_eq!(mount2_stats.applied_ops, 3);
        assert!(matches!(
            mount2_fs.overlay.get(Path::new("/tmp/reboot-visible-a")),
            Some(OverlayNode::Deleted)
        ));
        assert!(matches!(
            mount2_fs.overlay.get(Path::new("/tmp/reboot-visible-b")),
            Some(OverlayNode::Regular {
                data,
                executable: false
            }) if data == b"fir"
        ));
    }
}
