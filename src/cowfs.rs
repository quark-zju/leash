use std::ffi::OsStr;
use std::fs::Metadata;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use fs_err as fs;
use fuse::{
    self, FileAttr, FileType, Filesystem, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry,
    ReplyOpen, Request,
};
use libc::{EACCES, EIO, ENOENT};

use crate::profile::{Profile, RuleAction, Visibility};

const TTL: Duration = Duration::from_secs(1);
const ROOT_INO: u64 = 1;

pub struct CowFs {
    profile: Profile,
    next_ino: u64,
    ino_to_path: std::collections::HashMap<u64, PathBuf>,
    path_to_ino: std::collections::HashMap<PathBuf, u64>,
    overlay: std::collections::HashMap<PathBuf, OverlayNode>,
}

#[derive(Debug, Clone)]
enum OverlayNode {
    Deleted,
    Dir,
    Regular { data: Vec<u8>, executable: bool },
    Symlink { target: PathBuf },
}

impl CowFs {
    pub fn new(profile: Profile) -> Self {
        let mut ino_to_path = std::collections::HashMap::new();
        let mut path_to_ino = std::collections::HashMap::new();
        ino_to_path.insert(ROOT_INO, std::path::PathBuf::from("/"));
        path_to_ino.insert(std::path::PathBuf::from("/"), ROOT_INO);

        Self {
            profile,
            next_ino: ROOT_INO + 1,
            ino_to_path,
            path_to_ino,
            overlay: std::collections::HashMap::new(),
        }
    }

    pub fn mount(self, mountpoint: &Path) -> Result<()> {
        let options = [
            OsStr::new("-o"),
            OsStr::new("default_permissions"),
            OsStr::new("-o"),
            OsStr::new("fsname=cowjail"),
        ];
        fuse::mount(self, mountpoint, &options).with_context(|| {
            format!(
                "failed to mount fuse filesystem at {}",
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
        // allow write open only for rw rules; actual writes land in overlay.
        if flags & libc::O_ACCMODE as u32 != libc::O_RDONLY as u32
            && self.profile.first_match_action(path) != Some(RuleAction::ReadWrite)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_profile(src: &str) -> Profile {
        Profile::parse(src, Path::new("/")).expect("profile parse")
    }

    #[test]
    fn overlay_deleted_hides_host_file() {
        let mut fs = CowFs::new(parse_profile("/tmp/** rw"));
        let path = PathBuf::from("/tmp/cowjail-overlay-deleted");
        std::fs::write(&path, b"host").expect("seed host");
        fs.overlay_set(path.clone(), OverlayNode::Deleted);
        let got = fs.effective_node(&path).expect("effective node");
        assert!(got.is_none());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn overlay_regular_overrides_host_file() {
        let mut fs = CowFs::new(parse_profile("/tmp/** rw"));
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
        let mut fs = CowFs::new(parse_profile("/tmp/** rw"));
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
}
