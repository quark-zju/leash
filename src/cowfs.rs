use std::ffi::OsStr;
use std::fs::Metadata;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;
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
    ino_to_path: std::collections::HashMap<u64, std::path::PathBuf>,
    path_to_ino: std::collections::HashMap<std::path::PathBuf, u64>,
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

        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                let attr = self.attr_for_path(&path, &metadata);
                reply.entry(&TTL, &attr, 0);
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => reply.error(ENOENT),
            Err(_) => reply.error(EIO),
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
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                let attr = self.attr_for_path(&path, &metadata);
                reply.attr(&TTL, &attr);
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => reply.error(ENOENT),
            Err(_) => reply.error(EIO),
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

        let meta = match fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(_) => {
                reply.error(ENOENT);
                return;
            }
        };
        if !meta.file_type().is_dir() {
            reply.error(ENOENT);
            return;
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

        let rd = match fs::read_dir(&path) {
            Ok(rd) => rd,
            Err(_) => {
                reply.error(EIO);
                return;
            }
        };
        for child in rd {
            let Ok(child) = child else { continue };
            let child_path = child.path();
            if !self.is_visible(&child_path) {
                continue;
            }
            let Ok(metadata) = child.metadata() else {
                continue;
            };
            let child_ino = self.ensure_ino(&child_path);
            let child_type = filetype_from_metadata(&metadata);
            entries.push((child_ino, child_type, child.file_name()));
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
        // deny write opens for now, mount mode is read-only passthrough in this phase.
        if flags & libc::O_ACCMODE as u32 != libc::O_RDONLY as u32 {
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

fn system_time_from_unix(sec: i64, nsec: i64) -> SystemTime {
    if sec < 0 || nsec < 0 {
        return SystemTime::UNIX_EPOCH;
    }
    SystemTime::UNIX_EPOCH + Duration::new(sec as u64, nsec as u32)
}
