use std::ffi::OsStr;
use std::os::unix::prelude::PermissionsExt;
use std::path::{Component, Path, PathBuf};

use fs_err as fs;
use log::debug;

#[derive(Debug)]
pub(crate) struct GitRwFilter {
    system_git: Option<PathBuf>,
}

impl GitRwFilter {
    pub(crate) fn new() -> Self {
        let system_git = resolve_system_git_path();
        Self::with_system_git(system_git)
    }

    pub(crate) fn with_system_git(system_git: Option<PathBuf>) -> Self {
        debug!("git-rw: resolved system git path to {:?}", system_git);
        Self { system_git }
    }

    pub(crate) fn is_git_metadata_path(&self, path: &Path) -> bool {
        path.components().any(|component| match component {
            Component::Normal(name) => name == OsStr::new(".git"),
            _ => false,
        })
    }

    pub(crate) fn is_exact_git_dir_path(&self, path: &Path) -> bool {
        path.file_name() == Some(OsStr::new(".git"))
    }

    pub(crate) fn is_commit_editmsg_path(&self, path: &Path) -> bool {
        let mut components = path.components().peekable();
        while let Some(component) = components.next() {
            if component == Component::Normal(OsStr::new(".git")) {
                if components.next() == Some(Component::Normal(OsStr::new("COMMIT_EDITMSG")))
                    && components.next().is_none()
                {
                    return true;
                }
                return false;
            }
        }
        false
    }

    pub(crate) fn allow_git_metadata_for_pid(&self, pid: u32, mount_root: Option<&Path>) -> bool {
        let allowed = self.inspect_process(pid, mount_root);
        debug!("git-rw: evaluated pid={} allowed={}", pid, allowed);
        allowed
    }

    pub(crate) fn allow_git_metadata_for_exe(&self, exe_path: Option<&Path>) -> bool {
        let Some(system_git) = self.system_git.as_ref() else {
            return false;
        };
        let Some(exe_path) = exe_path else {
            return false;
        };
        normalize_git_exe_path(exe_path).as_ref() == Some(system_git)
    }

    fn inspect_process(&self, pid: u32, mount_root: Option<&Path>) -> bool {
        let Some(system_git) = self.system_git.as_ref() else {
            debug!("git-rw: deny pid={pid}: no system git resolved");
            return false;
        };

        let exe_path = match fs::read_link(format!("/proc/{pid}/exe")) {
            Ok(path) => strip_mount_root_prefix(path, mount_root),
            Err(err) => {
                debug!("git-rw: deny pid={pid}: read /proc/{pid}/exe failed: {err}");
                return false;
            }
        };
        let exe_path = normalize_git_exe_path(&exe_path);
        if exe_path.as_ref() != Some(system_git) {
            debug!(
                "git-rw: deny pid={pid}: exe path {:?} does not match trusted git {}",
                exe_path,
                system_git.display()
            );
            return false;
        }

        debug!("git-rw: allow pid={pid}: exe path matches trusted git");
        true
    }
}

pub(crate) fn resolve_system_git_path() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join("git");
        let meta = match fs::metadata(&candidate) {
            Ok(meta) => meta,
            Err(_) => continue,
        };
        if !meta.is_file() || meta.permissions().mode() & 0o111 == 0 {
            continue;
        }
        return normalize_git_exe_path(&candidate);
    }
    None
}

fn normalize_git_exe_path(path: &Path) -> Option<PathBuf> {
    fs::canonicalize(path).ok().or_else(|| {
        if path.is_absolute() {
            Some(path.to_path_buf())
        } else {
            None
        }
    })
}

fn strip_mount_root_prefix(path: PathBuf, mount_root: Option<&Path>) -> PathBuf {
    let Some(root) = mount_root else {
        return path;
    };
    let Ok(suffix) = path.strip_prefix(root) else {
        return path;
    };
    if suffix.as_os_str().is_empty() {
        PathBuf::from("/")
    } else {
        Path::new("/").join(suffix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marks_dot_git_paths_as_metadata() {
        let filter = GitRwFilter::new();
        assert!(filter.is_exact_git_dir_path(Path::new("/tmp/repo/.git")));
        assert!(!filter.is_exact_git_dir_path(Path::new("/tmp/repo/.git/config")));
        assert!(filter.is_git_metadata_path(Path::new("/tmp/repo/.git")));
        assert!(filter.is_git_metadata_path(Path::new("/tmp/repo/.git/config")));
        assert!(!filter.is_git_metadata_path(Path::new("/tmp/repo/src/main.rs")));
    }

    #[test]
    fn identifies_commit_editmsg_path() {
        let filter = GitRwFilter::new();
        assert!(filter.is_commit_editmsg_path(Path::new("/tmp/repo/.git/COMMIT_EDITMSG")));
        assert!(!filter.is_commit_editmsg_path(Path::new("/tmp/repo/.git/sub/COMMIT_EDITMSG")));
        assert!(!filter.is_commit_editmsg_path(Path::new("/tmp/repo/.git/config")));
        assert!(!filter.is_commit_editmsg_path(Path::new("/tmp/repo/.git")));
        assert!(!filter.is_commit_editmsg_path(Path::new("/tmp/repo/COMMIT_EDITMSG")));
    }

    #[test]
    fn strip_mount_root_prefix_rewrites_fuse_backed_exe_path() {
        let stripped = strip_mount_root_prefix(
            PathBuf::from("/run/user/1000/leash/demo/mount/usr/bin/git"),
            Some(Path::new("/run/user/1000/leash/demo/mount")),
        );
        assert_eq!(stripped, PathBuf::from("/usr/bin/git"));
    }
}
