use std::collections::HashMap;
use std::ffi::OsStr;
use std::os::unix::prelude::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;

use fs_err as fs;
use log::{debug, trace};

#[derive(Debug)]
pub(crate) struct GitRwFilter {
    system_git: Option<PathBuf>,
    repo_root_cache: Mutex<HashMap<PathBuf, Option<PathBuf>>>,
}

impl GitRwFilter {
    pub(crate) fn new() -> Self {
        let system_git = resolve_system_git();
        debug!("git-rw: resolved system git path to {:?}", system_git);
        Self {
            system_git,
            repo_root_cache: Mutex::new(HashMap::new()),
        }
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

    pub(crate) fn repo_root_for(&self, path: &Path) -> Option<PathBuf> {
        let mut current = if path.is_dir() {
            path.to_path_buf()
        } else {
            path.parent()?.to_path_buf()
        };
        let mut visited = Vec::new();

        loop {
            if let Ok(cache) = self.repo_root_cache.lock()
                && let Some(cached) = cache.get(&current)
            {
                trace!(
                    "git-rw: repo root cache hit path={} repo_root={:?}",
                    current.display(),
                    cached
                );
                return cached.clone();
            }

            visited.push(current.clone());
            if current.join(".git/config").is_file() {
                debug!(
                    "git-rw: detected repo root {} while resolving {}",
                    current.display(),
                    path.display()
                );
                self.fill_repo_root_cache(&visited, Some(current.clone()));
                return Some(current);
            }
            let Some(parent) = current.parent() else {
                trace!(
                    "git-rw: no repo root found while resolving {}",
                    path.display()
                );
                self.fill_repo_root_cache(&visited, None);
                return None;
            };
            current = parent.to_path_buf();
        }
    }

    pub(crate) fn path_is_git_repo_member(&self, path: &Path) -> bool {
        if self.is_git_metadata_path(path) {
            trace!(
                "git-rw: path={} is inside git metadata, not part of the working copy",
                path.display()
            );
            return false;
        }
        let is_member = self.repo_root_for(path).is_some();
        trace!(
            "git-rw: working copy membership path={} member={}",
            path.display(),
            is_member
        );
        is_member
    }

    pub(crate) fn allow_git_metadata_for_pid(&self, pid: u32, mount_root: Option<&Path>) -> bool {
        let allowed = self.inspect_process(pid, mount_root);
        debug!("git-rw: evaluated pid={} allowed={}", pid, allowed);
        allowed
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

    fn fill_repo_root_cache(&self, visited: &[PathBuf], repo_root: Option<PathBuf>) {
        let Ok(mut cache) = self.repo_root_cache.lock() else {
            return;
        };
        trace!(
            "git-rw: fill repo root cache visited={} repo_root={:?}",
            visited.len(),
            repo_root
        );
        for path in visited {
            cache.insert(path.clone(), repo_root.clone());
        }
    }

    #[cfg(test)]
    fn repo_root_cache_len(&self) -> usize {
        self.repo_root_cache
            .lock()
            .expect("repo root cache lock")
            .len()
    }
}

fn resolve_system_git() -> Option<PathBuf> {
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
    use tempfile::tempdir;

    #[test]
    fn detects_plain_git_dir_repo_layout() {
        let dir = tempdir().expect("tempdir");
        let repo = dir.path().join("repo");
        let nested = repo.join("src/lib.rs");
        fs::create_dir_all(repo.join(".git")).expect("mkdir .git");
        fs::create_dir_all(repo.join("src")).expect("mkdir src");
        fs::write(repo.join(".git/config"), b"[core]\n").expect("write config");
        fs::write(&nested, b"fn main() {}\n").expect("write nested file");

        let filter = GitRwFilter::new();
        assert_eq!(filter.repo_root_for(&nested), Some(repo));
        assert!(filter.path_is_git_repo_member(&nested));
        assert!(!filter.path_is_git_repo_member(dir.path()));
    }

    #[test]
    fn repo_root_lookup_populates_cache_for_visited_directories() {
        let dir = tempdir().expect("tempdir");
        let repo = dir.path().join("repo");
        let nested_dir = repo.join("a/b");
        let nested = nested_dir.join("lib.rs");
        fs::create_dir_all(repo.join(".git")).expect("mkdir .git");
        fs::create_dir_all(&nested_dir).expect("mkdir nested");
        fs::write(repo.join(".git/config"), b"[core]\n").expect("write config");
        fs::write(&nested, b"fn main() {}\n").expect("write nested file");

        let filter = GitRwFilter::new();
        assert_eq!(filter.repo_root_cache_len(), 0);
        assert_eq!(filter.repo_root_for(&nested), Some(repo.clone()));
        assert!(filter.repo_root_cache_len() >= 3);
        assert_eq!(filter.repo_root_for(&nested_dir), Some(repo));
    }

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
    fn strip_mount_root_prefix_rewrites_fuse_backed_exe_path() {
        let stripped = strip_mount_root_prefix(
            PathBuf::from("/run/user/1000/cowjail/demo/mount/usr/bin/git"),
            Some(Path::new("/run/user/1000/cowjail/demo/mount")),
        );
        assert_eq!(stripped, PathBuf::from("/usr/bin/git"));
    }
}
