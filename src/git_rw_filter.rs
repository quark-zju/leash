use std::collections::HashMap;
use std::ffi::OsStr;
use std::os::unix::fs::MetadataExt;
use std::os::unix::prelude::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;

use fs_err as fs;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProcIdentity {
    ctime: i64,
    ctime_nsec: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CachedDecision {
    identity: ProcIdentity,
    allowed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SystemGit {
    dev: u64,
    ino: u64,
}

#[derive(Debug)]
pub(crate) struct GitRwFilter {
    system_git: Option<SystemGit>,
    proc_cache: Mutex<HashMap<u32, CachedDecision>>,
    repo_root_cache: Mutex<HashMap<PathBuf, Option<PathBuf>>>,
}

impl GitRwFilter {
    pub(crate) fn new() -> Self {
        Self {
            system_git: resolve_system_git(),
            proc_cache: Mutex::new(HashMap::new()),
            repo_root_cache: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn is_git_metadata_path(&self, path: &Path) -> bool {
        path.components().any(|component| match component {
            Component::Normal(name) => name == OsStr::new(".git"),
            _ => false,
        })
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
                return cached.clone();
            }

            visited.push(current.clone());
            if current.join(".git/config").is_file() {
                self.fill_repo_root_cache(&visited, Some(current.clone()));
                return Some(current);
            }
            let Some(parent) = current.parent() else {
                self.fill_repo_root_cache(&visited, None);
                return None;
            };
            current = parent.to_path_buf();
        }
    }

    pub(crate) fn path_is_git_repo_member(&self, path: &Path) -> bool {
        if self.is_git_metadata_path(path) {
            return false;
        }
        self.repo_root_for(path).is_some()
    }

    pub(crate) fn allow_git_metadata_for_pid(&self, pid: u32) -> bool {
        let proc_dir = PathBuf::from(format!("/proc/{pid}"));
        let meta = match fs::metadata(&proc_dir) {
            Ok(meta) => meta,
            Err(_) => return false,
        };
        let identity = ProcIdentity {
            ctime: meta.ctime(),
            ctime_nsec: meta.ctime_nsec(),
        };

        if let Ok(cache) = self.proc_cache.lock()
            && let Some(entry) = cache.get(&pid)
            && entry.identity == identity
        {
            return entry.allowed;
        }

        let allowed = self.inspect_process(pid);
        if let Ok(mut cache) = self.proc_cache.lock() {
            cache.insert(pid, CachedDecision { identity, allowed });
        }
        allowed
    }

    fn inspect_process(&self, pid: u32) -> bool {
        let Some(system_git) = self.system_git.as_ref() else {
            return false;
        };

        let exe_meta = match fs::metadata(format!("/proc/{pid}/exe")) {
            Ok(meta) => meta,
            Err(_) => return false,
        };
        if exe_meta.dev() != system_git.dev || exe_meta.ino() != system_git.ino {
            return false;
        }

        let cmdline = match fs::read(format!("/proc/{pid}/cmdline")) {
            Ok(data) => data,
            Err(_) => return false,
        };
        let Some(subcommand) = first_git_subcommand(&cmdline) else {
            return false;
        };
        matches!(
            subcommand,
            "commit" | "status" | "add" | "rm" | "revert" | "log"
        )
    }

    fn fill_repo_root_cache(&self, visited: &[PathBuf], repo_root: Option<PathBuf>) {
        let Ok(mut cache) = self.repo_root_cache.lock() else {
            return;
        };
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

fn resolve_system_git() -> Option<SystemGit> {
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
        return Some(SystemGit {
            dev: meta.dev(),
            ino: meta.ino(),
        });
    }
    None
}

fn first_git_subcommand(cmdline: &[u8]) -> Option<&str> {
    let argv: Vec<&[u8]> = cmdline.split(|b| *b == 0).filter(|part| !part.is_empty()).collect();
    if argv.is_empty() {
        return None;
    }

    let mut idx = 1usize;
    while idx < argv.len() {
        let arg = std::str::from_utf8(argv[idx]).ok()?;
        if arg == "--" {
            return None;
        }
        if takes_value(arg) {
            idx += 2;
            continue;
        }
        if is_option_with_inline_value(arg) || arg.starts_with('-') {
            idx += 1;
            continue;
        }
        return Some(arg);
    }
    None
}

fn takes_value(arg: &str) -> bool {
    matches!(arg, "-C" | "-c" | "--git-dir" | "--work-tree" | "--namespace" | "--config-env")
}

fn is_option_with_inline_value(arg: &str) -> bool {
    arg.starts_with("--git-dir=")
        || arg.starts_with("--work-tree=")
        || arg.starts_with("--namespace=")
        || arg.starts_with("--config-env=")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn first_git_subcommand_skips_common_global_options() {
        let cmdline = b"git\0-C\0/tmp/repo\0-c\0a=b\0status\0";
        assert_eq!(first_git_subcommand(cmdline), Some("status"));
    }

    #[test]
    fn first_git_subcommand_handles_inline_options() {
        let cmdline = b"git\0--git-dir=/tmp/repo/.git\0log\0";
        assert_eq!(first_git_subcommand(cmdline), Some("log"));
    }

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
        assert!(filter.is_git_metadata_path(Path::new("/tmp/repo/.git")));
        assert!(filter.is_git_metadata_path(Path::new("/tmp/repo/.git/config")));
        assert!(!filter.is_git_metadata_path(Path::new("/tmp/repo/src/main.rs")));
    }
}
