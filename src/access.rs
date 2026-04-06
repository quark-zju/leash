use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

pub type ProcessNameGetter = fn(u32) -> Option<String>;

pub trait CallerCondition {
    fn exe_match(&mut self, expected: &Path) -> bool;
    fn env_match(&mut self, name: &str) -> bool;
}

fn parse_environ(raw: Vec<u8>) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for pair in raw.split(|byte| *byte == 0) {
        if pair.is_empty() {
            continue;
        }
        let Some(eq) = pair.iter().position(|byte| *byte == b'=') else {
            continue;
        };
        let key = String::from_utf8_lossy(&pair[..eq]).into_owned();
        let value = String::from_utf8_lossy(&pair[eq + 1..]).into_owned();
        out.insert(key, value);
    }
    out
}

#[derive(Debug)]
pub struct Caller {
    pub pid: Option<u32>,
    process_name: OnceLock<Option<String>>,
    exe: OnceLock<Option<PathBuf>>,
    env: OnceLock<Box<HashMap<String, String>>>,
    get_name: ProcessNameGetter,
}

impl Caller {
    pub fn new(pid: Option<u32>, get_name: ProcessNameGetter) -> Self {
        Self {
            pid,
            process_name: OnceLock::new(),
            exe: OnceLock::new(),
            env: OnceLock::new(),
            get_name,
        }
    }

    pub fn with_process_name(pid: Option<u32>, process_name: Option<String>) -> Self {
        let process_name_cell = OnceLock::new();
        let _ = process_name_cell.set(process_name);
        Self {
            pid,
            process_name: process_name_cell,
            exe: OnceLock::new(),
            env: OnceLock::new(),
            get_name: |_| None,
        }
    }

    pub fn process_name(&self) -> Option<&str> {
        let pid = self.pid?;
        let loaded = self
            .process_name
            .get_or_init(|| (self.get_name)(pid))
            .as_deref();
        if let Some(name) = loaded {
            let candidate = PathBuf::from(name);
            if candidate.is_absolute() {
                let _ = self.exe.set(Some(candidate));
            }
        }
        loaded
    }

    pub fn process_name_cached(&self) -> Option<&str> {
        self.process_name.get().and_then(|name| name.as_deref())
    }

    fn exe(&self) -> Option<&Path> {
        let pid = self.pid?;
        self.exe
            .get_or_init(|| {
                if let Some(process_name) = self.process_name_cached() {
                    let candidate = PathBuf::from(process_name);
                    if candidate.is_absolute() {
                        return Some(candidate);
                    }
                }
                std::fs::read_link(format!("/proc/{pid}/exe")).ok()
            })
            .as_deref()
    }

    fn has_env(&self, name: &str) -> bool {
        let Some(pid) = self.pid else {
            return false;
        };
        let env = self.env.get_or_init(|| {
            Box::new(
                std::fs::read(format!("/proc/{pid}/environ"))
                    .map(parse_environ)
                    .unwrap_or_default(),
            )
        });
        env.contains_key(name)
    }
}

impl CallerCondition for &Caller {
    fn exe_match(&mut self, expected: &Path) -> bool {
        self.exe() == Some(expected)
    }

    fn env_match(&mut self, name: &str) -> bool {
        self.has_env(name)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Lookup,
    GetAttr,
    ReadDir,
    ReadLink,
    OpenRead,
    OpenWrite,
    Read,
    Write,
    Create,
    Mkdir,
    Unlink,
    Rmdir,
    Symlink,
    Link,
    Rename,
    SetAttr,
    Access,
    Fsync,
    FsyncDir,
    StatFs,
    GetLock,
    SetReadLock,
    SetWriteLock,
    Unlock,
}

impl Operation {
    pub fn is_write(self) -> bool {
        matches!(
            self,
            Self::OpenWrite
                | Self::Write
                | Self::Create
                | Self::Mkdir
                | Self::Unlink
                | Self::Rmdir
                | Self::Symlink
                | Self::Link
                | Self::Rename
                | Self::SetAttr
                | Self::SetWriteLock
                | Self::Fsync
                | Self::FsyncDir
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessDecision {
    Allow,
    Deny(i32),
}

#[derive(Debug, Clone, Copy)]
pub struct AccessRequest<'a> {
    pub caller: &'a Caller,
    pub path: &'a Path,
    pub operation: Operation,
}

pub trait AccessController: Send + Sync + 'static {
    fn check(
        &self,
        request: &AccessRequest<'_>,
        caller_condition: &mut dyn CallerCondition,
    ) -> AccessDecision;

    fn should_cache_readdir(&self, _path: &Path) -> bool {
        true
    }
}

impl<T: AccessController + ?Sized> AccessController for Arc<T> {
    fn check(
        &self,
        request: &AccessRequest<'_>,
        caller_condition: &mut dyn CallerCondition,
    ) -> AccessDecision {
        (**self).check(request, caller_condition)
    }

    fn should_cache_readdir(&self, path: &Path) -> bool {
        (**self).should_cache_readdir(path)
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct AllowAll;

impl AccessController for AllowAll {
    fn check(
        &self,
        _request: &AccessRequest<'_>,
        _caller_condition: &mut dyn CallerCondition,
    ) -> AccessDecision {
        AccessDecision::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static PROCESS_NAME_READS: AtomicUsize = AtomicUsize::new(0);

    fn counting_process_name_getter(_pid: u32) -> Option<String> {
        PROCESS_NAME_READS.fetch_add(1, Ordering::Relaxed);
        Some("/usr/bin/leash-test".to_owned())
    }

    #[test]
    fn caller_condition_reuses_loaded_process_name_for_exe_match() {
        PROCESS_NAME_READS.store(0, Ordering::Relaxed);
        let caller = Caller::new(Some(42), counting_process_name_getter);
        assert_eq!(caller.process_name(), Some("/usr/bin/leash-test"));
        assert_eq!(PROCESS_NAME_READS.load(Ordering::Relaxed), 1);

        let mut caller_condition = &caller;
        assert!(caller_condition.exe_match(Path::new("/usr/bin/leash-test")));
        assert!(caller_condition.exe_match(Path::new("/usr/bin/leash-test")));
        assert_eq!(PROCESS_NAME_READS.load(Ordering::Relaxed), 1);
    }
}
