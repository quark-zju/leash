use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

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
    exe: OnceLock<Option<PathBuf>>,
    env: OnceLock<Box<HashMap<String, String>>>,
}

impl Caller {
    pub fn new(pid: Option<u32>) -> Self {
        Self {
            pid,
            exe: OnceLock::new(),
            env: OnceLock::new(),
        }
    }

    #[cfg(test)]
    pub fn with_process_name(pid: Option<u32>, process_name: Option<String>) -> Self {
        let exe = OnceLock::new();
        let process_name = process_name.and_then(|name| {
            let candidate = PathBuf::from(name);
            candidate.is_absolute().then_some(candidate)
        });
        let _ = exe.set(process_name);
        Self {
            pid,
            exe,
            env: OnceLock::new(),
        }
    }

    #[cfg(test)]
    pub fn process_name(&self) -> Option<&str> {
        self.exe
            .get()
            .and_then(|path| path.as_ref())
            .and_then(|path| path.to_str())
    }

    fn exe(&self) -> Option<&Path> {
        let pid = self.pid?;
        self.exe
            .get_or_init(|| std::fs::read_link(format!("/proc/{pid}/exe")).ok())
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

#[cfg(test)]
#[derive(Debug, Default, Clone, Copy)]
pub struct AllowAll;

#[cfg(test)]
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

    #[test]
    fn caller_condition_reuses_loaded_process_name_for_exe_match() {
        let caller = Caller::with_process_name(Some(42), Some("/usr/bin/leash-test".to_owned()));
        assert_eq!(caller.process_name(), Some("/usr/bin/leash-test"));

        let mut caller_condition = &caller;
        assert!(caller_condition.exe_match(Path::new("/usr/bin/leash-test")));
        assert!(caller_condition.exe_match(Path::new("/usr/bin/leash-test")));
    }
}
