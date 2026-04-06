use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, OnceLock};

pub type ProcessNameGetter = fn(u32) -> Option<String>;

pub trait CallerCondition {
    fn exe_match(&mut self, expected: &Path) -> bool;
    fn env_match(&mut self, name: &str) -> bool;
}

pub struct ProcCallerCondition {
    pid: Option<u32>,
    exe_loaded: bool,
    exe: Option<std::path::PathBuf>,
    env_loaded: bool,
    env: HashMap<String, String>,
}

impl ProcCallerCondition {
    pub fn from_pid(pid: Option<u32>) -> Self {
        Self {
            pid,
            exe_loaded: false,
            exe: None,
            env_loaded: false,
            env: HashMap::new(),
        }
    }
}

impl CallerCondition for ProcCallerCondition {
    fn exe_match(&mut self, expected: &Path) -> bool {
        if !self.exe_loaded {
            self.exe = self
                .pid
                .and_then(|pid| std::fs::read_link(format!("/proc/{pid}/exe")).ok());
            self.exe_loaded = true;
        }
        self.exe.as_deref() == Some(expected)
    }

    fn env_match(&mut self, name: &str) -> bool {
        if !self.env_loaded {
            self.env = self
                .pid
                .and_then(|pid| std::fs::read(format!("/proc/{pid}/environ")).ok())
                .map(parse_environ)
                .unwrap_or_default();
            self.env_loaded = true;
        }
        self.env.contains_key(name)
    }
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
    get_name: ProcessNameGetter,
}

impl Caller {
    pub fn new(pid: Option<u32>, get_name: ProcessNameGetter) -> Self {
        Self {
            pid,
            process_name: OnceLock::new(),
            get_name,
        }
    }

    pub fn with_process_name(pid: Option<u32>, process_name: Option<String>) -> Self {
        let process_name_cell = OnceLock::new();
        let _ = process_name_cell.set(process_name);
        Self {
            pid,
            process_name: process_name_cell,
            get_name: |_| None,
        }
    }

    pub fn process_name(&self) -> Option<&str> {
        let pid = self.pid?;
        self.process_name
            .get_or_init(|| (self.get_name)(pid))
            .as_deref()
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
