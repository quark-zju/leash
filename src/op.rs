use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FileState {
    Deleted,
    Regular(Vec<u8>),
    Executable(Vec<u8>),
    Symlink(PathBuf),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Operation {
    WriteFile { path: PathBuf, state: FileState },
    CreateDir { path: PathBuf },
    RemoveDir { path: PathBuf },
    Rename { from: PathBuf, to: PathBuf },
    Truncate { path: PathBuf, size: u64 },
}
