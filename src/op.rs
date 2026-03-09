use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Operation {
    WriteFile { path: PathBuf, data: Vec<u8> },
    CreateDir { path: PathBuf },
    RemoveFile { path: PathBuf },
    RemoveDir { path: PathBuf },
    Rename { from: PathBuf, to: PathBuf },
    Truncate { path: PathBuf, size: u64 },
}
