use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Operation {
    WriteFile {
        path: PathBuf,
        data: Option<Vec<u8>>,
        #[serde(default)]
        executable: bool,
    },
    CreateDir { path: PathBuf },
    RemoveFile { path: PathBuf },
    RemoveDir { path: PathBuf },
    CreateSymlink { path: PathBuf, target: PathBuf },
    Rename { from: PathBuf, to: PathBuf },
    Truncate { path: PathBuf, size: u64 },
}
