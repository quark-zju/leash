use fs_err as fs;
use std::path::PathBuf;
use tempfile::tempdir;

pub(super) fn temp_record_path(name: &str) -> (tempfile::TempDir, PathBuf) {
    let root = tempdir().expect("tempdir for record path");
    let p = root.path().join(format!("cowjail-main-{name}.cjr"));
    (root, p)
}

pub(super) fn temp_profile_path(name: &str, content: &str) -> (tempfile::TempDir, PathBuf) {
    let root = tempdir().expect("tempdir for profile path");
    let p = root.path().join(format!("cowjail-main-{name}.profile"));
    fs::write(&p, content).expect("write profile");
    (root, p)
}

mod runtime;
mod flush;
