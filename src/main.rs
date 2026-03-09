mod cli;
mod op;
mod profile;
mod record;

use anyhow::{Context, Result, bail};
use cli::{Command, FlushCommand, MountCommand, RunCommand};
use fs_err as fs;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

fn main() {
    if let Err(err) = try_main() {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}

fn try_main() -> Result<()> {
    match cli::parse_env()? {
        Command::Run(run) => run_command(run),
        Command::Mount(mount) => mount_command(mount),
        Command::Flush(flush) => flush_command(flush),
    }
}

fn run_command(run: RunCommand) -> Result<()> {
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        bail!(
            "cowjail run requires root euid (current euid={euid}).\n\
             Example setuid setup:\n\
             sudo chown root:root $(command -v cowjail)\n\
             sudo chmod u+s $(command -v cowjail)"
        );
    }

    let _profile = load_profile(Path::new(&run.profile))?;
    let record_path = run
        .record
        .unwrap_or(default_record_path().context("failed to build default record path")?);
    ensure_record_parent_dir(&record_path)?;

    let _writer = record::Writer::open_append(&record_path)?;

    bail!(
        "run is not implemented yet (profile ok, record path: {})",
        record_path.display()
    )
}

fn mount_command(mount: MountCommand) -> Result<()> {
    let _profile = load_profile(Path::new(&mount.profile))?;
    ensure_record_parent_dir(&mount.record)?;
    let _writer = record::Writer::open_append(&mount.record)?;
    bail!(
        "mount is not implemented yet (profile ok, record path: {})",
        mount.record.display()
    )
}

fn flush_command(flush: FlushCommand) -> Result<()> {
    let record_path = if let Some(path) = flush.record {
        path
    } else {
        newest_record_path()?.ok_or_else(|| {
            anyhow::anyhow!(
                "no record file specified and no default record found under {}",
                default_record_dir().display()
            )
        })?
    };

    let stats = flush_record(&record_path, flush.dry_run)?;
    println!(
        "record: {} | total={} pending={} skipped={} optimized={} marked={} dry_run={}",
        record_path.display(),
        stats.total,
        stats.pending,
        stats.skipped,
        stats.optimized,
        stats.marked,
        flush.dry_run
    );
    Ok(())
}

fn load_profile(profile_path: &Path) -> Result<profile::Profile> {
    let source = fs::read_to_string(profile_path)
        .with_context(|| format!("failed to read profile file: {}", profile_path.display()))?;
    let cwd = std::env::current_dir().context("failed to get current directory")?;
    profile::Profile::parse(&source, &cwd)
        .with_context(|| format!("failed to parse profile file: {}", profile_path.display()))
}

fn default_record_dir() -> PathBuf {
    PathBuf::from(".cache/cowjail")
}

fn default_record_path() -> Result<PathBuf> {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before unix epoch")?
        .as_millis();
    Ok(default_record_dir().join(format!("{millis}.cjr")))
}

fn ensure_record_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create record directory: {}", parent.display()))?;
    }
    Ok(())
}

fn newest_record_path() -> Result<Option<PathBuf>> {
    let dir = default_record_dir();
    if !dir.exists() {
        return Ok(None);
    }

    let mut newest: Option<(std::time::SystemTime, PathBuf)> = None;
    for entry in fs::read_dir(&dir)
        .with_context(|| format!("failed to list record directory: {}", dir.display()))?
    {
        let entry =
            entry.with_context(|| format!("failed to read entry under {}", dir.display()))?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("cjr") {
            continue;
        }
        let metadata = entry
            .metadata()
            .with_context(|| format!("failed to stat record file: {}", path.display()))?;
        if !metadata.is_file() {
            continue;
        }
        let modified = metadata
            .modified()
            .with_context(|| format!("failed to get mtime: {}", path.display()))?;

        match &newest {
            Some((best, _)) if modified <= *best => {}
            _ => newest = Some((modified, path)),
        }
    }

    Ok(newest.map(|(_, path)| path))
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct FlushStats {
    total: usize,
    pending: usize,
    skipped: usize,
    optimized: usize,
    marked: usize,
}

fn flush_record(path: &Path, dry_run: bool) -> Result<FlushStats> {
    let frames = record::read_frames(path)?;
    let mut stats = FlushStats {
        total: frames.len(),
        ..FlushStats::default()
    };

    let mut pending = Vec::new();
    for frame in frames {
        if frame.flushed {
            stats.skipped += 1;
            continue;
        }
        if frame.tag != record::TAG_WRITE_OP {
            stats.skipped += 1;
            continue;
        }

        let op: op::Operation = match record::decode_cbor(&frame) {
            Ok(op) => op,
            Err(_) => {
                stats.skipped += 1;
                continue;
            }
        };

        pending.push(PendingOp {
            offset: frame.offset,
            op,
        });
    }

    stats.pending = pending.len();
    let apply_offsets = plan_apply_offsets(&pending);
    stats.optimized = pending.len().saturating_sub(apply_offsets.len());

    for item in pending {
        if !dry_run && apply_offsets.contains(&item.offset) {
            apply_operation(&item.op)?;
        }
        if !dry_run && record::mark_flushed(path, item.offset)? {
            stats.marked += 1;
        }
    }

    Ok(stats)
}

#[derive(Debug, Clone)]
struct PendingOp {
    offset: u64,
    op: op::Operation,
}

fn plan_apply_offsets(items: &[PendingOp]) -> HashSet<u64> {
    if items.iter().any(|item| matches!(item.op, op::Operation::Rename { .. })) {
        return items.iter().map(|item| item.offset).collect();
    }

    let mut by_path: HashMap<&Path, u64> = HashMap::new();
    let mut without_path: HashSet<u64> = HashSet::new();
    for item in items {
        if let Some(path) = op_primary_path(&item.op) {
            by_path.insert(path, item.offset);
        } else {
            without_path.insert(item.offset);
        }
    }

    let mut out: HashSet<u64> = by_path.into_values().collect();
    out.extend(without_path);
    out
}

fn op_primary_path(op: &op::Operation) -> Option<&Path> {
    match op {
        op::Operation::WriteFile { path, .. }
        | op::Operation::CreateDir { path }
        | op::Operation::RemoveDir { path }
        | op::Operation::Truncate { path, .. } => Some(path.as_path()),
        op::Operation::Rename { .. } => None,
    }
}

fn apply_operation(op: &op::Operation) -> Result<()> {
    match op {
        op::Operation::WriteFile { path, state } => {
            validate_abs(path)?;
            match state {
                op::FileState::Deleted => match fs::remove_file(path) {
                    Ok(()) => Ok(()),
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    Err(err) => {
                        Err(err).with_context(|| format!("failed to remove file: {}", path.display()))
                    }
                },
                op::FileState::Regular(data) => {
                    if let Some(parent) = path.parent() {
                        fs::create_dir_all(parent).with_context(|| {
                            format!("failed to create parent directories for {}", path.display())
                        })?;
                    }
                    fs::write(path, data).with_context(|| {
                        format!("failed to write file from record: {}", path.display())
                    })?;
                    set_executable_bit(path, false)
                }
                op::FileState::Executable(data) => {
                    if let Some(parent) = path.parent() {
                        fs::create_dir_all(parent).with_context(|| {
                            format!("failed to create parent directories for {}", path.display())
                        })?;
                    }
                    fs::write(path, data).with_context(|| {
                        format!("failed to write file from record: {}", path.display())
                    })?;
                    set_executable_bit(path, true)
                }
                op::FileState::Symlink(target) => {
                    if let Some(parent) = path.parent() {
                        fs::create_dir_all(parent).with_context(|| {
                            format!(
                                "failed to create parent directories for symlink {}",
                                path.display()
                            )
                        })?;
                    }
                    create_symlink(path, target)
                }
            }
        }
        op::Operation::CreateDir { path } => {
            validate_abs(path)?;
            fs::create_dir_all(path)
                .with_context(|| format!("failed to create directory: {}", path.display()))
        }
        op::Operation::RemoveDir { path } => {
            validate_abs(path)?;
            match fs::remove_dir(path) {
                Ok(()) => Ok(()),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(err) => Err(err)
                    .with_context(|| format!("failed to remove directory: {}", path.display())),
            }
        }
        op::Operation::Rename { from, to } => {
            validate_abs(from)?;
            validate_abs(to)?;
            if let Some(parent) = to.parent() {
                fs::create_dir_all(parent).with_context(|| {
                    format!(
                        "failed to create parent directories for rename target {}",
                        to.display()
                    )
                })?;
            }
            fs::rename(from, to).with_context(|| {
                format!(
                    "failed to rename {} -> {}",
                    from.display(),
                    to.display()
                )
            })
        }
        op::Operation::Truncate { path, size } => {
            validate_abs(path)?;
            let file = fs::OpenOptions::new()
                .create(false)
                .write(true)
                .open(path)
                .with_context(|| format!("failed to open file for truncate: {}", path.display()))?;
            file.set_len(*size)
                .with_context(|| format!("failed to truncate file: {}", path.display()))
        }
    }
}

fn validate_abs(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        bail!("operation path must be absolute: {}", path.display());
    }
    Ok(())
}

#[cfg(unix)]
fn set_executable_bit(path: &Path, executable: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perm = fs::metadata(path)
        .with_context(|| format!("failed to stat file after write: {}", path.display()))?
        .permissions();
    let mode = perm.mode();
    let next = if executable {
        mode | 0o111
    } else {
        mode & !0o111
    };
    if next != mode {
        perm.set_mode(next);
        fs::set_permissions(path, perm)
            .with_context(|| format!("failed to set permissions on {}", path.display()))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn set_executable_bit(_path: &Path, _executable: bool) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn create_symlink(path: &Path, target: &Path) -> Result<()> {
    use std::os::unix::fs as unix_fs;

    match unix_fs::symlink(target, path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = fs::read_link(path)
                .with_context(|| format!("failed to read existing symlink {}", path.display()))?;
            if existing == target {
                return Ok(());
            }
            fs::remove_file(path)
                .with_context(|| format!("failed to replace existing symlink {}", path.display()))?;
            unix_fs::symlink(target, path).with_context(|| {
                format!(
                    "failed to create replacement symlink {} -> {}",
                    path.display(),
                    target.display()
                )
            })
        }
        Err(err) => Err(err).with_context(|| {
            format!(
                "failed to create symlink {} -> {}",
                path.display(),
                target.display()
            )
        }),
    }
}

#[cfg(not(unix))]
fn create_symlink(path: &Path, target: &Path) -> Result<()> {
    bail!(
        "symlink replay is only supported on unix targets ({} -> {})",
        path.display(),
        target.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_record_path(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be monotonic")
            .as_nanos();
        p.push(format!("cowjail-main-{name}-{now}.cjr"));
        p
    }

    #[test]
    fn flush_dry_run_does_not_mark() {
        let path = temp_record_path("dry-run");
        let mut writer = record::Writer::open_append(&path).expect("writer open");
        let op = op::Operation::WriteFile {
            path: temp_record_path("target"),
            state: op::FileState::Regular(b"hello".to_vec()),
        };
        writer
            .append_cbor(record::TAG_WRITE_OP, &op)
            .expect("append");
        writer.sync().expect("sync");

        let stats = flush_record(&path, true).expect("flush dry-run");
        assert_eq!(stats.total, 1);
        assert_eq!(stats.pending, 1);
        assert_eq!(stats.marked, 0);

        let frames = record::read_frames(&path).expect("read frames");
        assert!(!frames[0].flushed);
    }

    #[test]
    fn flush_marks_and_becomes_idempotent() {
        let path = temp_record_path("mark");
        let out_path = temp_record_path("write-target");
        let mut writer = record::Writer::open_append(&path).expect("writer open");
        let op = op::Operation::WriteFile {
            path: out_path.clone(),
            state: op::FileState::Regular(b"world".to_vec()),
        };
        writer
            .append_cbor(record::TAG_WRITE_OP, &op)
            .expect("append");
        writer.sync().expect("sync");

        let first = flush_record(&path, false).expect("first flush");
        assert_eq!(first.pending, 1);
        assert_eq!(first.marked, 1);
        let bytes = fs::read(&out_path).expect("output should be written");
        assert_eq!(bytes, b"world");

        let second = flush_record(&path, false).expect("second flush");
        assert_eq!(second.pending, 0);
        assert_eq!(second.marked, 0);
        assert_eq!(second.skipped, 1);
    }

    #[test]
    fn flush_applies_rename() {
        let path = temp_record_path("rename-record");
        let from = temp_record_path("rename-from");
        let to = temp_record_path("rename-to");
        fs::write(&from, b"rename-me").expect("seed source");

        let mut writer = record::Writer::open_append(&path).expect("writer open");
        let op = op::Operation::Rename {
            from: from.clone(),
            to: to.clone(),
        };
        writer
            .append_cbor(record::TAG_WRITE_OP, &op)
            .expect("append");
        writer.sync().expect("sync");

        let stats = flush_record(&path, false).expect("flush");
        assert_eq!(stats.marked, 1);
        assert!(!from.exists());
        let bytes = fs::read(&to).expect("renamed target");
        assert_eq!(bytes, b"rename-me");
    }

    #[test]
    fn flush_applies_truncate() {
        let path = temp_record_path("truncate-record");
        let target = temp_record_path("truncate-target");
        fs::write(&target, b"abcdef").expect("seed target");

        let mut writer = record::Writer::open_append(&path).expect("writer open");
        let op = op::Operation::Truncate {
            path: target.clone(),
            size: 3,
        };
        writer
            .append_cbor(record::TAG_WRITE_OP, &op)
            .expect("append");
        writer.sync().expect("sync");

        let stats = flush_record(&path, false).expect("flush");
        assert_eq!(stats.marked, 1);
        let bytes = fs::read(&target).expect("truncated target");
        assert_eq!(bytes, b"abc");
    }

    #[test]
    fn flush_applies_create_and_remove_ops() {
        let path = temp_record_path("create-remove-record");
        let dir = temp_record_path("ops-dir");
        let file = dir.join("f.txt");

        let mut writer = record::Writer::open_append(&path).expect("writer open");
        let ops = [
            op::Operation::CreateDir { path: dir.clone() },
            op::Operation::WriteFile {
                path: file.clone(),
                state: op::FileState::Regular(b"x".to_vec()),
            },
            op::Operation::WriteFile {
                path: file.clone(),
                state: op::FileState::Deleted,
            },
            op::Operation::RemoveDir { path: dir.clone() },
        ];
        for op in ops {
            writer
                .append_cbor(record::TAG_WRITE_OP, &op)
                .expect("append op");
        }
        writer.sync().expect("sync");

        let stats = flush_record(&path, false).expect("flush");
        assert_eq!(stats.marked, 4);
        assert!(!file.exists());
        assert!(!dir.exists());
    }

    #[cfg(unix)]
    #[test]
    fn flush_applies_executable_bit() {
        use std::os::unix::fs::PermissionsExt;

        let path = temp_record_path("chmod-record");
        let target = temp_record_path("chmod-target");
        let mut writer = record::Writer::open_append(&path).expect("writer open");

        let op = op::Operation::WriteFile {
            path: target.clone(),
            state: op::FileState::Executable(b"#!/bin/sh\necho hi\n".to_vec()),
        };
        writer
            .append_cbor(record::TAG_WRITE_OP, &op)
            .expect("append");
        writer.sync().expect("sync");

        let stats = flush_record(&path, false).expect("flush");
        assert_eq!(stats.marked, 1);

        let mode = fs::metadata(&target)
            .expect("target metadata")
            .permissions()
            .mode();
        assert_ne!(mode & 0o111, 0);
    }

    #[cfg(unix)]
    #[test]
    fn flush_applies_symlink_creation() {
        let path = temp_record_path("symlink-record");
        let dir = temp_record_path("symlink-dir");
        let target = dir.join("target.txt");
        let link = dir.join("link.txt");
        fs::create_dir_all(&dir).expect("mkdir");
        fs::write(&target, b"link-target").expect("seed target");

        let mut writer = record::Writer::open_append(&path).expect("writer open");
        let op = op::Operation::WriteFile {
            path: link.clone(),
            state: op::FileState::Symlink(target.clone()),
        };
        writer
            .append_cbor(record::TAG_WRITE_OP, &op)
            .expect("append");
        writer.sync().expect("sync");

        let stats = flush_record(&path, false).expect("flush");
        assert_eq!(stats.marked, 1);
        let resolved = fs::read_link(&link).expect("read link");
        assert_eq!(resolved, target);
    }

    #[test]
    fn flush_compacts_multiple_writes_then_delete() {
        let path = temp_record_path("compact-delete-record");
        let target = temp_record_path("compact-delete-target");
        let mut writer = record::Writer::open_append(&path).expect("writer open");

        let ops = [
            op::Operation::WriteFile {
                path: target.clone(),
                state: op::FileState::Regular(b"v1".to_vec()),
            },
            op::Operation::WriteFile {
                path: target.clone(),
                state: op::FileState::Regular(b"v2".to_vec()),
            },
            op::Operation::WriteFile {
                path: target.clone(),
                state: op::FileState::Deleted,
            },
        ];
        for op in ops {
            writer
                .append_cbor(record::TAG_WRITE_OP, &op)
                .expect("append op");
        }
        writer.sync().expect("sync");

        let stats = flush_record(&path, false).expect("flush");
        assert_eq!(stats.pending, 3);
        assert_eq!(stats.optimized, 2);
        assert_eq!(stats.marked, 3);
        assert!(!target.exists());
    }
}
