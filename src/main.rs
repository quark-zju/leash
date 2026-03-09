mod cli;
mod op;
mod profile;
mod record;

use anyhow::{Context, Result, bail};
use cli::{Command, FlushCommand, MountCommand, RunCommand};
use fs_err as fs;
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
        "record: {} | total={} pending={} skipped={} marked={} dry_run={}",
        record_path.display(),
        stats.total,
        stats.pending,
        stats.skipped,
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
    marked: usize,
}

fn flush_record(path: &Path, dry_run: bool) -> Result<FlushStats> {
    let frames = record::read_frames(path)?;
    let mut stats = FlushStats {
        total: frames.len(),
        ..FlushStats::default()
    };

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

        stats.pending += 1;
        if !dry_run {
            apply_operation(&op)?;
        }
        if !dry_run && record::mark_flushed(path, frame.offset)? {
            stats.marked += 1;
        }
    }

    Ok(stats)
}

fn apply_operation(op: &op::Operation) -> Result<()> {
    match op {
        op::Operation::WriteFile {
            path,
            data,
            executable,
        } => {
            validate_abs(path)?;
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).with_context(|| {
                    format!("failed to create parent directories for {}", path.display())
                })?;
            }
            fs::write(path, data)
                .with_context(|| format!("failed to write file from record: {}", path.display()))?;
            set_executable_bit(path, *executable)
        }
        op::Operation::CreateDir { path } => {
            validate_abs(path)?;
            fs::create_dir_all(path)
                .with_context(|| format!("failed to create directory: {}", path.display()))
        }
        op::Operation::RemoveFile { path } => {
            validate_abs(path)?;
            match fs::remove_file(path) {
                Ok(()) => Ok(()),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(err) => Err(err)
                    .with_context(|| format!("failed to remove file: {}", path.display())),
            }
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
            data: b"hello".to_vec(),
            executable: false,
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
            data: b"world".to_vec(),
            executable: false,
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
                data: b"x".to_vec(),
                executable: false,
            },
            op::Operation::RemoveFile { path: file.clone() },
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
            data: b"#!/bin/sh\necho hi\n".to_vec(),
            executable: true,
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
}
