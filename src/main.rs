mod cli;
mod profile;
mod record;

use anyhow::{Context, Result, bail};
use cli::{Command, FlushCommand, MountCommand, RunCommand};
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
    let source = fs_err::read_to_string(profile_path)
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
        fs_err::create_dir_all(parent)
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
    for entry in fs_err::read_dir(&dir)
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

        stats.pending += 1;
        if !dry_run && record::mark_flushed(path, frame.offset)? {
            stats.marked += 1;
        }
    }

    Ok(stats)
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
        writer
            .append_cbor(record::TAG_WRITE_OP, &1u32)
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
        let mut writer = record::Writer::open_append(&path).expect("writer open");
        writer
            .append_cbor(record::TAG_WRITE_OP, &1u32)
            .expect("append");
        writer.sync().expect("sync");

        let first = flush_record(&path, false).expect("first flush");
        assert_eq!(first.pending, 1);
        assert_eq!(first.marked, 1);

        let second = flush_record(&path, false).expect("second flush");
        assert_eq!(second.pending, 0);
        assert_eq!(second.marked, 0);
        assert_eq!(second.skipped, 1);
    }
}
