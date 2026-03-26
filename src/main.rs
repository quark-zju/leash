mod cli;
mod cmd_mount;
mod cmd_run;
mod cowfs;
mod op;
mod profile;
mod profile_loader;
mod record;

use anyhow::{Context, Result, bail};
use cli::{Command, FlushCommand};
use fs_err as fs;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use profile_loader::{
    ProfileHeaderFrame, default_record_dir, load_profile, newest_record_path,
    parse_profile_from_normalized_source,
};

fn main() {
    match try_main() {
        Ok(code) => std::process::exit(code),
        Err(err) => {
        eprintln!("error: {err:#}");
        std::process::exit(1);
        }
    }
}

fn try_main() -> Result<i32> {
    match cli::parse_env()? {
        Command::Help(topic) => {
            println!("{}", cli::help_text(topic));
            Ok(0)
        }
        Command::Run(run) => cmd_run::run_command(run).context("run subcommand failed"),
        Command::Mount(mount) => {
            cmd_mount::mount_command(mount).context("mount subcommand failed")?;
            Ok(0)
        }
        Command::Flush(flush) => {
            flush_command(flush).context("flush subcommand failed")?;
            Ok(0)
        }
    }
}

fn flush_command(flush: FlushCommand) -> Result<()> {
    let record_path = if let Some(path) = flush.record {
        path
    } else {
        let default_dir = default_record_dir()?;
        newest_record_path()?.ok_or_else(|| {
            anyhow::anyhow!(
                "no record file specified and no default record found under {}",
                default_dir.display()
            )
        })?
    };

    let stats = flush_record(&record_path, flush.dry_run, flush.profile.as_deref())
        .with_context(|| format!("failed to flush record file {}", record_path.display()))?;
    vlog(
        flush.verbose,
        format!(
            "flush: record={} total={} pending={} skipped={} optimized={} blocked={} marked={} dry_run={}",
            record_path.display(),
            stats.total,
            stats.pending,
            stats.skipped,
            stats.optimized,
            stats.blocked,
            stats.marked,
            flush.dry_run
        ),
    );
    println!(
        "record: {} | total={} pending={} skipped={} optimized={} blocked={} marked={} dry_run={}",
        record_path.display(),
        stats.total,
        stats.pending,
        stats.skipped,
        stats.optimized,
        stats.blocked,
        stats.marked,
        flush.dry_run
    );
    Ok(())
}

fn vlog(verbose: bool, msg: String) {
    if verbose {
        eprintln!("{msg}");
    }
}


#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct FlushStats {
    total: usize,
    pending: usize,
    skipped: usize,
    optimized: usize,
    blocked: usize,
    marked: usize,
}

fn flush_record(path: &Path, dry_run: bool, profile_override: Option<&str>) -> Result<FlushStats> {
    let mut record_lock = record::lock_record(path)
        .with_context(|| format!("failed to lock record {}", path.display()))?;
    let frames = record_lock
        .read_frames()
        .with_context(|| format!("failed to read frames from {}", path.display()))?;
    let replay_profile = resolve_flush_profile(profile_override, &frames)
        .with_context(|| format!("failed to resolve flush profile for {}", path.display()))?;
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
            if !op_allowed_by_profile(replay_profile.as_ref(), &item.op) {
                stats.blocked += 1;
                continue;
            }
            apply_operation(&item.op)?;
        }
        if !dry_run && record_lock.mark_flushed(item.offset)? {
            stats.marked += 1;
        }
    }

    Ok(stats)
}

fn resolve_flush_profile(
    profile_override: Option<&str>,
    frames: &[record::Frame],
) -> Result<Option<profile::Profile>> {
    if let Some(profile_path) = profile_override {
        let loaded = load_profile(Path::new(profile_path))?;
        return Ok(Some(loaded.profile));
    }

    for frame in frames.iter().rev() {
        if frame.tag != record::TAG_PROFILE_HEADER {
            continue;
        }
        let header: ProfileHeaderFrame = match record::decode_cbor(frame) {
            Ok(header) => header,
            Err(_) => continue,
        };
        return Ok(Some(parse_profile_from_normalized_source(
            &header.normalized_profile,
        )?));
    }

    Ok(None)
}

fn op_allowed_by_profile(policy: Option<&profile::Profile>, op: &op::Operation) -> bool {
    let Some(policy) = policy else {
        return true;
    };
    for path in op_paths(op) {
        if policy.first_match_action(path) != Some(profile::RuleAction::ReadWrite) {
            return false;
        }
    }
    true
}

fn op_paths(op: &op::Operation) -> Vec<&Path> {
    match op {
        op::Operation::WriteFile { path, .. }
        | op::Operation::CreateDir { path }
        | op::Operation::RemoveDir { path }
        | op::Operation::Truncate { path, .. } => vec![path.as_path()],
        op::Operation::Rename { from, to } => vec![from.as_path(), to.as_path()],
    }
}

#[derive(Debug, Clone)]
struct PendingOp {
    offset: u64,
    op: op::Operation,
}

fn plan_apply_offsets(items: &[PendingOp]) -> HashSet<u64> {
    let mut keep = HashSet::new();
    let mut segment_start = 0usize;

    for (idx, item) in items.iter().enumerate() {
        if matches!(item.op, op::Operation::Rename { .. }) {
            keep.extend(compact_segment_offsets(&items[segment_start..idx]));
            keep.insert(item.offset);
            segment_start = idx + 1;
        }
    }
    keep.extend(compact_segment_offsets(&items[segment_start..]));
    keep
}

fn compact_segment_offsets(items: &[PendingOp]) -> HashSet<u64> {
    let mut by_path: HashMap<&Path, u64> = HashMap::new();
    let mut keep: HashSet<u64> = HashSet::new();
    for item in items {
        if let Some(path) = op_primary_path(&item.op) {
            by_path.insert(path, item.offset);
        } else {
            keep.insert(item.offset);
        }
    }
    keep.extend(by_path.into_values());
    keep
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
                    Err(err) => Err(err)
                        .with_context(|| format!("failed to remove file: {}", path.display())),
                },
                op::FileState::Regular(data) => {
                    prepare_file_destination(path)?;
                    fs::write(path, data).with_context(|| {
                        format!("failed to write file from record: {}", path.display())
                    })?;
                    set_executable_bit(path, false)
                }
                op::FileState::Executable(data) => {
                    prepare_file_destination(path)?;
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
            ensure_safe_parent_dirs(to, "rename target")?;
            fs::rename(from, to)
                .with_context(|| format!("failed to rename {} -> {}", from.display(), to.display()))
        }
        op::Operation::Truncate { path, size } => {
            validate_abs(path)?;
            match fs::symlink_metadata(path) {
                Ok(meta) if meta.file_type().is_symlink() => {
                    bail!("refusing to truncate symlink during replay: {}", path.display());
                }
                Ok(_) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    return Err(err).with_context(|| {
                        format!("failed to inspect truncate target {}", path.display())
                    });
                }
            }
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

fn prepare_file_destination(path: &Path) -> Result<()> {
    ensure_safe_parent_dirs(path, "file replay destination")?;

    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => fs::remove_file(path)
            .with_context(|| format!("failed to replace symlink destination {}", path.display())),
        Ok(meta) if meta.is_dir() => bail!(
            "refusing to replace directory with regular file during replay: {}",
            path.display()
        ),
        Ok(_) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err)
            .with_context(|| format!("failed to inspect replay destination {}", path.display())),
    }
}

fn ensure_safe_parent_dirs(path: &Path, context: &str) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };

    let mut current = PathBuf::from("/");
    for component in parent.components() {
        use std::path::Component;

        match component {
            Component::RootDir => {}
            Component::Normal(seg) => {
                current.push(seg);
                match fs::symlink_metadata(&current) {
                    Ok(meta) if meta.file_type().is_symlink() => {
                        bail!(
                            "refusing to create {context} under symlink parent: {}",
                            current.display()
                        );
                    }
                    Ok(_) => {}
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                    Err(err) => {
                        return Err(err).with_context(|| {
                            format!("failed to inspect parent {} for {}", current.display(), context)
                        });
                    }
                }
            }
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {}
        }
    }

    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create parent directories for {}", path.display()))
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
            match fs::symlink_metadata(path) {
                Ok(meta) if meta.file_type().is_symlink() => {
                    let existing = fs::read_link(path).with_context(|| {
                        format!("failed to read existing symlink {}", path.display())
                    })?;
                    if existing == target {
                        return Ok(());
                    }
                    fs::remove_file(path).with_context(|| {
                        format!("failed to replace existing symlink {}", path.display())
                    })?;
                }
                Ok(meta) if meta.is_dir() => {
                    bail!(
                        "refusing to replace directory with symlink during replay: {}",
                        path.display()
                    );
                }
                Ok(_) => {
                    fs::remove_file(path).with_context(|| {
                        format!("failed to replace existing file {}", path.display())
                    })?;
                }
                Err(err) => {
                    return Err(err).with_context(|| {
                        format!("failed to inspect existing destination {}", path.display())
                    });
                }
            }
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
#[path = "tests.rs"]
mod tests;
