use anyhow::{Context, Result, bail};
use fs_err as fs;
use std::collections::{HashMap, HashSet};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::cli::{FlushCommand, LowLevelFlushCommand};
use crate::jail;
use crate::op;
use crate::profile;
use crate::profile_loader::{
    ProfileHeaderFrame, load_profile, parse_profile_from_normalized_source,
};
use crate::record;
use crate::run_with_log;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FlushStats {
    pub(crate) total: usize,
    pub(crate) pending: usize,
    pub(crate) skipped: usize,
    pub(crate) optimized: usize,
    pub(crate) blocked: usize,
    pub(crate) marked: usize,
}

#[derive(Debug, Clone)]
struct PendingOp {
    offset: u64,
    op: op::Operation,
}

pub(crate) fn flush_command(flush: FlushCommand) -> Result<()> {
    let resolved = run_with_log(
        || {
            jail::resolve(
                flush.name.as_deref(),
                flush.profile.as_deref(),
                jail::ResolveMode::MustExist,
            )
        },
        || "resolve flush jail".to_string(),
    )?;
    let record_path = resolved.paths.record_path.clone();
    let replay_profile = run_with_log(
        || parse_profile_from_normalized_source(&resolved.normalized_profile),
        || "parse resolved jail profile".to_string(),
    )?;

    let stats = run_with_log(
        || flush_record_with_policy(&record_path, flush.dry_run, Some(replay_profile)),
        || format!("flush record file {}", record_path.display()),
    )?;
    crate::vlog!(
        "flush: record={} total={} pending={} skipped={} optimized={} blocked={} marked={} dry_run={}",
        record_path.display(),
        stats.total,
        stats.pending,
        stats.skipped,
        stats.optimized,
        stats.blocked,
        stats.marked,
        flush.dry_run
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

pub(crate) fn low_level_flush_command(flush: LowLevelFlushCommand) -> Result<()> {
    let stats = run_with_log(
        || flush_record(&flush.record, flush.dry_run, flush.profile.as_deref()),
        || format!("flush record file {}", flush.record.display()),
    )?;
    crate::vlog!(
        "_flush: record={} total={} pending={} skipped={} optimized={} blocked={} marked={} dry_run={}",
        flush.record.display(),
        stats.total,
        stats.pending,
        stats.skipped,
        stats.optimized,
        stats.blocked,
        stats.marked,
        flush.dry_run
    );
    println!(
        "record: {} | total={} pending={} skipped={} optimized={} blocked={} marked={} dry_run={}",
        flush.record.display(),
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

pub(crate) fn flush_record(
    path: &Path,
    dry_run: bool,
    profile_override: Option<&str>,
) -> Result<FlushStats> {
    let replay_profile = if let Some(profile_path) = profile_override {
        let loaded = load_profile(Path::new(profile_path))?;
        Some(loaded.profile)
    } else {
        None
    };
    flush_record_with_policy(path, dry_run, replay_profile)
}

pub(crate) fn flush_record_with_policy(
    path: &Path,
    dry_run: bool,
    replay_profile: Option<profile::Profile>,
) -> Result<FlushStats> {
    let mut record_lock = record::lock_record(path)
        .with_context(|| format!("failed to lock record {}", path.display()))?;
    let frames = record_lock
        .read_frames()
        .with_context(|| format!("failed to read frames from {}", path.display()))?;
    let replay_profile = match replay_profile {
        Some(profile) => Some(profile),
        None => resolve_record_header_profile(&frames)
            .with_context(|| format!("failed to resolve flush profile for {}", path.display()))?,
    };
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
            if !op_allowed_by_ownership(&item.op)? {
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

fn resolve_record_header_profile(frames: &[record::Frame]) -> Result<Option<profile::Profile>> {
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
        if policy.first_match_action(path) != Some(profile::RuleAction::Cow) {
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

fn op_allowed_by_ownership(op: &op::Operation) -> Result<bool> {
    let current_uid = unsafe { libc::geteuid() };
    let owns = |path: &Path| path_owned_by_uid(path, current_uid);
    let parent_owns = |path: &Path| parent_owned_by_uid(path, current_uid);
    match op {
        op::Operation::WriteFile { path, state } => match state {
            op::FileState::Deleted => {
                if path.exists() {
                    owns(path)
                } else {
                    parent_owns(path)
                }
            }
            op::FileState::Regular(_)
            | op::FileState::Executable(_)
            | op::FileState::Symlink(_) => {
                if path.exists() {
                    owns(path)
                } else {
                    parent_owns(path)
                }
            }
        },
        op::Operation::CreateDir { path } => {
            if path.exists() {
                owns(path)
            } else {
                parent_owns(path)
            }
        }
        op::Operation::RemoveDir { path } => {
            if path.exists() {
                owns(path)
            } else {
                parent_owns(path)
            }
        }
        op::Operation::Truncate { path, .. } => owns(path),
        op::Operation::Rename { from, to } => {
            if !owns(from)? {
                return Ok(false);
            }
            if to.exists() {
                owns(to)
            } else {
                parent_owns(to)
            }
        }
    }
}

fn path_owned_by_uid(path: &Path, uid: u32) -> Result<bool> {
    validate_abs(path)?;
    match fs::symlink_metadata(path) {
        Ok(meta) => Ok(meta.uid() == uid),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => {
            Err(err).with_context(|| format!("failed to inspect ownership: {}", path.display()))
        }
    }
}

fn parent_owned_by_uid(path: &Path, uid: u32) -> Result<bool> {
    validate_abs(path)?;
    let Some(mut current) = path.parent() else {
        return Ok(false);
    };

    loop {
        match fs::symlink_metadata(current) {
            Ok(meta) => return Ok(meta.uid() == uid),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let Some(parent) = current.parent() else {
                    return Ok(false);
                };
                current = parent;
            }
            Err(err) => {
                return Err(err).with_context(|| {
                    format!(
                        "failed to inspect ownership of parent directory: {}",
                        current.display()
                    )
                });
            }
        }
    }
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
                    ensure_safe_parent_dirs(path, "symlink replay destination")?;
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
                    bail!(
                        "refusing to truncate symlink during replay: {}",
                        path.display()
                    );
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
                            format!(
                                "failed to inspect parent {} for {}",
                                current.display(),
                                context
                            )
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
