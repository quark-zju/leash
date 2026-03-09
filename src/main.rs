mod cli;
mod cowfs;
mod op;
mod profile;
mod record;

use anyhow::{Context, Result, bail};
use cli::{Command, FlushCommand, MountCommand, RunCommand};
use fs_err as fs;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;

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
        Command::Run(run) => run_command(run).context("run subcommand failed"),
        Command::Mount(mount) => {
            mount_command(mount).context("mount subcommand failed")?;
            Ok(0)
        }
        Command::Flush(flush) => {
            flush_command(flush).context("flush subcommand failed")?;
            Ok(0)
        }
    }
}

fn run_command(run: RunCommand) -> Result<i32> {
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        bail!(
            "cowjail run requires root euid (current euid={euid}).\n\
             Example setuid setup:\n\
             sudo chown root:root $(command -v cowjail)\n\
             sudo chmod u+s $(command -v cowjail)"
        );
    }

    let cwd = std::env::current_dir().context("failed to resolve current working directory")?;
    let ruid = unsafe { libc::getuid() };
    let rgid = unsafe { libc::getgid() };
    let record_path = run
        .record
        .clone()
        .unwrap_or(default_record_path().context("failed to build default record path")?);
    ensure_record_parent_dir(&record_path)?;

    let loaded = load_profile(Path::new(&run.profile))
        .with_context(|| format!("failed to load run profile '{}'", run.profile))?;
    let writer = record::Writer::open_append(&record_path).with_context(|| {
        format!(
            "failed to open run record writer at {}",
            record_path.display()
        )
    })?;
    append_profile_header(&writer, &loaded.normalized_source).with_context(|| {
        format!(
            "failed to append run profile header into {}",
            record_path.display()
        )
    })?;
    let cowfs = cowfs::CowFs::new(loaded.profile, writer);

    let mountpoint = make_run_mountpoint()?;
    vlog(
        run.verbose,
        format!("run: creating temporary mountpoint {}", mountpoint.display()),
    );
    fs::create_dir_all(&mountpoint).with_context(|| {
        format!(
            "failed to create run mountpoint directory: {}",
            mountpoint.display()
        )
    })?;

    let bg = {
        // SAFETY: session object is held until command exits; drop unmounts after wait.
        vlog(
            run.verbose,
            format!("run: mounting fuse filesystem at {}", mountpoint.display()),
        );
        unsafe { cowfs.mount_background(&mountpoint) }.with_context(|| {
            format!(
                "failed to mount run filesystem at temporary mountpoint {}",
                mountpoint.display()
            )
        })?
    };

    vlog(
        run.verbose,
        format!(
            "run: preparing child chroot to {} then chdir to {}",
            mountpoint.display(),
            cwd.display()
        ),
    );
    let status = run_child_in_chroot(&run, &mountpoint, &cwd, ruid, rgid)
        .with_context(|| format!("failed to execute jailed command {:?}", run.program));

    vlog(run.verbose, "run: waiting for child completion done".to_string());
    vlog(
        run.verbose,
        format!("run: unmounting fuse mount {}", mountpoint.display()),
    );
    drop(bg);
    vlog(
        run.verbose,
        format!("run: removing temporary mountpoint {}", mountpoint.display()),
    );
    let _ = fs::remove_dir(&mountpoint);
    vlog(run.verbose, "run: cleanup complete".to_string());

    let status = status?;
    Ok(exit_code_from_status(status))
}

fn mount_command(mount: MountCommand) -> Result<()> {
    let loaded = load_profile(Path::new(&mount.profile))
        .with_context(|| format!("failed to load mount profile '{}'", mount.profile))?;
    ensure_record_parent_dir(&mount.record)?;
    let writer = record::Writer::open_append(&mount.record).with_context(|| {
        format!(
            "failed to open mount record writer at {}",
            mount.record.display()
        )
    })?;
    append_profile_header(&writer, &loaded.normalized_source).with_context(|| {
        format!(
            "failed to append mount profile header into {}",
            mount.record.display()
        )
    })?;

    let fs = cowfs::CowFs::new(loaded.profile, writer);
    vlog(
        mount.verbose,
        format!(
            "mount: mounting fuse at {} with record {}",
            mount.path.display(),
            mount.record.display()
        ),
    );
    fs.mount(&mount.path)
}

fn run_child_in_chroot(
    run: &RunCommand,
    mountpoint: &Path,
    old_cwd: &Path,
    ruid: libc::uid_t,
    rgid: libc::gid_t,
) -> Result<std::process::ExitStatus> {
    let mount_c = CString::new(mountpoint.as_os_str().as_encoded_bytes())
        .context("mount path contains interior NUL byte")?;
    let cwd_c = CString::new(old_cwd.as_os_str().as_encoded_bytes())
        .context("cwd contains interior NUL byte")?;

    let mut cmd = ProcessCommand::new(&run.program);
    cmd.args(&run.args);
    // SAFETY: libc chroot/chdir are async-signal-safe enough for pre_exec setup.
    unsafe {
        cmd.pre_exec(move || {
            if libc::chroot(mount_c.as_ptr()) != 0 {
                let err = std::io::Error::last_os_error();
                return Err(std::io::Error::new(
                    err.kind(),
                    format!("chroot failed: {err}"),
                ));
            }
            if libc::chdir(cwd_c.as_ptr()) != 0 {
                let err = std::io::Error::last_os_error();
                return Err(std::io::Error::new(
                    err.kind(),
                    format!("chdir failed: {err}"),
                ));
            }
            if libc::setgid(rgid) != 0 {
                let err = std::io::Error::last_os_error();
                return Err(std::io::Error::new(
                    err.kind(),
                    format!("setgid({rgid}) failed: {err}"),
                ));
            }
            if libc::setuid(ruid) != 0 {
                let err = std::io::Error::last_os_error();
                return Err(std::io::Error::new(
                    err.kind(),
                    format!("setuid({ruid}) failed: {err}"),
                ));
            }
            Ok(())
        });
    }
    let mut child = cmd
        .spawn()
        .context("failed to spawn child command in jail")?;
    child.wait().context("failed waiting for child command")
}

fn exit_code_from_status(status: std::process::ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return 128 + sig;
        }
    }
    1
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

#[derive(Debug)]
struct LoadedProfile {
    profile: profile::Profile,
    normalized_source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProfileHeaderFrame {
    normalized_profile: String,
}

fn append_profile_header(writer: &record::Writer, normalized_source: &str) -> Result<()> {
    let header = ProfileHeaderFrame {
        normalized_profile: normalized_source.to_string(),
    };
    writer
        .append_cbor(record::TAG_PROFILE_HEADER, &header)
        .map(|_| ())
        .context("failed to append profile header frame")?;
    writer
        .sync()
        .context("failed to flush profile header frame")
}

fn load_profile(profile_path: &Path) -> Result<LoadedProfile> {
    let source = fs::read_to_string(profile_path)
        .with_context(|| format!("failed to read profile file: {}", profile_path.display()))?;
    let cwd = std::env::current_dir().context("failed to get current directory")?;
    let profile = profile::Profile::parse(&source, &cwd)
        .with_context(|| format!("failed to parse profile file: {}", profile_path.display()))?;
    let normalized_source = profile::normalize_source(&source, &cwd)
        .with_context(|| format!("failed to normalize profile file: {}", profile_path.display()))?;
    Ok(LoadedProfile {
        profile,
        normalized_source,
    })
}

fn parse_profile_from_normalized_source(source: &str) -> Result<profile::Profile> {
    profile::Profile::parse(source, Path::new("/"))
        .context("failed to parse normalized profile source from record")
}

fn default_record_dir() -> PathBuf {
    PathBuf::from(".cache/cowjail")
}

fn make_run_mountpoint() -> Result<PathBuf> {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before unix epoch")?
        .as_nanos();
    Ok(PathBuf::from(format!("/tmp/cowjail-run-{pid}-{nanos}")))
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
            fs::rename(from, to)
                .with_context(|| format!("failed to rename {} -> {}", from.display(), to.display()))
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
            fs::remove_file(path).with_context(|| {
                format!("failed to replace existing symlink {}", path.display())
            })?;
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

    fn temp_profile_path(name: &str, content: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be monotonic")
            .as_nanos();
        p.push(format!("cowjail-main-{name}-{now}.profile"));
        fs::write(&p, content).expect("write profile");
        p
    }

    #[test]
    fn flush_dry_run_does_not_mark() {
        let path = temp_record_path("dry-run");
        let writer = record::Writer::open_append(&path).expect("writer open");
        let op = op::Operation::WriteFile {
            path: temp_record_path("target"),
            state: op::FileState::Regular(b"hello".to_vec()),
        };
        writer
            .append_cbor(record::TAG_WRITE_OP, &op)
            .expect("append");
        writer.sync().expect("sync");

        let stats = flush_record(&path, true, None).expect("flush dry-run");
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
        let writer = record::Writer::open_append(&path).expect("writer open");
        let op = op::Operation::WriteFile {
            path: out_path.clone(),
            state: op::FileState::Regular(b"world".to_vec()),
        };
        writer
            .append_cbor(record::TAG_WRITE_OP, &op)
            .expect("append");
        writer.sync().expect("sync");

        let first = flush_record(&path, false, None).expect("first flush");
        assert_eq!(first.pending, 1);
        assert_eq!(first.marked, 1);
        let bytes = fs::read(&out_path).expect("output should be written");
        assert_eq!(bytes, b"world");

        let second = flush_record(&path, false, None).expect("second flush");
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

        let writer = record::Writer::open_append(&path).expect("writer open");
        let op = op::Operation::Rename {
            from: from.clone(),
            to: to.clone(),
        };
        writer
            .append_cbor(record::TAG_WRITE_OP, &op)
            .expect("append");
        writer.sync().expect("sync");

        let stats = flush_record(&path, false, None).expect("flush");
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

        let writer = record::Writer::open_append(&path).expect("writer open");
        let op = op::Operation::Truncate {
            path: target.clone(),
            size: 3,
        };
        writer
            .append_cbor(record::TAG_WRITE_OP, &op)
            .expect("append");
        writer.sync().expect("sync");

        let stats = flush_record(&path, false, None).expect("flush");
        assert_eq!(stats.marked, 1);
        let bytes = fs::read(&target).expect("truncated target");
        assert_eq!(bytes, b"abc");
    }

    #[test]
    fn flush_applies_create_and_remove_ops() {
        let path = temp_record_path("create-remove-record");
        let dir = temp_record_path("ops-dir");
        let file = dir.join("f.txt");

        let writer = record::Writer::open_append(&path).expect("writer open");
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

        let stats = flush_record(&path, false, None).expect("flush");
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
        let writer = record::Writer::open_append(&path).expect("writer open");

        let op = op::Operation::WriteFile {
            path: target.clone(),
            state: op::FileState::Executable(b"#!/bin/sh\necho hi\n".to_vec()),
        };
        writer
            .append_cbor(record::TAG_WRITE_OP, &op)
            .expect("append");
        writer.sync().expect("sync");

        let stats = flush_record(&path, false, None).expect("flush");
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

        let writer = record::Writer::open_append(&path).expect("writer open");
        let op = op::Operation::WriteFile {
            path: link.clone(),
            state: op::FileState::Symlink(target.clone()),
        };
        writer
            .append_cbor(record::TAG_WRITE_OP, &op)
            .expect("append");
        writer.sync().expect("sync");

        let stats = flush_record(&path, false, None).expect("flush");
        assert_eq!(stats.marked, 1);
        let resolved = fs::read_link(&link).expect("read link");
        assert_eq!(resolved, target);
    }

    #[test]
    fn flush_compacts_multiple_writes_then_delete() {
        let path = temp_record_path("compact-delete-record");
        let target = temp_record_path("compact-delete-target");
        let writer = record::Writer::open_append(&path).expect("writer open");

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

        let stats = flush_record(&path, false, None).expect("flush");
        assert_eq!(stats.pending, 3);
        assert_eq!(stats.optimized, 2);
        assert_eq!(stats.marked, 3);
        assert!(!target.exists());
    }

    #[test]
    fn flush_compaction_respects_rename_boundaries() {
        let path = temp_record_path("compact-rename-boundary-record");
        let a = temp_record_path("compact-rename-a");
        let b = temp_record_path("compact-rename-b");
        let writer = record::Writer::open_append(&path).expect("writer open");

        let ops = [
            op::Operation::WriteFile {
                path: a.clone(),
                state: op::FileState::Regular(b"v1".to_vec()),
            },
            op::Operation::WriteFile {
                path: a.clone(),
                state: op::FileState::Regular(b"v2".to_vec()),
            },
            op::Operation::Rename {
                from: a.clone(),
                to: b.clone(),
            },
            op::Operation::WriteFile {
                path: a.clone(),
                state: op::FileState::Regular(b"v3".to_vec()),
            },
        ];
        for op in ops {
            writer
                .append_cbor(record::TAG_WRITE_OP, &op)
                .expect("append op");
        }
        writer.sync().expect("sync");

        let stats = flush_record(&path, false, None).expect("flush");
        assert_eq!(stats.pending, 4);
        assert_eq!(stats.optimized, 1);
        assert_eq!(stats.marked, 4);
        assert_eq!(fs::read(&b).expect("renamed content"), b"v2");
        assert_eq!(fs::read(&a).expect("post-rename write"), b"v3");
    }

    #[test]
    fn flush_blocks_when_profile_header_disallows_write() {
        let path = temp_record_path("profile-block-record");
        let target = temp_record_path("profile-block-target");
        let writer = record::Writer::open_append(&path).expect("writer open");

        let header = ProfileHeaderFrame {
            normalized_profile: format!("{} ro\n", target.display()),
        };
        writer
            .append_cbor(record::TAG_PROFILE_HEADER, &header)
            .expect("append header");
        writer
            .append_cbor(
                record::TAG_WRITE_OP,
                &op::Operation::WriteFile {
                    path: target.clone(),
                    state: op::FileState::Regular(b"blocked".to_vec()),
                },
            )
            .expect("append write");
        writer.sync().expect("sync");

        let stats = flush_record(&path, false, None).expect("flush");
        assert_eq!(stats.pending, 1);
        assert_eq!(stats.blocked, 1);
        assert_eq!(stats.marked, 0);
        assert!(!target.exists());
    }

    #[test]
    fn flush_profile_override_can_allow_previously_blocked_write() {
        let path = temp_record_path("profile-override-record");
        let target = temp_record_path("profile-override-target");
        let writer = record::Writer::open_append(&path).expect("writer open");

        let header = ProfileHeaderFrame {
            normalized_profile: format!("{} ro\n", target.display()),
        };
        writer
            .append_cbor(record::TAG_PROFILE_HEADER, &header)
            .expect("append header");
        writer
            .append_cbor(
                record::TAG_WRITE_OP,
                &op::Operation::WriteFile {
                    path: target.clone(),
                    state: op::FileState::Regular(b"allowed".to_vec()),
                },
            )
            .expect("append write");
        writer.sync().expect("sync");

        let first = flush_record(&path, false, None).expect("flush blocked");
        assert_eq!(first.blocked, 1);
        assert_eq!(first.marked, 0);

        let override_profile =
            temp_profile_path("profile-override", &format!("{} rw\n", target.display()));
        let override_profile_str = override_profile.to_string_lossy().to_string();
        let second =
            flush_record(&path, false, Some(&override_profile_str)).expect("flush with override");
        assert_eq!(second.blocked, 0);
        assert_eq!(second.marked, 1);
        assert_eq!(fs::read(&target).expect("read target"), b"allowed");
    }
}
