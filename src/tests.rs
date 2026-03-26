use super::{cli, cmd_flush, jail, ns_runtime, op, profile, profile_loader, record};
use crate::profile_loader::ProfileHeaderFrame;
use fs_err as fs;
use std::path::Path;
use tempfile::tempdir;

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
fn explicit_jail_name_validation_rejects_reserved_and_invalid_names() {
    jail::validate_explicit_name("good-name_1.2").expect("valid name");
    assert!(jail::validate_explicit_name("").is_err());
    assert!(jail::validate_explicit_name(".").is_err());
    assert!(jail::validate_explicit_name("..").is_err());
    assert!(jail::validate_explicit_name("bad/name").is_err());
    assert!(jail::validate_explicit_name("unnamed-1234").is_err());
    assert!(jail::validate_explicit_name("white space").is_err());
}

#[test]
fn auto_jail_name_uses_reserved_prefix() {
    let name = jail::derive_auto_name("/tmp rw\n");
    assert!(name.starts_with(jail::AUTO_NAME_PREFIX));
    assert!(jail::is_generated_name(&name));
}

#[test]
fn cowjail_path_helpers_are_testable_without_process_home() {
    let home = Path::new("/tmp/cowjail-home");
    let layout = jail::layout_from_home(home);
    assert_eq!(
        jail::config_root_from_home(home),
        home.join(".config/cowjail")
    );
    assert_eq!(
        jail::state_root_from_home(home),
        home.join(".local/state/cowjail")
    );
    assert_eq!(
        profile_loader::default_record_dir_from_home(home),
        home.join(".cache/cowjail")
    );
    assert_eq!(
        jail::profile_definition_path_in(&layout, "default"),
        home.join(".config/cowjail/profiles/default")
    );
    assert_eq!(
        jail::jail_paths_in(&layout, "demo").record_path,
        home.join(".local/state/cowjail/demo/record")
    );
}

#[test]
fn resolve_in_can_materialize_generated_jail_without_global_home() {
    let temp = tempdir().expect("tempdir");
    let mut layout = jail::layout_from_home(temp.path());
    layout.runtime_root = temp.path().join("run");
    let profile_path = temp.path().join("test.profile");
    fs::write(&profile_path, ". rw\n/tmp ro\n").expect("write profile");

    let resolved = jail::resolve_in(
        &layout,
        None,
        Some(profile_path.to_str().expect("utf-8 path")),
        jail::ResolveMode::EnsureExists,
    )
    .expect("resolve generated jail");

    assert!(resolved.generated);
    assert!(resolved.name.starts_with(jail::AUTO_NAME_PREFIX));
    assert_eq!(
        fs::read_to_string(&resolved.paths.profile_path).expect("read stored profile"),
        resolved.normalized_profile
    );
    assert!(resolved.paths.record_path.exists());
    assert_eq!(
        resolved.paths.runtime_dir,
        layout.runtime_root.join(&resolved.name)
    );
}

#[test]
fn remove_jail_can_follow_profile_selected_generated_identity() {
    let temp = tempdir().expect("tempdir");
    let mut layout = jail::layout_from_home(temp.path());
    layout.runtime_root = temp.path().join("run");
    let profile_path = temp.path().join("test.profile");
    fs::write(&profile_path, ". rw\n/tmp ro\n").expect("write profile");
    let profile_arg = profile_path.to_str().expect("utf-8 path");

    let created = jail::resolve_in(
        &layout,
        None,
        Some(profile_arg),
        jail::ResolveMode::EnsureExists,
    )
    .expect("create generated jail");
    fs::create_dir_all(&created.paths.runtime_dir).expect("create runtime dir");

    let selected = jail::resolve_in(
        &layout,
        None,
        Some(profile_arg),
        jail::ResolveMode::MustExist,
    )
    .expect("reselect generated jail");
    assert_eq!(selected.name, created.name);

    jail::remove_jail(&selected.paths).expect("remove jail");
    assert!(!selected.paths.state_dir.exists());
    assert!(!selected.paths.runtime_dir.exists());
}

#[test]
fn resolve_in_rejects_rebinding_existing_named_jail_to_different_profile() {
    let temp = tempdir().expect("tempdir");
    let mut layout = jail::layout_from_home(temp.path());
    layout.runtime_root = temp.path().join("run");
    let profile_a = temp.path().join("a.profile");
    let profile_b = temp.path().join("b.profile");
    fs::write(&profile_a, ". rw\n/tmp ro\n").expect("write profile a");
    fs::write(&profile_b, ". rw\n/etc ro\n").expect("write profile b");

    jail::resolve_in(
        &layout,
        Some("demo"),
        Some(profile_a.to_str().expect("utf-8 path")),
        jail::ResolveMode::EnsureExists,
    )
    .expect("create named jail");

    let err = jail::resolve_in(
        &layout,
        Some("demo"),
        Some(profile_b.to_str().expect("utf-8 path")),
        jail::ResolveMode::EnsureExists,
    )
    .expect_err("rebind should fail");
    assert!(err.to_string().contains("bound to a different profile"));
}

#[test]
fn ns_runtime_paths_track_runtime_layout() {
    let home = Path::new("/tmp/cowjail-home");
    let mut layout = jail::layout_from_home(home);
    layout.runtime_root = Path::new("/run/cowjail-test").to_path_buf();

    let jail_paths = jail::jail_paths_in(&layout, "demo");
    let runtime = ns_runtime::paths_for(&jail_paths);

    assert_eq!(runtime.runtime_dir, Path::new("/run/cowjail-test/demo"));
    assert_eq!(
        runtime.mntns_path,
        Path::new("/run/cowjail-test/demo/mntns")
    );
    assert_eq!(
        runtime.ipcns_path,
        Path::new("/run/cowjail-test/demo/ipcns")
    );
    assert_eq!(runtime.lock_path, Path::new("/run/cowjail-test/demo/lock"));
}

#[test]
fn ns_runtime_helpers_manage_temp_runtime_dir() {
    let temp = tempdir().expect("tempdir");
    let mut layout = jail::layout_from_home(temp.path());
    layout.runtime_root = temp.path().join("run");
    let jail_paths = jail::jail_paths_in(&layout, "demo");

    let before = ns_runtime::inspect(&jail_paths).expect("inspect before");
    assert!(!before.runtime_dir_exists);
    assert!(!before.mntns_exists);
    assert!(!before.ipcns_exists);
    assert!(!before.lock_exists);
    assert_eq!(
        ns_runtime::classify(&before),
        ns_runtime::RuntimeState::Missing
    );

    let runtime = ns_runtime::ensure_runtime_dir(&jail_paths).expect("ensure runtime dir");
    assert!(runtime.runtime_dir.exists());

    let lock = ns_runtime::open_lock(&jail_paths).expect("open lock");
    let after = ns_runtime::inspect(&jail_paths).expect("inspect after");
    assert!(after.runtime_dir_exists);
    assert!(after.lock_exists);
    assert!(!after.mntns_exists);
    assert!(!after.ipcns_exists);
    assert_eq!(
        ns_runtime::classify(&after),
        ns_runtime::RuntimeState::SkeletonOnly
    );
    assert_eq!(lock.path(), runtime.lock_path.as_path());

    drop(lock);
    ns_runtime::remove_runtime(&jail_paths).expect("remove runtime");
    let removed = ns_runtime::inspect(&jail_paths).expect("inspect removed");
    assert!(!removed.runtime_dir_exists);
    assert!(!removed.lock_exists);
    assert_eq!(
        ns_runtime::classify(&removed),
        ns_runtime::RuntimeState::Missing
    );
}

#[test]
fn ns_runtime_lock_is_exclusive() {
    let temp = tempdir().expect("tempdir");
    let mut layout = jail::layout_from_home(temp.path());
    layout.runtime_root = temp.path().join("run");
    let jail_paths = jail::jail_paths_in(&layout, "demo");

    let first = ns_runtime::open_lock(&jail_paths).expect("first lock");
    let second = ns_runtime::try_open_lock(&jail_paths).expect("second open");
    assert!(second.is_none());

    drop(first);

    let third = ns_runtime::try_open_lock(&jail_paths).expect("third open");
    assert!(third.is_some());
}

#[test]
fn ns_runtime_ensure_skeleton_creates_runtime_dir_and_lock() {
    let temp = tempdir().expect("tempdir");
    let mut layout = jail::layout_from_home(temp.path());
    layout.runtime_root = temp.path().join("run");
    let jail_paths = jail::jail_paths_in(&layout, "demo");

    let status = ns_runtime::ensure_runtime_skeleton(&jail_paths).expect("ensure skeleton");
    assert!(status.runtime_dir_exists);
    assert!(status.lock_exists);
    assert!(!status.mntns_exists);
    assert!(!status.ipcns_exists);
    assert_eq!(
        ns_runtime::classify(&status),
        ns_runtime::RuntimeState::SkeletonOnly
    );
}

#[test]
fn ns_runtime_classify_detects_partial_and_ready_handles() {
    let temp = tempdir().expect("tempdir");
    let mut layout = jail::layout_from_home(temp.path());
    layout.runtime_root = temp.path().join("run");
    let jail_paths = jail::jail_paths_in(&layout, "demo");

    let _lock = ns_runtime::open_lock(&jail_paths).expect("open lock");
    fs::write(&jail_paths.mntns_path, b"mnt").expect("write mntns placeholder");
    let partial = ns_runtime::inspect(&jail_paths).expect("inspect partial");
    assert_eq!(
        ns_runtime::classify(&partial),
        ns_runtime::RuntimeState::PartialHandles
    );

    fs::write(&jail_paths.ipcns_path, b"ipc").expect("write ipcns placeholder");
    let ready = ns_runtime::inspect(&jail_paths).expect("inspect ready");
    assert_eq!(
        ns_runtime::classify(&ready),
        ns_runtime::RuntimeState::Ready
    );
}

#[test]
fn ns_runtime_ensure_runtime_with_builds_missing_runtime() {
    let temp = tempdir().expect("tempdir");
    let mut layout = jail::layout_from_home(temp.path());
    layout.runtime_root = temp.path().join("run");
    let jail_paths = jail::jail_paths_in(&layout, "demo");

    let ensured = ns_runtime::ensure_runtime_with(&jail_paths, |paths| {
        fs::write(&paths.mntns_path, b"mnt").expect("write mntns");
        fs::write(&paths.ipcns_path, b"ipc").expect("write ipcns");
        Ok(())
    })
    .expect("ensure runtime");

    assert_eq!(ensured.state_before, ns_runtime::RuntimeState::SkeletonOnly);
    assert_eq!(ensured.state_after, ns_runtime::RuntimeState::Ready);
    assert!(ensured.rebuilt);
}

#[test]
fn ns_runtime_ensure_runtime_with_reuses_ready_runtime() {
    let temp = tempdir().expect("tempdir");
    let mut layout = jail::layout_from_home(temp.path());
    layout.runtime_root = temp.path().join("run");
    let jail_paths = jail::jail_paths_in(&layout, "demo");

    let first = ns_runtime::ensure_runtime_with(&jail_paths, |paths| {
        fs::write(&paths.mntns_path, b"mnt").expect("write mntns");
        fs::write(&paths.ipcns_path, b"ipc").expect("write ipcns");
        Ok(())
    })
    .expect("first ensure");
    assert_eq!(first.state_after, ns_runtime::RuntimeState::Ready);

    let mut called = false;
    let second = ns_runtime::ensure_runtime_with(&jail_paths, |_| {
        called = true;
        Ok(())
    })
    .expect("second ensure");

    assert_eq!(second.state_before, ns_runtime::RuntimeState::Ready);
    assert_eq!(second.state_after, ns_runtime::RuntimeState::Ready);
    assert!(!second.rebuilt);
    assert!(!called);
}

#[test]
fn ns_runtime_ensure_runtime_with_repairs_partial_runtime() {
    let temp = tempdir().expect("tempdir");
    let mut layout = jail::layout_from_home(temp.path());
    layout.runtime_root = temp.path().join("run");
    let jail_paths = jail::jail_paths_in(&layout, "demo");

    let _ = ns_runtime::ensure_runtime_skeleton(&jail_paths).expect("ensure skeleton");
    fs::write(&jail_paths.mntns_path, b"stale-mnt").expect("write stale mntns");

    let ensured = ns_runtime::ensure_runtime_with(&jail_paths, |paths| {
        let mnt_before = fs::read(&paths.mntns_path).ok();
        assert!(mnt_before.is_none());
        fs::write(&paths.mntns_path, b"fresh-mnt").expect("write fresh mntns");
        fs::write(&paths.ipcns_path, b"fresh-ipc").expect("write fresh ipcns");
        Ok(())
    })
    .expect("repair runtime");

    assert_eq!(
        ensured.state_before,
        ns_runtime::RuntimeState::PartialHandles
    );
    assert_eq!(ensured.state_after, ns_runtime::RuntimeState::Ready);
    assert!(ensured.rebuilt);
    assert_eq!(
        fs::read(&jail_paths.mntns_path).expect("read repaired mntns"),
        b"fresh-mnt"
    );
}

#[test]
fn ns_runtime_ensure_placeholders_sets_ready_state() {
    let temp = tempdir().expect("tempdir");
    let mut layout = jail::layout_from_home(temp.path());
    layout.runtime_root = temp.path().join("run");
    let jail_paths = jail::jail_paths_in(&layout, "demo");

    let ensured =
        ns_runtime::ensure_runtime_placeholders(&jail_paths).expect("ensure placeholders");
    assert_eq!(ensured.state_before, ns_runtime::RuntimeState::SkeletonOnly);
    assert_eq!(ensured.state_after, ns_runtime::RuntimeState::Ready);
    assert!(ensured.rebuilt);
    assert!(jail_paths.mntns_path.exists());
    assert!(jail_paths.ipcns_path.exists());
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

    let stats = cmd_flush::flush_record(&path, true, None).expect("flush dry-run");
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

    let first = cmd_flush::flush_record(&path, false, None).expect("first flush");
    assert_eq!(first.pending, 1);
    assert_eq!(first.marked, 1);
    let bytes = fs::read(&out_path).expect("output should be written");
    assert_eq!(bytes, b"world");

    let second = cmd_flush::flush_record(&path, false, None).expect("second flush");
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

    let stats = cmd_flush::flush_record(&path, false, None).expect("flush");
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

    let stats = cmd_flush::flush_record(&path, false, None).expect("flush");
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

    let stats = cmd_flush::flush_record(&path, false, None).expect("flush");
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

    let stats = cmd_flush::flush_record(&path, false, None).expect("flush");
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

    let stats = cmd_flush::flush_record(&path, false, None).expect("flush");
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

    let stats = cmd_flush::flush_record(&path, false, None).expect("flush");
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

    let stats = cmd_flush::flush_record(&path, false, None).expect("flush");
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

    let stats = cmd_flush::flush_record(&path, false, None).expect("flush");
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

    let first = cmd_flush::flush_record(&path, false, None).expect("flush blocked");
    assert_eq!(first.blocked, 1);
    assert_eq!(first.marked, 0);

    let override_profile =
        temp_profile_path("profile-override", &format!("{} rw\n", target.display()));
    let override_profile_str = override_profile.to_string_lossy().to_string();
    let second = cmd_flush::flush_record(&path, false, Some(&override_profile_str))
        .expect("flush with override");
    assert_eq!(second.blocked, 0);
    assert_eq!(second.marked, 1);
    assert_eq!(fs::read(&target).expect("read target"), b"allowed");
}

#[test]
fn load_profile_uses_builtin_default_profile() {
    let loaded = profile_loader::load_profile(Path::new(cli::DEFAULT_PROFILE))
        .expect("load builtin default");
    assert_eq!(
        loaded.profile.first_match_action(Path::new("/bin/sh")),
        Some(profile::RuleAction::ReadOnly)
    );
    assert_eq!(
        loaded.profile.first_match_action(Path::new("/tmp")),
        Some(profile::RuleAction::ReadWrite)
    );
}

#[cfg(unix)]
#[test]
fn flush_regular_write_replaces_existing_symlink_instead_of_following_it() {
    use std::os::unix::fs as unix_fs;

    let temp = tempdir().expect("tempdir");
    let record = temp.path().join("record.cjr");
    let real_target = temp.path().join("real-target.txt");
    let link_path = temp.path().join("link.txt");
    fs::write(&real_target, b"host-target").expect("seed target");
    unix_fs::symlink(&real_target, &link_path).expect("seed symlink");

    let writer = record::Writer::open_append(&record).expect("writer open");
    writer
        .append_cbor(
            record::TAG_WRITE_OP,
            &op::Operation::WriteFile {
                path: link_path.clone(),
                state: op::FileState::Regular(b"replacement".to_vec()),
            },
        )
        .expect("append write");
    writer.sync().expect("sync");

    let stats = cmd_flush::flush_record(&record, false, None).expect("flush");
    assert_eq!(stats.marked, 1);
    assert_eq!(
        fs::read(&link_path).expect("read replaced file"),
        b"replacement"
    );
    assert_eq!(
        fs::read(&real_target).expect("read original target"),
        b"host-target"
    );
    assert!(
        !fs::symlink_metadata(&link_path)
            .expect("metadata")
            .file_type()
            .is_symlink()
    );
}

#[cfg(unix)]
#[test]
fn flush_symlink_write_replaces_existing_regular_file() {
    let temp = tempdir().expect("tempdir");
    let record = temp.path().join("record.cjr");
    let real_target = temp.path().join("real-target.txt");
    let link_path = temp.path().join("link.txt");
    fs::write(&real_target, b"target").expect("seed target");
    fs::write(&link_path, b"old-file").expect("seed file");

    let writer = record::Writer::open_append(&record).expect("writer open");
    writer
        .append_cbor(
            record::TAG_WRITE_OP,
            &op::Operation::WriteFile {
                path: link_path.clone(),
                state: op::FileState::Symlink(real_target.clone()),
            },
        )
        .expect("append write");
    writer.sync().expect("sync");

    let stats = cmd_flush::flush_record(&record, false, None).expect("flush");
    assert_eq!(stats.marked, 1);
    assert!(
        fs::symlink_metadata(&link_path)
            .expect("metadata")
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read_link(&link_path).expect("read link"), real_target);
}

#[test]
fn flush_rename_to_blocked_target_is_rejected() {
    let temp = tempdir().expect("tempdir");
    let record = temp.path().join("record.cjr");
    let from = temp.path().join("from.txt");
    let to = temp.path().join("to.txt");
    fs::write(&from, b"rename-me").expect("seed source");

    let writer = record::Writer::open_append(&record).expect("writer open");
    let header = ProfileHeaderFrame {
        normalized_profile: format!("{} rw\n{} ro\n", from.display(), to.display()),
    };
    writer
        .append_cbor(record::TAG_PROFILE_HEADER, &header)
        .expect("append header");
    writer
        .append_cbor(
            record::TAG_WRITE_OP,
            &op::Operation::Rename {
                from: from.clone(),
                to: to.clone(),
            },
        )
        .expect("append rename");
    writer.sync().expect("sync");

    let stats = cmd_flush::flush_record(&record, false, None).expect("flush");
    assert_eq!(stats.pending, 1);
    assert_eq!(stats.blocked, 1);
    assert_eq!(stats.marked, 0);
    assert!(from.exists());
    assert!(!to.exists());
}

#[test]
fn flush_regular_write_into_existing_directory_fails_without_marking() {
    let temp = tempdir().expect("tempdir");
    let record = temp.path().join("record.cjr");
    let target_dir = temp.path().join("target");
    fs::create_dir_all(&target_dir).expect("mkdir");

    let writer = record::Writer::open_append(&record).expect("writer open");
    writer
        .append_cbor(
            record::TAG_WRITE_OP,
            &op::Operation::WriteFile {
                path: target_dir.clone(),
                state: op::FileState::Regular(b"replacement".to_vec()),
            },
        )
        .expect("append write");
    writer.sync().expect("sync");

    let err = cmd_flush::flush_record(&record, false, None).expect_err("flush should fail");
    assert!(
        err.to_string()
            .contains("refusing to replace directory with regular file")
    );
    assert!(target_dir.is_dir());
    let frames = record::read_frames(&record).expect("read frames");
    assert!(!frames[0].flushed);
}

#[cfg(unix)]
#[test]
fn flush_symlink_write_into_existing_directory_fails_without_marking() {
    let temp = tempdir().expect("tempdir");
    let record = temp.path().join("record.cjr");
    let target_dir = temp.path().join("target");
    let symlink_target = temp.path().join("real-target.txt");
    fs::create_dir_all(&target_dir).expect("mkdir");
    fs::write(&symlink_target, b"payload").expect("seed target");

    let writer = record::Writer::open_append(&record).expect("writer open");
    writer
        .append_cbor(
            record::TAG_WRITE_OP,
            &op::Operation::WriteFile {
                path: target_dir.clone(),
                state: op::FileState::Symlink(symlink_target),
            },
        )
        .expect("append write");
    writer.sync().expect("sync");

    let err = cmd_flush::flush_record(&record, false, None).expect_err("flush should fail");
    assert!(
        err.to_string()
            .contains("refusing to replace directory with symlink")
    );
    assert!(target_dir.is_dir());
    let frames = record::read_frames(&record).expect("read frames");
    assert!(!frames[0].flushed);
}

#[test]
fn flush_rename_over_non_empty_directory_fails_without_marking() {
    let temp = tempdir().expect("tempdir");
    let record = temp.path().join("record.cjr");
    let from = temp.path().join("from.txt");
    let target_dir = temp.path().join("target-dir");
    let child = target_dir.join("child.txt");
    fs::write(&from, b"rename-me").expect("seed source");
    fs::create_dir_all(&target_dir).expect("mkdir");
    fs::write(&child, b"keep").expect("seed child");

    let writer = record::Writer::open_append(&record).expect("writer open");
    writer
        .append_cbor(
            record::TAG_WRITE_OP,
            &op::Operation::Rename {
                from: from.clone(),
                to: target_dir.clone(),
            },
        )
        .expect("append rename");
    writer.sync().expect("sync");

    let err = cmd_flush::flush_record(&record, false, None).expect_err("flush should fail");
    assert!(
        err.to_string().contains("failed to rename")
            || err.to_string().contains("Is a directory")
            || err.to_string().contains("Directory not empty")
    );
    assert!(from.exists());
    assert!(target_dir.is_dir());
    assert!(child.exists());
    let frames = record::read_frames(&record).expect("read frames");
    assert!(!frames[0].flushed);
}

#[test]
fn flush_truncate_directory_fails_without_marking() {
    let temp = tempdir().expect("tempdir");
    let record = temp.path().join("record.cjr");
    let target_dir = temp.path().join("target");
    fs::create_dir_all(&target_dir).expect("mkdir");

    let writer = record::Writer::open_append(&record).expect("writer open");
    writer
        .append_cbor(
            record::TAG_WRITE_OP,
            &op::Operation::Truncate {
                path: target_dir.clone(),
                size: 1,
            },
        )
        .expect("append truncate");
    writer.sync().expect("sync");

    let err = cmd_flush::flush_record(&record, false, None).expect_err("flush should fail");
    assert!(
        err.to_string().contains("failed to open file for truncate")
            || err.to_string().contains("Is a directory")
    );
    assert!(target_dir.is_dir());
    let frames = record::read_frames(&record).expect("read frames");
    assert!(!frames[0].flushed);
}

#[test]
fn flush_remove_dir_on_regular_file_fails_without_marking() {
    let temp = tempdir().expect("tempdir");
    let record = temp.path().join("record.cjr");
    let target_file = temp.path().join("target");
    fs::write(&target_file, b"keep").expect("seed file");

    let writer = record::Writer::open_append(&record).expect("writer open");
    writer
        .append_cbor(
            record::TAG_WRITE_OP,
            &op::Operation::RemoveDir {
                path: target_file.clone(),
            },
        )
        .expect("append rmdir");
    writer.sync().expect("sync");

    let err = cmd_flush::flush_record(&record, false, None).expect_err("flush should fail");
    assert!(
        err.to_string().contains("failed to remove directory")
            || err.to_string().contains("Not a directory")
    );
    assert!(target_file.is_file());
    let frames = record::read_frames(&record).expect("read frames");
    assert!(!frames[0].flushed);
}

#[test]
fn flush_create_dir_on_existing_file_fails_without_marking() {
    let temp = tempdir().expect("tempdir");
    let record = temp.path().join("record.cjr");
    let target_file = temp.path().join("target");
    fs::write(&target_file, b"keep").expect("seed file");

    let writer = record::Writer::open_append(&record).expect("writer open");
    writer
        .append_cbor(
            record::TAG_WRITE_OP,
            &op::Operation::CreateDir {
                path: target_file.clone(),
            },
        )
        .expect("append mkdir");
    writer.sync().expect("sync");

    let err = cmd_flush::flush_record(&record, false, None).expect_err("flush should fail");
    assert!(
        err.to_string().contains("failed to create directory")
            || err.to_string().contains("File exists")
    );
    assert!(target_file.is_file());
    let frames = record::read_frames(&record).expect("read frames");
    assert!(!frames[0].flushed);
}

#[cfg(unix)]
#[test]
fn flush_delete_on_symlink_removes_link_not_target() {
    use std::os::unix::fs as unix_fs;

    let temp = tempdir().expect("tempdir");
    let record = temp.path().join("record.cjr");
    let real_target = temp.path().join("real-target.txt");
    let link_path = temp.path().join("link.txt");
    fs::write(&real_target, b"keep-target").expect("seed target");
    unix_fs::symlink(&real_target, &link_path).expect("seed symlink");

    let writer = record::Writer::open_append(&record).expect("writer open");
    writer
        .append_cbor(
            record::TAG_WRITE_OP,
            &op::Operation::WriteFile {
                path: link_path.clone(),
                state: op::FileState::Deleted,
            },
        )
        .expect("append delete");
    writer.sync().expect("sync");

    let stats = cmd_flush::flush_record(&record, false, None).expect("flush");
    assert_eq!(stats.marked, 1);
    assert!(!link_path.exists());
    assert_eq!(
        fs::read(&real_target).expect("read original target"),
        b"keep-target"
    );
}

#[cfg(unix)]
#[test]
fn flush_truncate_on_symlink_fails_without_marking_or_modifying_target() {
    use std::os::unix::fs as unix_fs;

    let temp = tempdir().expect("tempdir");
    let record = temp.path().join("record.cjr");
    let real_target = temp.path().join("real-target.txt");
    let link_path = temp.path().join("link.txt");
    fs::write(&real_target, b"abcdef").expect("seed target");
    unix_fs::symlink(&real_target, &link_path).expect("seed symlink");

    let writer = record::Writer::open_append(&record).expect("writer open");
    writer
        .append_cbor(
            record::TAG_WRITE_OP,
            &op::Operation::Truncate {
                path: link_path.clone(),
                size: 3,
            },
        )
        .expect("append truncate");
    writer.sync().expect("sync");

    let err = cmd_flush::flush_record(&record, false, None).expect_err("flush should fail");
    assert!(
        err.to_string().contains("refusing to truncate symlink")
            || err.to_string().contains("failed to open file for truncate")
    );
    assert!(
        fs::symlink_metadata(&link_path)
            .expect("metadata")
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        fs::read(&real_target).expect("read original target"),
        b"abcdef"
    );
    let frames = record::read_frames(&record).expect("read frames");
    assert!(!frames[0].flushed);
}

#[cfg(unix)]
#[test]
fn flush_rename_over_symlink_replaces_link_not_target() {
    use std::os::unix::fs as unix_fs;

    let temp = tempdir().expect("tempdir");
    let record = temp.path().join("record.cjr");
    let from = temp.path().join("from.txt");
    let symlink_target = temp.path().join("real-target.txt");
    let link_path = temp.path().join("link.txt");
    fs::write(&from, b"rename-me").expect("seed source");
    fs::write(&symlink_target, b"keep-target").expect("seed target");
    unix_fs::symlink(&symlink_target, &link_path).expect("seed symlink");

    let writer = record::Writer::open_append(&record).expect("writer open");
    writer
        .append_cbor(
            record::TAG_WRITE_OP,
            &op::Operation::Rename {
                from: from.clone(),
                to: link_path.clone(),
            },
        )
        .expect("append rename");
    writer.sync().expect("sync");

    let stats = cmd_flush::flush_record(&record, false, None).expect("flush");
    assert_eq!(stats.marked, 1);
    assert!(!from.exists());
    assert_eq!(
        fs::read(&link_path).expect("read renamed file"),
        b"rename-me"
    );
    assert_eq!(
        fs::read(&symlink_target).expect("read original target"),
        b"keep-target"
    );
    assert!(
        !fs::symlink_metadata(&link_path)
            .expect("metadata")
            .file_type()
            .is_symlink()
    );
}

#[cfg(unix)]
#[test]
fn flush_rename_into_symlink_parent_fails_without_marking_or_modifying_target_tree() {
    use std::os::unix::fs as unix_fs;

    let temp = tempdir().expect("tempdir");
    let record = temp.path().join("record.cjr");
    let from = temp.path().join("from.txt");
    let real_dir = temp.path().join("real-dir");
    let symlink_dir = temp.path().join("link-dir");
    let redirected_target = real_dir.join("renamed.txt");
    fs::write(&from, b"rename-me").expect("seed source");
    fs::create_dir_all(&real_dir).expect("mkdir");
    unix_fs::symlink(&real_dir, &symlink_dir).expect("seed dir symlink");

    let writer = record::Writer::open_append(&record).expect("writer open");
    writer
        .append_cbor(
            record::TAG_WRITE_OP,
            &op::Operation::Rename {
                from: from.clone(),
                to: symlink_dir.join("renamed.txt"),
            },
        )
        .expect("append rename");
    writer.sync().expect("sync");

    let err = cmd_flush::flush_record(&record, false, None).expect_err("flush should fail");
    assert!(
        err.to_string()
            .contains("refusing to create rename target under symlink parent")
            || err
                .to_string()
                .contains("failed to create parent directories for rename target")
    );
    assert!(from.exists());
    assert!(
        fs::symlink_metadata(&symlink_dir)
            .expect("metadata")
            .file_type()
            .is_symlink()
    );
    assert!(!redirected_target.exists());
    let frames = record::read_frames(&record).expect("read frames");
    assert!(!frames[0].flushed);
}
