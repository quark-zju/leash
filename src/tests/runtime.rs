use crate::{jail, ns_runtime, proc_mounts, profile};
use fs_err as fs;
use std::path::Path;
use tempfile::tempdir;

#[test]
fn explicit_jail_name_validation_rejects_reserved_and_invalid_names() {
    jail::validate_explicit_name("good-name_1.2").expect("valid name");
    jail::validate_explicit_name("0123456789abcdef").expect("hex name remains valid");
    assert!(jail::validate_explicit_name("").is_err());
    assert!(jail::validate_explicit_name(".").is_err());
    assert!(jail::validate_explicit_name("..").is_err());
    assert!(jail::validate_explicit_name("bad/name").is_err());
    assert!(jail::validate_explicit_name("white space").is_err());
}

#[test]
fn auto_jail_name_is_stable_hex() {
    let name = jail::derive_auto_name("/tmp rw\n");
    assert_eq!(name.len(), 16);
    assert!(name.bytes().all(|b| b.is_ascii_hexdigit()));
}

#[test]
fn leash_path_helpers_are_testable_without_process_home() {
    let home = Path::new("/tmp/leash-home");
    let layout = jail::layout_from_home(home);
    assert_eq!(
        jail::config_root_from_home(home),
        home.join(".config/leash")
    );
    assert_eq!(
        jail::state_root_from_home(home),
        jail::runtime_root().join("state")
    );
    assert_eq!(
        jail::profile_definition_path_in(&layout, "default"),
        home.join(".config/leash/profiles/default")
    );
}

#[test]
fn resolve_in_can_materialize_generated_jail_without_global_home() {
    let temp = tempdir().expect("tempdir");
    let mut layout = jail::layout_from_home(temp.path());
    layout.runtime_root = temp.path().join("run");
    layout.state_root = layout.runtime_root.join("state");
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
    assert_eq!(resolved.name.len(), 16);
    assert_eq!(
        fs::read_to_string(&resolved.paths.profile_path).expect("read stored profile"),
        resolved.normalized_profile
    );
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
    layout.state_root = layout.runtime_root.join("state");
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
fn resolve_in_must_exist_does_not_create_generated_jail_for_profile_selector() {
    let temp = tempdir().expect("tempdir");
    let mut layout = jail::layout_from_home(temp.path());
    layout.runtime_root = temp.path().join("run");
    layout.state_root = layout.runtime_root.join("state");
    let profile_path = temp.path().join("test.profile");
    fs::write(&profile_path, ". rw\n/tmp ro\n").expect("write profile");
    let profile_arg = profile_path.to_str().expect("utf-8 path");
    let expected_name = jail::derive_auto_name(". rw\n/tmp ro\n");

    let err = jail::resolve_in(
        &layout,
        None,
        Some(profile_arg),
        jail::ResolveMode::MustExist,
    )
    .expect_err("must-exist resolve should fail without creating");
    assert!(err.to_string().contains("jail does not exist"));
    assert!(!layout.state_root.join(&expected_name).exists());
    assert!(!layout.runtime_root.join(&expected_name).exists());
}

#[test]
fn resolve_in_rejects_rebinding_existing_named_jail_to_different_profile() {
    let temp = tempdir().expect("tempdir");
    let mut layout = jail::layout_from_home(temp.path());
    layout.runtime_root = temp.path().join("run");
    layout.state_root = layout.runtime_root.join("state");
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
    let home = Path::new("/tmp/leash-home");
    let mut layout = jail::layout_from_home(home);
    layout.runtime_root = Path::new("/run/leash-test").to_path_buf();
    layout.state_root = layout.runtime_root.join("state");

    let jail_paths = jail::jail_paths_in(&layout, "demo");
    let runtime = ns_runtime::paths_for(&jail_paths);

    assert_eq!(runtime.runtime_dir, Path::new("/run/leash-test/demo"));
    assert_eq!(runtime.mntns_path, Path::new("/run/leash-test/demo/mntns"));
    assert_eq!(runtime.ipcns_path, Path::new("/run/leash-test/demo/ipcns"));
    assert_eq!(runtime.lock_path, Path::new("/run/leash-test/demo/lock"));
}

#[test]
fn ns_runtime_helpers_manage_temp_runtime_dir() {
    let temp = tempdir().expect("tempdir");
    let mut layout = jail::layout_from_home(temp.path());
    layout.runtime_root = temp.path().join("run");
    layout.state_root = layout.runtime_root.join("state");
    let jail_paths = jail::jail_paths_in(&layout, "demo");

    let before = ns_runtime::inspect(&jail_paths).expect("inspect before");
    assert!(!before.runtime_dir_exists);
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
    assert_eq!(
        ns_runtime::classify(&after),
        ns_runtime::RuntimeState::Ready
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
    layout.state_root = layout.runtime_root.join("state");
    let jail_paths = jail::jail_paths_in(&layout, "demo");

    let first = ns_runtime::open_lock(&jail_paths).expect("first lock");
    let second = ns_runtime::try_open_lock(&jail_paths).expect("second open");
    assert!(second.is_none());

    drop(first);

    let third = ns_runtime::try_open_lock(&jail_paths).expect("third open");
    assert!(third.is_some());
}

#[test]
fn proc_mount_coverage_matches_profile_monitor_patterns() {
    let mounts = vec![
        proc_mounts::MountEntry {
            mount_point: Path::new("/").to_path_buf(),
            fs_type: "ext4".to_string(),
            source: "/dev/root".to_string(),
        },
        proc_mounts::MountEntry {
            mount_point: Path::new("/work").to_path_buf(),
            fs_type: "ext4".to_string(),
            source: "/dev/root".to_string(),
        },
        proc_mounts::MountEntry {
            mount_point: Path::new("/work/foo").to_path_buf(),
            fs_type: "bind".to_string(),
            source: "/dev/root".to_string(),
        },
        proc_mounts::MountEntry {
            mount_point: Path::new("/tmp").to_path_buf(),
            fs_type: "tmpfs".to_string(),
            source: "tmpfs".to_string(),
        },
    ];
    let patterns = profile::monitor_glob_patterns_for_normalized_source("/work/**/.git rw\n")
        .expect("monitor patterns");

    let covered = proc_mounts::covered_mount_points(&mounts, &patterns).expect("covered mounts");
    assert_eq!(
        covered,
        vec![
            Path::new("/").to_path_buf(),
            Path::new("/work").to_path_buf(),
            Path::new("/work/foo").to_path_buf(),
        ]
    );

    let uncovered =
        proc_mounts::uncovered_mount_points(&mounts, &patterns).expect("uncovered mounts");
    assert_eq!(uncovered, vec![Path::new("/tmp").to_path_buf()]);
}

#[test]
fn proc_mount_coverage_does_not_require_proc_when_profile_omits_it() {
    let mounts = vec![
        proc_mounts::MountEntry {
            mount_point: Path::new("/").to_path_buf(),
            fs_type: "ext4".to_string(),
            source: "/dev/root".to_string(),
        },
        proc_mounts::MountEntry {
            mount_point: Path::new("/proc").to_path_buf(),
            fs_type: "proc".to_string(),
            source: "proc".to_string(),
        },
    ];
    let patterns = profile::monitor_glob_patterns_for_normalized_source("/work rw\n")
        .expect("monitor patterns");
    let uncovered =
        proc_mounts::uncovered_mount_points(&mounts, &patterns).expect("uncovered mounts");
    assert_eq!(uncovered, vec![Path::new("/proc").to_path_buf()]);
}

#[test]
fn ns_runtime_ensure_skeleton_creates_runtime_dir_and_lock() {
    let temp = tempdir().expect("tempdir");
    let mut layout = jail::layout_from_home(temp.path());
    layout.runtime_root = temp.path().join("run");
    layout.state_root = layout.runtime_root.join("state");
    let jail_paths = jail::jail_paths_in(&layout, "demo");

    let status = ns_runtime::ensure_runtime_skeleton(&jail_paths).expect("ensure skeleton");
    assert!(status.runtime_dir_exists);
    assert!(status.lock_exists);
    assert_eq!(
        ns_runtime::classify(&status),
        ns_runtime::RuntimeState::Ready
    );
}

#[test]
fn ns_runtime_classify_detects_partial_and_ready_handles() {
    let temp = tempdir().expect("tempdir");
    let mut layout = jail::layout_from_home(temp.path());
    layout.runtime_root = temp.path().join("run");
    layout.state_root = layout.runtime_root.join("state");
    let jail_paths = jail::jail_paths_in(&layout, "demo");

    let _lock = ns_runtime::open_lock(&jail_paths).expect("open lock");
    fs::write(&jail_paths.ipcns_path, b"ipc").expect("write ipcns placeholder");
    let partial = ns_runtime::inspect(&jail_paths).expect("inspect partial");
    assert_eq!(
        ns_runtime::classify(&partial),
        ns_runtime::RuntimeState::Ready
    );
}

#[test]
fn ns_runtime_ensure_runtime_with_builds_missing_runtime() {
    let temp = tempdir().expect("tempdir");
    let mut layout = jail::layout_from_home(temp.path());
    layout.runtime_root = temp.path().join("run");
    layout.state_root = layout.runtime_root.join("state");
    let jail_paths = jail::jail_paths_in(&layout, "demo");

    let mut called = false;
    let ensured = ns_runtime::ensure_runtime_with(&jail_paths, |paths| {
        called = true;
        fs::write(&paths.ipcns_path, b"ipc").expect("write ipcns");
        Ok(())
    })
    .expect("ensure runtime");

    assert_eq!(ensured.state_before, ns_runtime::RuntimeState::Ready);
    assert_eq!(ensured.state_after, ns_runtime::RuntimeState::Ready);
    assert!(!ensured.rebuilt);
    assert!(!called);
}

#[test]
fn ns_runtime_ensure_runtime_with_reuses_ready_runtime() {
    let temp = tempdir().expect("tempdir");
    let mut layout = jail::layout_from_home(temp.path());
    layout.runtime_root = temp.path().join("run");
    layout.state_root = layout.runtime_root.join("state");
    let jail_paths = jail::jail_paths_in(&layout, "demo");

    let first = ns_runtime::ensure_runtime_with(&jail_paths, |paths| {
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
    layout.state_root = layout.runtime_root.join("state");
    let jail_paths = jail::jail_paths_in(&layout, "demo");

    let _ = ns_runtime::ensure_runtime_skeleton(&jail_paths).expect("ensure skeleton");
    fs::remove_file(&jail_paths.ipcns_path).ok();

    let ensured = ns_runtime::ensure_runtime_with(&jail_paths, |paths| {
        fs::write(&paths.ipcns_path, b"fresh-ipc").expect("write fresh ipcns");
        Ok(())
    })
    .expect("repair runtime");

    assert_eq!(ensured.state_before, ns_runtime::RuntimeState::Ready);
    assert_eq!(ensured.state_after, ns_runtime::RuntimeState::Ready);
    assert!(!ensured.rebuilt);
}

#[test]
fn ns_runtime_ensure_placeholders_sets_ready_state() {
    let temp = tempdir().expect("tempdir");
    let mut layout = jail::layout_from_home(temp.path());
    layout.runtime_root = temp.path().join("run");
    layout.state_root = layout.runtime_root.join("state");
    let jail_paths = jail::jail_paths_in(&layout, "demo");

    let ensured =
        ns_runtime::ensure_runtime_placeholders(&jail_paths).expect("ensure placeholders");
    assert_eq!(ensured.state_before, ns_runtime::RuntimeState::Ready);
    assert_eq!(ensured.state_after, ns_runtime::RuntimeState::Ready);
    assert!(!ensured.rebuilt);
}

#[test]
fn ns_runtime_ensure_runtime_for_exec_succeeds() {
    let temp = tempdir().expect("tempdir");
    let mut layout = jail::layout_from_home(temp.path());
    layout.runtime_root = temp.path().join("run");
    layout.state_root = layout.runtime_root.join("state");
    let jail_paths = jail::jail_paths_in(&layout, "demo");
    let runtime_paths = ns_runtime::ensure_runtime_dir(&jail_paths).expect("ensure runtime");
    let exec_runtime = ns_runtime::ensure_runtime_for_exec(&jail_paths).expect("ensure exec");
    assert_eq!(
        exec_runtime.ensured.paths.runtime_dir,
        runtime_paths.runtime_dir
    );
}
