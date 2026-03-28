use super::{temp_profile_path, temp_record_path};
use crate::profile_loader::ProfileHeaderFrame;
use crate::{cli, cmd_flush, op, profile, profile_loader, record};
use fs_err as fs;
use std::path::Path;
use tempfile::tempdir;

#[test]
fn flush_dry_run_does_not_mark() {
    let (_path_root, path) = temp_record_path("dry-run");
    let (_target_root, target) = temp_record_path("target");
    let writer = record::Writer::open_append(&path).expect("writer open");
    let op = op::Operation::WriteFile {
        path: target,
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
    let (_path_root, path) = temp_record_path("mark");
    let (_out_root, out_path) = temp_record_path("write-target");
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
    let (_path_root, path) = temp_record_path("rename-record");
    let (_from_root, from) = temp_record_path("rename-from");
    let (_to_root, to) = temp_record_path("rename-to");
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
    let (_path_root, path) = temp_record_path("truncate-record");
    let (_target_root, target) = temp_record_path("truncate-target");
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
    let (_path_root, path) = temp_record_path("create-remove-record");
    let (dir_root, _dir_marker_path) = temp_record_path("ops-dir");
    let dir = dir_root.path().join("ops-dir");
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

    let (_path_root, path) = temp_record_path("chmod-record");
    let (_target_root, target) = temp_record_path("chmod-target");
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
    let (_path_root, path) = temp_record_path("symlink-record");
    let (dir_root, _dir_marker_path) = temp_record_path("symlink-dir");
    let dir = dir_root.path().join("symlink-dir");
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
    let (_path_root, path) = temp_record_path("compact-delete-record");
    let (_target_root, target) = temp_record_path("compact-delete-target");
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
    let (_path_root, path) = temp_record_path("compact-rename-boundary-record");
    let (_a_root, a) = temp_record_path("compact-rename-a");
    let (_b_root, b) = temp_record_path("compact-rename-b");
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
    let (_path_root, path) = temp_record_path("profile-block-record");
    let (_target_root, target) = temp_record_path("profile-block-target");
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
fn flush_profile_header_allows_cow_write_replay() {
    let (_path_root, path) = temp_record_path("profile-cow-allow-record");
    let (_target_root, target) = temp_record_path("profile-cow-allow-target");
    let writer = record::Writer::open_append(&path).expect("writer open");

    let header = ProfileHeaderFrame {
        normalized_profile: format!("{} cow\n", target.display()),
    };
    writer
        .append_cbor(record::TAG_PROFILE_HEADER, &header)
        .expect("append header");
    writer
        .append_cbor(
            record::TAG_WRITE_OP,
            &op::Operation::WriteFile {
                path: target.clone(),
                state: op::FileState::Regular(b"cow-ok".to_vec()),
            },
        )
        .expect("append write");
    writer.sync().expect("sync");

    let stats = cmd_flush::flush_record(&path, false, None).expect("flush");
    assert_eq!(stats.pending, 1);
    assert_eq!(stats.blocked, 0);
    assert_eq!(stats.marked, 1);
    assert_eq!(fs::read(&target).expect("read target"), b"cow-ok");
}

#[test]
fn flush_profile_header_blocks_rw_passthrough_replay() {
    let (_path_root, path) = temp_record_path("profile-rw-block-record");
    let (_target_root, target) = temp_record_path("profile-rw-block-target");
    let writer = record::Writer::open_append(&path).expect("writer open");

    let header = ProfileHeaderFrame {
        normalized_profile: format!("{} rw\n", target.display()),
    };
    writer
        .append_cbor(record::TAG_PROFILE_HEADER, &header)
        .expect("append header");
    writer
        .append_cbor(
            record::TAG_WRITE_OP,
            &op::Operation::WriteFile {
                path: target.clone(),
                state: op::FileState::Regular(b"rw-blocked".to_vec()),
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
    let (_path_root, path) = temp_record_path("profile-override-record");
    let (_target_root, target) = temp_record_path("profile-override-target");
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

    let (_profile_root, override_profile) =
        temp_profile_path("profile-override", &format!("{} cow\n", target.display()));
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
        Some(profile::RuleAction::Passthrough)
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
        normalized_profile: format!("{} cow\n{} ro\n", from.display(), to.display()),
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

#[cfg(unix)]
#[test]
fn flush_blocks_write_when_parent_not_owned_by_current_user() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }

    let temp = tempdir().expect("tempdir");
    let record = temp.path().join("record.cjr");
    let blocked_target = Path::new("/etc/cowjail-flush-owner-check-target");

    let writer = record::Writer::open_append(&record).expect("writer open");
    writer
        .append_cbor(
            record::TAG_WRITE_OP,
            &op::Operation::WriteFile {
                path: blocked_target.to_path_buf(),
                state: op::FileState::Regular(b"blocked".to_vec()),
            },
        )
        .expect("append write");
    writer.sync().expect("sync");

    let stats = cmd_flush::flush_record(&record, false, None).expect("flush");
    assert_eq!(stats.pending, 1);
    assert_eq!(stats.blocked, 1);
    assert_eq!(stats.marked, 0);

    let frames = record::read_frames(&record).expect("read frames");
    assert!(!frames[0].flushed);
}
