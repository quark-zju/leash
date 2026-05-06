use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use log::debug;

use crate::profile::{Action, Condition, Profile, Rule, pattern_matches_implicit_ancestor};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountPlanEntry {
    Bind { path: PathBuf, read_only: bool },
    Tmpfs { path: PathBuf },
    Proc { read_only: bool },
    DevPts { path: PathBuf, read_only: bool },
    DevPtmx { path: PathBuf, read_only: bool },
}

pub fn build_mount_plan(profile: &Profile) -> Result<Vec<MountPlanEntry>> {
    let mut plan = Vec::new();
    let rules = profile.rules();

    for rule in rules {
        let path = Path::new(&rule.pattern);
        if path.starts_with("/proc") {
            append_proc_mount(rule, &mut plan)?;
        } else if path.starts_with("/sys") {
            append_sys_mount(rule, &mut plan)?;
        } else if path.starts_with("/dev") {
            append_dev_mount(rule, &mut plan)?;
        }
    }
    append_tmp_mount(rules, &mut plan)?;
    append_tmpfs_mounts(rules, &mut plan)?;

    retain_existing_bind_sources(&mut plan)?;
    reorder_pty_mounts(&mut plan);
    validate_mount_conflicts(&plan, rules)?;
    Ok(plan)
}

fn reorder_pty_mounts(plan: &mut Vec<MountPlanEntry>) {
    let mut first_ptmx = None;
    let mut first_pts = None;
    for (idx, entry) in plan.iter().enumerate() {
        match entry {
            MountPlanEntry::DevPts { .. } if first_pts.is_none() => first_pts = Some(idx),
            MountPlanEntry::DevPtmx { .. } if first_ptmx.is_none() => first_ptmx = Some(idx),
            _ => {}
        }
    }
    if let (Some(ptmx), Some(pts)) = (first_ptmx, first_pts)
        && pts > ptmx
    {
        plan.swap(pts, ptmx);
    }
}

fn append_tmp_mount(rules: &[Rule], plan: &mut Vec<MountPlanEntry>) -> Result<()> {
    append_bind_fast_path(rules, plan, Path::new("/tmp"), "/tmp bind fast path")
}

fn append_bind_fast_path(
    rules: &[Rule],
    plan: &mut Vec<MountPlanEntry>,
    root: &Path,
    label: &str,
) -> Result<()> {
    let Some(rule) = rules.iter().find(|rule| Path::new(&rule.pattern) == root) else {
        return Ok(());
    };
    if !rule.conditions.is_empty() {
        return Ok(());
    }
    let read_only = match rule.action {
        Action::ReadOnly => true,
        Action::ReadWrite => false,
        Action::Tmpfs | Action::Hide | Action::Deny => return Ok(()),
    };
    for rule in rules {
        let path = Path::new(&rule.pattern);
        if path == root {
            continue;
        }
        if path.starts_with(root) {
            bail!("{}: rule conflicts with {label}", rule.pattern);
        }
        if matches!(
            rule.action,
            Action::ReadOnly | Action::ReadWrite | Action::Tmpfs
        ) && pattern_matches_implicit_ancestor(&rule.pattern, root)
        {
            bail!(
                "{}: implicit ancestor visibility conflicts with {label}",
                rule.pattern
            );
        }
    }
    plan.push(MountPlanEntry::Bind {
        path: root.to_path_buf(),
        read_only,
    });
    Ok(())
}

fn append_tmpfs_mounts(rules: &[Rule], plan: &mut Vec<MountPlanEntry>) -> Result<()> {
    for rule in rules {
        if rule.action != Action::Tmpfs {
            continue;
        }
        reject_conditional_tmpfs_rule(rule)?;
        reject_glob_mount_rule(rule, "tmpfs")?;
        let path = Path::new(&rule.pattern);
        if !tmpfs_path_is_allowed(path) {
            bail!(
                "{}: tmpfs is only supported for /tmp and /run/user",
                rule.pattern
            );
        }
        reject_descendant_rules_for_mount_root(rules, path, "tmpfs mount")?;
        plan.push(MountPlanEntry::Tmpfs {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn reject_conditional_tmpfs_rule(rule: &Rule) -> Result<()> {
    if !rule.conditions.is_empty() {
        bail!("{}: tmpfs mount rules must be unconditional", rule.pattern);
    }
    Ok(())
}

fn tmpfs_path_is_allowed(path: &Path) -> bool {
    path == Path::new("/tmp") || path == Path::new("/run/user")
}

fn reject_descendant_rules_for_mount_root(rules: &[Rule], root: &Path, label: &str) -> Result<()> {
    for rule in rules {
        let path = Path::new(&rule.pattern);
        if path == root {
            continue;
        }
        if path.starts_with(root) {
            bail!(
                "{}: rule conflicts with {label} {}",
                rule.pattern,
                root.display()
            );
        }
        if matches!(
            rule.action,
            Action::ReadOnly | Action::ReadWrite | Action::Tmpfs
        ) && pattern_matches_implicit_ancestor(&rule.pattern, root)
        {
            bail!(
                "{}: implicit ancestor visibility conflicts with {label} {}",
                rule.pattern,
                root.display()
            );
        }
    }
    Ok(())
}

fn append_proc_mount(rule: &Rule, plan: &mut Vec<MountPlanEntry>) -> Result<()> {
    reject_conditional_mount_rule(rule)?;
    reject_glob_mount_rule(rule, "/proc")?;
    if rule.pattern != "/proc" {
        bail!("{}: /proc only allows the exact path /proc", rule.pattern);
    }
    match rule.action {
        Action::ReadOnly => plan.push(MountPlanEntry::Proc { read_only: true }),
        Action::ReadWrite => plan.push(MountPlanEntry::Proc { read_only: false }),
        Action::Hide => {}
        Action::Tmpfs | Action::Deny => {
            bail!("{}: /proc only supports ro/rw/hide", rule.pattern)
        }
    }
    Ok(())
}

fn append_sys_mount(rule: &Rule, plan: &mut Vec<MountPlanEntry>) -> Result<()> {
    let _ = plan;
    reject_conditional_mount_rule(rule)?;
    reject_glob_mount_rule(rule, "/sys")?;
    if rule.pattern != "/sys" {
        bail!("{}: /sys only allows the exact path /sys", rule.pattern);
    }
    match rule.action {
        Action::ReadOnly | Action::ReadWrite | Action::Hide => {}
        Action::Tmpfs | Action::Deny => bail!("{}: /sys only supports ro/rw/hide", rule.pattern),
    }
    Ok(())
}

fn append_dev_mount(rule: &Rule, plan: &mut Vec<MountPlanEntry>) -> Result<()> {
    reject_glob_mount_rule(rule, "/dev")?;
    for condition in &rule.conditions {
        if matches!(condition, Condition::AncestorHas(_)) {
            bail!(
                "{}: /dev mount rules do not support ancestor-has conditions",
                rule.pattern
            );
        }
        if matches!(condition, Condition::Exe(_) | Condition::Env(_)) {
            bail!(
                "{}: /dev mount rules must be unconditional because bind mounts are built before exec",
                rule.pattern
            );
        }
    }

    let read_only = match rule.action {
        Action::ReadOnly => true,
        Action::ReadWrite => false,
        Action::Tmpfs | Action::Deny | Action::Hide => {
            bail!("{}: /dev only supports ro/rw", rule.pattern)
        }
    };

    let path = PathBuf::from(&rule.pattern);
    if path == Path::new("/dev/pts") {
        plan.push(MountPlanEntry::DevPts { path, read_only });
    } else if path == Path::new("/dev/ptmx") {
        plan.push(MountPlanEntry::DevPtmx { path, read_only });
    } else {
        plan.push(MountPlanEntry::Bind { path, read_only });
    }
    Ok(())
}

fn reject_conditional_mount_rule(rule: &Rule) -> Result<()> {
    if !rule.conditions.is_empty() {
        bail!(
            "{}: /proc and /sys mount rules must be unconditional",
            rule.pattern
        );
    }
    Ok(())
}

fn reject_glob_mount_rule(rule: &Rule, root: &str) -> Result<()> {
    if has_glob_syntax(&rule.pattern) {
        bail!("{}: {root} rules do not allow glob patterns", rule.pattern);
    }
    Ok(())
}

fn validate_mount_conflicts(plan: &[MountPlanEntry], rules: &[Rule]) -> Result<()> {
    for mount_root in plan.iter().filter_map(MountPlanEntry::path) {
        for rule in rules {
            let path = Path::new(&rule.pattern);
            if path != mount_root && path.starts_with(mount_root) {
                bail!(
                    "{}: rule conflicts with mounted root {}",
                    rule.pattern,
                    mount_root.display()
                );
            }
        }
    }
    Ok(())
}

fn retain_existing_bind_sources(plan: &mut Vec<MountPlanEntry>) -> Result<()> {
    let mut retained = Vec::with_capacity(plan.len());
    for entry in plan.drain(..) {
        let (path, read_only, entry_kind) = match entry {
            MountPlanEntry::Bind { path, read_only } => (path, read_only, 0),
            MountPlanEntry::DevPts { path, read_only } => (path, read_only, 1),
            MountPlanEntry::DevPtmx { path, read_only } => (path, read_only, 2),
            other => {
                retained.push(other);
                continue;
            }
        };
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                debug!("mount-plan: skip missing bind source {}", path.display());
                continue;
            }
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("{}: bind source is not accessible", path.display()));
            }
        };
        let file_type = metadata.file_type();
        if !file_type.is_char_device() && !file_type.is_dir() {
            debug!("mount-plan: skip non-bindable source {}", path.display());
            continue;
        }
        match entry_kind {
            0 => retained.push(MountPlanEntry::Bind { path, read_only }),
            1 => retained.push(MountPlanEntry::DevPts { path, read_only }),
            _ => retained.push(MountPlanEntry::DevPtmx { path, read_only }),
        }
    }
    *plan = retained;
    Ok(())
}

fn has_glob_syntax(value: &str) -> bool {
    value.contains('*') || value.contains('?') || value.contains('[')
}

impl MountPlanEntry {
    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::Bind { path, .. }
            | Self::Tmpfs { path }
            | Self::DevPts { path, .. }
            | Self::DevPtmx { path, .. } => Some(path),
            Self::Proc { .. } => Some(Path::new("/proc")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{NoIncludes, PathExeResolver, parse};
    use std::os::unix::fs::symlink;
    use tempfile::tempdir;

    fn profile_from(src: &str) -> Profile {
        parse(
            src,
            Path::new("/home/tester"),
            Path::new("/tmp"),
            &NoIncludes,
            &PathExeResolver,
        )
        .expect("profile should parse")
    }

    #[test]
    fn proc_rule_builds_mount_entry_but_sys_rule_stays_in_fuse() {
        let profile = profile_from("/proc ro\n/sys rw\n");
        assert_eq!(
            build_mount_plan(&profile).expect("plan"),
            vec![MountPlanEntry::Proc { read_only: true }]
        );
    }

    #[test]
    fn hidden_proc_and_sys_rules_do_not_mount() {
        let profile = profile_from("/proc hide\n/sys hide\n");
        assert_eq!(build_mount_plan(&profile).expect("plan"), vec![]);
    }

    #[test]
    fn proc_and_sys_subpath_rules_are_rejected() {
        let err = build_mount_plan(&profile_from("/proc/self ro\n")).unwrap_err();
        assert!(err.to_string().contains("exact path /proc"), "{err:#}");

        let err = build_mount_plan(&profile_from("/sys/kernel ro\n")).unwrap_err();
        assert!(err.to_string().contains("exact path /sys"), "{err:#}");
    }

    #[test]
    fn proc_and_sys_conditional_rules_are_rejected() {
        let err = build_mount_plan(&profile_from("/proc ro when env=DEBUG\n")).unwrap_err();
        assert!(err.to_string().contains("must be unconditional"), "{err:#}");
    }

    #[test]
    fn dev_directory_rule_becomes_bind_mount() {
        let profile = profile_from("/dev/pts rw\n");
        assert_eq!(
            build_mount_plan(&profile).expect("plan"),
            vec![MountPlanEntry::DevPts {
                path: PathBuf::from("/dev/pts"),
                read_only: false,
            }]
        );
    }

    #[test]
    fn dev_pts_and_ptmx_rules_use_special_mount_entries_in_order() {
        let profile = profile_from("/dev/ptmx rw\n/dev/pts rw\n");
        assert_eq!(
            build_mount_plan(&profile).expect("plan"),
            vec![
                MountPlanEntry::DevPts {
                    path: PathBuf::from("/dev/pts"),
                    read_only: false,
                },
                MountPlanEntry::DevPtmx {
                    path: PathBuf::from("/dev/ptmx"),
                    read_only: false,
                },
            ]
        );
    }

    #[test]
    fn tmp_rule_becomes_bind_mount_when_unconditional_and_conflict_free() {
        let profile = profile_from("/tmp rw\n/proc ro\n");
        assert_eq!(
            build_mount_plan(&profile).expect("plan"),
            vec![
                MountPlanEntry::Proc { read_only: true },
                MountPlanEntry::Bind {
                    path: PathBuf::from("/tmp"),
                    read_only: false,
                },
            ]
        );
    }

    #[test]
    fn tmpfs_rules_become_tmpfs_mounts_when_unconditional_and_allowed() {
        let profile = profile_from("/tmp tmpfs\n/run/user tmpfs\n/proc ro\n");
        assert_eq!(
            build_mount_plan(&profile).expect("plan"),
            vec![
                MountPlanEntry::Proc { read_only: true },
                MountPlanEntry::Tmpfs {
                    path: PathBuf::from("/tmp"),
                },
                MountPlanEntry::Tmpfs {
                    path: PathBuf::from("/run/user"),
                },
            ]
        );
    }

    #[test]
    fn dev_mounts_are_planned_before_tmp_fast_path() {
        let profile = profile_from("/tmp rw\n/dev/null rw\n");
        assert_eq!(
            build_mount_plan(&profile).expect("plan"),
            vec![
                MountPlanEntry::Bind {
                    path: PathBuf::from("/dev/null"),
                    read_only: false,
                },
                MountPlanEntry::Bind {
                    path: PathBuf::from("/tmp"),
                    read_only: false,
                },
            ]
        );
    }

    #[test]
    fn conditional_tmp_rule_stays_in_fuse() {
        let profile = profile_from("/tmp rw when env=LEASH_TMP\n/proc ro\n");
        assert_eq!(
            build_mount_plan(&profile).expect("plan"),
            vec![MountPlanEntry::Proc { read_only: true }]
        );
    }

    #[test]
    fn tmp_bind_fast_path_rejects_descendant_rules() {
        let err = build_mount_plan(&profile_from("/tmp rw\n/tmp/cache ro\n")).unwrap_err();
        assert!(err.to_string().contains("/tmp bind fast path"), "{err:#}");
    }

    #[test]
    fn tmp_bind_fast_path_rejects_implicit_ancestor_rules() {
        let err = build_mount_plan(&profile_from("/tmp rw\n/**/secret.txt ro\n")).unwrap_err();
        assert!(
            err.to_string().contains("implicit ancestor visibility"),
            "{err:#}"
        );
    }

    #[test]
    fn tmpfs_rules_reject_conditions() {
        let err = build_mount_plan(&profile_from("/run/user tmpfs when env=LEASH_RUN_USER\n"))
            .unwrap_err();
        assert!(err.to_string().contains("must be unconditional"), "{err:#}");
    }

    #[test]
    fn tmpfs_rules_reject_unsupported_paths() {
        let err = build_mount_plan(&profile_from("/var/tmp tmpfs\n")).unwrap_err();
        assert!(err.to_string().contains("only supported"), "{err:#}");
    }

    #[test]
    fn tmpfs_rules_reject_descendant_rules() {
        let err =
            build_mount_plan(&profile_from("/run/user tmpfs\n/run/user/1000 ro\n")).unwrap_err();
        assert!(err.to_string().contains("tmpfs mount /run/user"), "{err:#}");
    }

    #[test]
    fn tmpfs_rules_reject_implicit_ancestor_rules() {
        let err =
            build_mount_plan(&profile_from("/run/user tmpfs\n/**/default.sock ro\n")).unwrap_err();
        assert!(
            err.to_string().contains("implicit ancestor visibility"),
            "{err:#}"
        );
    }

    #[test]
    fn missing_dev_bind_source_is_skipped() {
        let profile = profile_from("/dev/leash-definitely-missing-node rw\n/proc ro\n");
        assert_eq!(
            build_mount_plan(&profile).expect("plan"),
            vec![MountPlanEntry::Proc { read_only: true }]
        );
    }

    #[test]
    fn dev_symlink_source_is_skipped_without_following_target() {
        let profile = profile_from("/dev/stderr rw\n/proc ro\n");
        assert_eq!(
            build_mount_plan(&profile).expect("plan"),
            vec![MountPlanEntry::Proc { read_only: true }]
        );
    }

    #[test]
    fn dev_symlink_rule_is_rejected() {
        let dir = tempdir().expect("tempdir");
        let link = dir.path().join("tty-link");
        symlink("/dev/null", &link).expect("symlink");

        let profile = profile_from(&format!("{} ro\n", link.display()));
        assert_eq!(build_mount_plan(&profile).expect("plan"), vec![]);
    }

    #[test]
    fn dev_glob_rules_are_rejected() {
        let err = build_mount_plan(&profile_from("/dev/tty* rw\n")).unwrap_err();
        assert!(err.to_string().contains("glob patterns"), "{err:#}");
    }

    #[test]
    fn dev_ancestor_has_rules_are_rejected() {
        let err =
            build_mount_plan(&profile_from("/dev/pts rw when ancestor-has=.git\n")).unwrap_err();
        assert!(err.to_string().contains("ancestor-has"), "{err:#}");
    }

    #[test]
    fn dev_deny_rules_are_rejected() {
        let err = build_mount_plan(&profile_from("/dev/null deny\n")).unwrap_err();
        assert!(
            err.to_string().contains("/dev only supports ro/rw"),
            "{err:#}"
        );
    }

    #[test]
    fn mounted_root_rejects_descendant_rules() {
        let err = build_mount_plan(&profile_from("/proc ro\n/proc/self ro\n")).unwrap_err();
        assert!(err.to_string().contains("exact path /proc"), "{err:#}");
    }

    #[test]
    fn dev_bind_root_rejects_descendant_rules() {
        let err = build_mount_plan(&profile_from("/dev/pts rw\n/dev/pts/0 ro\n")).unwrap_err();
        assert!(err.to_string().contains("mounted root /dev/pts"), "{err:#}");
    }
}
