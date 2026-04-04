use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use log::debug;

use crate::profile::{Action, Condition, Profile, Rule};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountPlanEntry {
    Bind { path: PathBuf, read_only: bool },
    Proc { read_only: bool },
    Sys { read_only: bool },
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

    retain_existing_bind_sources(&mut plan)?;
    validate_mount_conflicts(&plan, rules)?;
    Ok(plan)
}

fn append_tmp_mount(rules: &[Rule], plan: &mut Vec<MountPlanEntry>) -> Result<()> {
    let Some(rule) = rules.iter().find(|rule| rule.pattern == "/tmp") else {
        return Ok(());
    };
    if !rule.conditions.is_empty() {
        return Ok(());
    }
    let read_only = match rule.action {
        Action::ReadOnly => true,
        Action::ReadWrite => false,
        Action::Hide | Action::Deny => return Ok(()),
    };
    let tmp = Path::new("/tmp");
    for rule in rules {
        if rule.pattern == "/tmp" {
            continue;
        }
        let path = Path::new(&rule.pattern);
        if path.starts_with(tmp) {
            bail!("{}: rule conflicts with /tmp bind fast path", rule.pattern);
        }
        if matches!(rule.action, Action::ReadOnly | Action::ReadWrite)
            && rule.ancestor_glob.is_match(tmp)
        {
            bail!(
                "{}: implicit ancestor visibility conflicts with /tmp bind fast path",
                rule.pattern
            );
        }
    }
    plan.push(MountPlanEntry::Bind {
        path: tmp.to_path_buf(),
        read_only,
    });
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
        Action::Deny => bail!("{}: /proc only supports ro/rw/hide", rule.pattern),
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
        Action::Deny => bail!("{}: /sys only supports ro/rw/hide", rule.pattern),
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
        Action::Deny | Action::Hide => bail!("{}: /dev only supports ro/rw", rule.pattern),
    };

    plan.push(MountPlanEntry::Bind {
        path: PathBuf::from(&rule.pattern),
        read_only,
    });
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
        let MountPlanEntry::Bind { path, read_only } = entry else {
            retained.push(entry);
            continue;
        };
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                debug!("mount-plan: skip missing bind source {}", path.display());
                continue;
            }
            Err(err) => {
                return Err(err).with_context(|| {
                    format!("{}: /dev bind source is not accessible", path.display())
                });
            }
        };
        let kind = metadata.file_type();
        if !kind.is_char_device() && !kind.is_dir() {
            debug!(
                "mount-plan: skip non-bindable source {}",
                path.display()
            );
            continue;
        }
        retained.push(MountPlanEntry::Bind { path, read_only });
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
            Self::Bind { path, .. } => Some(path),
            Self::Proc { .. } => Some(Path::new("/proc")),
            Self::Sys { .. } => Some(Path::new("/sys")),
        }
    }

    pub fn read_only(&self) -> bool {
        match self {
            Self::Bind { read_only, .. } | Self::Proc { read_only } | Self::Sys { read_only } => {
                *read_only
            }
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
            vec![MountPlanEntry::Bind {
                path: PathBuf::from("/dev/pts"),
                read_only: false,
            }]
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
    fn missing_dev_bind_source_is_skipped() {
        let profile = profile_from("/dev/leash2-definitely-missing-node rw\n/proc ro\n");
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
