use crate::profile::{self, RuleAction};
use anyhow::{Result, bail};
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MountPlanEntry {
    Bind { path: PathBuf, read_only: bool },
    Proc { path: PathBuf, read_only: bool },
    Sys { path: PathBuf, read_only: bool },
}

#[derive(Debug, Clone)]
struct RuleLine {
    path: PathBuf,
    action: RuleAction,
    line_no: usize,
}

pub(crate) fn build_mount_plan(normalized_profile: &str) -> Result<Vec<MountPlanEntry>> {
    let parsed = profile::parse_normalized_rule_lines(normalized_profile)?;
    let rules: Vec<RuleLine> = parsed
        .into_iter()
        .map(|line| RuleLine {
            path: line.path,
            action: line.action,
            line_no: line.line_no,
        })
        .collect();
    let mut plan = Vec::new();

    for rule in &rules {
        let path_str = rule
            .path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("profile path is not valid UTF-8"))?;
        let has_glob = has_glob_syntax(path_str);
        let under_dev = rule.path.starts_with("/dev");
        let under_proc = rule.path.starts_with("/proc");
        let under_sys = rule.path.starts_with("/sys");

        if under_dev && has_glob {
            bail!("line {}: /dev rules do not allow glob patterns", rule.line_no);
        }
        if under_proc && has_glob {
            bail!("line {}: /proc rules do not allow glob patterns", rule.line_no);
        }
        if under_sys && has_glob {
            bail!("line {}: /sys rules do not allow glob patterns", rule.line_no);
        }

        if under_proc {
            if rule.path != Path::new("/proc") {
                bail!("line {}: /proc only allows the exact path /proc", rule.line_no);
            }
            let read_only = match rule.action {
                RuleAction::ReadOnly => true,
                RuleAction::Passthrough => false,
                _ => bail!("line {}: /proc only supports ro or rw", rule.line_no),
            };
            plan.push(MountPlanEntry::Proc {
                path: rule.path.clone(),
                read_only,
            });
            continue;
        }
        if under_sys {
            if rule.path != Path::new("/sys") {
                bail!("line {}: /sys only allows the exact path /sys", rule.line_no);
            }
            let read_only = match rule.action {
                RuleAction::ReadOnly => true,
                RuleAction::Passthrough => false,
                _ => bail!("line {}: /sys only supports ro or rw", rule.line_no),
            };
            plan.push(MountPlanEntry::Sys {
                path: rule.path.clone(),
                read_only,
            });
            continue;
        }

        if under_dev && matches!(rule.action, RuleAction::ReadOnly | RuleAction::Passthrough) {
            let meta = std::fs::symlink_metadata(&rule.path);
            let Ok(meta) = meta else {
                continue;
            };
            let ft = meta.file_type();
            if ft.is_char_device() || ft.is_dir() {
                let read_only = rule.action == RuleAction::ReadOnly;
                plan.push(MountPlanEntry::Bind {
                    path: rule.path.clone(),
                    read_only,
                });
            }
        }
    }

    validate_bind_conflicts(&rules, &plan)?;
    Ok(plan)
}

fn validate_bind_conflicts(rules: &[RuleLine], plan: &[MountPlanEntry]) -> Result<()> {
    for entry in plan {
        let bind_root = match entry {
            MountPlanEntry::Bind { path, .. }
            | MountPlanEntry::Proc { path, .. }
            | MountPlanEntry::Sys { path, .. } => path,
        };
        for rule in rules {
            if rule.path == *bind_root {
                continue;
            }
            if rule.path.starts_with(bind_root) {
                bail!(
                    "line {}: rule {} conflicts with mounted root {}",
                    rule.line_no,
                    rule.path.display(),
                    bind_root.display()
                );
            }
        }
    }
    Ok(())
}

fn has_glob_syntax(value: &str) -> bool {
    value.contains('*') || value.contains('?') || value.contains('[')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_rule_must_be_exact_and_ro_or_rw() {
        let err = build_mount_plan("/proc/self ro\n").expect_err("must fail");
        assert!(err.to_string().contains("exact path /proc"));
        let err = build_mount_plan("/proc deny\n").expect_err("must fail");
        assert!(err.to_string().contains("only supports ro or rw"));
    }

    #[test]
    fn proc_subrule_conflicts_with_proc_mount_root() {
        let err = build_mount_plan("/proc ro\n/proc/sys ro\n").expect_err("must fail");
        assert!(err.to_string().contains("exact path /proc"));
    }

    #[test]
    fn sys_rule_must_be_exact_and_ro_or_rw() {
        let err = build_mount_plan("/sys/kernel ro\n").expect_err("must fail");
        assert!(err.to_string().contains("exact path /sys"));
        let err = build_mount_plan("/sys deny\n").expect_err("must fail");
        assert!(err.to_string().contains("only supports ro or rw"));
    }

    #[test]
    fn dev_char_or_dir_rule_becomes_bind_mount() {
        let plan = build_mount_plan("/dev/pts rw\n").expect("plan");
        assert_eq!(
            plan,
            vec![MountPlanEntry::Bind {
                path: PathBuf::from("/dev/pts"),
                read_only: false
            }]
        );
    }

    #[test]
    fn dev_bind_root_rejects_descendant_rules() {
        let err = build_mount_plan("/dev/pts rw\n/dev/pts/0 ro\n").expect_err("must fail");
        assert!(err.to_string().contains("conflicts with mounted root /dev/pts"));
    }

    #[test]
    fn sys_root_rejects_descendant_rules() {
        let err = build_mount_plan("/sys ro\n/sys/fs ro\n").expect_err("must fail");
        assert!(err.to_string().contains("exact path /sys"));
    }
}
