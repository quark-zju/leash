use crate::profile::{self, RuleAction};
use anyhow::{Context, Result, bail};
use globset::GlobBuilder;
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
        let exact_tmp = rule.path == Path::new("/tmp");
        let loc = rule_loc(rule.line_no);

        if under_dev && has_glob {
            bail!("{loc}: /dev rules do not allow glob patterns");
        }
        if under_proc && has_glob {
            bail!("{loc}: /proc rules do not allow glob patterns");
        }
        if under_sys && has_glob {
            bail!("{loc}: /sys rules do not allow glob patterns");
        }
        if under_proc {
            if rule.path != Path::new("/proc") {
                bail!("{loc}: /proc only allows the exact path /proc");
            }
            let read_only = match rule.action {
                RuleAction::ReadOnly => true,
                RuleAction::Passthrough => false,
                _ => bail!("{loc}: /proc only supports ro or rw"),
            };
            plan.push(MountPlanEntry::Proc {
                path: rule.path.clone(),
                read_only,
            });
            continue;
        }
        if under_sys {
            if rule.path != Path::new("/sys") {
                bail!("{loc}: /sys only allows the exact path /sys");
            }
            let read_only = match rule.action {
                RuleAction::ReadOnly => true,
                RuleAction::Passthrough => false,
                _ => bail!("{loc}: /sys only supports ro or rw"),
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

        if exact_tmp && matches!(rule.action, RuleAction::ReadOnly | RuleAction::Passthrough) {
            validate_exact_tmp_bind_rule(rule, &rules)?;
            let read_only = rule.action == RuleAction::ReadOnly;
            plan.push(MountPlanEntry::Bind {
                path: rule.path.clone(),
                read_only,
            });
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
                let loc = rule_loc(rule.line_no);
                bail!(
                    "{}: rule {} conflicts with mounted root {}",
                    loc,
                    rule.path.display(),
                    bind_root.display()
                );
            }
        }
    }
    Ok(())
}

fn validate_exact_tmp_bind_rule(current: &RuleLine, rules: &[RuleLine]) -> Result<()> {
    for rule in rules {
        if std::ptr::eq(rule, current) {
            continue;
        }
        if rule_mentions_or_matches_tmp(rule)? {
            let current_loc = rule_loc(current.line_no);
            let other_loc = rule_loc(rule.line_no);
            bail!(
                "{current_loc}: exact /tmp ro/rw bind mount requires /tmp to be mentioned only once; conflicting rule at {other_loc}: {}",
                rule.path.display()
            );
        }
    }
    Ok(())
}

fn rule_mentions_or_matches_tmp(rule: &RuleLine) -> Result<bool> {
    if rule.path == Path::new("/tmp") || rule.path.starts_with("/tmp/") {
        return Ok(true);
    }
    let pattern = rule
        .path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("profile path is not valid UTF-8"))?;
    if !has_glob_syntax(pattern) {
        return Ok(false);
    }
    let glob = GlobBuilder::new(pattern)
        .literal_separator(true)
        .build()
        .with_context(|| format!("invalid glob pattern in mount plan: {pattern}"))?;
    Ok(glob.compile_matcher().is_match("/tmp"))
}

fn has_glob_syntax(value: &str) -> bool {
    value.contains('*') || value.contains('?') || value.contains('[')
}

fn rule_loc(line_no: usize) -> String {
    format!("line {line_no}")
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
        assert!(
            err.to_string()
                .contains("conflicts with mounted root /dev/pts")
        );
    }

    #[test]
    fn tmp_ro_rule_becomes_bind_mount() {
        let plan = build_mount_plan("/tmp ro\n").expect("plan");
        assert_eq!(
            plan,
            vec![MountPlanEntry::Bind {
                path: PathBuf::from("/tmp"),
                read_only: true
            }]
        );
    }

    #[test]
    fn tmp_rw_rule_becomes_bind_mount() {
        let plan = build_mount_plan("/tmp rw\n").expect("plan");
        assert_eq!(
            plan,
            vec![MountPlanEntry::Bind {
                path: PathBuf::from("/tmp"),
                read_only: false
            }]
        );
    }

    #[test]
    fn tmp_bind_root_rejects_descendant_rules() {
        let err = build_mount_plan("/tmp rw\n/tmp/cache ro\n").expect_err("must fail");
        assert!(err.to_string().contains("mentioned only once"));
    }

    #[test]
    fn tmp_bind_rejects_duplicate_exact_tmp_rules() {
        let err = build_mount_plan("/tmp rw\n/tmp ro\n").expect_err("must fail");
        assert!(err.to_string().contains("mentioned only once"));
    }

    #[test]
    fn tmp_bind_rejects_other_rule_that_matches_tmp() {
        let err = build_mount_plan("/** ro\n/tmp rw\n").expect_err("must fail");
        assert!(err.to_string().contains("mentioned only once"));
    }

    #[test]
    fn sys_root_rejects_descendant_rules() {
        let err = build_mount_plan("/sys ro\n/sys/fs ro\n").expect_err("must fail");
        assert!(err.to_string().contains("exact path /sys"));
    }
}
