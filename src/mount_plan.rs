use anyhow::{Context, Result, bail};
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
    action: Action,
    line_no: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    ReadOnly,
    ReadWrite,
    Cow,
    Deny,
    Hide,
}

pub(crate) fn build_mount_plan(normalized_profile: &str) -> Result<Vec<MountPlanEntry>> {
    let rules = parse_rules(normalized_profile)?;
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
                Action::ReadOnly => true,
                Action::ReadWrite => false,
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
                Action::ReadOnly => true,
                Action::ReadWrite => false,
                _ => bail!("line {}: /sys only supports ro or rw", rule.line_no),
            };
            plan.push(MountPlanEntry::Sys {
                path: rule.path.clone(),
                read_only,
            });
            continue;
        }

        if under_dev && matches!(rule.action, Action::ReadOnly | Action::ReadWrite) {
            let meta = std::fs::symlink_metadata(&rule.path);
            let Ok(meta) = meta else {
                continue;
            };
            let ft = meta.file_type();
            if ft.is_char_device() || ft.is_dir() {
                let read_only = rule.action == Action::ReadOnly;
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

fn parse_rules(normalized_profile: &str) -> Result<Vec<RuleLine>> {
    let mut out = Vec::new();
    for (idx, line) in normalized_profile.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        let path = parts
            .next()
            .with_context(|| format!("line {} missing path", idx + 1))?;
        let action = parts
            .next()
            .with_context(|| format!("line {} missing action", idx + 1))?;
        if parts.next().is_some() {
            bail!("line {} has extra tokens", idx + 1);
        }
        out.push(RuleLine {
            path: PathBuf::from(path),
            action: parse_action(action).with_context(|| format!("line {} invalid action", idx + 1))?,
            line_no: idx + 1,
        });
    }
    Ok(out)
}

fn parse_action(value: &str) -> Result<Action> {
    match value {
        "ro" => Ok(Action::ReadOnly),
        "rw" => Ok(Action::ReadWrite),
        "cow" => Ok(Action::Cow),
        "deny" => Ok(Action::Deny),
        "hide" => Ok(Action::Hide),
        _ => bail!("action must be one of ro/rw/cow/deny/hide"),
    }
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
