use anyhow::{Context, Result, bail};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use globset::{GlobBuilder, GlobSetBuilder};

pub(crate) const DEFAULT_MOUNTINFO_PATH: &str = "/proc/self/mountinfo";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MountEntry {
    pub(crate) mount_point: PathBuf,
    pub(crate) fs_type: String,
    pub(crate) source: String,
}

pub(crate) fn read_mount_table() -> Result<Vec<MountEntry>> {
    read_mount_table_from(Path::new(DEFAULT_MOUNTINFO_PATH))
}

pub(crate) fn read_mount_table_from(path: &Path) -> Result<Vec<MountEntry>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read mount table {}", path.display()))?;
    parse_mountinfo(&content)
}

pub(crate) fn covered_mount_points(
    mounts: &[MountEntry],
    monitor_globs: &[String],
) -> Result<Vec<PathBuf>> {
    let globset = build_globset(monitor_globs)?;
    let mut out = BTreeSet::new();
    for mount in mounts {
        if globset.is_match(&mount.mount_point) {
            out.insert(mount.mount_point.clone());
        }
    }
    Ok(out.into_iter().collect())
}

pub(crate) fn uncovered_mount_points(
    mounts: &[MountEntry],
    monitor_globs: &[String],
) -> Result<Vec<PathBuf>> {
    let covered: BTreeSet<PathBuf> = covered_mount_points(mounts, monitor_globs)?.into_iter().collect();
    Ok(mounts
        .iter()
        .map(|mount| mount.mount_point.clone())
        .filter(|mount_point| !covered.contains(mount_point))
        .collect())
}

pub(crate) fn mount_points_for_paths(mounts: &[MountEntry], paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut out = BTreeSet::new();
    for path in paths {
        if let Some(mount_point) = deepest_mount_point_for_path(mounts, path) {
            out.insert(mount_point);
        }
    }
    out.into_iter().collect()
}

fn build_globset(patterns: &[String]) -> Result<globset::GlobSet> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        let glob = GlobBuilder::new(pattern)
            .literal_separator(true)
            .build()
            .with_context(|| format!("invalid monitor glob: {pattern}"))?;
        builder.add(glob);
    }
    builder
        .build()
        .context("failed to build monitor globset from mount coverage patterns")
}

fn deepest_mount_point_for_path(mounts: &[MountEntry], path: &Path) -> Option<PathBuf> {
    mounts
        .iter()
        .filter(|mount| path == mount.mount_point || path.starts_with(&mount.mount_point))
        .max_by_key(|mount| mount.mount_point.components().count())
        .map(|mount| mount.mount_point.clone())
}

fn parse_mountinfo(content: &str) -> Result<Vec<MountEntry>> {
    content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(parse_mountinfo_line)
        .collect()
}

fn parse_mountinfo_line(line: &str) -> Result<MountEntry> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    let sep = fields
        .iter()
        .position(|field| *field == "-")
        .ok_or_else(|| anyhow::anyhow!("mountinfo line missing separator: {line}"))?;
    if sep < 6 || fields.len() <= sep + 2 {
        bail!("mountinfo line is malformed: {line}");
    }
    Ok(MountEntry {
        mount_point: PathBuf::from(unescape_mount_field(fields[4])),
        fs_type: fields[sep + 1].to_string(),
        source: fields[sep + 2].to_string(),
    })
}

fn unescape_mount_field(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut idx = 0usize;
    while idx < bytes.len() {
        if bytes[idx] == b'\\' && idx + 3 < bytes.len() {
            let octal = &input[idx + 1..idx + 4];
            if octal.as_bytes().iter().all(|b| matches!(b, b'0'..=b'7'))
                && let Ok(value) = u8::from_str_radix(octal, 8)
            {
                out.push(value as char);
                idx += 4;
                continue;
            }
        }
        out.push(bytes[idx] as char);
        idx += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mountinfo_extracts_mount_point_and_fs() {
        let mounts = parse_mountinfo(
            "29 23 0:26 / /tmp rw,nosuid,nodev - tmpfs tmpfs rw,size=65536k\n",
        )
        .expect("parse mountinfo");
        assert_eq!(
            mounts,
            vec![MountEntry {
                mount_point: PathBuf::from("/tmp"),
                fs_type: "tmpfs".to_string(),
                source: "tmpfs".to_string(),
            }]
        );
    }

    #[test]
    fn parse_mountinfo_unescapes_spaces() {
        let mounts = parse_mountinfo(
            "40 23 8:1 / /media/My\\040Drive rw,relatime - ext4 /dev/sda1 rw\n",
        )
        .expect("parse mountinfo");
        assert_eq!(mounts[0].mount_point, PathBuf::from("/media/My Drive"));
    }

    #[test]
    fn covered_mount_points_respect_monitor_globs() {
        let mounts = vec![
            MountEntry {
                mount_point: PathBuf::from("/"),
                fs_type: "ext4".to_string(),
                source: "/dev/root".to_string(),
            },
            MountEntry {
                mount_point: PathBuf::from("/work"),
                fs_type: "ext4".to_string(),
                source: "/dev/root".to_string(),
            },
            MountEntry {
                mount_point: PathBuf::from("/work/foo"),
                fs_type: "bind".to_string(),
                source: "/dev/root".to_string(),
            },
            MountEntry {
                mount_point: PathBuf::from("/tmp"),
                fs_type: "tmpfs".to_string(),
                source: "tmpfs".to_string(),
            },
        ];
        let covered = covered_mount_points(&mounts, &["/work/**".to_string(), "/work".to_string()])
            .expect("covered mount points");
        assert_eq!(
            covered,
            vec![PathBuf::from("/work"), PathBuf::from("/work/foo")]
        );
    }

    #[test]
    fn uncovered_mount_points_return_remaining_mounts() {
        let mounts = vec![
            MountEntry {
                mount_point: PathBuf::from("/"),
                fs_type: "ext4".to_string(),
                source: "/dev/root".to_string(),
            },
            MountEntry {
                mount_point: PathBuf::from("/tmp"),
                fs_type: "tmpfs".to_string(),
                source: "tmpfs".to_string(),
            },
        ];
        let uncovered = uncovered_mount_points(&mounts, &["/tmp".to_string()])
            .expect("uncovered mount points");
        assert_eq!(uncovered, vec![PathBuf::from("/")]);
    }

    #[test]
    fn mount_points_for_paths_choose_deepest_covering_mount() {
        let mounts = vec![
            MountEntry {
                mount_point: PathBuf::from("/"),
                fs_type: "ext4".to_string(),
                source: "/dev/root".to_string(),
            },
            MountEntry {
                mount_point: PathBuf::from("/tmp"),
                fs_type: "tmpfs".to_string(),
                source: "tmpfs".to_string(),
            },
            MountEntry {
                mount_point: PathBuf::from("/run/user/1000"),
                fs_type: "tmpfs".to_string(),
                source: "tmpfs".to_string(),
            },
        ];
        let selected = mount_points_for_paths(
            &mounts,
            &[
                PathBuf::from("/"),
                PathBuf::from("/tmp/demo"),
                PathBuf::from("/run/user/1000/leash"),
            ],
        );
        assert_eq!(
            selected,
            vec![
                PathBuf::from("/"),
                PathBuf::from("/run/user/1000"),
                PathBuf::from("/tmp"),
            ]
        );
    }
}
