use anyhow::Result;
use std::collections::BTreeSet;

use crate::cli::ShowCommand;
use crate::jail;
use crate::op;
use crate::record;
use crate::run_with_log;

pub(crate) fn show_command(show: ShowCommand) -> Result<()> {
    let resolved = run_with_log(
        || jail::resolve(Some(show.name.as_str()), None, jail::ResolveMode::MustExist),
        || format!("resolve jail '{}'", show.name),
    )?;
    let frames = run_with_log(
        || record::read_frames_best_effort(&resolved.paths.record_path),
        || format!("read record {}", resolved.paths.record_path.display()),
    )?;
    let pending_unflushed_writes = frames
        .iter()
        .filter(|frame| frame.tag == record::TAG_WRITE_OP && !frame.flushed)
        .count();
    let mut pending_paths: BTreeSet<String> = BTreeSet::new();
    if show.verbose {
        for frame in &frames {
            if frame.tag != record::TAG_WRITE_OP || frame.flushed {
                continue;
            }
            let Ok(op) = record::decode_cbor::<op::Operation>(frame) else {
                continue;
            };
            match op {
                op::Operation::WriteFile { path, .. }
                | op::Operation::CreateDir { path }
                | op::Operation::RemoveDir { path }
                | op::Operation::Truncate { path, .. } => {
                    pending_paths.insert(path.display().to_string());
                }
                op::Operation::Rename { from, to } => {
                    pending_paths.insert(from.display().to_string());
                    pending_paths.insert(to.display().to_string());
                }
            }
        }
    }

    println!("name: {}", resolved.name);
    println!("pending_unflushed_writes: {pending_unflushed_writes}");
    if show.verbose {
        println!("pending_paths:");
        for path in &pending_paths {
            println!("  {path}");
        }
    }
    println!("profile:");
    print!("{}", resolved.normalized_profile);
    if !resolved.normalized_profile.ends_with('\n') {
        println!();
    }
    Ok(())
}
