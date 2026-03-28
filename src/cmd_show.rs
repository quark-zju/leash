use anyhow::Result;

use crate::cli::ShowCommand;
use crate::jail;
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

    println!("name: {}", resolved.name);
    println!("pending_unflushed_writes: {pending_unflushed_writes}");
    println!("profile:");
    print!("{}", resolved.normalized_profile);
    if !resolved.normalized_profile.ends_with('\n') {
        println!();
    }
    Ok(())
}
