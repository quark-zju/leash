use anyhow::Result;

use crate::cli::ShowCommand;
use crate::jail;
use crate::run_with_log;

pub(crate) fn show_command(show: ShowCommand) -> Result<()> {
    let resolved = run_with_log(
        || {
            jail::resolve(
                show.name.as_deref(),
                show.profile.as_deref(),
                jail::ResolveMode::MustExist,
            )
        },
        || "resolve show jail".to_string(),
    )?;
    println!("name: {}", resolved.name);
    println!("profile:");
    print!("{}", resolved.normalized_profile);
    if !resolved.normalized_profile.ends_with('\n') {
        println!();
    }
    Ok(())
}
