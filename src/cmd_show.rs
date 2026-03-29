use anyhow::Result;

use crate::cli::ShowCommand;
use crate::jail;
use crate::run_with_log;

pub(crate) fn show_command(show: ShowCommand) -> Result<()> {
    let mut first = true;
    for name in show.selectors {
        let resolved = run_with_log(
            || jail::resolve(Some(&name), None, jail::ResolveMode::MustExist),
            || format!("resolve jail '{name}'"),
        )?;
        if !first {
            println!();
        }
        first = false;
        println!("name: {}", resolved.name);
        println!("profile:");
        print!("{}", resolved.normalized_profile);
        if !resolved.normalized_profile.ends_with('\n') {
            println!();
        }
    }
    Ok(())
}
