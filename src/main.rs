mod cli;
mod cmd_flush;
mod cmd_mount;
mod cmd_run;
mod cowfs;
mod op;
mod profile;
mod profile_loader;
mod record;

use anyhow::{Context, Result};
use cli::Command;

fn main() {
    match try_main() {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            eprintln!("error: {err:#}");
            std::process::exit(1);
        }
    }
}

fn try_main() -> Result<i32> {
    match cli::parse_env()? {
        Command::Help(topic) => {
            println!("{}", cli::help_text(topic));
            Ok(0)
        }
        Command::Run(run) => cmd_run::run_command(run).context("run subcommand failed"),
        Command::Mount(mount) => {
            cmd_mount::mount_command(mount).context("mount subcommand failed")?;
            Ok(0)
        }
        Command::Flush(flush) => {
            cmd_flush::flush_command(flush).context("flush subcommand failed")?;
            Ok(0)
        }
    }
}

pub(crate) fn vlog(verbose: bool, msg: String) {
    if verbose {
        eprintln!("{msg}");
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
