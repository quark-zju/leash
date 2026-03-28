mod cli;
mod cmd_help;
mod cmd_flush;
mod cmd_fuse;
mod cmd_jail;
mod cmd_mount;
mod cmd_run;
mod cmd_suid;
mod cowfs;
mod jail;
mod ns_runtime;
mod op;
mod privileges;
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
        Command::Help { topic, verbose } => {
            cmd_help::print_help(topic, verbose);
            Ok(0)
        }
        Command::Add(add) => {
            cmd_jail::add_command(add).context("add subcommand failed")?;
            Ok(0)
        }
        Command::List(list) => {
            cmd_jail::list_command(list).context("list subcommand failed")?;
            Ok(0)
        }
        Command::Rm(rm) => {
            cmd_jail::rm_command(rm).context("rm subcommand failed")?;
            Ok(0)
        }
        Command::Run(run) => cmd_run::run_command(run).context("run subcommand failed"),
        Command::LowLevelMount(mount) => {
            cmd_mount::mount_command(mount).context("_mount subcommand failed")?;
            Ok(0)
        }
        Command::Flush(flush) => {
            cmd_flush::flush_command(flush).context("flush subcommand failed")?;
            Ok(0)
        }
        Command::LowLevelFlush(flush) => {
            cmd_flush::low_level_flush_command(flush).context("_flush subcommand failed")?;
            Ok(0)
        }
        Command::LowLevelFuse(fuse) => {
            cmd_fuse::fuse_command(fuse).context("_fuse subcommand failed")?;
            Ok(0)
        }
        Command::LowLevelSuid(suid) => {
            cmd_suid::suid_command(suid).context("_suid subcommand failed")?;
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
mod tests;
