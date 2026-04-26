mod access;
mod ancestor_has_cache;
mod cli;
mod cmd_fuse;
mod cmd_help;
mod cmd_kill;
mod cmd_profile;
mod cmd_run;
mod cmd_tail;
mod fuse_runtime;
mod mirrorfs;
mod mount_plan;
mod process_name;
mod profile;
mod profile_store;
mod sparse_bitset;
mod tail_ipc;
mod userns_run;

use anyhow::{Context, Result};
use cli::Command;
use log::LevelFilter;

fn main() {
    let status = match try_main() {
        Ok(status) => status,
        Err(err) => {
            eprintln!("error: {err:#}");
            1
        }
    };
    std::process::exit(status);
}

fn try_main() -> Result<i32> {
    let command = cli::parse_env()?;
    init_logging(command_verbose(&command));

    match command {
        Command::Help { topic, verbose } => {
            cmd_help::print_help(topic, verbose);
            Ok(0)
        }
        Command::Run(run) => cmd_run::run_command(run).context("run subcommand failed"),
        Command::Tail(tail) => {
            cmd_tail::tail_command(tail).context("tail subcommand failed")?;
            Ok(0)
        }
        Command::LowLevelFuse(fuse) => {
            cmd_fuse::fuse_command(fuse).context("_fuse subcommand failed")?;
            Ok(0)
        }
        Command::Profile(profile) => {
            cmd_profile::profile_command(profile).context("profile subcommand failed")?;
            Ok(0)
        }
        Command::LowLevelKill => {
            cmd_kill::kill_command().context("_kill subcommand failed")?;
            Ok(0)
        }
    }
}

fn command_verbose(command: &Command) -> bool {
    match command {
        Command::Help { verbose, .. } => *verbose,
        Command::Run(run) => run.verbose,
        Command::Tail(_) => false,
        Command::LowLevelFuse(fuse) => fuse.verbose,
        Command::LowLevelKill => false,
        Command::Profile(_) => false,
    }
}

fn init_logging(verbose: bool) {
    let mut builder = env_logger::Builder::from_default_env();
    if verbose {
        builder.filter_level(LevelFilter::Debug);
    } else if std::env::var_os("RUST_LOG").is_none() {
        builder.filter_level(LevelFilter::Warn);
    }
    if verbose {
        builder.filter_module("globset", LevelFilter::Info);
    }
    builder.format_timestamp(None).init();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{HelpTopic, LowLevelFuseCommand, RunCommand};
    use std::ffi::OsString;

    #[test]
    fn command_verbose_tracks_run_and_fuse_flags() {
        assert!(command_verbose(&Command::Run(RunCommand {
            verbose: true,
            program: OsString::from("true"),
            args: vec![],
        })));
        assert!(command_verbose(&Command::LowLevelFuse(
            LowLevelFuseCommand { verbose: true }
        )));
        assert!(!command_verbose(&Command::Help {
            topic: HelpTopic::Root,
            verbose: false,
        }));
    }
}
