mod cli;
mod cmd_completion;
mod cmd_flush;
mod cmd_fuse;
mod cmd_help;
mod cmd_jail;
mod cmd_mount;
mod cmd_profile;
mod cmd_run;
mod cmd_show;
mod cmd_suid;
mod cowfs;
mod git_rw_filter;
mod jail;
mod mount_plan;
mod ns_runtime;
mod op;
mod privileges;
mod profile;
mod profile_loader;
mod record;

use anyhow::{Context, Result};
use cli::Command;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicBool, Ordering};

static VERBOSE_LOG: AtomicBool = AtomicBool::new(false);

pub(crate) fn is_verbose() -> bool {
    VERBOSE_LOG.load(Ordering::Relaxed)
}

macro_rules! vlog {
    ($($arg:tt)*) => {{
        if $crate::is_verbose() {
            eprintln!($($arg)*);
        }
    }};
}
pub(crate) use vlog;

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
    let cmd = cli::parse_env()?;
    set_verbose(command_verbose(&cmd));
    if let Some(reason) = require_priviledge_reason(&cmd) {
        crate::vlog!("privileges: keeping elevated euid, reason: {reason}");
    } else {
        drop_privileges_for_unprivileged_command()?;
    }

    match cmd {
        Command::Help { topic, verbose } => {
            cmd_help::print_help(topic, verbose);
            Ok(0)
        }
        Command::Completion(completion) => {
            cmd_completion::completion_command(completion)
                .context("completion subcommand failed")?;
            Ok(0)
        }
        Command::Profile(profile) => {
            cmd_profile::profile_command(profile).context("profile subcommand failed")?;
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
        Command::Show(show) => {
            cmd_show::show_command(show).context("show subcommand failed")?;
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
            env_logger::Builder::from_env(env_logger::Env::default().filter("COWJAIL_FUSE_LOG"))
                .init();
            cmd_fuse::fuse_command(fuse).context("_fuse subcommand failed")?;
            Ok(0)
        }
        Command::LowLevelSuid(suid) => {
            cmd_suid::suid_command(suid).context("_suid subcommand failed")?;
            Ok(0)
        }
    }
}

fn command_verbose(cmd: &Command) -> bool {
    match cmd {
        Command::Help { verbose, .. } => *verbose,
        Command::Completion(_) => false,
        Command::Profile(_) => false,
        Command::Show(show) => show.verbose,
        Command::Rm(rm) => rm.verbose,
        Command::Run(run) => run.verbose,
        Command::LowLevelMount(mount) => mount.verbose,
        Command::Flush(flush) => flush.verbose,
        Command::LowLevelFlush(flush) => flush.verbose,
        Command::LowLevelFuse(fuse) => fuse.verbose,
        Command::LowLevelSuid(suid) => suid.verbose,
        Command::Add(_) | Command::List(_) => false,
    }
}

fn require_priviledge_reason(cmd: &Command) -> Option<&'static str> {
    match cmd {
        Command::Run(_) => Some("run requires root for pivot_root and runtime setup"),
        Command::Rm(_) => Some("rm may need root to clean state/runtime artifacts"),
        Command::LowLevelFuse(_) => Some("_fuse requires root euid to mount FUSE daemon"),
        Command::LowLevelSuid(_) => Some("_suid updates binary ownership/mode"),
        Command::Help { .. }
        | Command::Completion(_)
        | Command::Profile(_)
        | Command::Add(_)
        | Command::List(_)
        | Command::Show(_)
        | Command::LowLevelMount(_)
        | Command::Flush(_)
        | Command::LowLevelFlush(_) => None,
    }
}

fn drop_privileges_for_unprivileged_command() -> Result<()> {
    run_with_log(privileges::drop_root_euid_if_needed, || {
        "drop elevated privileges for unprivileged command".to_string()
    })?;
    Ok(())
}

pub(crate) fn set_verbose(enabled: bool) {
    VERBOSE_LOG.store(enabled, Ordering::Relaxed);
}

pub(crate) fn run_with_log<T, F, D>(func: F, desc: D) -> Result<T>
where
    F: FnOnce() -> Result<T>,
    D: Fn() -> String,
{
    let verbose = VERBOSE_LOG.load(Ordering::Relaxed);
    let label = LazyLock::new(desc);
    let get_label = || label.as_str();

    if verbose {
        eprintln!("begin {}", get_label());
    }
    match func() {
        Ok(v) => {
            if verbose {
                eprintln!("ok {}", get_label());
            }
            Ok(v)
        }
        Err(err) => {
            if verbose {
                eprintln!("err {}: {err:#}", get_label());
            }
            Err(err).with_context(|| label.to_string())
        }
    }
}

#[cfg(test)]
mod tests;
