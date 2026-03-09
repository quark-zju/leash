use std::convert::Infallible;
use std::ffi::OsString;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use pico_args::Arguments;

pub const DEFAULT_PROFILE: &str = "default";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Help(HelpTopic),
    Run(RunCommand),
    Mount(MountCommand),
    Flush(FlushCommand),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelpTopic {
    Root,
    Run,
    Mount,
    Flush,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunCommand {
    pub profile: String,
    pub record: Option<PathBuf>,
    pub verbose: bool,
    pub program: OsString,
    pub args: Vec<OsString>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountCommand {
    pub profile: String,
    pub record: PathBuf,
    pub verbose: bool,
    pub path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlushCommand {
    pub record: Option<PathBuf>,
    pub profile: Option<String>,
    pub dry_run: bool,
    pub verbose: bool,
}

pub fn parse_from<I>(argv: I) -> Result<Command>
where
    I: IntoIterator<Item = OsString>,
{
    let raw: Vec<OsString> = argv.into_iter().collect();
    if raw.is_empty() {
        return Ok(Command::Help(HelpTopic::Root));
    }
    if raw[0] == "-h" || raw[0] == "--help" {
        return Ok(Command::Help(HelpTopic::Root));
    }

    let mut args = Arguments::from_vec(raw);
    let subcmd = args
        .subcommand()?
        .ok_or_else(|| anyhow::anyhow!("missing subcommand (expected: run, mount, flush)"))?;

    let command = match subcmd.as_str() {
        "run" => parse_run(args)?,
        "mount" => parse_mount(args)?,
        "flush" => parse_flush(args)?,
        other => bail!("unknown subcommand: {other}"),
    };

    Ok(command)
}

pub fn parse_env() -> Result<Command> {
    let argv: Vec<OsString> = std::env::args_os().skip(1).collect();
    parse_from(argv)
}

fn parse_run(mut args: Arguments) -> Result<Command> {
    if args.contains(["-h", "--help"]) {
        return Ok(Command::Help(HelpTopic::Run));
    }
    let verbose = args.contains(["-v", "--verbose"]);
    let profile = args
        .opt_value_from_str("--profile")?
        .unwrap_or_else(|| DEFAULT_PROFILE.to_string());
    let record = args.opt_value_from_os_str("--record", parse_pathbuf)?;

    let mut trailing = args.finish();
    if trailing.is_empty() {
        bail!("run requires a command to execute");
    }

    let program = trailing.remove(0);
    Ok(Command::Run(RunCommand {
        profile,
        record,
        verbose,
        program,
        args: trailing,
    }))
}

fn parse_mount(mut args: Arguments) -> Result<Command> {
    if args.contains(["-h", "--help"]) {
        return Ok(Command::Help(HelpTopic::Mount));
    }
    let verbose = args.contains(["-v", "--verbose"]);
    let profile = args
        .value_from_str("--profile")
        .context("mount requires --profile <profile>")?;
    let record = args
        .value_from_os_str("--record", parse_pathbuf)
        .context("mount requires --record <record_path>")?;
    let path = args
        .free_from_os_str(parse_pathbuf)
        .context("mount requires <path>")?;

    let extra = args.finish();
    if !extra.is_empty() {
        bail!("mount got unexpected trailing arguments");
    }

    Ok(Command::Mount(MountCommand {
        profile,
        record,
        verbose,
        path,
    }))
}

fn parse_flush(mut args: Arguments) -> Result<Command> {
    if args.contains(["-h", "--help"]) {
        return Ok(Command::Help(HelpTopic::Flush));
    }
    let verbose = args.contains(["-v", "--verbose"]);
    let dry_run = args.contains("--dry-run");
    let profile = args.opt_value_from_str("--profile")?;
    let record = args.opt_value_from_os_str("--record", parse_pathbuf)?;

    let extra = args.finish();
    if !extra.is_empty() {
        bail!("flush got unexpected trailing arguments");
    }

    Ok(Command::Flush(FlushCommand {
        record,
        profile,
        dry_run,
        verbose,
    }))
}

fn parse_pathbuf(raw: &std::ffi::OsStr) -> Result<PathBuf, Infallible> {
    Ok(PathBuf::from(raw))
}

pub fn help_text(topic: HelpTopic) -> &'static str {
    match topic {
        HelpTopic::Root => {
            "cowjail\n\nUSAGE:\n  cowjail run [--profile <profile>] [--record <record_path>] [-v|--verbose] command ...\n  cowjail mount --profile <profile> --record <record_path> [-v|--verbose] <path>\n  cowjail flush [--record <record_path>] [--profile <profile>] [--dry-run] [-v|--verbose]\n\nRun `cowjail <subcommand> --help` for details."
        }
        HelpTopic::Run => {
            "cowjail run\n\nUSAGE:\n  cowjail run [--profile <profile>] [--record <record_path>] [-v|--verbose] command ...\n\nOPTIONS:\n  --profile <profile>   Profile path. Default: default\n  --record <record>     Record output path. Default: .cache/cowjail/<timestamp>.cjr\n  -v, --verbose         Print progress logs"
        }
        HelpTopic::Mount => {
            "cowjail mount\n\nUSAGE:\n  cowjail mount --profile <profile> --record <record_path> [-v|--verbose] <path>\n\nOPTIONS:\n  --profile <profile>   Profile path (required)\n  --record <record>     Record output path (required)\n  -v, --verbose         Print progress logs"
        }
        HelpTopic::Flush => {
            "cowjail flush\n\nUSAGE:\n  cowjail flush [--record <record_path>] [--profile <profile>] [--dry-run] [-v|--verbose]\n\nOPTIONS:\n  --record <record>     Record path. Default: newest under .cache/cowjail\n  --profile <profile>   Replay policy profile override\n  --dry-run             Preview without applying or marking flushed\n  -v, --verbose         Print progress logs"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(args: &[&str]) -> Vec<OsString> {
        args.iter().map(|s| OsString::from(*s)).collect()
    }

    #[test]
    fn parse_run_defaults_profile() {
        let cmd = parse_from(os(&["run", "echo", "hi"]))
            .expect("run command should parse with default profile");
        let run = match cmd {
            Command::Run(run) => run,
            other => panic!("expected run, got {other:?}"),
        };
        assert_eq!(run.profile, DEFAULT_PROFILE);
        assert!(!run.verbose);
        assert_eq!(run.program, OsString::from("echo"));
        assert_eq!(run.args, vec![OsString::from("hi")]);
    }

    #[test]
    fn parse_mount_requires_all_flags() {
        let err = parse_from(os(&["mount", "./mnt"]))
            .expect_err("mount without required flags should fail");
        assert!(err.to_string().contains("mount requires --profile"));
    }

    #[test]
    fn parse_flush_dry_run() {
        let cmd = parse_from(os(&["flush", "--dry-run"])).expect("flush should parse with dry-run");
        let flush = match cmd {
            Command::Flush(flush) => flush,
            other => panic!("expected flush, got {other:?}"),
        };
        assert!(flush.dry_run);
        assert!(!flush.verbose);
        assert!(flush.profile.is_none());
        assert!(flush.record.is_none());
    }

    #[test]
    fn parse_verbose_short_flag() {
        let cmd = parse_from(os(&["run", "-v", "echo"])).expect("run should parse verbose");
        let run = match cmd {
            Command::Run(run) => run,
            other => panic!("expected run, got {other:?}"),
        };
        assert!(run.verbose);
    }

    #[test]
    fn parse_root_help_flag() {
        let cmd = parse_from(os(&["--help"])).expect("help should parse");
        assert_eq!(cmd, Command::Help(HelpTopic::Root));
    }

    #[test]
    fn parse_subcommand_help_flag() {
        let cmd = parse_from(os(&["run", "--help"])).expect("run help should parse");
        assert_eq!(cmd, Command::Help(HelpTopic::Run));
    }
}
