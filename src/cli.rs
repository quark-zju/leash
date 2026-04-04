use std::ffi::OsString;

use anyhow::{Result, bail};
use pico_args::Arguments;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Help { topic: HelpTopic, verbose: bool },
    Run(RunCommand),
    Profile(ProfileCommand),
    LowLevelFuse(LowLevelFuseCommand),
    LowLevelKill,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelpTopic {
    Root,
    Run,
    Profile,
    LowLevelFuse,
    LowLevelKill,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunCommand {
    pub verbose: bool,
    pub program: OsString,
    pub args: Vec<OsString>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileCommand {
    pub action: ProfileAction,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileAction {
    Show,
    Edit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LowLevelFuseCommand {
    pub verbose: bool,
}

pub fn parse_env() -> Result<Command> {
    parse_from(std::env::args_os().skip(1))
}

pub fn parse_from<I>(argv: I) -> Result<Command>
where
    I: IntoIterator<Item = OsString>,
{
    let raw: Vec<OsString> = argv.into_iter().collect();
    if raw.is_empty() {
        return Ok(help_command(HelpTopic::Root, false));
    }
    if raw[0] == "-h" || raw[0] == "--help" {
        let verbose = raw.iter().any(|arg| arg == "-v" || arg == "--verbose");
        return Ok(help_command(HelpTopic::Root, verbose));
    }

    let mut args = Arguments::from_vec(raw);
    let Some(subcmd) = args.subcommand()? else {
        bail!("missing subcommand (expected: help, profile, run, _fuse, _kill)");
    };

    match subcmd.as_str() {
        "help" => parse_help(args),
        "run" => parse_run(args),
        "profile" => parse_profile(args),
        "_fuse" => parse_low_level_fuse(args),
        "_kill" => parse_low_level_kill(args),
        other => bail!("unknown subcommand: {other}"),
    }
}

fn parse_help(mut args: Arguments) -> Result<Command> {
    let verbose = args.contains(["-v", "--verbose"]);
    let extra = args.finish();
    if extra.is_empty() {
        return Ok(help_command(HelpTopic::Root, verbose));
    }
    if extra.len() != 1 {
        bail!("help got unexpected trailing arguments");
    }

    let topic_name = extra[0]
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("help topic must be valid UTF-8"))?;
    let Some(topic) = crate::cmd_help::topic_from_name(topic_name) else {
        bail!("unknown help topic: {topic_name}");
    };
    Ok(help_command(topic, verbose))
}

fn parse_run(mut args: Arguments) -> Result<Command> {
    if args.contains(["-h", "--help"]) {
        return Ok(help_command(HelpTopic::Run, false));
    }
    let verbose = args.contains(["-v", "--verbose"]);
    let mut trailing = args.finish();
    if trailing.first().is_some_and(|arg| arg == "--") {
        trailing.remove(0);
    }
    if trailing.is_empty() {
        bail!("run requires a command to execute");
    }
    let program = trailing.remove(0);
    Ok(Command::Run(RunCommand {
        verbose,
        program,
        args: trailing,
    }))
}

fn parse_profile(mut args: Arguments) -> Result<Command> {
    if args.contains(["-h", "--help"]) {
        return Ok(help_command(HelpTopic::Profile, false));
    }
    let extra = args.finish();
    if extra.len() != 1 {
        bail!("profile requires subcommand: show or edit");
    }
    let subcmd = extra[0]
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("profile subcommand must be valid UTF-8"))?;
    let action = match subcmd {
        "show" => ProfileAction::Show,
        "edit" => ProfileAction::Edit,
        other => bail!("unknown profile subcommand: {other}"),
    };
    Ok(Command::Profile(ProfileCommand { action }))
}

fn parse_low_level_fuse(mut args: Arguments) -> Result<Command> {
    if args.contains(["-h", "--help"]) {
        return Ok(help_command(HelpTopic::LowLevelFuse, true));
    }
    let verbose = args.contains(["-v", "--verbose"]);
    let extra = args.finish();
    if !extra.is_empty() {
        bail!("_fuse got unexpected trailing arguments");
    }
    Ok(Command::LowLevelFuse(LowLevelFuseCommand { verbose }))
}

fn parse_low_level_kill(mut args: Arguments) -> Result<Command> {
    if args.contains(["-h", "--help"]) {
        return Ok(help_command(HelpTopic::LowLevelKill, true));
    }
    let extra = args.finish();
    if !extra.is_empty() {
        bail!("_kill got unexpected trailing arguments");
    }
    Ok(Command::LowLevelKill)
}

fn help_command(topic: HelpTopic, verbose: bool) -> Command {
    Command::Help { topic, verbose }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(args: &[&str]) -> Vec<OsString> {
        args.iter().map(|arg| OsString::from(*arg)).collect()
    }

    #[test]
    fn parse_root_help_without_subcommand() {
        assert_eq!(
            parse_from(Vec::<OsString>::new()).expect("parse"),
            Command::Help {
                topic: HelpTopic::Root,
                verbose: false,
            }
        );
    }

    #[test]
    fn parse_root_help_verbose_flag() {
        assert_eq!(
            parse_from(os(&["--help", "-v"])).expect("parse"),
            Command::Help {
                topic: HelpTopic::Root,
                verbose: true,
            }
        );
    }

    #[test]
    fn parse_run_command_with_args() {
        assert_eq!(
            parse_from(os(&["run", "-v", "--", "echo", "hello"])).expect("parse"),
            Command::Run(RunCommand {
                verbose: true,
                program: OsString::from("echo"),
                args: vec![OsString::from("hello")],
            })
        );
    }

    #[test]
    fn parse_run_requires_program() {
        let err = parse_from(os(&["run", "-v"])).expect_err("parse should fail");
        assert!(err.to_string().contains("requires a command"), "{err:#}");
    }

    #[test]
    fn parse_profile_show_and_edit() {
        assert_eq!(
            parse_from(os(&["profile", "show"])).expect("parse"),
            Command::Profile(ProfileCommand {
                action: ProfileAction::Show,
            })
        );
        assert_eq!(
            parse_from(os(&["profile", "edit"])).expect("parse"),
            Command::Profile(ProfileCommand {
                action: ProfileAction::Edit,
            })
        );
    }

    #[test]
    fn parse_low_level_fuse_verbose() {
        assert_eq!(
            parse_from(os(&["_fuse", "--verbose"])).expect("parse"),
            Command::LowLevelFuse(LowLevelFuseCommand { verbose: true })
        );
    }

    #[test]
    fn parse_low_level_kill() {
        assert_eq!(
            parse_from(os(&["_kill"])).expect("parse"),
            Command::LowLevelKill
        );
    }

    #[test]
    fn parse_unknown_subcommand_fails() {
        let err = parse_from(os(&["_unknown"])).expect_err("parse should fail");
        assert!(err.to_string().contains("unknown subcommand"), "{err:#}");
    }
}
