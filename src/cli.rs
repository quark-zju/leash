use std::ffi::OsString;
use std::path::PathBuf;

use anyhow::{Result, bail};
use pico_args::Arguments;

use crate::tail_ipc::EventKind;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Help { topic: HelpTopic, verbose: bool },
    Run(RunCommand),
    Tail(TailCommand),
    Profile(ProfileCommand),
    LowLevelFuse(LowLevelFuseCommand),
    LowLevelKill,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelpTopic {
    Root,
    Run,
    Tail,
    Rules,
    LowLevelFuse,
    LowLevelKill,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunCommand {
    pub verbose: bool,
    pub landlock_network_restriction: bool,
    pub program: OsString,
    pub args: Vec<OsString>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileCommand {
    pub action: ProfileAction,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailCommand {
    pub kinds: Vec<EventKind>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileAction {
    Show,
    Edit,
    Test { path: PathBuf, exe: Option<String> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LowLevelFuseCommand {
    pub verbose: bool,
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
        bail!("missing subcommand (expected: help, rules, run, tail, _fuse, _kill)");
    };

    match subcmd.as_str() {
        "help" => parse_help(args),
        "run" => parse_run(args),
        "tail" => parse_tail(args),
        "rules" => parse_rules(args),
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

fn parse_run(args: Arguments) -> Result<Command> {
    let mut verbose = false;
    let mut landlock_network_restriction = true;
    let mut trailing = args.finish();
    let mut command_index = 0;
    while let Some(arg) = trailing.get(command_index) {
        if arg == "--" {
            command_index += 1;
            break;
        }
        if arg == "-h" || arg == "--help" {
            return Ok(help_command(HelpTopic::Run, false));
        }
        if arg == "-v" || arg == "--verbose" {
            verbose = true;
            command_index += 1;
            continue;
        }
        if arg == "-L" || arg == "--no-landlock-network-restriction" {
            landlock_network_restriction = false;
            command_index += 1;
            continue;
        }
        break;
    }
    trailing.drain(..command_index);
    if trailing.is_empty() {
        bail!("run requires a command to execute");
    }
    let program = trailing.remove(0);
    Ok(Command::Run(RunCommand {
        verbose,
        landlock_network_restriction,
        program,
        args: trailing,
    }))
}

fn parse_rules(mut args: Arguments) -> Result<Command> {
    if args.contains(["-h", "--help"]) {
        return Ok(help_command(HelpTopic::Rules, false));
    }
    let Some(subcmd) = args.subcommand()? else {
        bail!("rules requires subcommand: show, edit, or test");
    };
    let action = match subcmd.as_str() {
        "show" => {
            if !args.finish().is_empty() {
                bail!("rules show got unexpected trailing arguments");
            }
            ProfileAction::Show
        }
        "edit" => {
            if !args.finish().is_empty() {
                bail!("rules edit got unexpected trailing arguments");
            }
            ProfileAction::Edit
        }
        "test" => {
            let mut exe: Option<String> = None;
            let mut path: Option<PathBuf> = None;
            let extra = args.finish();
            let mut i = 0;
            while i < extra.len() {
                let token = &extra[i];
                let token_str = token
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("rules test arguments must be valid UTF-8"))?;
                if let Some(value) = token_str.strip_prefix("--exe=") {
                    if exe.replace(value.to_owned()).is_some() {
                        bail!("rules test got duplicate --exe option");
                    }
                    i += 1;
                    continue;
                }
                if token_str == "--exe" {
                    let Some(value) = extra.get(i + 1) else {
                        bail!("rules test --exe requires a value");
                    };
                    let value = value.to_str().ok_or_else(|| {
                        anyhow::anyhow!("rules test --exe value must be valid UTF-8")
                    })?;
                    if exe.replace(value.to_owned()).is_some() {
                        bail!("rules test got duplicate --exe option");
                    }
                    i += 2;
                    continue;
                }
                if path.replace(PathBuf::from(token.clone())).is_some() {
                    bail!("rules test requires exactly one PATH argument");
                }
                i += 1;
            }
            let Some(path) = path else {
                bail!("rules test requires exactly one PATH argument");
            };
            ProfileAction::Test { path, exe }
        }
        other => bail!("unknown rules subcommand: {other}"),
    };
    Ok(Command::Profile(ProfileCommand { action }))
}

fn parse_tail(mut args: Arguments) -> Result<Command> {
    if args.contains(["-h", "--help"]) {
        return Ok(help_command(HelpTopic::Tail, false));
    }
    let kinds_raw: Option<String> = args.opt_value_from_str("--kinds")?;
    let extra = args.finish();
    if !extra.is_empty() {
        bail!("tail got unexpected trailing arguments");
    }
    let kinds = parse_tail_kinds(kinds_raw.as_deref())?;
    Ok(Command::Tail(TailCommand { kinds }))
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

fn parse_tail_kinds(raw: Option<&str>) -> Result<Vec<EventKind>> {
    let Some(raw) = raw else {
        return Ok(vec![]);
    };
    let mut kinds = Vec::new();
    for token in raw.split(',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        let kind = EventKind::parse_token(token)
            .ok_or_else(|| anyhow::anyhow!("unknown tail event kind: {token}"))?;
        if !kinds.contains(&kind) {
            kinds.push(kind);
        }
    }
    Ok(kinds)
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
                landlock_network_restriction: true,
                program: OsString::from("echo"),
                args: vec![OsString::from("hello")],
            })
        );
    }

    #[test]
    fn parse_run_without_landlock_network_restriction() {
        assert_eq!(
            parse_from(os(&[
                "run",
                "-L",
                "--",
                "echo",
                "--no-landlock-network-restriction",
            ]))
            .expect("parse"),
            Command::Run(RunCommand {
                verbose: false,
                landlock_network_restriction: false,
                program: OsString::from("echo"),
                args: vec![OsString::from("--no-landlock-network-restriction")],
            })
        );
    }

    #[test]
    fn parse_run_preserves_command_flags_without_separator() {
        assert_eq!(
            parse_from(os(&["run", "echo", "-L", "-v", "--help"])).expect("parse"),
            Command::Run(RunCommand {
                verbose: false,
                landlock_network_restriction: true,
                program: OsString::from("echo"),
                args: os(&["-L", "-v", "--help"]),
            })
        );
    }

    #[test]
    fn parse_run_separator_ends_leash_options() {
        assert_eq!(
            parse_from(os(&["run", "--", "echo", "-L"])).expect("parse"),
            Command::Run(RunCommand {
                verbose: false,
                landlock_network_restriction: true,
                program: OsString::from("echo"),
                args: os(&["-L"]),
            })
        );
    }

    #[test]
    fn parse_run_requires_program() {
        let err = parse_from(os(&["run", "-v"])).expect_err("parse should fail");
        assert!(err.to_string().contains("requires a command"), "{err:#}");
    }

    #[test]
    fn parse_rules_show_and_edit() {
        assert_eq!(
            parse_from(os(&["rules", "show"])).expect("parse"),
            Command::Profile(ProfileCommand {
                action: ProfileAction::Show,
            })
        );
        assert_eq!(
            parse_from(os(&["rules", "edit"])).expect("parse"),
            Command::Profile(ProfileCommand {
                action: ProfileAction::Edit,
            })
        );
    }

    #[test]
    fn parse_rules_test_with_optional_exe() {
        assert_eq!(
            parse_from(os(&["rules", "test", "/tmp"])).expect("parse"),
            Command::Profile(ProfileCommand {
                action: ProfileAction::Test {
                    path: PathBuf::from("/tmp"),
                    exe: None,
                },
            })
        );
        assert_eq!(
            parse_from(os(&["rules", "test", "--exe=git", "/tmp"])).expect("parse"),
            Command::Profile(ProfileCommand {
                action: ProfileAction::Test {
                    path: PathBuf::from("/tmp"),
                    exe: Some("git".to_owned()),
                },
            })
        );
    }

    #[test]
    fn parse_tail_with_kinds() {
        assert_eq!(
            parse_from(os(&["tail", "--kinds", "lookup-miss,lock"])).expect("parse"),
            Command::Tail(TailCommand {
                kinds: vec![EventKind::LookupMiss, EventKind::Lock],
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
