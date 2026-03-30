use std::convert::Infallible;
use std::ffi::OsString;
use std::path::PathBuf;

use anyhow::{Result, bail};
use pico_args::Arguments;

pub const DEFAULT_PROFILE: &str = "default";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Help { topic: HelpTopic, verbose: bool },
    Completion(CompletionCommand),
    Profile(ProfileCommand),
    Run(RunCommand),
    LowLevelDaemon(LowLevelDaemonCommand),
    LowLevelList(ListCommand),
    LowLevelShow(ShowCommand),
    LowLevelRm(RmCommand),
    LowLevelSuid(LowLevelSuidCommand),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelpTopic {
    Root,
    Profile,
    Run,
    Completion,
    LowLevelDaemon,
    LowLevelList,
    LowLevelShow,
    LowLevelRm,
    LowLevelSuid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileCommand {
    pub action: ProfileAction,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileAction {
    List,
    Show { name: String },
    Edit { name: String },
    Rm { name: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListCommand;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShowCommand {
    pub selectors: Vec<String>,
    pub verbose: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RmCommand {
    pub selectors: Vec<String>,
    pub verbose: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunCommand {
    pub profile: Option<String>,
    pub verbose: bool,
    pub program: OsString,
    pub args: Vec<OsString>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LowLevelSuidCommand {
    pub verbose: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LowLevelDaemonCommand {
    pub socket: Option<PathBuf>,
    pub verbose: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletionCommand {
    pub shell: Option<String>,
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
    let subcmd = args.subcommand()?.ok_or_else(|| {
        anyhow::anyhow!("missing subcommand (expected: completion, profile, run)")
    })?;

    let command = match subcmd.as_str() {
        "help" => parse_help(args)?,
        "completion" => parse_completion(args)?,
        "profile" => parse_profile(args)?,
        "run" => parse_run(args)?,
        "_daemon" => parse_low_level_daemon(args)?,
        "_list" => parse_list(args)?,
        "_show" => parse_show(args)?,
        "_rm" => parse_rm(args)?,
        "_suid" => parse_low_level_suid(args)?,
        other => bail!("unknown subcommand: {other}"),
    };

    Ok(command)
}

fn parse_help(mut args: Arguments) -> Result<Command> {
    let verbose = args.contains(["-v", "--verbose"]);
    let extra = args.finish();
    if extra.is_empty() {
        return Ok(help_command(HelpTopic::Root, verbose));
    }
    if extra.len() > 1 {
        bail!("help got unexpected trailing arguments");
    }
    let topic = extra[0]
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("help topic must be valid UTF-8"))?;
    let topic = crate::cmd_help::topic_from_name(topic)
        .ok_or_else(|| anyhow::anyhow!("unknown help topic: {topic}"))?;
    Ok(help_command(topic, verbose))
}

fn parse_completion(mut args: Arguments) -> Result<Command> {
    if args.contains(["-h", "--help"]) {
        return Ok(help_command(HelpTopic::Completion, false));
    }
    let extra = args.finish();
    if extra.len() > 1 {
        bail!("completion got unexpected trailing arguments");
    }
    let shell = extra
        .first()
        .map(|raw| {
            raw.to_str()
                .ok_or_else(|| anyhow::anyhow!("completion SHELL must be valid UTF-8"))
                .map(ToOwned::to_owned)
        })
        .transpose()?;
    Ok(Command::Completion(CompletionCommand { shell }))
}

fn parse_profile(mut args: Arguments) -> Result<Command> {
    if args.contains(["-h", "--help"]) {
        return Ok(help_command(HelpTopic::Profile, false));
    }
    let extra = args.finish();
    if extra.is_empty() {
        bail!("profile requires subcommand: list, show, edit or rm");
    }
    let subcmd = extra[0]
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("profile subcommand must be valid UTF-8"))?;
    match subcmd {
        "list" => {
            if extra.len() != 1 {
                bail!("profile list got unexpected trailing arguments");
            }
            Ok(Command::Profile(ProfileCommand {
                action: ProfileAction::List,
            }))
        }
        "show" | "edit" | "rm" => {
            if extra.len() > 2 {
                bail!("profile {subcmd} got unexpected trailing arguments");
            }
            let name = parse_optional_profile_name(&extra, 1)?;
            let action = match subcmd {
                "show" => ProfileAction::Show { name },
                "edit" => ProfileAction::Edit { name },
                _ => ProfileAction::Rm { name },
            };
            Ok(Command::Profile(ProfileCommand { action }))
        }
        other => bail!("unknown profile subcommand: {other}"),
    }
}

/// Extract an optional profile name from positional arguments.
/// Returns `DEFAULT_PROFILE` if the argument at `pos` is absent.
fn parse_optional_profile_name(extra: &[std::ffi::OsString], pos: usize) -> Result<String> {
    if extra.len() > pos {
        extra[pos]
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("profile NAME must be valid UTF-8"))
            .map(ToOwned::to_owned)
    } else {
        Ok(DEFAULT_PROFILE.to_string())
    }
}

fn help_command(topic: HelpTopic, verbose: bool) -> Command {
    Command::Help { topic, verbose }
}

pub fn parse_env() -> Result<Command> {
    let argv: Vec<OsString> = std::env::args_os().skip(1).collect();
    parse_from(argv)
}

fn parse_run(mut args: Arguments) -> Result<Command> {
    if args.contains(["-h", "--help"]) {
        return Ok(help_command(HelpTopic::Run, false));
    }
    let verbose = args.contains(["-v", "--verbose"]);
    if args.opt_value_from_str::<_, String>("--name")?.is_some() {
        bail!("run no longer accepts --name; use --profile <profile>");
    }
    let profile = args.opt_value_from_str("--profile")?;

    let mut trailing = args.finish();
    if trailing.is_empty() {
        bail!("run requires a command to execute");
    }
    if trailing.first().is_some_and(|arg| arg == "--") {
        trailing.remove(0);
    }
    if trailing.is_empty() {
        bail!("run requires a command to execute");
    }

    let program = trailing.remove(0);
    Ok(Command::Run(RunCommand {
        profile,
        verbose,
        program,
        args: trailing,
    }))
}

fn parse_list(mut args: Arguments) -> Result<Command> {
    if args.contains(["-h", "--help"]) {
        return Ok(help_command(HelpTopic::LowLevelList, true));
    }
    let extra = args.finish();
    if !extra.is_empty() {
        bail!("_list got unexpected trailing arguments");
    }
    Ok(Command::LowLevelList(ListCommand))
}

fn parse_low_level_daemon(mut args: Arguments) -> Result<Command> {
    if args.contains(["-h", "--help"]) {
        return Ok(help_command(HelpTopic::LowLevelDaemon, true));
    }
    let verbose = args.contains(["-v", "--verbose"]);
    let socket = args.opt_value_from_os_str("--socket", parse_pathbuf)?;
    let extra = args.finish();
    if !extra.is_empty() {
        bail!("_daemon got unexpected trailing arguments");
    }
    Ok(Command::LowLevelDaemon(LowLevelDaemonCommand {
        socket,
        verbose,
    }))
}

fn parse_show(mut args: Arguments) -> Result<Command> {
    if args.contains(["-h", "--help"]) {
        return Ok(help_command(HelpTopic::LowLevelShow, true));
    }
    let verbose = args.contains(["-v", "--verbose"]);
    let selectors = parse_low_level_name_selectors(args, "_show")?;
    Ok(Command::LowLevelShow(ShowCommand { selectors, verbose }))
}

fn parse_rm(mut args: Arguments) -> Result<Command> {
    if args.contains(["-h", "--help"]) {
        return Ok(help_command(HelpTopic::LowLevelRm, true));
    }
    let verbose = args.contains(["-v", "--verbose"]);
    let selectors = parse_low_level_name_selectors(args, "_rm")?;
    Ok(Command::LowLevelRm(RmCommand { selectors, verbose }))
}

fn parse_low_level_name_selectors(mut args: Arguments, command: &str) -> Result<Vec<String>> {
    if args.opt_value_from_str::<_, String>("--name")?.is_some() {
        bail!("{command} no longer accepts --name; pass NAME or GLOB positionally");
    }
    if args.opt_value_from_str::<_, String>("--profile")?.is_some() {
        bail!("{command} no longer accepts --profile; pass NAME or GLOB positionally");
    }
    let extra = args.finish();
    if extra.is_empty() {
        bail!("{command} requires one or more NAME or GLOB selectors");
    }
    extra
        .into_iter()
        .map(|raw| {
            raw.to_str()
                .ok_or_else(|| anyhow::anyhow!("{command} NAME must be valid UTF-8"))
                .map(ToOwned::to_owned)
        })
        .collect()
}

fn parse_pathbuf(raw: &std::ffi::OsStr) -> Result<PathBuf, Infallible> {
    Ok(PathBuf::from(raw))
}

fn parse_low_level_suid(mut args: Arguments) -> Result<Command> {
    if args.contains(["-h", "--help"]) {
        return Ok(help_command(HelpTopic::LowLevelSuid, true));
    }
    let verbose = args.contains(["-v", "--verbose"]);
    let extra = args.finish();
    if !extra.is_empty() {
        bail!("_suid got unexpected trailing arguments");
    }
    Ok(Command::LowLevelSuid(LowLevelSuidCommand { verbose }))
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
        assert!(run.profile.is_none());
        assert!(!run.verbose);
        assert_eq!(run.program, OsString::from("echo"));
        assert_eq!(run.args, vec![OsString::from("hi")]);
    }

    #[test]
    fn parse_run_accepts_double_dash_before_command() {
        let cmd = parse_from(os(&["run", "--profile", "dev", "--", "echo", "hi"]))
            .expect("run command should parse with leading --");
        let run = match cmd {
            Command::Run(run) => run,
            other => panic!("expected run, got {other:?}"),
        };
        assert_eq!(run.profile.as_deref(), Some("dev"));
        assert!(!run.verbose);
        assert_eq!(run.program, OsString::from("echo"));
        assert_eq!(run.args, vec![OsString::from("hi")]);
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
        assert_eq!(
            cmd,
            Command::Help {
                topic: HelpTopic::Root,
                verbose: false,
            }
        );
    }

    #[test]
    fn parse_profile_list_subcommand() {
        let cmd = parse_from(os(&["profile", "list"])).expect("profile list should parse");
        assert_eq!(
            cmd,
            Command::Profile(ProfileCommand {
                action: ProfileAction::List
            })
        );
    }

    #[test]
    fn parse_completion_without_shell() {
        let cmd = parse_from(os(&["completion"])).expect("completion should parse");
        assert_eq!(cmd, Command::Completion(CompletionCommand { shell: None }));
    }

    #[test]
    fn parse_daemon_accepts_optional_socket() {
        let cmd = parse_from(os(&["_daemon", "--socket", "/tmp/leashd.sock", "-v"]))
            .expect("_daemon should parse");
        assert_eq!(
            cmd,
            Command::LowLevelDaemon(LowLevelDaemonCommand {
                socket: Some(std::path::PathBuf::from("/tmp/leashd.sock")),
                verbose: true,
            })
        );
    }

    #[test]
    fn parse_completion_with_shell() {
        let cmd = parse_from(os(&["completion", "bash"])).expect("completion shell should parse");
        assert_eq!(
            cmd,
            Command::Completion(CompletionCommand {
                shell: Some("bash".to_string())
            })
        );
    }

    #[test]
    fn parse_profile_edit_subcommand() {
        let cmd =
            parse_from(os(&["profile", "edit", "default"])).expect("profile edit should parse");
        assert_eq!(
            cmd,
            Command::Profile(ProfileCommand {
                action: ProfileAction::Edit {
                    name: "default".to_string()
                }
            })
        );
    }

    #[test]
    fn parse_profile_show_subcommand() {
        let cmd =
            parse_from(os(&["profile", "show", "default"])).expect("profile show should parse");
        assert_eq!(
            cmd,
            Command::Profile(ProfileCommand {
                action: ProfileAction::Show {
                    name: "default".to_string()
                }
            })
        );
    }

    #[test]
    fn parse_profile_rm_subcommand() {
        let cmd = parse_from(os(&["profile", "rm", "default"])).expect("profile rm should parse");
        assert_eq!(
            cmd,
            Command::Profile(ProfileCommand {
                action: ProfileAction::Rm {
                    name: "default".to_string()
                }
            })
        );
    }

    #[test]
    fn parse_profile_show_defaults_to_default_name() {
        let cmd = parse_from(os(&["profile", "show"])).expect("profile show should default name");
        assert_eq!(
            cmd,
            Command::Profile(ProfileCommand {
                action: ProfileAction::Show {
                    name: DEFAULT_PROFILE.to_string()
                }
            })
        );
    }

    #[test]
    fn parse_profile_edit_defaults_to_default_name() {
        let cmd = parse_from(os(&["profile", "edit"])).expect("profile edit should default name");
        assert_eq!(
            cmd,
            Command::Profile(ProfileCommand {
                action: ProfileAction::Edit {
                    name: DEFAULT_PROFILE.to_string()
                }
            })
        );
    }

    #[test]
    fn parse_profile_rm_defaults_to_default_name() {
        let cmd = parse_from(os(&["profile", "rm"])).expect("profile rm should default name");
        assert_eq!(
            cmd,
            Command::Profile(ProfileCommand {
                action: ProfileAction::Rm {
                    name: DEFAULT_PROFILE.to_string()
                }
            })
        );
    }

    #[test]
    fn parse_help_profile_topic() {
        let cmd = parse_from(os(&["help", "profile"])).expect("help profile should parse");
        assert_eq!(
            cmd,
            Command::Help {
                topic: HelpTopic::Profile,
                verbose: false,
            }
        );
        let text = crate::cmd_help::help_text(HelpTopic::Profile, false);
        assert!(text.contains("ACTIONS:"));
        assert!(text.contains("ancestor-has="));
    }

    #[test]
    fn parse_help_supports_all_registered_topics() {
        for (name, topic) in crate::cmd_help::topic_names() {
            let cmd = parse_from(os(&["help", name]))
                .unwrap_or_else(|err| panic!("help topic '{name}' should parse: {err:#}"));
            assert_eq!(
                cmd,
                Command::Help {
                    topic: topic.clone(),
                    verbose: false,
                }
            );
            let text = crate::cmd_help::help_text(topic.clone(), false);
            assert!(!text.is_empty());
        }
    }

    #[test]
    fn parse_help_accepts_verbose_flag() {
        let cmd = parse_from(os(&["help", "-v"])).expect("help -v should parse");
        assert_eq!(
            cmd,
            Command::Help {
                topic: HelpTopic::Root,
                verbose: true,
            }
        );

        let cmd = parse_from(os(&["help", "run", "-v"])).expect("help run -v should parse");
        assert_eq!(
            cmd,
            Command::Help {
                topic: HelpTopic::Run,
                verbose: true,
            }
        );
    }

    #[test]
    fn parse_subcommand_help_flag() {
        let cmd = parse_from(os(&["run", "--help"])).expect("run help should parse");
        assert_eq!(
            cmd,
            Command::Help {
                topic: HelpTopic::Run,
                verbose: false,
            }
        );
    }

    #[test]
    fn parse_list_has_no_args() {
        let cmd = parse_from(os(&["_list"])).expect("_list should parse");
        assert_eq!(cmd, Command::LowLevelList(ListCommand));
    }

    #[test]
    fn parse_show_requires_one_or_more_selectors() {
        let err = parse_from(os(&["_show"])).expect_err("_show without selector should fail");
        assert!(err.to_string().contains("requires one or more"));
    }

    #[test]
    fn parse_show_accepts_name() {
        let cmd = parse_from(os(&["_show", "agent"])).expect("_show with name should parse");
        let show = match cmd {
            Command::LowLevelShow(show) => show,
            other => panic!("expected _show, got {other:?}"),
        };
        assert_eq!(show.selectors, vec!["agent"]);
        assert!(!show.verbose);
    }

    #[test]
    fn parse_show_verbose_flag() {
        let cmd = parse_from(os(&["_show", "-v", "agent"])).expect("_show -v should parse");
        let show = match cmd {
            Command::LowLevelShow(show) => show,
            other => panic!("expected _show, got {other:?}"),
        };
        assert_eq!(show.selectors, vec!["agent"]);
        assert!(show.verbose);
    }

    #[test]
    fn parse_show_accepts_multiple_selectors() {
        let cmd = parse_from(os(&["_show", "a*", "b"])).expect("_show selectors should parse");
        let show = match cmd {
            Command::LowLevelShow(show) => show,
            other => panic!("expected _show, got {other:?}"),
        };
        assert_eq!(show.selectors, vec!["a*", "b"]);
    }

    #[test]
    fn parse_show_rejects_legacy_flags() {
        let err =
            parse_from(os(&["_show", "--name", "a"])).expect_err("_show should reject --name");
        assert!(err.to_string().contains("no longer accepts --name"));

        let err = parse_from(os(&["_show", "--profile", "b"]))
            .expect_err("_show should reject --profile");
        assert!(err.to_string().contains("no longer accepts --profile"));
    }

    #[test]
    fn parse_rm_requires_one_or_more_selectors() {
        let err = parse_from(os(&["_rm"])).expect_err("_rm without selector should fail");
        assert!(err.to_string().contains("requires one or more"));
    }

    #[test]
    fn parse_rm_accepts_positional_name() {
        let cmd = parse_from(os(&["_rm", "agent"])).expect("_rm with positional name should parse");
        let rm = match cmd {
            Command::LowLevelRm(rm) => rm,
            other => panic!("expected _rm, got {other:?}"),
        };
        assert_eq!(rm.selectors, vec!["agent"]);
        assert!(!rm.verbose);
    }

    #[test]
    fn parse_rm_verbose_flag() {
        let cmd = parse_from(os(&["_rm", "-v", "agent"])).expect("_rm with -v should parse");
        let rm = match cmd {
            Command::LowLevelRm(rm) => rm,
            other => panic!("expected _rm, got {other:?}"),
        };
        assert_eq!(rm.selectors, vec!["agent"]);
        assert!(rm.verbose);
    }

    #[test]
    fn parse_rm_accepts_multiple_selectors() {
        let cmd = parse_from(os(&["_rm", "a*", "b"])).expect("_rm selectors should parse");
        let rm = match cmd {
            Command::LowLevelRm(rm) => rm,
            other => panic!("expected _rm, got {other:?}"),
        };
        assert_eq!(rm.selectors, vec!["a*", "b"]);
    }

    #[test]
    fn parse_run_rejects_unknown_name_flag() {
        let err = parse_from(os(&["run", "--name", "a", "echo"]))
            .expect_err("run no longer accepts --name");
        assert!(err.to_string().contains("no longer accepts --name"));
    }

    #[test]
    fn parse_root_help_can_list_hidden_commands() {
        let cmd = parse_from(os(&["--help", "-v"])).expect("verbose help should parse");
        assert_eq!(
            cmd,
            Command::Help {
                topic: HelpTopic::Root,
                verbose: true,
            }
        );
        let text = crate::cmd_help::help_text(HelpTopic::Root, true);
        assert!(text.contains("leash _suid"));
    }

    #[test]
    fn subcommand_help_matches_help_subcommand() {
        let via_flag = parse_from(os(&["run", "--help"])).expect("run --help should parse");
        let via_help = parse_from(os(&["help", "run"])).expect("help run should parse");
        assert_eq!(via_flag, via_help);
    }

    #[test]
    fn parse_low_level_help_topics() {
        let suid_help = parse_from(os(&["_suid", "--help"])).expect("_suid help should parse");
        assert_eq!(
            suid_help,
            Command::Help {
                topic: HelpTopic::LowLevelSuid,
                verbose: true,
            }
        );

        let list_help = parse_from(os(&["_list", "--help"])).expect("_list help should parse");
        assert_eq!(
            list_help,
            Command::Help {
                topic: HelpTopic::LowLevelList,
                verbose: true,
            }
        );

        let show_help = parse_from(os(&["_show", "--help"])).expect("_show help should parse");
        assert_eq!(
            show_help,
            Command::Help {
                topic: HelpTopic::LowLevelShow,
                verbose: true,
            }
        );

        let rm_help = parse_from(os(&["_rm", "--help"])).expect("_rm help should parse");
        assert_eq!(
            rm_help,
            Command::Help {
                topic: HelpTopic::LowLevelRm,
                verbose: true,
            }
        );
    }
}
