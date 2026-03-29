use std::convert::Infallible;
use std::ffi::OsString;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use pico_args::Arguments;

pub const DEFAULT_PROFILE: &str = "default";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Help { topic: HelpTopic, verbose: bool },
    Completion(CompletionCommand),
    Profile(ProfileCommand),
    Add(AddCommand),
    List(ListCommand),
    Show(ShowCommand),
    Rm(RmCommand),
    Run(RunCommand),
    Flush(FlushCommand),
    LowLevelMount(MountCommand),
    LowLevelFlush(LowLevelFlushCommand),
    LowLevelFuse(LowLevelFuseCommand),
    LowLevelSuid(LowLevelSuidCommand),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelpTopic {
    Root,
    Profile,
    Add,
    List,
    Show,
    Rm,
    Run,
    Flush,
    Completion,
    LowLevelMount,
    LowLevelFlush,
    LowLevelFuse,
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
pub struct AddCommand {
    pub name: Option<String>,
    pub profile: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListCommand;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShowCommand {
    pub name: Option<String>,
    pub profile: Option<String>,
    pub verbose: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RmCommand {
    pub name: Option<String>,
    pub profile: Option<String>,
    pub verbose: bool,
    pub allow_dirty: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunCommand {
    pub name: Option<String>,
    pub profile: Option<String>,
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
    pub name: Option<String>,
    pub profile: Option<String>,
    pub dry_run: bool,
    pub verbose: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LowLevelFlushCommand {
    pub record: PathBuf,
    pub profile: Option<String>,
    pub dry_run: bool,
    pub verbose: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LowLevelFuseCommand {
    pub profile: String,
    pub record: PathBuf,
    pub mountpoint: PathBuf,
    pub pid_path: PathBuf,
    pub verbose: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LowLevelSuidCommand {
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
        anyhow::anyhow!(
            "missing subcommand (expected: completion, profile, add, list, show, rm, run, flush)"
        )
    })?;

    let command = match subcmd.as_str() {
        "help" => parse_help(args)?,
        "completion" => parse_completion(args)?,
        "profile" => parse_profile(args)?,
        "add" => parse_add(args)?,
        "list" => parse_list(args)?,
        "show" => parse_show(args)?,
        "rm" => parse_rm(args)?,
        "run" => parse_run(args)?,
        "flush" => parse_flush(args)?,
        "_mount" => parse_mount(args)?,
        "_flush" => parse_low_level_flush(args)?,
        "_fuse" => parse_low_level_fuse(args)?,
        "_suid" => parse_low_level_suid(args)?,
        other => bail!("unknown subcommand: {other}"),
    };

    Ok(command)
}

fn parse_help(args: Arguments) -> Result<Command> {
    let extra = args.finish();
    if extra.is_empty() {
        return Ok(help_command(HelpTopic::Root, false));
    }
    if extra.len() > 1 {
        bail!("help got unexpected trailing arguments");
    }
    let topic = extra[0]
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("help topic must be valid UTF-8"))?;
    let topic = crate::cmd_help::topic_from_name(topic)
        .ok_or_else(|| anyhow::anyhow!("unknown help topic: {topic}"))?;
    Ok(help_command(topic, false))
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
        "edit" => {
            if extra.len() > 2 {
                bail!("profile edit got unexpected trailing arguments");
            }
            let name = if extra.len() == 2 {
                extra[1]
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("profile NAME must be valid UTF-8"))?
                    .to_string()
            } else {
                DEFAULT_PROFILE.to_string()
            };
            Ok(Command::Profile(ProfileCommand {
                action: ProfileAction::Edit { name },
            }))
        }
        "show" => {
            if extra.len() > 2 {
                bail!("profile show got unexpected trailing arguments");
            }
            let name = if extra.len() == 2 {
                extra[1]
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("profile NAME must be valid UTF-8"))?
                    .to_string()
            } else {
                DEFAULT_PROFILE.to_string()
            };
            Ok(Command::Profile(ProfileCommand {
                action: ProfileAction::Show { name },
            }))
        }
        "rm" => {
            if extra.len() > 2 {
                bail!("profile rm got unexpected trailing arguments");
            }
            let name = if extra.len() == 2 {
                extra[1]
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("profile NAME must be valid UTF-8"))?
                    .to_string()
            } else {
                DEFAULT_PROFILE.to_string()
            };
            Ok(Command::Profile(ProfileCommand {
                action: ProfileAction::Rm { name },
            }))
        }
        other => bail!("unknown profile subcommand: {other}"),
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
    let name = args.opt_value_from_str("--name")?;
    let profile = args.opt_value_from_str("--profile")?;
    if name.is_some() && profile.is_some() {
        bail!("run accepts only one of --name <name> or --profile <profile>");
    }

    let mut trailing = args.finish();
    if trailing.is_empty() {
        bail!("run requires a command to execute");
    }

    let program = trailing.remove(0);
    Ok(Command::Run(RunCommand {
        name,
        profile,
        verbose,
        program,
        args: trailing,
    }))
}

fn parse_add(mut args: Arguments) -> Result<Command> {
    if args.contains(["-h", "--help"]) {
        return Ok(help_command(HelpTopic::Add, false));
    }
    let name_flag = args.opt_value_from_str("--name")?;
    let profile = args.opt_value_from_str("--profile")?;
    let extra = args.finish();
    if extra.len() > 1 {
        bail!("add got unexpected trailing arguments");
    }
    let positional_name = extra.first().map(|raw| {
        raw.to_str()
            .ok_or_else(|| anyhow::anyhow!("add NAME must be valid UTF-8"))
            .map(ToOwned::to_owned)
    });
    let positional_name = positional_name.transpose()?;
    if name_flag.is_some() && positional_name.is_some() {
        bail!("add accepts only one NAME source: positional NAME or --name <name>");
    }
    let name = name_flag.or(positional_name);
    if name.is_none() && profile.is_none() {
        bail!("add requires NAME, --name <name>, or --profile <profile>");
    }
    Ok(Command::Add(AddCommand { name, profile }))
}

fn parse_list(mut args: Arguments) -> Result<Command> {
    if args.contains(["-h", "--help"]) {
        return Ok(help_command(HelpTopic::List, false));
    }
    let extra = args.finish();
    if !extra.is_empty() {
        bail!("list got unexpected trailing arguments");
    }
    Ok(Command::List(ListCommand))
}

fn parse_show(mut args: Arguments) -> Result<Command> {
    if args.contains(["-h", "--help"]) {
        return Ok(help_command(HelpTopic::Show, false));
    }
    let verbose = args.contains(["-v", "--verbose"]);
    let selector = parse_optional_jail_selector(args, "show")?;
    Ok(Command::Show(ShowCommand {
        name: selector.name,
        profile: selector.profile,
        verbose,
    }))
}

fn parse_rm(mut args: Arguments) -> Result<Command> {
    if args.contains(["-h", "--help"]) {
        return Ok(help_command(HelpTopic::Rm, false));
    }
    let verbose = args.contains(["-v", "--verbose"]);
    let allow_dirty = args.contains("--allow-dirty");
    let selector = parse_optional_jail_selector(args, "rm")?;
    let name = selector.name;
    let profile = selector.profile;
    if name.is_none() && profile.is_none() {
        bail!("rm requires NAME, --name <name>, or --profile <profile>");
    }
    Ok(Command::Rm(RmCommand {
        name,
        profile,
        verbose,
        allow_dirty,
    }))
}

fn parse_mount(mut args: Arguments) -> Result<Command> {
    if args.contains(["-h", "--help"]) {
        return Ok(help_command(HelpTopic::LowLevelMount, true));
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

    Ok(Command::LowLevelMount(MountCommand {
        profile,
        record,
        verbose,
        path,
    }))
}

fn parse_flush(mut args: Arguments) -> Result<Command> {
    if args.contains(["-h", "--help"]) {
        return Ok(help_command(HelpTopic::Flush, false));
    }
    let verbose = args.contains(["-v", "--verbose"]);
    let dry_run = args.contains(["-n", "--dry-run"]);
    let selector = parse_optional_jail_selector(args, "flush")?;

    Ok(Command::Flush(FlushCommand {
        name: selector.name,
        profile: selector.profile,
        dry_run,
        verbose,
    }))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct JailSelector {
    name: Option<String>,
    profile: Option<String>,
}

fn parse_optional_jail_selector(mut args: Arguments, command: &str) -> Result<JailSelector> {
    let name_flag = args.opt_value_from_str("--name")?;
    let profile = args.opt_value_from_str("--profile")?;
    let extra = args.finish();
    if extra.len() > 1 {
        bail!("{command} got unexpected trailing arguments");
    }
    let positional_name = extra.first().map(|raw| {
        raw.to_str()
            .ok_or_else(|| anyhow::anyhow!("{command} NAME must be valid UTF-8"))
            .map(ToOwned::to_owned)
    });
    let positional_name = positional_name.transpose()?;
    if name_flag.is_some() && positional_name.is_some() {
        bail!("{command} accepts only one NAME source: positional NAME or --name <name>");
    }
    let name = name_flag.or(positional_name);
    if name.is_some() && profile.is_some() {
        bail!("{command} accepts only one of --name <name> or --profile <profile>");
    }
    Ok(JailSelector { name, profile })
}

fn parse_low_level_flush(mut args: Arguments) -> Result<Command> {
    if args.contains(["-h", "--help"]) {
        return Ok(help_command(HelpTopic::LowLevelFlush, true));
    }
    let verbose = args.contains(["-v", "--verbose"]);
    let dry_run = args.contains(["-n", "--dry-run"]);
    let profile = args.opt_value_from_str("--profile")?;
    let record = args
        .value_from_os_str("--record", parse_pathbuf)
        .context("_flush requires --record <record_path>")?;

    let extra = args.finish();
    if !extra.is_empty() {
        bail!("_flush got unexpected trailing arguments");
    }

    Ok(Command::LowLevelFlush(LowLevelFlushCommand {
        record,
        profile,
        dry_run,
        verbose,
    }))
}

fn parse_low_level_fuse(mut args: Arguments) -> Result<Command> {
    if args.contains(["-h", "--help"]) {
        return Ok(help_command(HelpTopic::LowLevelFuse, true));
    }
    let verbose = args.contains(["-v", "--verbose"]);
    let profile = args
        .value_from_str("--profile")
        .context("_fuse requires --profile <profile>")?;
    let record = args
        .value_from_os_str("--record", parse_pathbuf)
        .context("_fuse requires --record <record_path>")?;
    let mountpoint = args
        .value_from_os_str("--mountpoint", parse_pathbuf)
        .context("_fuse requires --mountpoint <path>")?;
    let pid_path = args
        .value_from_os_str("--pid-path", parse_pathbuf)
        .context("_fuse requires --pid-path <path>")?;

    let extra = args.finish();
    if !extra.is_empty() {
        bail!("_fuse got unexpected trailing arguments");
    }

    Ok(Command::LowLevelFuse(LowLevelFuseCommand {
        profile,
        record,
        mountpoint,
        pid_path,
        verbose,
    }))
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
        assert!(run.name.is_none());
        assert!(run.profile.is_none());
        assert!(!run.verbose);
        assert_eq!(run.program, OsString::from("echo"));
        assert_eq!(run.args, vec![OsString::from("hi")]);
    }

    #[test]
    fn parse_mount_requires_all_flags() {
        let err = parse_from(os(&["_mount", "./mnt"]))
            .expect_err("_mount without required flags should fail");
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
        assert!(flush.name.is_none());
        assert!(flush.profile.is_none());
    }

    #[test]
    fn parse_flush_short_dry_run() {
        let cmd = parse_from(os(&["flush", "-n"])).expect("flush should parse with short dry-run");
        let flush = match cmd {
            Command::Flush(flush) => flush,
            other => panic!("expected flush, got {other:?}"),
        };
        assert!(flush.dry_run);
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
        assert!(text.contains("cow"));
        assert!(text.contains("git-rw"));
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
    fn parse_add_accepts_positional_name() {
        let cmd = parse_from(os(&["add", "dev"])).expect("add with positional name should parse");
        let add = match cmd {
            Command::Add(add) => add,
            other => panic!("expected add, got {other:?}"),
        };
        assert_eq!(add.name.as_deref(), Some("dev"));
        assert!(add.profile.is_none());
    }

    #[test]
    fn parse_list_has_no_args() {
        let cmd = parse_from(os(&["list"])).expect("list should parse");
        assert_eq!(cmd, Command::List(ListCommand));
    }

    #[test]
    fn parse_show_accepts_implicit_selector() {
        let cmd = parse_from(os(&["show"])).expect("show without selector should parse");
        let show = match cmd {
            Command::Show(show) => show,
            other => panic!("expected show, got {other:?}"),
        };
        assert!(show.name.is_none());
        assert!(show.profile.is_none());
        assert!(!show.verbose);
    }

    #[test]
    fn parse_show_accepts_name() {
        let cmd = parse_from(os(&["show", "agent"])).expect("show with name should parse");
        let show = match cmd {
            Command::Show(show) => show,
            other => panic!("expected show, got {other:?}"),
        };
        assert_eq!(show.name.as_deref(), Some("agent"));
        assert!(show.profile.is_none());
        assert!(!show.verbose);
    }

    #[test]
    fn parse_show_verbose_flag() {
        let cmd = parse_from(os(&["show", "-v", "agent"])).expect("show -v should parse");
        let show = match cmd {
            Command::Show(show) => show,
            other => panic!("expected show, got {other:?}"),
        };
        assert_eq!(show.name.as_deref(), Some("agent"));
        assert!(show.profile.is_none());
        assert!(show.verbose);
    }

    #[test]
    fn parse_show_accepts_profile_selector() {
        let cmd = parse_from(os(&["show", "--profile", "dev"])).expect("show profile should parse");
        let show = match cmd {
            Command::Show(show) => show,
            other => panic!("expected show, got {other:?}"),
        };
        assert!(show.name.is_none());
        assert_eq!(show.profile.as_deref(), Some("dev"));
    }

    #[test]
    fn parse_show_requires_exactly_one_selector_source() {
        let err = parse_from(os(&["show", "--name", "a", "b"]))
            .expect_err("show with positional and --name should fail");
        assert!(err.to_string().contains("only one NAME source"));

        let err = parse_from(os(&["show", "--name", "a", "--profile", "b"]))
            .expect_err("show with name and profile should fail");
        assert!(err.to_string().contains("only one of"));
    }

    #[test]
    fn parse_rm_requires_exactly_one_selector() {
        let err = parse_from(os(&["rm"])).expect_err("rm without selector should fail");
        assert!(err.to_string().contains("rm requires"));

        let err = parse_from(os(&["rm", "--name", "a", "--profile", "b"]))
            .expect_err("rm with two selectors should fail");
        assert!(err.to_string().contains("only one of"));
    }

    #[test]
    fn parse_rm_accepts_positional_name() {
        let cmd = parse_from(os(&["rm", "agent"])).expect("rm with positional name should parse");
        let rm = match cmd {
            Command::Rm(rm) => rm,
            other => panic!("expected rm, got {other:?}"),
        };
        assert_eq!(rm.name.as_deref(), Some("agent"));
        assert!(rm.profile.is_none());
        assert!(!rm.verbose);
        assert!(!rm.allow_dirty);
    }

    #[test]
    fn parse_rm_verbose_flag() {
        let cmd = parse_from(os(&["rm", "-v", "agent"])).expect("rm with -v should parse");
        let rm = match cmd {
            Command::Rm(rm) => rm,
            other => panic!("expected rm, got {other:?}"),
        };
        assert_eq!(rm.name.as_deref(), Some("agent"));
        assert!(rm.verbose);
        assert!(!rm.allow_dirty);
    }

    #[test]
    fn parse_rm_allow_dirty_flag() {
        let cmd = parse_from(os(&["rm", "--allow-dirty", "agent"]))
            .expect("rm with --allow-dirty should parse");
        let rm = match cmd {
            Command::Rm(rm) => rm,
            other => panic!("expected rm, got {other:?}"),
        };
        assert_eq!(rm.name.as_deref(), Some("agent"));
        assert!(rm.allow_dirty);
    }

    #[test]
    fn parse_flush_accepts_positional_name() {
        let cmd =
            parse_from(os(&["flush", "agent"])).expect("flush with positional name should parse");
        let flush = match cmd {
            Command::Flush(flush) => flush,
            other => panic!("expected flush, got {other:?}"),
        };
        assert_eq!(flush.name.as_deref(), Some("agent"));
        assert!(flush.profile.is_none());
    }

    #[test]
    fn parse_run_requires_exactly_one_selector() {
        let err = parse_from(os(&["run", "--name", "a", "--profile", "b", "echo"]))
            .expect_err("run with two selectors should fail");
        assert!(err.to_string().contains("only one of"));
    }

    #[test]
    fn parse_flush_requires_exactly_one_selector() {
        let err = parse_from(os(&["flush", "--name", "a", "--profile", "b"]))
            .expect_err("flush with two selectors should fail");
        assert!(err.to_string().contains("only one of"));
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
        assert!(text.contains("cowjail _mount"));
        assert!(text.contains("cowjail _flush"));
        assert!(text.contains("cowjail _suid"));
    }

    #[test]
    fn subcommand_help_matches_help_subcommand() {
        let via_flag = parse_from(os(&["run", "--help"])).expect("run --help should parse");
        let via_help = parse_from(os(&["help", "run"])).expect("help run should parse");
        assert_eq!(via_flag, via_help);
    }

    #[test]
    fn parse_low_level_flush_requires_record() {
        let err = parse_from(os(&["_flush"])).expect_err("_flush without record should fail");
        assert!(err.to_string().contains("_flush requires --record"));
    }

    #[test]
    fn parse_low_level_flush_short_dry_run() {
        let cmd = parse_from(os(&["_flush", "-n", "--record", "/tmp/r"]))
            .expect("_flush should parse with short dry-run");
        let flush = match cmd {
            Command::LowLevelFlush(flush) => flush,
            other => panic!("expected low-level flush, got {other:?}"),
        };
        assert!(flush.dry_run);
    }

    #[test]
    fn parse_low_level_help_topics() {
        let mount_help = parse_from(os(&["_mount", "--help"])).expect("_mount help should parse");
        assert_eq!(
            mount_help,
            Command::Help {
                topic: HelpTopic::LowLevelMount,
                verbose: true,
            }
        );

        let flush_help = parse_from(os(&["_flush", "--help"])).expect("_flush help should parse");
        assert_eq!(
            flush_help,
            Command::Help {
                topic: HelpTopic::LowLevelFlush,
                verbose: true,
            }
        );

        let fuse_help = parse_from(os(&["_fuse", "--help"])).expect("_fuse help should parse");
        assert_eq!(
            fuse_help,
            Command::Help {
                topic: HelpTopic::LowLevelFuse,
                verbose: true,
            }
        );

        let suid_help = parse_from(os(&["_suid", "--help"])).expect("_suid help should parse");
        assert_eq!(
            suid_help,
            Command::Help {
                topic: HelpTopic::LowLevelSuid,
                verbose: true,
            }
        );
    }
}
