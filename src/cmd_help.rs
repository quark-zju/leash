use crate::cli::HelpTopic;
use crate::profile_loader;

const HELP_TOPIC_NAMES: &[(&str, HelpTopic)] = &[
    ("profile", HelpTopic::Profile),
    ("completion", HelpTopic::Completion),
    ("add", HelpTopic::Add),
    ("list", HelpTopic::List),
    ("show", HelpTopic::Show),
    ("rm", HelpTopic::Rm),
    ("run", HelpTopic::Run),
    ("flush", HelpTopic::Flush),
    ("_mount", HelpTopic::LowLevelMount),
    ("_flush", HelpTopic::LowLevelFlush),
    ("_fuse", HelpTopic::LowLevelFuse),
    ("_suid", HelpTopic::LowLevelSuid),
];

pub(crate) fn print_help(topic: HelpTopic, verbose: bool) {
    match topic {
        HelpTopic::Profile => println!("{}", profile_help_text()),
        _ => println!("{}", help_text(topic, verbose)),
    }
}

pub(crate) fn topic_from_name(name: &str) -> Option<HelpTopic> {
    HELP_TOPIC_NAMES
        .iter()
        .find_map(|(n, topic)| (*n == name).then_some(topic.clone()))
}

#[cfg(test)]
pub(crate) fn topic_names() -> &'static [(&'static str, HelpTopic)] {
    HELP_TOPIC_NAMES
}

pub(crate) fn help_text(topic: HelpTopic, verbose: bool) -> String {
    match topic {
        HelpTopic::Root => root_help_text(verbose),
        HelpTopic::Profile => concat!(
            "cowjail help profile\n\n",
            "PROFILE SYNTAX:\n",
            "  <pattern> <action>\n\n",
            "ACTIONS:\n",
            "  ro      Read-only visibility\n",
            "  rw      Writable passthrough (applies to host immediately)\n",
            "  git-rw  Writable only inside detected git working trees\n",
            "  cow     Writable copy-on-write (captured and applied by flush)\n",
            "  deny    Visible but access is denied (EACCES)\n",
            "  hide    Hidden/inaccessible (ENOENT)\n\n",
            "NOTES:\n",
            "  - Empty lines are ignored\n",
            "  - Lines starting with # are comments\n",
            "  - Directive: %set max_size = <size|none> (default: 2gb)\n",
            "  - Directive: %include <name> (short profile name only; missing file ignored)\n",
            "  - Globs are supported; `*` does not cross `/`, use `**` for any depth (including 0)\n",
            "  - Rules are first-match wins\n",
            "  - `.` expands to launch cwd\n\n",
            "EXAMPLE:\n",
            "  /bin ro\n",
            "  /usr ro\n",
            "  /tmp rw\n",
            "  . git-rw\n",
            "  /home/*/.ssh deny",
        )
        .to_string(),
        HelpTopic::Completion => concat!(
            "cowjail completion\n\n",
            "USAGE:\n",
            "  cowjail completion [bash|zsh|fish]\n\n",
            "DESCRIPTION:\n",
            "  Print shell completion script to stdout.\n",
            "  If shell is omitted, detect from SHELL.\n\n",
            "EXAMPLE:\n",
            "  source <(cowjail completion)\n",
        )
        .to_string(),
        HelpTopic::Add => concat!(
            "cowjail add\n\n",
            "USAGE:\n",
            "  cowjail add [<name> | --name <name>] [--profile <profile>]\n\n",
            "NOTES:\n",
            "  () means required choice, [] means optional\n\n",
            "OPTIONS:\n",
            "  --name <name>         Explicit jail name (same as positional NAME)\n",
            "  --profile <profile>   Profile path. Default: default",
        )
        .to_string(),
        HelpTopic::List => concat!("cowjail list\n\n", "USAGE:\n", "  cowjail list").to_string(),
        HelpTopic::Show => concat!(
            "cowjail show\n\n",
            "USAGE:\n",
            "  cowjail show [--name <name> | <name> | --profile <profile>] [-v|--verbose]\n\n",
            "NOTES:\n",
            "  () means required choice, [] means optional\n\n",
            "DESCRIPTION:\n",
            "  Print jail profile and pending unflushed write-op count.\n\n",
            "OPTIONS:\n",
            "  --name <name>         Show a jail by name (same as positional NAME)\n",
            "  --profile <profile>   Show the jail selected by profile-derived identity\n",
            "  -v, --verbose         Also print pending write paths"
        )
        .to_string(),
        HelpTopic::Rm => concat!(
            "cowjail rm\n\n",
            "USAGE:\n",
            "  cowjail rm (<name> | --name <name> | --profile <profile>) [-v|--verbose]\n\n",
            "NOTES:\n",
            "  () means required choice, [] means optional\n\n",
            "OPTIONS:\n",
            "  --name <name>         Remove by jail name or glob (same as positional NAME)\n",
            "  --profile <profile>   Remove the jail selected by profile-derived identity\n",
            "  --allow-dirty         Skip pending-write warning and delay before remove\n",
            "  -v, --verbose         Print cleanup syscall progress",
        )
        .to_string(),
        HelpTopic::Run => concat!(
            "cowjail run\n\n",
            "USAGE:\n",
            "  cowjail run [--name <name> | --profile <profile>] [-v|--verbose] command ...\n\n",
            "OPTIONS:\n",
            "  --name <name>         Reuse or create an explicit jail name\n",
            "  --profile <profile>   Select/create the profile-derived jail identity\n",
            "  -v, --verbose         Print progress logs\n\n",
            "TROUBLESHOOTING:\n",
            "  Profile behavior and rule matching: cowjail help profile",
        )
        .to_string(),
        HelpTopic::LowLevelMount => concat!(
            "cowjail _mount\n\n",
            "USAGE:\n",
            "  cowjail _mount --profile <profile> --record <record_path> [-v|--verbose] <path>\n\n",
            "OPTIONS:\n",
            "  --profile <profile>   Profile path (required)\n",
            "  --record <record>     Record output path (required)\n",
            "  -v, --verbose         Print progress logs",
        )
        .to_string(),
        HelpTopic::Flush => concat!(
            "cowjail flush\n\n",
            "USAGE:\n",
            "  cowjail flush [--name <name> | <name> | --profile <profile>] [-n|--dry-run] [-v|--verbose]\n\n",
            "NOTES:\n",
            "  () means required choice, [] means optional\n\n",
            "OPTIONS:\n",
            "  --name <name>         Flush a jail by name (same as positional NAME)\n",
            "  --profile <profile>   Flush the jail selected by profile-derived identity\n",
            "  -n, --dry-run         Preview without applying or marking flushed\n",
            "  -v, --verbose         Print progress logs",
        )
        .to_string(),
        HelpTopic::LowLevelFlush => concat!(
            "cowjail _flush\n\n",
            "USAGE:\n",
            "  cowjail _flush --record <record_path> [--profile <profile>] [-n|--dry-run] [-v|--verbose]\n\n",
            "OPTIONS:\n",
            "  --record <record>     Record path (required)\n",
            "  --profile <profile>   Replay policy profile override\n",
            "  -n, --dry-run         Preview without applying or marking flushed\n",
            "  -v, --verbose         Print progress logs",
        )
        .to_string(),
        HelpTopic::LowLevelFuse => concat!(
            "cowjail _fuse\n\n",
            "USAGE:\n",
            "  cowjail _fuse --profile <profile> --record <record_path> --mountpoint <path> \\\n",
            "       --pid-path <path> [-v|--verbose]\n\n",
            "OPTIONS:\n",
            "  --profile <profile>   Profile path (required)\n",
            "  --record <record>     Record output path (required)\n",
            "  --mountpoint <path>   Mountpoint inside target mntns (required)\n",
            "  --pid-path <path>     PID file path (required)\n",
            "  -v, --verbose         Print progress logs",
        )
        .to_string(),
        HelpTopic::LowLevelSuid => concat!(
            "cowjail _suid\n\n",
            "USAGE:\n",
            "  cowjail _suid [-v|--verbose]\n\n",
            "DESCRIPTION:\n",
            "  Ensure current cowjail binary is setuid-root.\n",
            "  If not running as root, this command reinvokes itself via sudo.\n\n",
            "OPTIONS:\n",
            "  -v, --verbose         Print progress logs",
        )
        .to_string(),
    }
}

fn root_help_text(verbose: bool) -> String {
    let mut out = String::from(concat!(
        "cowjail\n\n",
        "USAGE:\n",
        "  cowjail <subcommand> [options]\n\n",
        "COMMON:\n",
        "  cowjail run [--name <name> | --profile <profile>] [-v|--verbose] command ...\n",
        "  cowjail flush [--name <name> | <name> | --profile <profile>] [-n|--dry-run] [-v|--verbose]\n",
        "  cowjail help profile\n\n",
        "PROFILE:\n",
        "  cowjail profile list\n",
        "  cowjail profile show [name]\n",
        "  cowjail profile edit [name]\n",
        "  cowjail profile rm [name]\n\n",
        "NAMED JAILS:\n",
        "  cowjail add [<name> | --name <name>] [--profile <profile>]\n",
        "  cowjail show <name>\n",
        "  cowjail rm (<name> | --name <name> | --profile <profile>) [-v|--verbose]\n",
        "  cowjail list\n",
    ));
    if verbose {
        out.push_str(concat!(
            "\n",
            "LOW-LEVEL (DEBUG):\n",
            "  cowjail _mount --profile <profile> --record <record_path> [-v|--verbose] <path>\n",
            "  cowjail _flush --record <record_path> [--profile <profile>] [-n|--dry-run] [-v|--verbose]\n",
            "  cowjail _suid [-v|--verbose]\n\n",
            "  cowjail _fuse --profile <profile> --record <record_path> \\\n",
            "       --mountpoint <path> --pid-path <path> [-v|--verbose]\n",
        ));
    }
    out.push('\n');
    out.push_str(if verbose {
        "Run `cowjail <subcommand> --help` for details."
    } else {
        "Run `cowjail --help -v` to list low-level debugging commands.\nRun `cowjail <subcommand> --help` for details."
    });
    out
}

fn profile_help_text() -> String {
    let mut out = String::from(help_text(HelpTopic::Profile, false));
    out.push_str(
        "\n\nEFFECTIVE DEFAULT PROFILE SOURCE (`~/.config/cowjail/profiles/default` if present; otherwise built-in):\n",
    );
    for line in profile_loader::default_profile_source_for_help().lines() {
        out.push_str("  ");
        out.push_str(line);
        out.push('\n');
    }
    out.push_str("\nTo reset to built-in default, run: cowjail profile rm default\n");
    out
}
