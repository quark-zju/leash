use crate::cli::HelpTopic;

const HELP_TOPIC_NAMES: &[(&str, HelpTopic)] = &[
    ("profile", HelpTopic::Profile),
    ("add", HelpTopic::Add),
    ("list", HelpTopic::List),
    ("rm", HelpTopic::Rm),
    ("run", HelpTopic::Run),
    ("flush", HelpTopic::Flush),
    ("_mount", HelpTopic::LowLevelMount),
    ("_flush", HelpTopic::LowLevelFlush),
    ("_fuse", HelpTopic::LowLevelFuse),
    ("_suid", HelpTopic::LowLevelSuid),
];

pub(crate) fn print_help(topic: HelpTopic, verbose: bool) {
    println!("{}", help_text(topic, verbose));
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

pub(crate) fn help_text(topic: HelpTopic, verbose: bool) -> &'static str {
    match topic {
        HelpTopic::Root if verbose => concat!(
            "cowjail\n\n",
            "USAGE:\n",
            "  cowjail <subcommand> [options]\n\n",
            "COMMON:\n",
            "  cowjail run [--name <name> | --profile <profile>] [-v|--verbose] command ...\n",
            "  cowjail flush [--name <name> | <name> | --profile <profile>] [--dry-run] [-v|--verbose]\n",
            "  cowjail help profile\n",
            "\n",
            "NAMED JAILS:\n",
            "  cowjail add [<name> | --name <name>] [--profile <profile>]\n",
            "  cowjail rm (<name> | --name <name> | --profile <profile>) [-v|--verbose]\n",
            "  cowjail list\n",
            "\n",
            "LOW-LEVEL (DEBUG):\n",
            "  cowjail _mount --profile <profile> --record <record_path> [-v|--verbose] <path>\n",
            "  cowjail _flush --record <record_path> [--profile <profile>] [--dry-run] [-v|--verbose]\n",
            "  cowjail _suid [-v|--verbose]\n\n",
            "  cowjail _fuse --profile <profile> --record <record_path> \\\n",
            "       --mountpoint <path> --pid-path <path> [--uid <uid>] [--gid <gid>] [-v|--verbose]\n\n",
            "Run `cowjail <subcommand> --help` for details.",
        ),
        HelpTopic::Root => concat!(
            "cowjail\n\n",
            "USAGE:\n",
            "  cowjail <subcommand> [options]\n\n",
            "COMMON:\n",
            "  cowjail run [--name <name> | --profile <profile>] [-v|--verbose] command ...\n",
            "  cowjail flush [--name <name> | <name> | --profile <profile>] [--dry-run] [-v|--verbose]\n",
            "  cowjail help profile\n\n",
            "NAMED JAILS:\n",
            "  cowjail add [<name> | --name <name>] [--profile <profile>]\n",
            "  cowjail rm (<name> | --name <name> | --profile <profile>) [-v|--verbose]\n",
            "  cowjail list\n\n",
            "Run `cowjail --help -v` to list low-level debugging commands.\n",
            "Run `cowjail <subcommand> --help` for details.",
        ),
        HelpTopic::Profile => concat!(
            "cowjail help profile\n\n",
            "PROFILE SYNTAX:\n",
            "  <pattern> <action>\n\n",
            "ACTIONS:\n",
            "  ro      Read-only visibility\n",
            "  rw      Writable passthrough (applies to host immediately)\n",
            "  cow     Writable copy-on-write (captured and applied by flush)\n",
            "  deny    Visible but access is denied (EACCES)\n",
            "  hide    Hidden/inaccessible (ENOENT)\n\n",
            "NOTES:\n",
            "  - Empty lines are ignored\n",
            "  - Lines starting with # are comments\n",
            "  - Rules are first-match wins\n",
            "  - `.` expands to launch cwd\n\n",
            "EXAMPLE:\n",
            "  /bin ro\n",
            "  /usr ro\n",
            "  /tmp rw\n",
            "  . cow\n",
            "  /home/*/.ssh deny",
        ),
        HelpTopic::Add => concat!(
            "cowjail add\n\n",
            "USAGE:\n",
            "  cowjail add [<name> | --name <name>] [--profile <profile>]\n\n",
            "NOTES:\n",
            "  () means required choice, [] means optional\n\n",
            "OPTIONS:\n",
            "  --name <name>         Explicit jail name (same as positional NAME)\n",
            "  --profile <profile>   Profile path. Default: default",
        ),
        HelpTopic::List => concat!("cowjail list\n\n", "USAGE:\n", "  cowjail list"),
        HelpTopic::Rm => concat!(
            "cowjail rm\n\n",
            "USAGE:\n",
            "  cowjail rm (<name> | --name <name> | --profile <profile>) [-v|--verbose]\n\n",
            "NOTES:\n",
            "  () means required choice, [] means optional\n\n",
            "OPTIONS:\n",
            "  --name <name>         Remove a jail by name (same as positional NAME)\n",
            "  --profile <profile>   Remove the jail selected by profile-derived identity\n",
            "  -v, --verbose         Print cleanup syscall progress",
        ),
        HelpTopic::Run => concat!(
            "cowjail run\n\n",
            "USAGE:\n",
            "  cowjail run [--name <name> | --profile <profile>] [-v|--verbose] command ...\n\n",
            "OPTIONS:\n",
            "  --name <name>         Reuse or create an explicit jail name\n",
            "  --profile <profile>   Select/create the profile-derived jail identity\n",
            "  -v, --verbose         Print progress logs",
        ),
        HelpTopic::LowLevelMount => concat!(
            "cowjail _mount\n\n",
            "USAGE:\n",
            "  cowjail _mount --profile <profile> --record <record_path> [-v|--verbose] <path>\n\n",
            "OPTIONS:\n",
            "  --profile <profile>   Profile path (required)\n",
            "  --record <record>     Record output path (required)\n",
            "  -v, --verbose         Print progress logs",
        ),
        HelpTopic::Flush => concat!(
            "cowjail flush\n\n",
            "USAGE:\n",
            "  cowjail flush [--name <name> | <name> | --profile <profile>] [--dry-run] [-v|--verbose]\n\n",
            "NOTES:\n",
            "  () means required choice, [] means optional\n\n",
            "OPTIONS:\n",
            "  --name <name>         Flush a jail by name (same as positional NAME)\n",
            "  --profile <profile>   Flush the jail selected by profile-derived identity\n",
            "  --dry-run             Preview without applying or marking flushed\n",
            "  -v, --verbose         Print progress logs",
        ),
        HelpTopic::LowLevelFlush => concat!(
            "cowjail _flush\n\n",
            "USAGE:\n",
            "  cowjail _flush --record <record_path> [--profile <profile>] [--dry-run] [-v|--verbose]\n\n",
            "OPTIONS:\n",
            "  --record <record>     Record path (required)\n",
            "  --profile <profile>   Replay policy profile override\n",
            "  --dry-run             Preview without applying or marking flushed\n",
            "  -v, --verbose         Print progress logs",
        ),
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
        ),
        HelpTopic::LowLevelSuid => concat!(
            "cowjail _suid\n\n",
            "USAGE:\n",
            "  cowjail _suid [-v|--verbose]\n\n",
            "DESCRIPTION:\n",
            "  Ensure current cowjail binary is setuid-root.\n",
            "  If not running as root, this command reinvokes itself via sudo.\n\n",
            "OPTIONS:\n",
            "  -v, --verbose         Print progress logs",
        ),
    }
}
