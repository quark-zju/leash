use crate::cli::HelpTopic;
use crate::profile_loader;

const HELP_TOPIC_NAMES: &[(&str, HelpTopic)] = &[
    ("profile", HelpTopic::Profile),
    ("completion", HelpTopic::Completion),
    ("run", HelpTopic::Run),
    ("_list", HelpTopic::LowLevelList),
    ("_show", HelpTopic::LowLevelShow),
    ("_rm", HelpTopic::LowLevelRm),
    ("_mount", HelpTopic::LowLevelMount),
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
            "leash help profile\n\n",
            "PROFILE SYNTAX:\n",
            "  <pattern> <action>\n\n",
            "ACTIONS:\n",
            "  ro      Read-only visibility\n",
            "  rw      Writable passthrough (applies to host immediately)\n",
            "  git-rw  Writable only inside detected git working trees\n",
            "  deny    Visible but access is denied (EACCES)\n",
            "  hide    Hidden/inaccessible (ENOENT)\n\n",
            "NOTES:\n",
            "  - Empty lines are ignored\n",
            "  - Lines starting with # are comments\n",
            "  - Directive: %include <name> (named profile or builtin:name; missing file ignored)\n",
            "  - builtin:name profiles are read-only; use profile show, not profile edit\n",
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
            "leash completion\n\n",
            "USAGE:\n",
            "  leash completion [bash|zsh|fish]\n\n",
            "DESCRIPTION:\n",
            "  Print shell completion script to stdout.\n",
            "  If shell is omitted, detect from SHELL.\n\n",
            "EXAMPLE:\n",
            "  source <(leash completion)\n",
        )
        .to_string(),
        HelpTopic::LowLevelList => {
            concat!("leash _list\n\n", "USAGE:\n", "  leash _list").to_string()
        }
        HelpTopic::LowLevelShow => concat!(
            "leash _show\n\n",
            "USAGE:\n",
            "  leash _show [-v|--verbose] <name-or-glob> [<name-or-glob> ...]\n\n",
            "DESCRIPTION:\n",
            "  Print low-level jail profile state for one or more runtime names.\n\n",
            "OPTIONS:\n",
            "  -v, --verbose         Reserved for extra debug output"
        )
        .to_string(),
        HelpTopic::LowLevelRm => concat!(
            "leash _rm\n\n",
            "USAGE:\n",
            "  leash _rm [-v|--verbose] <name-or-glob> [<name-or-glob> ...]\n\n",
            "OPTIONS:\n",
            "  -v, --verbose         Print cleanup syscall progress"
        )
        .to_string(),
        HelpTopic::Run => concat!(
            "leash run\n\n",
            "USAGE:\n",
            "  leash run [--profile <profile>] [-v|--verbose] command ...\n\n",
            "OPTIONS:\n",
            "  --profile <profile>   Select/create the profile-derived jail identity\n",
            "  -v, --verbose         Print progress logs\n\n",
            "TROUBLESHOOTING:\n",
            "  Profile behavior and rule matching: leash help profile",
        )
        .to_string(),
        HelpTopic::LowLevelMount => concat!(
            "leash _mount\n\n",
            "USAGE:\n",
            "  leash _mount --profile <profile> [-v|--verbose] <path>\n\n",
            "OPTIONS:\n",
            "  --profile <profile>   Profile path (required)\n",
            "  -v, --verbose         Print progress logs",
        )
        .to_string(),
        HelpTopic::LowLevelFuse => concat!(
            "leash _fuse\n\n",
            "USAGE:\n",
            "  leash _fuse --profile <profile> --mountpoint <path> \\\n",
            "       --pid-path <path> [-v|--verbose]\n\n",
            "OPTIONS:\n",
            "  --profile <profile>   Profile path (required)\n",
            "  --mountpoint <path>   Mountpoint inside target mntns (required)\n",
            "  --pid-path <path>     PID file path (required)\n",
            "  -v, --verbose         Print progress logs",
        )
        .to_string(),
        HelpTopic::LowLevelSuid => concat!(
            "leash _suid\n\n",
            "USAGE:\n",
            "  leash _suid [-v|--verbose]\n\n",
            "DESCRIPTION:\n",
            "  Ensure current leash binary is setuid-root.\n",
            "  If not running as root, this command reinvokes itself via sudo.\n\n",
            "OPTIONS:\n",
            "  -v, --verbose         Print progress logs",
        )
        .to_string(),
    }
}

fn root_help_text(verbose: bool) -> String {
    let mut out = String::from(concat!(
        "leash\n\n",
        "USAGE:\n",
        "  leash <subcommand> [options]\n\n",
        "COMMON:\n",
        "  leash run [--profile <profile>] [-v|--verbose] command ...\n",
        "\n",
        "PROFILE:\n",
        "  leash profile edit [name]\n",
        "  leash profile show [name]\n",
        "  leash profile list\n",
        "  leash profile rm [name]\n",
        "  leash help profile\n",
    ));
    if verbose {
        out.push_str(concat!(
            "\n",
            "LOW-LEVEL (DEBUG):\n",
            "  leash _list\n",
            "  leash _show [-v|--verbose] <name-or-glob> [<name-or-glob> ...]\n",
            "  leash _rm [-v|--verbose] <name-or-glob> [<name-or-glob> ...]\n",
            "  leash _mount --profile <profile> [-v|--verbose] <path>\n",
            "  leash _suid [-v|--verbose]\n\n",
            "  leash _fuse --profile <profile> \\\n",
            "       --mountpoint <path> --pid-path <path> [-v|--verbose]\n",
        ));
    }
    out.push('\n');
    out.push_str(if verbose {
        "Run `leash <subcommand> --help` for details."
    } else {
        "Run `leash --help -v` to list low-level debugging commands.\nRun `leash <subcommand> --help` for details."
    });
    out
}

fn profile_help_text() -> String {
    let mut out = String::from(help_text(HelpTopic::Profile, false));
    out.push_str(
        "\n\nEFFECTIVE DEFAULT PROFILE SOURCE (`~/.config/leash/profiles/default` if present; otherwise built-in):\n",
    );
    for line in profile_loader::default_profile_source_for_help().lines() {
        out.push_str("  ");
        out.push_str(line);
        out.push('\n');
    }
    out.push_str("\nTo reset to built-in default, run: leash profile rm default\n");
    out
}
