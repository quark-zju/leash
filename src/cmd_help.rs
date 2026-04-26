use crate::cli::HelpTopic;

const HELP_TOPIC_NAMES: &[(&str, HelpTopic)] = &[
    ("run", HelpTopic::Run),
    ("tail", HelpTopic::Tail),
    ("rules", HelpTopic::Rules),
    ("_fuse", HelpTopic::LowLevelFuse),
    ("_kill", HelpTopic::LowLevelKill),
];

pub(crate) fn topic_from_name(name: &str) -> Option<HelpTopic> {
    HELP_TOPIC_NAMES
        .iter()
        .find_map(|(topic_name, topic)| (*topic_name == name).then_some(topic.clone()))
}

pub(crate) fn print_help(topic: HelpTopic, verbose: bool) {
    println!("{}", help_text(topic, verbose));
}

pub(crate) fn help_text(topic: HelpTopic, verbose: bool) -> String {
    match topic {
        HelpTopic::Root => root_help_text(verbose),
        HelpTopic::Run => concat!(
            "leash run\n\n",
            "USAGE:\n",
            "  leash run [-v|--verbose] command ...\n\n",
            "OPTIONS:\n",
            "  -v, --verbose         Print debug logs from run setup and spawned FUSE daemon\n",
        )
        .to_string(),
        HelpTopic::Tail => concat!(
            "leash tail\n\n",
            "USAGE:\n",
            "  leash tail [--kinds <list>]\n\n",
            "OPTIONS:\n",
            "  --kinds <list>        Comma-separated event kinds: lookup-miss,open-denied,mutation-denied,lock\n",
        )
        .to_string(),
        HelpTopic::Rules => concat!(
            "leash rules\n\n",
            "USAGE:\n",
            "  leash rules edit\n",
            "  leash rules show\n",
            "  leash rules test [--exe=<name-or-abs-path>] <path>\n",
            "\nPROFILE exe= MATCHING:\n",
            "  - bare names (no /) resolve via PATH to a full path, then match exactly\n",
            "  - /-prefixed values are glob patterns (* stays in one dir, ** may cross dirs)\n",
            "  - multiple values use | (for example: exe=git|/usr/**/git)\n",
        )
        .to_string(),
        HelpTopic::LowLevelFuse => concat!(
            "leash _fuse\n\n",
            "USAGE:\n",
            "  leash _fuse [-v|--verbose]\n\n",
            "DESCRIPTION:\n",
            "  Run the per-user mirror FUSE daemon in the foreground.\n",
            "  This command is primarily a low-level debug entrypoint; leash run starts it on demand.\n",
        )
        .to_string(),
        HelpTopic::LowLevelKill => concat!(
            "leash _kill\n\n",
            "USAGE:\n",
            "  leash _kill\n\n",
            "DESCRIPTION:\n",
            "  Stop the per-user mirror FUSE daemon and lazy-unmount the shared mountpoint.\n",
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
        "  leash run [-v|--verbose] command ...\n\n",
        "RULES:\n",
        "  leash rules edit\n",
        "  leash rules show\n",
        "  leash rules test [--exe=<name-or-abs-path>] <path>\n",
        "\nTAIL:\n",
        "  leash tail [--kinds <list>]\n",
    ));
    if verbose {
        out.push_str(concat!(
            "\n",
            "LOW-LEVEL (DEBUG):\n",
            "  leash _fuse [-v|--verbose]\n",
            "  leash _kill\n",
        ));
    }
    out.push('\n');
    out.push_str(if verbose {
        "Run leash help <subcommand> for details."
    } else {
        "Run leash --help -v to list low-level debugging commands.\nRun leash help <subcommand> for details."
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_help_hides_low_level_commands_by_default() {
        let text = help_text(HelpTopic::Root, false);
        assert!(text.contains("leash run"));
        assert!(!text.contains("leash _fuse"));
    }

    #[test]
    fn verbose_root_help_lists_low_level_commands() {
        let text = help_text(HelpTopic::Root, true);
        assert!(text.contains("leash _fuse"));
    }

    #[test]
    fn root_help_lists_rules_before_tail() {
        let text = help_text(HelpTopic::Root, false);
        let rules_pos = text.find("RULES:").expect("RULES section");
        let tail_pos = text.find("TAIL:").expect("TAIL section");
        assert!(rules_pos < tail_pos, "{text}");
    }

    #[test]
    fn topic_lookup_supports_registered_commands() {
        assert_eq!(topic_from_name("run"), Some(HelpTopic::Run));
        assert_eq!(topic_from_name("tail"), Some(HelpTopic::Tail));
        assert_eq!(topic_from_name("_fuse"), Some(HelpTopic::LowLevelFuse));
        assert_eq!(topic_from_name("rules"), Some(HelpTopic::Rules));
        assert_eq!(topic_from_name("_unknown"), None);
    }
}
