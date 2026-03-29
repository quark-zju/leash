use anyhow::{Result, bail};
use std::path::Path;

use crate::cli::CompletionCommand;

pub(crate) fn completion_command(cmd: CompletionCommand) -> Result<()> {
    let shell = match cmd.shell.as_deref() {
        Some(raw) => parse_shell(raw)?,
        None => detect_shell_from_env()?,
    };
    match shell {
        Shell::Bash => print!("{BASH_COMPLETION}"),
        Shell::Zsh => print!("{ZSH_COMPLETION}"),
        Shell::Fish => print!("{FISH_COMPLETION}"),
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shell {
    Bash,
    Zsh,
    Fish,
}

fn parse_shell(raw: &str) -> Result<Shell> {
    match raw {
        "bash" => Ok(Shell::Bash),
        "zsh" => Ok(Shell::Zsh),
        "fish" => Ok(Shell::Fish),
        _ => bail!("unsupported shell '{raw}' (expected: bash, zsh, fish)"),
    }
}

fn detect_shell_from_env() -> Result<Shell> {
    let raw = std::env::var("SHELL")
        .map_err(|_| anyhow::anyhow!("SHELL is not set; pass explicit shell: bash|zsh|fish"))?;
    let name = Path::new(&raw)
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow::anyhow!("SHELL is not a valid shell path: {raw}"))?;
    parse_shell(name)
}

const BASH_COMPLETION: &str = r#"_cowjail_complete() {
  local cur prev cmd1 cmd2
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"
  cmd1="${COMP_WORDS[1]}"
  cmd2="${COMP_WORDS[2]}"

  if [[ $COMP_CWORD -eq 1 ]]; then
    COMPREPLY=( $(compgen -W "completion profile help add list show rm run _mount _fuse _suid" -- "$cur") )
    return
  fi

  if [[ "$cmd1" == "help" && $COMP_CWORD -eq 2 ]]; then
    COMPREPLY=( $(compgen -W "profile completion add list show rm run _mount _fuse _suid" -- "$cur") )
    return
  fi

  if [[ "$cmd1" == "completion" && $COMP_CWORD -eq 2 ]]; then
    COMPREPLY=( $(compgen -W "bash zsh fish" -- "$cur") )
    return
  fi

  if [[ "$cmd1" == "profile" ]]; then
    if [[ $COMP_CWORD -eq 2 ]]; then
      COMPREPLY=( $(compgen -W "list show edit rm" -- "$cur") )
      return
    fi
    if [[ $COMP_CWORD -eq 3 && ( "$cmd2" == "show" || "$cmd2" == "edit" || "$cmd2" == "rm" ) ]]; then
      local profiles
      profiles="$(cowjail profile list 2>/dev/null)"
      COMPREPLY=( $(compgen -W "$profiles" -- "$cur") )
      return
    fi
  fi

  if [[ "$prev" == "--name" ]]; then
    local names
    names="$(cowjail list 2>/dev/null)"
    COMPREPLY=( $(compgen -W "$names" -- "$cur") )
    return
  fi
  if [[ "$prev" == "--profile" ]]; then
    local profiles
    profiles="$(cowjail profile list 2>/dev/null)"
    COMPREPLY=( $(compgen -W "default $profiles" -- "$cur") )
    return
  fi

  if [[ "$cmd1" == "show" || "$cmd1" == "rm" ]]; then
    if [[ $COMP_CWORD -eq 2 && "${cur#-}" == "$cur" ]]; then
      local names
      names="$(cowjail list 2>/dev/null)"
      COMPREPLY=( $(compgen -W "$names" -- "$cur") )
      return
    fi
  fi

  case "$cmd1" in
    run) COMPREPLY=( $(compgen -W "--name --profile -v --verbose" -- "$cur") ) ;;
    rm) COMPREPLY=( $(compgen -W "--name --profile -v --verbose" -- "$cur") ) ;;
    add) COMPREPLY=( $(compgen -W "--name --profile" -- "$cur") ) ;;
    show) COMPREPLY=( $(compgen -W "-v --verbose" -- "$cur") ) ;;
    _mount) COMPREPLY=( $(compgen -W "--profile -v --verbose" -- "$cur") ) ;;
    _fuse) COMPREPLY=( $(compgen -W "--profile --mountpoint --pid-path -v --verbose" -- "$cur") ) ;;
    _suid) COMPREPLY=( $(compgen -W "-v --verbose" -- "$cur") ) ;;
  esac
}

complete -F _cowjail_complete cowjail
"#;

const ZSH_COMPLETION: &str = r#"#compdef cowjail
_cowjail() {
  local -a subcmds help_topics profile_subcmds shells
  subcmds=(completion profile help add list show rm run _mount _fuse _suid)
  help_topics=(profile completion add list show rm run _mount _fuse _suid)
  profile_subcmds=(list show edit rm)
  shells=(bash zsh fish)

  if (( CURRENT == 2 )); then
    _describe 'subcommand' subcmds
    return
  fi

  case "$words[2]" in
    completion)
      if (( CURRENT == 3 )); then
        _describe 'shell' shells
      fi
      return
      ;;
    help)
      if (( CURRENT == 3 )); then
        _describe 'topic' help_topics
      fi
      return
      ;;
    profile)
      if (( CURRENT == 3 )); then
        _describe 'profile action' profile_subcmds
        return
      fi
      if (( CURRENT == 4 )) && [[ "$words[3]" == "show" || "$words[3]" == "edit" || "$words[3]" == "rm" ]]; then
        local -a profiles
        profiles=(${(f)"$(cowjail profile list 2>/dev/null)"})
        _describe 'profile name' profiles
        return
      fi
      return
      ;;
  esac
}
compdef _cowjail cowjail
"#;

const FISH_COMPLETION: &str = r#"complete -c cowjail -f -n '__fish_use_subcommand' -a 'completion profile help add list show rm run _mount _fuse _suid'
complete -c cowjail -f -n '__fish_seen_subcommand_from completion; and not __fish_seen_subcommand_from bash zsh fish' -a 'bash zsh fish'
complete -c cowjail -f -n '__fish_seen_subcommand_from help; and not __fish_seen_subcommand_from profile completion add list show rm run _mount _fuse _suid' -a 'profile completion add list show rm run _mount _fuse _suid'
complete -c cowjail -f -n '__fish_seen_subcommand_from profile; and not __fish_seen_subcommand_from list show edit rm' -a 'list show edit rm'
complete -c cowjail -f -n '__fish_seen_subcommand_from profile show profile edit profile rm' -a '(cowjail profile list 2>/dev/null)'
"#;
