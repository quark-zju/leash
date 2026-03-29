use anyhow::{Context, Result};
use globset::Glob;

use crate::cli::{ListCommand, RmCommand};
use crate::jail;
use crate::privileges;
use crate::run_with_log;

pub(crate) fn list_command(_list: ListCommand) -> Result<()> {
    let names = run_with_log(jail::list_named_jails, || "list named jails".to_string())?;
    for name in names {
        println!("{}", name.to_string_lossy());
    }
    Ok(())
}

pub(crate) fn rm_command(rm: RmCommand) -> Result<()> {
    privileges::require_root_euid("cowjail _rm")?;
    for selector in rm.selectors {
        if !contains_glob_syntax(&selector) {
            remove_one_jail(&selector)?;
            continue;
        }

        let matched_names = run_with_log(
            || expand_name_glob_selector(&selector),
            || format!("expand jail name glob '{selector}'"),
        )?;
        if matched_names.is_empty() {
            anyhow::bail!("rm name glob matched no jails: {selector}");
        }
        for name in matched_names {
            remove_one_jail(&name)?;
        }
    }
    Ok(())
}

fn remove_one_jail(name: &str) -> Result<()> {
    let resolved = run_with_log(
        || jail::resolve(Some(name), None, jail::ResolveMode::MustExist),
        || format!("resolve jail '{name}'"),
    )?;
    run_with_log(
        || jail::remove_jail(&resolved.paths),
        || format!("remove jail runtime/state artifacts '{}'", resolved.name),
    )
}

fn expand_name_glob_selector(selector: &str) -> Result<Vec<String>> {
    let matcher = Glob::new(selector)
        .with_context(|| format!("invalid rm name glob pattern '{selector}'"))?
        .compile_matcher();
    let names = jail::list_named_jails()?;
    let mut matched = Vec::new();
    for name in names {
        let Some(name) = name.to_str() else {
            continue;
        };
        if matcher.is_match(name) {
            matched.push(name.to_string());
        }
    }
    Ok(matched)
}

fn contains_glob_syntax(value: &str) -> bool {
    value.contains('*') || value.contains('?') || value.contains('[')
}

#[cfg(test)]
mod tests {
    use super::contains_glob_syntax;

    #[test]
    fn glob_syntax_detection() {
        assert!(contains_glob_syntax("abc*"));
        assert!(contains_glob_syntax("foo?"));
        assert!(contains_glob_syntax("name[0-9]"));
        assert!(!contains_glob_syntax("agent-prod"));
    }
}
