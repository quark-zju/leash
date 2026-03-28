use anyhow::{Context, Result};
use globset::Glob;

use crate::cli::{AddCommand, ListCommand, RmCommand};
use crate::jail;
use crate::privileges;
use crate::run_with_log;

pub(crate) fn add_command(add: AddCommand) -> Result<()> {
    if let Some(name) = add.name.as_deref() {
        run_with_log(
            || jail::validate_explicit_name(name),
            || format!("validate jail name '{name}'"),
        )
        .with_context(|| format!("invalid jail name '{name}'"))?;
    }
    run_with_log(
        || {
            jail::resolve(
                add.name.as_deref(),
                add.profile.as_deref(),
                jail::ResolveMode::EnsureExists,
            )
        },
        || "create or reuse explicit jail".to_string(),
    )?;
    Ok(())
}

pub(crate) fn list_command(_list: ListCommand) -> Result<()> {
    let names = run_with_log(jail::list_named_jails, || "list named jails".to_string())?;
    for name in names {
        println!("{}", name.to_string_lossy());
    }
    Ok(())
}

pub(crate) fn rm_command(rm: RmCommand) -> Result<()> {
    privileges::require_root_euid("cowjail rm")?;
    if let Some(profile) = rm.profile.as_deref() {
        return remove_one_jail(None, Some(profile));
    }

    let Some(name_selector) = rm.name.as_deref() else {
        unreachable!("cli parser ensures rm has at least one selector");
    };

    if !contains_glob_syntax(name_selector) {
        return remove_one_jail(Some(name_selector), None);
    }

    let matched_names = run_with_log(
        || expand_name_glob_selector(name_selector),
        || format!("expand jail name glob '{name_selector}'"),
    )?;
    if matched_names.is_empty() {
        anyhow::bail!("rm name glob matched no jails: {name_selector}");
    }
    for name in matched_names {
        remove_one_jail(Some(&name), None)?;
    }
    Ok(())
}

fn remove_one_jail(name: Option<&str>, profile: Option<&str>) -> Result<()> {
    let resolved = run_with_log(
        || jail::resolve(name, profile, jail::ResolveMode::MustExist),
        || match (name, profile) {
            (Some(name), None) => format!("resolve jail '{name}'"),
            (None, Some(profile)) => format!("resolve jail by profile '{profile}'"),
            _ => "resolve jail".to_string(),
        },
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
        assert!(contains_glob_syntax("unnamed-*"));
        assert!(contains_glob_syntax("foo?"));
        assert!(contains_glob_syntax("name[0-9]"));
        assert!(!contains_glob_syntax("agent-prod"));
    }
}
