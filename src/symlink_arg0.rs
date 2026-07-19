use std::ffi::OsString;

use anyhow::{Context, Result};

use crate::cli::RunCommand;
use crate::path_search;

/// If `argv[0]` basename is not "leash" (e.g. invoked via a symlink like
/// `/usr/local/bin/codex` -> `leash`), search PATH for the real binary and
/// run it under leash's sandbox.
///
/// Returns `Ok(Some(exit_code))` when the symlink case was handled,
/// `Ok(None)` when `argv[0]` is "leash" and normal CLI parsing should
/// proceed.
pub fn try_handle_arg0(args: &[OsString]) -> Result<Option<i32>> {
    let argv0 = match args.first() {
        Some(a) => a,
        None => return Ok(None),
    };

    let basename = std::path::Path::new(argv0)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("leash");

    if basename == "leash" {
        return Ok(None);
    }

    let found = path_search::find_in_path_excluding_current_exe(std::ffi::OsStr::new(basename))
        .with_context(|| format!("{basename}: command not found"))?;

    let remaining: Vec<OsString> = args[1..].to_vec();
    crate::cmd_run::run_command(RunCommand {
        verbose: false,
        landlock_network_restriction: true,
        program: found.into(),
        args: remaining,
    })
    .map(Some)
}
