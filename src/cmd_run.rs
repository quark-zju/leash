use anyhow::Result;

use crate::cli::RunCommand;
use crate::daemon_client;
use crate::jail;
use crate::ns_runtime;
use crate::privileges;
use crate::run_env;
use crate::run_with_log;

pub(crate) fn run_command(run: RunCommand) -> Result<i32> {
    privileges::require_root_euid("leash run")?;
    run_env::set_process_name(c"leash-run")?;

    let cwd = run_with_log(jail::current_pwd, || {
        "resolve current working directory".to_string()
    })?;
    let resolved = run_with_log(
        || {
            jail::resolve(
                None,
                run.profile.as_deref(),
                jail::ResolveMode::EnsureExists,
            )
        },
        || "resolve run jail".to_string(),
    )?;
    let runtime = run_with_log(
        || ns_runtime::ensure_runtime_for_exec(&resolved.paths),
        || "ensure runtime".to_string(),
    )?;
    crate::vlog!(
        "run: runtime={} state_before={:?} state_after={:?} rebuilt={}",
        runtime.ensured.paths.runtime_dir.display(),
        runtime.ensured.state_before,
        runtime.ensured.state_after,
        runtime.ensured.rebuilt
    );
    crate::vlog!(
        "run: preparing child namespace setup then chdir to {}",
        cwd.display()
    );

    run_with_log(
        || daemon_client::ensure_daemon_running(run.verbose),
        || "ensure daemon".to_string(),
    )?;

    run_with_log(run_env::setup_run_namespaces, || {
        "unshare run namespaces".to_string()
    })?;
    run_with_log(
        || daemon_client::register_session(&resolved.paths.profile_path),
        || {
            format!(
                "register current mount namespace session {}",
                resolved.paths.profile_path.display()
            )
        },
    )?;
    let status = run_with_log(
        || run_env::run_child_in_jail(&run, &cwd),
        || format!("execute jailed command {:?}", run.program),
    )?;

    Ok(exit_code_from_status(status))
}

fn exit_code_from_status(status: std::process::ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return 128 + sig;
        }
    }
    1
}
