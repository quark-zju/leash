use std::path::Path;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command as ProcessCommand, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use log::debug;

use crate::cli::RunCommand;
use crate::fuse_runtime::{self, MountState};
use crate::mount_plan;
use crate::profile_store;
use crate::userns_run::{self, UsernsRunConfig};

const FUSE_STARTUP_TIMEOUT: Duration = Duration::from_secs(5);
const FUSE_STARTUP_POLL: Duration = Duration::from_millis(20);

pub(crate) fn run_command(run: RunCommand) -> Result<i32> {
    let cwd = std::env::current_dir().context("failed to resolve current working directory")?;
    let profile = profile_store::load_default_profile(&cwd)?;
    let mount_plan = mount_plan::build_mount_plan(&profile).context("failed to build mount plan")?;
    let fuse_mount_root = ensure_fuse_daemon_running(run.verbose)?;

    let config = UsernsRunConfig::new(
        fuse_mount_root,
        cwd,
        run.program.clone(),
        run.args.clone(),
        mount_plan,
    );
    userns_run::run_in_user_namespace(&config)
}

fn ensure_fuse_daemon_running(verbose: bool) -> Result<std::path::PathBuf> {
    let mountpoint = fuse_runtime::ensure_global_mountpoint()?;
    match fuse_runtime::read_global_mount_state(&mountpoint)? {
        MountState::Fuse { fs_type } => {
            debug!(
                "run: shared mirrorfs already mounted at {} as {}",
                mountpoint.display(),
                fs_type
            );
            return Ok(mountpoint);
        }
        MountState::Other { fs_type } => {
            bail!(
                "shared mountpoint {} is occupied by non-FUSE filesystem {}",
                mountpoint.display(),
                fs_type
            );
        }
        MountState::Unmounted => {}
    }

    let mut child = spawn_fuse_daemon(verbose)?;
    wait_for_fuse_mount(&mountpoint, &mut child)?;
    Ok(mountpoint)
}

fn spawn_fuse_daemon(verbose: bool) -> Result<Child> {
    let exe = std::env::current_exe().context("failed to resolve current executable")?;
    let mut command = ProcessCommand::new(exe);
    command.arg("_fuse");
    if verbose {
        command.arg("--verbose");
        command.stdout(Stdio::inherit());
        command.stderr(Stdio::inherit());
    } else {
        command.stdin(Stdio::null());
        command.stdout(Stdio::null());
        command.stderr(Stdio::null());
    }
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    debug!("run: spawn background _fuse daemon");
    command.spawn().context("failed to spawn _fuse daemon")
}

fn wait_for_fuse_mount(mountpoint: &Path, child: &mut Child) -> Result<()> {
    let deadline = Instant::now() + FUSE_STARTUP_TIMEOUT;
    loop {
        match fuse_runtime::read_global_mount_state(mountpoint)? {
            MountState::Fuse { fs_type } => {
                debug!(
                    "run: observed shared mirrorfs mount {} as {}",
                    mountpoint.display(),
                    fs_type
                );
                return Ok(());
            }
            MountState::Other { fs_type } => {
                bail!(
                    "shared mountpoint {} was mounted by non-FUSE filesystem {}",
                    mountpoint.display(),
                    fs_type
                );
            }
            MountState::Unmounted => {}
        }

        if let Some(status) = child.try_wait().context("failed to poll _fuse daemon")? {
            bail!("_fuse daemon exited before mounting {mountpoint:?}: {status}");
        }
        if Instant::now() >= deadline {
            bail!("timed out waiting for _fuse to mount {}", mountpoint.display());
        }
        thread::sleep(FUSE_STARTUP_POLL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn wait_for_fuse_mount_fails_on_non_fuse_mount() {
        let tempdir = tempdir().expect("tempdir");
        let mountpoint = tempdir.path().join("mount");
        std::fs::create_dir(&mountpoint).expect("mkdir mountpoint");

        let mut child = ProcessCommand::new("sh")
            .arg("-c")
            .arg("sleep 1")
            .spawn()
            .expect("spawn sleep");
        let err = wait_for_fuse_mount(Path::new("/"), &mut child).expect_err("must fail");
        let _ = child.kill();
        let _ = child.wait();

        assert!(
            err.to_string().contains("non-FUSE filesystem")
                || err.to_string().contains("timed out")
                || err.to_string().contains("exited before mounting"),
            "{err:#}"
        );
    }
}
