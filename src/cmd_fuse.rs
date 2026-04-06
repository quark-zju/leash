use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use fuser::Notifier;
use log::{info, warn};

use crate::cli::LowLevelFuseCommand;
use crate::fuse_runtime::{self, MountState};
use crate::mirrorfs::MirrorFs;
use crate::profile::ProfileController;
use crate::profile_store;
use crate::tail_ipc;

const PROFILE_RELOAD_POLL: Duration = Duration::from_millis(100);

static PROFILE_RELOAD_REQUESTED: AtomicBool = AtomicBool::new(false);

pub(crate) fn fuse_command(_command: LowLevelFuseCommand) -> Result<()> {
    let mountpoint = fuse_runtime::ensure_global_mountpoint()?;
    let state = fuse_runtime::read_global_mount_state(&mountpoint)?;
    match state {
        MountState::Unmounted => {}
        MountState::Fuse { fs_type } => {
            bail!(
                "shared FUSE mountpoint {} is already mounted as {}",
                mountpoint.display(),
                fs_type
            );
        }
        MountState::Other { fs_type } => {
            bail!(
                "shared mountpoint {} is occupied by non-FUSE filesystem {}",
                mountpoint.display(),
                fs_type
            );
        }
    }

    let profile = profile_store::load_default_profile(Path::new("/"))?;
    let controller = Arc::new(ProfileController::new(profile));
    let (tail_sink, _tail_server_guard) = tail_ipc::start_global_server()?;
    let fs = MirrorFs::new_with_tail(PathBuf::from("/"), Arc::clone(&controller), Some(tail_sink));
    let _pid_file = DaemonPidFile::write()?;

    info!("mounting shared mirrorfs at {}", mountpoint.display());
    let session = unsafe { fs.mount_background(Path::new(&mountpoint))? };
    let _reload_thread = spawn_profile_reload_thread(Arc::clone(&controller), session.notifier())?;
    session
        .join()
        .context("mirrorfs background session exited unexpectedly")
}

fn spawn_profile_reload_thread(
    controller: Arc<ProfileController>,
    notifier: Notifier,
) -> Result<thread::JoinHandle<()>> {
    install_sighup_reload_handler()?;
    thread::Builder::new()
        .name("leash-profile-reload".to_owned())
        .spawn(move || {
            loop {
                if PROFILE_RELOAD_REQUESTED.swap(false, Ordering::Relaxed) {
                    reload_default_profile(&controller, &notifier);
                }
                thread::sleep(PROFILE_RELOAD_POLL);
            }
        })
        .context("failed to spawn profile reload thread")
}

fn install_sighup_reload_handler() -> Result<()> {
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_flags = 0;
    action.sa_sigaction = handle_sighup_reload as *const () as libc::sighandler_t;
    let rc = unsafe {
        libc::sigemptyset(&mut action.sa_mask);
        libc::sigaction(libc::SIGHUP, &action, std::ptr::null_mut())
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("failed to install SIGHUP handler");
    }
    Ok(())
}

extern "C" fn handle_sighup_reload(_signal: libc::c_int) {
    PROFILE_RELOAD_REQUESTED.store(true, Ordering::Relaxed);
}

fn reload_default_profile(controller: &ProfileController, notifier: &Notifier) {
    reload_profile_with(
        controller,
        || profile_store::load_default_profile(Path::new("/")),
        Some(notifier),
    );
}

fn reload_profile_with(
    controller: &ProfileController,
    load_profile: impl FnOnce() -> Result<crate::profile::Profile>,
    notifier: Option<&Notifier>,
) {
    match load_profile() {
        Ok(profile) => {
            controller.replace_profile(profile);
            if let Some(notifier) = notifier
                && let Err(err) = notifier.increment_epoch()
            {
                warn!("profile reloaded, but failed to increment FUSE epoch: {err}");
            }
            info!("reloaded default profile after SIGHUP");
        }
        Err(err) => {
            warn!("ignoring failed SIGHUP profile reload: {err:#}");
        }
    }
}

struct DaemonPidFile;

impl DaemonPidFile {
    fn write() -> Result<Self> {
        fuse_runtime::write_global_daemon_pid()?;
        Ok(Self)
    }
}

impl Drop for DaemonPidFile {
    fn drop(&mut self) {
        if let Err(err) = fuse_runtime::clear_global_daemon_pid() {
            warn!("failed to clear daemon pid file: {err:#}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::{AccessController, AccessRequest, Caller, Operation};
    use crate::profile::{NoIncludes, PathExeResolver, parse};

    #[test]
    fn reload_default_profile_helper_keeps_serving_old_policy_on_parse_error() {
        let controller = ProfileController::new(
            parse(
                "/tmp ro\n",
                Path::new("/home/user"),
                Path::new("/"),
                &NoIncludes,
                &PathExeResolver,
            )
            .expect("parse profile"),
        );
        reload_profile_with(&controller, || bail!("bad profile syntax"), None);

        let caller = Caller::with_process_name(None, None);
        let mut caller_condition = &caller;
        assert_eq!(
            AccessController::check(
                &controller,
                &AccessRequest {
                    caller: &caller,
                    path: Path::new("/tmp/file.txt"),
                    operation: Operation::Lookup,
                },
                &mut caller_condition
            ),
            crate::access::AccessDecision::Allow
        );
    }
}
