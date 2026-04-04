use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use fs_err as fs;

use crate::profile::{IncludeResolver, PathExeResolver, Profile, parse};

const CONFIG_DIR_NAME: &str = "leash2";
const DEFAULT_PROFILE_NAME: &str = "profile";

const DEFAULT_PROFILE_SOURCE: &str = "\
%include builtin:basic
%include builtin:agents
/proc ro
/sys ro
~/**/.git/COMMIT_EDITMSG rw
~/**/.git rw when exe=git
~/**/.git deny
~ rw when ancestor-has=.git
~ ro
";

const BASIC_PROFILE_SOURCE: &str = "\
/tmp rw
/bin ro
/sbin ro
/usr ro
/lib ro
/lib64 ro
/etc ro
/dev/full rw
/dev/null rw
/dev/ptmx rw
/dev/pts rw
/dev/random ro
/dev/tty rw
/dev/urandom ro
/dev/zero rw
";

const AGENTS_PROFILE_SOURCE: &str = "\
~/.agents rw
~/.claude rw
~/.codex rw
~/.copilot rw
~/.cache/opencode rw
~/.config/opencode rw
~/.local/share/opencode rw
~/.local/state/opencode rw
~/.bun rw
~/.cargo ro
~/.gitconfig* ro
~/.gitignore* ro
~/.local/bin ro
~/.npm ro
~/.pyenv ro
~/.rustup ro

~/.local hide
~/.cache hide
~/.config hide
";

const BUILTINS: &[(&str, &str)] = &[
    ("builtin:default", DEFAULT_PROFILE_SOURCE),
    ("builtin:basic", BASIC_PROFILE_SOURCE),
    ("builtin:agents", AGENTS_PROFILE_SOURCE),
];

pub fn load_default_profile(cwd: &Path) -> Result<Profile> {
    let home = home_dir()?;
    let store = ProfileStore::new(config_dir(&home));
    let source = store.load_default_profile_source()?;
    parse(&source, &home, cwd, &store, &PathExeResolver)
        .map_err(|err| anyhow::anyhow!("{err}"))
        .context("failed to parse default profile")
}

#[derive(Debug, Clone)]
struct ProfileStore {
    dir: PathBuf,
}

impl ProfileStore {
    fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    fn load_default_profile_source(&self) -> Result<String> {
        self.load_profile_source(DEFAULT_PROFILE_NAME)
            .map(|source| source.unwrap_or_else(|| DEFAULT_PROFILE_SOURCE.to_owned()))
    }

    fn load_profile_source(&self, name: &str) -> Result<Option<String>> {
        if let Some(source) = builtin_source(name) {
            return Ok(Some(source.to_owned()));
        }
        validate_profile_name(name)?;
        let path = self.dir.join(name);
        match fs::read_to_string(&path) {
            Ok(source) => Ok(Some(source)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => {
                Err(err).with_context(|| format!("failed to read profile {}", path.display()))
            }
        }
    }
}

impl IncludeResolver for ProfileStore {
    fn resolve(&self, name: &str) -> std::result::Result<Option<String>, String> {
        self.load_profile_source(name)
            .map_err(|err| format!("{err:#}"))
    }
}

fn builtin_source(name: &str) -> Option<&'static str> {
    BUILTINS
        .iter()
        .find_map(|(builtin_name, source)| (*builtin_name == name).then_some(*source))
}

fn config_dir(home: &Path) -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".config"))
        .join(CONFIG_DIR_NAME)
}

fn home_dir() -> Result<PathBuf> {
    let Some(home) = std::env::var_os("HOME") else {
        bail!("HOME is not set");
    };
    Ok(PathBuf::from(home))
}

fn validate_profile_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.contains('/')
        || name == "."
        || name == ".."
        || name.contains('\0')
    {
        bail!("invalid profile name: {name:?}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn builtin_default_profile_is_valid() {
        let tempdir = tempdir().expect("tempdir");
        let home = tempdir.path().join("home");
        fs::create_dir_all(&home).expect("home");
        let store = ProfileStore::new(home.join(".config/leash2"));
        let source = store
            .load_default_profile_source()
            .expect("load default profile");

        let profile = parse(
            &source,
            &home,
            Path::new("/tmp"),
            &store,
            &PathExeResolver,
        )
        .expect("parse builtin profile");

        assert!(!profile.rules().is_empty());
    }

    #[test]
    fn default_profile_file_overrides_builtin_profile() {
        let tempdir = tempdir().expect("tempdir");
        let config_dir = tempdir.path().join("config");
        fs::create_dir_all(config_dir.join("leash2")).expect("config dir");
        fs::write(config_dir.join("leash2/profile"), "/tmp rw\n").expect("profile");

        let store = ProfileStore::new(config_dir.join("leash2"));
        let source = store
            .load_default_profile_source()
            .expect("load default profile");

        assert_eq!(source, "/tmp rw\n");
    }

    #[test]
    fn include_resolver_loads_named_profile_files() {
        let tempdir = tempdir().expect("tempdir");
        let dir = tempdir.path().join("profiles");
        fs::create_dir_all(&dir).expect("profile dir");
        fs::write(dir.join("extra"), "/opt rw\n").expect("extra profile");

        let store = ProfileStore::new(dir);

        assert_eq!(
            store.resolve("extra").expect("resolve"),
            Some("/opt rw\n".to_owned())
        );
        assert_eq!(store.resolve("missing").expect("resolve"), None);
        assert!(store.resolve("../escape").expect_err("invalid name").contains("invalid profile name"));
    }

    #[test]
    fn builtin_default_profile_has_a_valid_mount_plan() {
        let tempdir = tempdir().expect("tempdir");
        let home = tempdir.path().join("home");
        fs::create_dir_all(&home).expect("home");
        let store = ProfileStore::new(home.join(".config/leash2"));
        let source = store
            .load_default_profile_source()
            .expect("load default profile");
        let profile = parse(
            &source,
            &home,
            Path::new("/tmp"),
            &store,
            &PathExeResolver,
        )
        .expect("parse builtin profile");

        crate::mount_plan::build_mount_plan(&profile).expect("build mount plan");
    }
}
