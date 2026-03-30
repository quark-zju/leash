use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use fs_err as fs;

use crate::git_rw_filter::GitRwFilter;
use crate::profile::{CachingFsCheck, Profile, RuleAction, Visibility};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RequestedAccess {
    Read,
    Write,
    Execute,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Permission {
    Deny,
    ReadOnly,
    ReadWrite,
}

impl Permission {
    pub(crate) fn allows(self, access: RequestedAccess) -> bool {
        match (self, access) {
            (Permission::Deny, _) => false,
            (Permission::ReadOnly, RequestedAccess::Write) => false,
            (Permission::ReadOnly, RequestedAccess::Read | RequestedAccess::Execute) => true,
            (Permission::ReadWrite, _) => true,
        }
    }
}

pub(crate) trait RepoPolicy {
    fn is_git_metadata_path(&self, path: &Path) -> bool;
    fn is_exact_git_dir_path(&self, path: &Path) -> bool;
    fn is_commit_editmsg_path(&self, path: &Path) -> bool;
    fn allow_git_metadata_for_exe(&self, exe_path: Option<&Path>) -> bool;
}

pub(crate) struct FsRepoPolicy {
    git: GitRwFilter,
}

impl FsRepoPolicy {
    pub(crate) fn new(system_git: Option<PathBuf>) -> Self {
        Self {
            git: GitRwFilter::with_system_git(system_git),
        }
    }
}

impl RepoPolicy for FsRepoPolicy {
    fn is_git_metadata_path(&self, path: &Path) -> bool {
        self.git.is_git_metadata_path(path)
    }

    fn is_exact_git_dir_path(&self, path: &Path) -> bool {
        self.git.is_exact_git_dir_path(path)
    }

    fn is_commit_editmsg_path(&self, path: &Path) -> bool {
        self.git.is_commit_editmsg_path(path)
    }

    fn allow_git_metadata_for_exe(&self, exe_path: Option<&Path>) -> bool {
        self.git.allow_git_metadata_for_exe(exe_path)
    }
}

pub(crate) struct AccessPolicy<R = FsRepoPolicy> {
    profile: Profile,
    repo: R,
    fs_check: CachingFsCheck,
}

impl AccessPolicy<FsRepoPolicy> {
    pub(crate) fn new(profile: Profile, system_git: Option<PathBuf>) -> Self {
        Self {
            profile,
            repo: FsRepoPolicy::new(system_git),
            fs_check: CachingFsCheck::default(),
        }
    }

    pub(crate) fn from_normalized_profile_path(
        profile_path: &Path,
        system_git: Option<PathBuf>,
    ) -> Result<Self> {
        let normalized = fs::read_to_string(profile_path)
            .with_context(|| format!("failed to read profile file {}", profile_path.display()))?;
        let profile = Profile::parse_with_home(&normalized, Path::new("/"), Path::new("/"))
            .with_context(|| {
                format!(
                    "failed to parse normalized profile {}",
                    profile_path.display()
                )
            })?;
        Ok(Self::new(profile, system_git))
    }
}

impl<R: RepoPolicy> AccessPolicy<R> {
    pub(crate) fn with_repo_policy(profile: Profile, repo: R) -> Self {
        Self {
            profile,
            repo,
            fs_check: CachingFsCheck::default(),
        }
    }

    pub(crate) fn check_permission(
        &self,
        requested_path: &Path,
        exe_path: Option<&Path>,
        _access: RequestedAccess,
    ) -> Permission {
        if self.repo.is_exact_git_dir_path(requested_path) {
            return Permission::Deny;
        }
        if self.repo.is_git_metadata_path(requested_path) {
            if self.repo.is_commit_editmsg_path(requested_path) {
                return Permission::ReadWrite;
            }
            return if self.repo.allow_git_metadata_for_exe(exe_path) {
                Permission::ReadWrite
            } else {
                Permission::ReadOnly
            };
        }

        match self.dynamic_visibility(requested_path, exe_path) {
            Visibility::Hidden => Permission::Deny,
            Visibility::ImplicitAncestor => Permission::ReadOnly,
            Visibility::Action(RuleAction::Hide | RuleAction::Deny) => Permission::Deny,
            Visibility::Action(RuleAction::ReadOnly) => Permission::ReadOnly,
            Visibility::Action(RuleAction::Passthrough) => Permission::ReadWrite,
        }
    }

    fn dynamic_visibility(&self, path: &Path, exe_path: Option<&Path>) -> Visibility {
        self.profile
            .visibility_with_checks(path, exe_path, &self.fs_check)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[derive(Default)]
    struct MockRepoPolicy {
        git_metadata: BTreeSet<PathBuf>,
        exact_git_dirs: BTreeSet<PathBuf>,
        commit_editmsg: BTreeSet<PathBuf>,
        trusted_git: Option<PathBuf>,
    }

    impl RepoPolicy for MockRepoPolicy {
        fn is_git_metadata_path(&self, path: &Path) -> bool {
            self.git_metadata.contains(path)
        }

        fn is_exact_git_dir_path(&self, path: &Path) -> bool {
            self.exact_git_dirs.contains(path)
        }

        fn is_commit_editmsg_path(&self, path: &Path) -> bool {
            self.commit_editmsg.contains(path)
        }

        fn allow_git_metadata_for_exe(&self, exe_path: Option<&Path>) -> bool {
            exe_path == self.trusted_git.as_deref()
        }
    }

    #[test]
    fn deny_rule_returns_deny() {
        let profile =
            Profile::parse("/secret deny\n", Path::new("/")).expect("profile should parse");
        let policy = AccessPolicy::with_repo_policy(profile, MockRepoPolicy::default());
        assert_eq!(
            policy.check_permission(Path::new("/secret"), None, RequestedAccess::Read),
            Permission::Deny
        );
    }

    #[test]
    fn ro_rule_stays_read_only() {
        let profile =
            Profile::parse("/workspace ro\n", Path::new("/")).expect("profile should parse");
        let policy = AccessPolicy::with_repo_policy(profile, MockRepoPolicy::default());
        let permission = policy.check_permission(
            Path::new("/workspace/file.txt"),
            None,
            RequestedAccess::Write,
        );
        assert_eq!(permission, Permission::ReadOnly);
        assert!(!permission.allows(RequestedAccess::Write));
    }

    #[test]
    fn rw_rule_is_writable() {
        let profile =
            Profile::parse("/workspace rw\n", Path::new("/")).expect("profile should parse");
        let policy = AccessPolicy::with_repo_policy(profile, MockRepoPolicy::default());
        assert_eq!(
            policy.check_permission(
                Path::new("/workspace/file.txt"),
                None,
                RequestedAccess::Write
            ),
            Permission::ReadWrite
        );
    }

    #[test]
    fn ancestor_has_worktree_rule_is_writable() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo = temp.path().join("repo");
        let file = repo.join("src/lib.rs");
        std::fs::create_dir_all(repo.join(".git")).expect("mkdir .git");
        std::fs::create_dir_all(file.parent().expect("parent")).expect("mkdir src");
        std::fs::write(&file, b"fn main() {}\n").expect("write file");
        let profile = Profile::parse(
            &format!(
                "{} rw when ancestor-has=.git\n{} ro\n",
                temp.path().display(),
                temp.path().display()
            ),
            Path::new("/"),
        )
        .expect("profile should parse");
        let policy = AccessPolicy::with_repo_policy(profile, MockRepoPolicy::default());
        assert_eq!(
            policy.check_permission(&file, None, RequestedAccess::Write),
            Permission::ReadWrite
        );
    }

    #[test]
    fn fallback_ro_rule_is_read_only() {
        let profile = Profile::parse("/src rw when ancestor-has=.git\n/src ro\n", Path::new("/"))
            .expect("profile should parse");
        let policy = AccessPolicy::with_repo_policy(profile, MockRepoPolicy::default());
        assert_eq!(
            policy.check_permission(Path::new("/src/random.txt"), None, RequestedAccess::Write),
            Permission::ReadOnly
        );
    }

    #[test]
    fn git_metadata_requires_trusted_git_for_writes() {
        let profile = Profile::parse(
            "/src/**/.git rw when exe=git\n/src/**/.git deny\n/src ro\n",
            Path::new("/"),
        )
        .expect("profile should parse");
        let mut repo = MockRepoPolicy::default();
        repo.git_metadata
            .insert(PathBuf::from("/src/repo/.git/config"));
        repo.trusted_git = Some(PathBuf::from("/usr/bin/git"));
        let policy = AccessPolicy::with_repo_policy(profile, repo);

        assert_eq!(
            policy.check_permission(
                Path::new("/src/repo/.git/config"),
                Some(Path::new("/usr/bin/git")),
                RequestedAccess::Write,
            ),
            Permission::ReadWrite
        );
        assert_eq!(
            policy.check_permission(
                Path::new("/src/repo/.git/config"),
                Some(Path::new("/usr/bin/python")),
                RequestedAccess::Write,
            ),
            Permission::ReadOnly
        );
    }

    #[test]
    fn commit_editmsg_is_writable_without_trusted_git() {
        let profile = Profile::parse(
            "/src/**/.git/COMMIT_EDITMSG rw\n/src/**/.git deny\n/src ro\n",
            Path::new("/"),
        )
        .expect("profile should parse");
        let mut repo = MockRepoPolicy::default();
        let path = PathBuf::from("/src/repo/.git/COMMIT_EDITMSG");
        repo.git_metadata.insert(path.clone());
        repo.commit_editmsg.insert(path.clone());
        let policy = AccessPolicy::with_repo_policy(profile, repo);
        assert_eq!(
            policy.check_permission(&path, None, RequestedAccess::Write),
            Permission::ReadWrite
        );
    }

    #[test]
    fn unmatched_path_is_denied() {
        let profile = Profile::parse("/src rw\n", Path::new("/")).expect("profile should parse");
        let policy = AccessPolicy::with_repo_policy(profile, MockRepoPolicy::default());
        assert_eq!(
            policy.check_permission(Path::new("/etc/passwd"), None, RequestedAccess::Read),
            Permission::Deny
        );
    }
}
