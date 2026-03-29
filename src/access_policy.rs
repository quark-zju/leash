use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use fs_err as fs;

use crate::git_rw_filter::GitRwFilter;
use crate::profile::{Profile, RuleAction, Visibility};

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
    fn is_repo_member(&self, path: &Path) -> bool;
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
    fn is_repo_member(&self, path: &Path) -> bool {
        self.git.path_is_git_repo_member(path)
    }

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
}

impl AccessPolicy<FsRepoPolicy> {
    pub(crate) fn new(profile: Profile, system_git: Option<PathBuf>) -> Self {
        Self {
            profile,
            repo: FsRepoPolicy::new(system_git),
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
        Self { profile, repo }
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

        match self.dynamic_visibility(requested_path) {
            Visibility::Hidden => Permission::Deny,
            Visibility::ImplicitAncestor => Permission::ReadOnly,
            Visibility::Action(RuleAction::Hide | RuleAction::Deny) => Permission::Deny,
            Visibility::Action(RuleAction::ReadOnly) => Permission::ReadOnly,
            Visibility::Action(RuleAction::Passthrough) => Permission::ReadWrite,
            Visibility::Action(RuleAction::GitRw) => unreachable!("git-rw must be normalized"),
        }
    }

    fn dynamic_visibility(&self, path: &Path) -> Visibility {
        match self.profile.visibility(path) {
            Visibility::Action(RuleAction::GitRw) => {
                if self.repo.is_repo_member(path) {
                    Visibility::Action(RuleAction::Passthrough)
                } else {
                    Visibility::Action(RuleAction::ReadOnly)
                }
            }
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[derive(Default)]
    struct MockRepoPolicy {
        repo_members: BTreeSet<PathBuf>,
        git_metadata: BTreeSet<PathBuf>,
        exact_git_dirs: BTreeSet<PathBuf>,
        commit_editmsg: BTreeSet<PathBuf>,
        trusted_git: Option<PathBuf>,
    }

    impl RepoPolicy for MockRepoPolicy {
        fn is_repo_member(&self, path: &Path) -> bool {
            self.repo_members.contains(path)
        }

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
    fn git_rw_worktree_member_is_writable() {
        let profile =
            Profile::parse("/src git-rw\n", Path::new("/")).expect("profile should parse");
        let mut repo = MockRepoPolicy::default();
        repo.repo_members.insert(PathBuf::from("/src/repo/lib.rs"));
        let policy = AccessPolicy::with_repo_policy(profile, repo);
        assert_eq!(
            policy.check_permission(Path::new("/src/repo/lib.rs"), None, RequestedAccess::Write),
            Permission::ReadWrite
        );
    }

    #[test]
    fn git_rw_non_repo_member_is_read_only() {
        let profile =
            Profile::parse("/src git-rw\n", Path::new("/")).expect("profile should parse");
        let policy = AccessPolicy::with_repo_policy(profile, MockRepoPolicy::default());
        assert_eq!(
            policy.check_permission(Path::new("/src/random.txt"), None, RequestedAccess::Write),
            Permission::ReadOnly
        );
    }

    #[test]
    fn git_metadata_requires_trusted_git_for_writes() {
        let profile =
            Profile::parse("/src git-rw\n", Path::new("/")).expect("profile should parse");
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
        let profile =
            Profile::parse("/src git-rw\n", Path::new("/")).expect("profile should parse");
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
