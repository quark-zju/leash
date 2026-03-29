#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import shlex
import shutil
import stat
import subprocess
import tempfile
import textwrap
import time
import unittest
from pathlib import Path


def run_cmd(
    cmd: list[str],
    *,
    env: dict[str, str],
    cwd: Path | None = None,
    check: bool = True,
    capture_stdout: bool = True,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        cmd,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE if capture_stdout else subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    if check and completed.returncode != 0:
        raise AssertionError(
            f"command failed: {shlex.join(cmd)}\n"
            f"stdout:\n{completed.stdout}\n"
            f"stderr:\n{completed.stderr}"
        )
    return completed


def resolve_default_binary() -> Path:
    completed = run_cmd(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        env=os.environ.copy(),
    )
    data = json.loads(completed.stdout)
    return (Path(data["target_directory"]) / "debug" / "leash").resolve()


def binary_is_usable(leash_bin: Path) -> bool:
    if not leash_bin.is_file():
        return False
    if os.geteuid() == 0:
        return True
    meta = leash_bin.stat()
    return bool(meta.st_uid == 0 and meta.st_mode & stat.S_ISUID)


def ensure_usable_binary(leash_bin: Path) -> None:
    run_cmd(["cargo", "build"], env=os.environ.copy(), capture_stdout=False)
    if binary_is_usable(leash_bin):
        return
    run_cmd(["cargo", "run", "--", "_suid"], env=os.environ.copy(), capture_stdout=False)
    if not binary_is_usable(leash_bin):
        raise unittest.SkipTest(
            "leash integration tests require root or a setuid-root leash binary"
        )


class LeashIntegrationTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.leash_bin = resolve_default_binary()
        ensure_usable_binary(cls.leash_bin)
        cls.system_git = shutil.which("git")
        if cls.system_git is None:
            raise unittest.SkipTest("system git not found in PATH")

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(
            prefix="leash-integration-", ignore_cleanup_errors=True
        )
        self.tmpdir = Path(self._tmp.name)
        self.home = self.tmpdir / "home"
        self.runtime = self.tmpdir / "runtime"
        self.fixture = self.tmpdir / "fixture"
        self.ro_dir = self.fixture / "ro"
        self.rw_dir = self.fixture / "rw"
        self.deny_dir = self.fixture / "deny"
        self.workspace = self.fixture / "workspace"
        self.repo = self.workspace / "repo"
        self.nonrepo = self.workspace / "nonrepo"
        self.socket_dir = self.runtime / "leash"
        self.socket_path = self.socket_dir / "leashd.sock"
        self.profile_path = self.tmpdir / "runtime.profile"

        for path in [
            self.home / ".config" / "leash" / "profiles",
            self.runtime,
            self.ro_dir,
            self.rw_dir,
            self.deny_dir,
            self.repo,
            self.nonrepo,
        ]:
            path.mkdir(parents=True, exist_ok=True)
        self.runtime.chmod(0o700)

        self.ro_file = self.ro_dir / "note.txt"
        self.rw_file = self.rw_dir / "note.txt"
        self.deny_file = self.deny_dir / "secret.txt"
        self.repo_file = self.repo / "tracked.txt"
        self.nonrepo_file = self.nonrepo / "loose.txt"

        self.ro_file.write_text("ro-ok\n")
        self.rw_file.write_text("rw-before\n")
        self.deny_file.write_text("deny\n")
        self.repo_file.write_text("repo-before\n")
        self.nonrepo_file.write_text("nonrepo-before\n")

        self.env = os.environ.copy()
        self.env.update(
            {
                "HOME": str(self.home),
                "XDG_RUNTIME_DIR": str(self.runtime),
                "LC_ALL": "C",
                "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_AUTHOR_NAME": "leash integration",
                "GIT_AUTHOR_EMAIL": "leash@example.com",
                "GIT_COMMITTER_NAME": "leash integration",
                "GIT_COMMITTER_EMAIL": "leash@example.com",
            }
        )

        run_cmd([self.system_git, "init", "-q", str(self.repo)], env=self.env)
        run_cmd([self.system_git, "-C", str(self.repo), "add", "tracked.txt"], env=self.env)
        run_cmd(
            [self.system_git, "-C", str(self.repo), "commit", "-q", "-m", "initial"],
            env=self.env,
        )

        self.profile_path.write_text(
            textwrap.dedent(
                f"""\
                {self.deny_dir} deny
                {self.rw_dir} rw
                {self.workspace} git-rw
                {self.fixture} ro
                /bin ro
                /sbin ro
                /usr ro
                /lib ro
                /lib64 ro
                /etc ro
                /proc rw
                /dev/null rw
                /dev/urandom ro
                """
            )
        )

        self.daemon_log = (self.tmpdir / "daemon.log").open("w", encoding="utf-8")
        self.daemon = subprocess.Popen(
            [str(self.leash_bin), "_daemon"],
            env=self.env,
            stdout=self.daemon_log,
            stderr=subprocess.STDOUT,
            text=True,
        )
        self._wait_for_daemon()

    def tearDown(self) -> None:
        if hasattr(self, "daemon"):
            self.daemon.terminate()
            try:
                self.daemon.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.daemon.kill()
                self.daemon.wait(timeout=5)
        if hasattr(self, "daemon_log"):
            self.daemon_log.close()
        if hasattr(self, "_tmp"):
            try:
                self._tmp.cleanup()
            except PermissionError:
                pass

    def _wait_for_daemon(self) -> None:
        deadline = time.time() + 5
        while time.time() < deadline:
            if self.daemon.poll() is not None:
                self.fail(f"daemon exited early with code {self.daemon.returncode}")
            if self.socket_path.exists():
                return
            time.sleep(0.05)
        self.fail("daemon did not become ready before timeout")

    def leash_run(
        self,
        *cmd: str,
        check: bool = True,
        capture_stdout: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        completed = run_cmd(
            [str(self.leash_bin), "run", "--profile", str(self.profile_path), "--", *cmd],
            env=self.env,
            check=False,
            capture_stdout=capture_stdout,
        )
        if (
            completed.returncode != 0
            and "fanotify_mark(FAN_MARK_MNTNS)-failed" in completed.stderr
        ):
            raise unittest.SkipTest("kernel or privileges do not support FAN_MARK_MNTNS here")
        if check and completed.returncode != 0:
            raise AssertionError(
                f"command failed: {shlex.join([str(self.leash_bin), 'run', '--profile', str(self.profile_path), '--', *cmd])}\n"
                f"stdout:\n{completed.stdout}\n"
                f"stderr:\n{completed.stderr}"
            )
        return completed


class RuntimeSemanticsTests(LeashIntegrationTestCase):
    def test_rw_and_deny_semantics(self) -> None:
        self.leash_run(
            "/bin/sh",
            "-lc",
            'printf rw-after >"$1"',
            "sh",
            str(self.rw_file),
        )
        self.assertEqual(self.rw_file.read_text(), "rw-after")

        denied = self.leash_run(
            "/bin/sh",
            "-lc",
            'cat "$1"',
            "sh",
            str(self.deny_file),
            check=False,
            capture_stdout=True,
        )
        self.assertNotEqual(denied.returncode, 0)
        self.assertEqual(self.deny_file.read_text(), "deny\n")

    def test_git_rw_allows_git_but_not_shell_metadata_writes(self) -> None:
        shell_write = self.leash_run(
            "/bin/sh",
            "-lc",
            'printf hacked >"$1"',
            "sh",
            str(self.repo / ".git" / "config"),
            check=False,
        )
        self.assertNotEqual(shell_write.returncode, 0)

        git_write = self.leash_run(
            self.system_git,
            "-C",
            str(self.repo),
            "config",
            "leash.test",
            "1",
        )
        self.assertEqual(git_write.returncode, 0)

        config_text = (self.repo / ".git" / "config").read_text()
        self.assertIn("leash.test = 1", config_text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
