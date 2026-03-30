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
        self.keep_temp = os.environ.get("LEASH_KEEP_TEMP") == "1"
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
        self.default_profile_path = self.home / ".config" / "leash" / "profiles" / "default"

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
                {self.workspace}/**/.git/COMMIT_EDITMSG rw
                {self.workspace}/**/.git rw when exe=git
                {self.workspace}/**/.git deny
                {self.workspace} rw when ancestor-has=.git
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
            [str(self.leash_bin), "_daemon", "-v"],
            env=self.env,
            stdout=self.daemon_log,
            stderr=subprocess.STDOUT,
            text=True,
        )
        self._wait_for_daemon()
        run_cmd(
            [str(self.leash_bin), "_set-profile", str(self.profile_path)],
            env=self.env,
            capture_stdout=False,
        )

    def tearDown(self) -> None:
        if hasattr(self, "daemon"):
            if self.daemon.poll() is None:
                try:
                    run_cmd(
                        [str(self.leash_bin), "_shutdown-daemon"],
                        env=self.env,
                        capture_stdout=False,
                    )
                except AssertionError:
                    self.daemon.terminate()
            try:
                self.daemon.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.daemon.kill()
                self.daemon.wait(timeout=5)
        if hasattr(self, "daemon_log"):
            self.daemon_log.close()
        if hasattr(self, "_tmp") and not self.keep_temp:
            try:
                self._tmp.cleanup()
            except PermissionError:
                pass
        elif hasattr(self, "tmpdir"):
            if hasattr(self._tmp, "_finalizer"):
                self._tmp._finalizer.detach()
            print(f"kept integration tempdir: {self.tmpdir}")

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
        full_cmd = [
            str(self.leash_bin),
            "run",
            "-v",
            "--profile",
            str(self.profile_path),
            "--",
            *cmd,
        ]
        completed = run_cmd(
            full_cmd,
            env=self.env,
            check=False,
            capture_stdout=capture_stdout,
        )
        if check and completed.returncode != 0:
            self._dump_debug_logs(completed, full_cmd, note="command failed")
            raise AssertionError(
                f"command failed: {shlex.join(full_cmd)}\n"
                f"stdout:\n{completed.stdout}\n"
                f"stderr:\n{completed.stderr}"
            )
        return completed

    def wait_for_daemon_log(self, needle: str, *, timeout: float = 5.0) -> None:
        deadline = time.time() + timeout
        daemon_log_path = self.tmpdir / "daemon.log"
        while time.time() < deadline:
            if daemon_log_path.exists():
                content = daemon_log_path.read_text(encoding="utf-8", errors="replace")
                if needle in content:
                    return
            time.sleep(0.05)
        self._dump_debug_logs(note=f"missing daemon log marker: {needle}")
        self.fail(f"daemon log never contained {needle!r}")

    def wait_for_daemon_log_all(
        self, needles: list[str], *, timeout: float = 5.0
    ) -> None:
        deadline = time.time() + timeout
        daemon_log_path = self.tmpdir / "daemon.log"
        while time.time() < deadline:
            if daemon_log_path.exists():
                content = daemon_log_path.read_text(encoding="utf-8", errors="replace")
                if all(needle in content for needle in needles):
                    return
            time.sleep(0.05)
        self._dump_debug_logs(note=f"missing daemon log markers: {needles}")
        self.fail(f"daemon log never contained all of {needles!r}")

    def wait_for_daemon_log_line(
        self, fragments: list[str], *, timeout: float = 5.0
    ) -> None:
        deadline = time.time() + timeout
        daemon_log_path = self.tmpdir / "daemon.log"
        while time.time() < deadline:
            if daemon_log_path.exists():
                content = daemon_log_path.read_text(encoding="utf-8", errors="replace")
                for line in content.splitlines():
                    if all(fragment in line for fragment in fragments):
                        return
            time.sleep(0.05)
        self._dump_debug_logs(note=f"missing daemon log line: {fragments}")
        self.fail(f"daemon log never contained one line with all of {fragments!r}")

    def _dump_debug_logs(
        self,
        completed: subprocess.CompletedProcess[str] | None = None,
        cmd: list[str] | None = None,
        *,
        note: str,
    ) -> None:
        print(f"\n--- integration debug: {note} ---")
        print(f"tempdir: {self.tmpdir}")
        print(f"profile: {self.profile_path}")
        print(f"daemon socket: {self.socket_path}")
        if cmd is not None:
            print(f"command: {shlex.join(cmd)}")
        if completed is not None:
            print(f"returncode: {completed.returncode}")
            print("stdout:")
            print(completed.stdout or "<empty>")
            print("stderr:")
            print(completed.stderr or "<empty>")
        daemon_log_path = self.tmpdir / "daemon.log"
        print("daemon.log:")
        if daemon_log_path.exists():
            print(daemon_log_path.read_text(encoding="utf-8", errors="replace") or "<empty>")
        else:
            print("<missing>")
        print("--- end integration debug ---")


class RuntimeSemanticsTests(LeashIntegrationTestCase):
    def test_rw_and_deny_activity_is_logged(self) -> None:
        self.leash_run(
            "/bin/sh",
            "-lc",
            'printf rw-after >"$1"; sleep 0.2',
            "sh",
            str(self.rw_file),
        )
        self.assertEqual(self.rw_file.read_text(), "rw-after")
        self.wait_for_daemon_log_line(
            [
                "fanotify: controlled pid=",
                f"path={self.rw_file}",
                "decision=allow-rw",
                "access=write",
            ]
        )

        accessed = self.leash_run(
            "/bin/sh",
            "-lc",
            'content=$(<"$1"); printf "%s\n" "$content"; sleep 0.2',
            "sh",
            str(self.deny_file),
            capture_stdout=True,
        )
        self.assertEqual(accessed.stdout, "deny\n")
        self.assertEqual(self.deny_file.read_text(), "deny\n")
        self.wait_for_daemon_log_line(
            [
                "fanotify: controlled pid=",
                f"path={self.deny_file}",
                "decision=deny",
            ]
        )

    def test_git_activity_is_logged_from_controlled_pidns(self) -> None:
        shell_read = self.leash_run(
            "/bin/sh",
            "-lc",
            'cat "$1" >/dev/null',
            "sh",
            str(self.repo / ".git" / "config"),
        )
        self.assertEqual(shell_read.returncode, 0)

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
        self.assertIn("test = 1", config_text)

        git_probe = self.leash_run(
            "/bin/sh",
            "-lc",
            '(sleep 0.2; printf probe) | "$1" -C "$2" hash-object --stdin >/dev/null',
            "sh",
            self.system_git,
            str(self.repo),
        )
        self.assertEqual(git_probe.returncode, 0)

        self.wait_for_daemon_log_line(
            [
                "fanotify: controlled pid=",
                f"path={self.repo / '.git' / 'config'}",
                f"exe={self.system_git}",
                "decision=allow-rw",
            ]
        )

    def test_proc_mount_requires_explicit_profile_rule(self) -> None:
        no_proc_profile = self.tmpdir / "no-proc.profile"
        no_proc_profile.write_text(
            textwrap.dedent(
                f"""\
                {self.fixture} ro
                /bin ro
                /usr ro
                """
            )
        )
        without_proc = run_cmd(
            [
                str(self.leash_bin),
                "run",
                "--profile",
                str(no_proc_profile),
                "--",
                "/bin/sh",
                "-lc",
                'test ! -e /proc/self/status',
            ],
            env=self.env,
            check=False,
        )
        self.assertEqual(without_proc.returncode, 0, without_proc.stderr)

        proc_ro_profile = self.tmpdir / "proc-ro.profile"
        proc_ro_profile.write_text(
            textwrap.dedent(
                f"""\
                /proc ro
                {self.fixture} ro
                /bin ro
                /usr ro
                """
            )
        )
        with_proc = run_cmd(
            [
                str(self.leash_bin),
                "run",
                "--profile",
                str(proc_ro_profile),
                "--",
                "/bin/sh",
                "-lc",
                'test -r /proc/self/status',
            ],
            env=self.env,
            check=False,
        )
        self.assertEqual(with_proc.returncode, 0, with_proc.stderr)

        proc_rw_profile = self.tmpdir / "proc-rw.profile"
        proc_rw_profile.write_text(
            textwrap.dedent(
                f"""\
                /proc rw
                {self.fixture} ro
                /bin ro
                /usr ro
                """
            )
        )
        proc_rw = run_cmd(
            [
                str(self.leash_bin),
                "run",
                "--profile",
                str(proc_rw_profile),
                "--",
                "/usr/bin/python3",
                "-c",
                "from pathlib import Path; Path('/proc/self/comm').write_text('leash-rw\\n')",
            ],
            env=self.env,
            check=False,
        )
        self.assertEqual(proc_rw.returncode, 0, proc_rw.stderr)

        proc_ro = run_cmd(
            [
                str(self.leash_bin),
                "run",
                "--profile",
                str(proc_ro_profile),
                "--",
                "/usr/bin/python3",
                "-c",
                "from pathlib import Path\n"
                "import sys\n"
                "try:\n"
                "    Path('/proc/self/comm').write_text('leash-ro\\n')\n"
                "except OSError:\n"
                "    sys.exit(0)\n"
                "else:\n"
                "    sys.exit(1)\n",
            ],
            env=self.env,
            check=False,
        )
        self.assertEqual(proc_ro.returncode, 0, proc_ro.stderr)


class ProfileCommandTests(LeashIntegrationTestCase):
    def test_profile_show_reports_match_and_difference(self) -> None:
        source = f"{self.rw_dir} rw\n{self.fixture} ro\n/bin ro\n/usr ro\n"
        self.default_profile_path.write_text(source)
        run_cmd(
            [str(self.leash_bin), "_set-profile", str(self.default_profile_path)],
            env=self.env,
            capture_stdout=False,
        )

        shown = run_cmd(
            [str(self.leash_bin), "profile", "show"],
            env=self.env,
        )
        self.assertIn(source, shown.stdout)
        self.assertIn("# daemon profile matches default profile", shown.stdout)

        changed = f"{self.deny_dir} deny\n{self.fixture} ro\n/bin ro\n/usr ro\n"
        self.default_profile_path.write_text(changed)
        shown = run_cmd(
            [str(self.leash_bin), "profile", "show"],
            env=self.env,
        )
        self.assertIn(changed, shown.stdout)
        self.assertIn("# daemon profile differs from default profile", shown.stdout)

    def test_profile_edit_updates_default_profile_and_daemon(self) -> None:
        original = f"{self.rw_dir} rw\n{self.fixture} ro\n/bin ro\n/usr ro\n"
        updated = f"{self.deny_dir} deny\n{self.fixture} ro\n/bin ro\n/usr ro\n"
        self.default_profile_path.write_text(original)
        run_cmd(
            [str(self.leash_bin), "_set-profile", str(self.default_profile_path)],
            env=self.env,
            capture_stdout=False,
        )

        editor_script = self.tmpdir / "write-profile.py"
        editor_script.write_text(
            textwrap.dedent(
                f"""\
                #!/usr/bin/env python3
                import pathlib
                import sys

                pathlib.Path(sys.argv[1]).write_text({updated!r})
                """
            )
        )
        editor_script.chmod(0o755)
        self.env["EDITOR"] = f"python3 {editor_script}"

        edited = run_cmd(
            [str(self.leash_bin), "profile", "edit"],
            env=self.env,
        )
        self.assertEqual(self.default_profile_path.read_text(), updated)
        self.assertIn("daemon profile: updated (was different from disk)", edited.stderr)

        shown = run_cmd(
            [str(self.leash_bin), "profile", "show"],
            env=self.env,
        )
        self.assertIn(updated, shown.stdout)
        self.assertIn("# daemon profile matches default profile", shown.stdout)

    def test_profile_edit_invalid_source_does_not_write_default_profile(self) -> None:
        original = f"{self.rw_dir} rw\n{self.fixture} ro\n/bin ro\n/usr ro\n"
        self.default_profile_path.write_text(original)
        run_cmd(
            [str(self.leash_bin), "_set-profile", str(self.default_profile_path)],
            env=self.env,
            capture_stdout=False,
        )

        editor_script = self.tmpdir / "write-invalid-profile.py"
        editor_script.write_text(
            "#!/usr/bin/env python3\n"
            "import pathlib\n"
            "import sys\n\n"
            "pathlib.Path(sys.argv[1]).write_text(\"/tmp maybe\\n\")\n"
        )
        editor_script.chmod(0o755)
        self.env["EDITOR"] = f"python3 {editor_script}"

        edited = run_cmd(
            [str(self.leash_bin), "profile", "edit"],
            env=self.env,
            check=False,
        )
        self.assertNotEqual(edited.returncode, 0)
        self.assertIn("edited profile is invalid", edited.stderr)
        self.assertEqual(self.default_profile_path.read_text(), original)

        shown = run_cmd(
            [str(self.leash_bin), "profile", "show"],
            env=self.env,
        )
        self.assertIn(original, shown.stdout)
        self.assertIn("# daemon profile matches default profile", shown.stdout)

    def test_profile_show_without_daemon_omits_match_status(self) -> None:
        self.default_profile_path.write_text(f"{self.fixture} ro\n/bin ro\n/usr ro\n")
        run_cmd(
            [str(self.leash_bin), "_shutdown-daemon"],
            env=self.env,
            capture_stdout=False,
        )
        self.daemon.wait(timeout=5)

        shown = run_cmd(
            [str(self.leash_bin), "profile", "show"],
            env=self.env,
        )
        self.assertIn(f"{self.fixture} ro\n/bin ro\n/usr ro\n", shown.stdout)
        self.assertNotIn("# daemon profile matches default profile", shown.stdout)
        self.assertNotIn("# daemon profile differs from default profile", shown.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
