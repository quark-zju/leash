#!/usr/bin/env python3

from __future__ import annotations

import argparse
import contextlib
import os
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a high-level semantic smoke test for cowjail."
    )
    parser.add_argument(
        "--bin",
        type=Path,
        default=Path("target/debug/cowjail"),
        help="path to the cowjail binary",
    )
    parser.add_argument(
        "--keep-temp",
        action="store_true",
        help="keep the temporary workspace for debugging",
    )
    return parser.parse_args()


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def require_usable_binary(cowjail_bin: Path) -> None:
    if not cowjail_bin.is_file():
        fail(f"cowjail binary not found: {cowjail_bin}")

    if os.geteuid() == 0:
        return

    meta = cowjail_bin.stat()
    if meta.st_uid == 0 and meta.st_mode & stat.S_ISUID:
        return

    fail(
        "cowjail run requires root or a setuid-root binary; run the binary once with _suid first"
    )


def run(
    cmd: list[str],
    *,
    env: dict[str, str],
    cwd: Path | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    print("+", shlex.join(cmd))
    completed = subprocess.run(
        cmd,
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
    )
    if check and completed.returncode != 0:
        print(completed.stdout, end="")
        print(completed.stderr, end="", file=sys.stderr)
        fail(f"command failed with exit code {completed.returncode}: {shlex.join(cmd)}")
    return completed


def assert_contains(haystack: str, needle: str, *, what: str) -> None:
    if needle not in haystack:
        fail(f"expected {what} to contain {needle!r}, got: {haystack!r}")


def assert_eq(actual: str, expected: str, *, what: str) -> None:
    if actual != expected:
        fail(f"unexpected {what}: expected {expected!r}, got {actual!r}")


def jail(
    cowjail_bin: Path,
    env: dict[str, str],
    *args: str,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    return run([str(cowjail_bin), *args], env=env, check=check)


def main() -> None:
    args = parse_args()
    cowjail_bin = args.bin.resolve()
    require_usable_binary(cowjail_bin)

    system_git = shutil.which("git")
    if system_git is None:
        fail("system git not found in PATH")

    temp_context = (
        contextlib.nullcontext(Path(tempfile.mkdtemp(prefix="cowjail-e2e-")))
        if args.keep_temp
        else tempfile.TemporaryDirectory(prefix="cowjail-e2e-")
    )
    with temp_context as tmpdir_raw:
        tmpdir = Path(tmpdir_raw)
        if args.keep_temp:
            print(f"keeping temporary directory: {tmpdir}")

        home = tmpdir / "home"
        runtime = tmpdir / "runtime"
        fixture = tmpdir / "fixture"
        ro_dir = fixture / "ro"
        rw_dir = fixture / "rw"
        hidden_dir = fixture / "hidden"
        deny_dir = fixture / "deny"
        workspace = fixture / "workspace"
        repo = workspace / "repo"
        nonrepo = workspace / "nonrepo"

        for path in [
            home / ".config" / "cowjail" / "profiles",
            runtime,
            ro_dir,
            rw_dir,
            hidden_dir,
            deny_dir,
            repo,
            nonrepo,
        ]:
            path.mkdir(parents=True, exist_ok=True)
        runtime.chmod(0o700)

        ro_file = ro_dir / "note.txt"
        rw_file = rw_dir / "note.txt"
        hidden_file = hidden_dir / "secret.txt"
        deny_file = deny_dir / "secret.txt"
        repo_file = repo / "tracked.txt"
        nonrepo_file = nonrepo / "loose.txt"

        ro_file.write_text("ro-ok\n")
        rw_file.write_text("rw-before\n")
        hidden_file.write_text("hidden\n")
        deny_file.write_text("deny\n")
        repo_file.write_text("repo-before\n")
        nonrepo_file.write_text("nonrepo-before\n")

        base_env = os.environ.copy()
        base_env.update(
            {
                "HOME": str(home),
                "XDG_RUNTIME_DIR": str(runtime),
                "LC_ALL": "C",
                "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_AUTHOR_NAME": "cowjail e2e",
                "GIT_AUTHOR_EMAIL": "cowjail@example.com",
                "GIT_COMMITTER_NAME": "cowjail e2e",
                "GIT_COMMITTER_EMAIL": "cowjail@example.com",
            }
        )

        run([system_git, "init", "-q", str(repo)], env=base_env)
        run([system_git, "-C", str(repo), "add", "tracked.txt"], env=base_env)
        run(
            [system_git, "-C", str(repo), "commit", "-q", "-m", "initial"],
            env=base_env,
        )

        profile_path = tmpdir / "semantics.profile"
        profile_path.write_text(
            textwrap.dedent(
                f"""\
                {hidden_dir} hide
                {deny_dir} deny
                {rw_dir} rw
                {workspace} git-rw
                {fixture} ro
                /bin ro
                /sbin ro
                /usr ro
                /lib ro
                /lib64 ro
                /etc ro
                /proc rw
                /tmp rw
                /dev/null rw
                /dev/urandom ro
                """
            )
        )

        jail(
            cowjail_bin,
            base_env,
            "add",
            "--name",
            "semantics",
            "--profile",
            str(profile_path),
        )

        try:
            print("[1/5] verifying ro and rw")
            completed = jail(
                cowjail_bin,
                base_env,
                "run",
                "--name",
                "semantics",
                "--",
                "/bin/sh",
                "-lc",
                'cat "$1"',
                "sh",
                str(ro_file),
            )
            assert_eq(completed.stdout, "ro-ok\n", what="ro read output")

            completed = jail(
                cowjail_bin,
                base_env,
                "run",
                "--name",
                "semantics",
                "--",
                "/bin/sh",
                "-lc",
                'printf changed >"$1"',
                "sh",
                str(ro_file),
                check=False,
            )
            if completed.returncode == 0:
                fail("ro write unexpectedly succeeded")
            assert_eq(ro_file.read_text(), "ro-ok\n", what="host ro file content")

            jail(
                cowjail_bin,
                base_env,
                "run",
                "--name",
                "semantics",
                "--",
                "/bin/sh",
                "-lc",
                'printf rw-after >"$1"',
                "sh",
                str(rw_file),
            )
            assert_eq(rw_file.read_text(), "rw-after", what="host rw file content")

            print("[2/5] verifying hide")
            completed = jail(
                cowjail_bin,
                base_env,
                "run",
                "--name",
                "semantics",
                "--",
                "/bin/sh",
                "-lc",
                '[ ! -e "$1" ]',
                "sh",
                str(hidden_file),
            )
            if completed.returncode != 0:
                fail("hidden path was still visible inside the jail")

            print("[3/5] verifying deny")
            completed = jail(
                cowjail_bin,
                base_env,
                "run",
                "--name",
                "semantics",
                "--",
                "/bin/sh",
                "-lc",
                'cat "$1"',
                "sh",
                str(deny_file),
                check=False,
            )
            if completed.returncode == 0:
                fail("deny path unexpectedly became readable")
            assert_contains(
                completed.stderr,
                "Permission denied",
                what="deny stderr",
            )

            print("[4/5] verifying git-rw worktree and non-repo behavior")
            jail(
                cowjail_bin,
                base_env,
                "run",
                "--name",
                "semantics",
                "--",
                "/bin/sh",
                "-lc",
                'printf repo-after >"$1"',
                "sh",
                str(repo_file),
            )
            assert_eq(repo_file.read_text(), "repo-after", what="host repo file content")

            completed = jail(
                cowjail_bin,
                base_env,
                "run",
                "--name",
                "semantics",
                "--",
                "/bin/sh",
                "-lc",
                'printf blocked >"$1"',
                "sh",
                str(nonrepo_file),
                check=False,
            )
            if completed.returncode == 0:
                fail("non-repo write under git-rw unexpectedly succeeded")
            assert_eq(
                nonrepo_file.read_text(),
                "nonrepo-before\n",
                what="host non-repo file content",
            )

            print("[5/5] verifying .git protection and trusted git access")
            completed = jail(
                cowjail_bin,
                base_env,
                "run",
                "--name",
                "semantics",
                "--",
                "/bin/sh",
                "-lc",
                'cat "$1"',
                "sh",
                str(repo / ".git" / "HEAD"),
                check=False,
            )
            if completed.returncode == 0:
                fail("direct .git access unexpectedly succeeded")
            assert_contains(
                completed.stderr,
                "Permission denied",
                what=".git access stderr",
            )

            completed = jail(
                cowjail_bin,
                base_env,
                "run",
                "--name",
                "semantics",
                "--",
                system_git,
                "-C",
                str(repo),
                "status",
                "--short",
            )
            assert_contains(
                completed.stdout,
                "M tracked.txt",
                what="git status output",
            )

            completed = jail(
                cowjail_bin,
                base_env,
                "run",
                "--name",
                "semantics",
                "--",
                system_git,
                "-C",
                str(repo),
                "log",
                "-1",
                "--format=%s",
            )
            assert_eq(completed.stdout.strip(), "initial", what="git log output")
        finally:
            jail(
                cowjail_bin,
                base_env,
                "rm",
                "--name",
                "semantics",
                check=False,
            )

        print("PASS: semantic e2e checks succeeded")


if __name__ == "__main__":
    main()
