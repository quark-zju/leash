#!/usr/bin/env python3

import atexit
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent


def init_work_dir() -> Path:
    configured = os.environ.get("COWJAIL_E2E_WORK_ROOT")
    if configured:
        base = Path(configured)
    else:
        base = ROOT_DIR / ".e2e-work"
    try:
        base.mkdir(parents=True, exist_ok=True)
        return Path(tempfile.mkdtemp(prefix="cowjail-e2e-", dir=str(base)))
    except OSError:
        return Path(tempfile.mkdtemp(prefix="cowjail-e2e-", dir="/tmp"))


WORK_DIR = init_work_dir()
MOUNT_DIR = WORK_DIR / "mnt"
RECORD_PATH = WORK_DIR / "record.cjr"
PROFILE_PATH = WORK_DIR / "profile"
TARGET_PATH = WORK_DIR / "host.txt"
TARGET_PATH_HIGH = WORK_DIR / "host-high.txt"
# Use a random per-run jail name to avoid cross-run/profile binding conflicts.
HIGH_LEVEL_JAIL = f"e2e-high-level-{secrets.token_hex(6)}"
RUN_COWJAIL = [
    "cargo",
    "run",
    "--manifest-path",
    str(ROOT_DIR / "Cargo.toml"),
    "--bin",
    "cowjail",
    "--",
]

mount_proc: subprocess.Popen[str] | None = None


def run(cmd: list[str], *, stdout=None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, check=True, text=True, stdout=stdout)


def cleanup() -> None:
    global mount_proc
    if mount_proc is not None and mount_proc.poll() is None:
        subprocess.run(["fusermount", "-u", str(MOUNT_DIR)], check=False)
        mount_proc.terminate()
        try:
            mount_proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            mount_proc.kill()
            mount_proc.wait(timeout=2)
    shutil.rmtree(WORK_DIR, ignore_errors=True)


def fail(message: str) -> "NoReturn":
    print(message, file=sys.stderr)
    raise SystemExit(1)


def resolve_target_directory() -> Path:
    metadata = run(
        [
            "cargo",
            "metadata",
            "--manifest-path",
            str(ROOT_DIR / "Cargo.toml"),
            "--format-version",
            "1",
            "--no-deps",
        ],
        stdout=subprocess.PIPE,
    )
    return Path(json.loads(metadata.stdout)["target_directory"])


def resolve_built_binary_path() -> Path:
    target_dir = resolve_target_directory()
    candidates = [
        target_dir / "debug" / "cowjail",
        ROOT_DIR / "target" / "debug" / "cowjail",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    fail(
        "unable to locate built cowjail binary; looked at: "
        + ", ".join(str(p) for p in candidates)
    )


def prepare_inputs() -> None:
    MOUNT_DIR.mkdir(parents=True, exist_ok=True)
    TARGET_PATH.write_text("before\n", encoding="utf-8")
    TARGET_PATH_HIGH.write_text("before-high\n", encoding="utf-8")
    PROFILE_PATH.write_text(f"{WORK_DIR} rw\n/tmp ro\n", encoding="utf-8")


def run_low_level_smoke() -> None:
    global mount_proc
    print("[low 1/5] starting low-level mount")
    mount_proc = subprocess.Popen(
        RUN_COWJAIL
        + [
            "_mount",
            "--profile",
            str(PROFILE_PATH),
            "--record",
            str(RECORD_PATH),
            str(MOUNT_DIR),
        ],
        text=True,
    )
    time.sleep(1)

    if mount_proc.poll() is not None:
        fail("low-level mount process exited before test write")

    print("[low 2/5] writing through mounted view")
    mounted_target = MOUNT_DIR / TARGET_PATH.relative_to("/")
    mounted_target.write_text("after\n", encoding="utf-8")

    print("[low 3/5] verifying host not changed before flush")
    if TARGET_PATH.read_text(encoding="utf-8") != "before\n":
        fail("host content changed before low-level flush (unexpected)")

    print("[low 4/5] unmount and low-level flush")
    run(["fusermount", "-u", str(MOUNT_DIR)])
    mount_proc.wait(timeout=5)
    mount_proc = None
    run(RUN_COWJAIL + ["_flush", "--record", str(RECORD_PATH)])

    print("[low 5/5] verifying host changed after flush")
    if TARGET_PATH.read_text(encoding="utf-8") != "after\n":
        fail("host content was not updated by low-level flush")


def prepare_setuid_binary() -> Path | None:
    built = resolve_built_binary_path()

    try:
        run([str(built), "_suid"], stdout=subprocess.DEVNULL)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    return built


def run_high_level_smoke() -> bool:
    suid_bin = prepare_setuid_binary()
    if suid_bin is None:
        print("[high] SKIP: failed to setup setuid binary via _suid")
        return False

    print("[high 1/6] cleaning old jail if present")
    subprocess.run(
        [str(suid_bin), "rm", "--name", HIGH_LEVEL_JAIL],
        check=False,
        text=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        print("[high 2/6] creating named jail")
        run([str(suid_bin), "add", "--name", HIGH_LEVEL_JAIL, "--profile", str(PROFILE_PATH)])

        print("[high 3/6] writing via high-level run")
        try:
            run_result = subprocess.run(
                [
                    str(suid_bin),
                    "run",
                    "--name",
                    HIGH_LEVEL_JAIL,
                    "/bin/sh",
                    "-lc",
                    f"printf 'after-high\\n' > '{TARGET_PATH_HIGH}'",
                ],
                check=False,
                text=True,
                capture_output=True,
                timeout=20,
            )
        except subprocess.TimeoutExpired as exc:
            print(exc.stdout or "", end="")
            print(exc.stderr or "", end="", file=sys.stderr)
            fail("high-level run timed out after 20s at [high 3/6]")
        if run_result.returncode != 0:
            merged = f"{run_result.stdout}\n{run_result.stderr}"
            if "requires root euid" in merged:
                print(
                    "[high] SKIP: setuid binary did not gain root euid "
                    "(likely nosuid mount on work dir)"
                )
                return False
            print(run_result.stdout, end="")
            print(run_result.stderr, end="", file=sys.stderr)
            fail(f"high-level run failed with exit code {run_result.returncode}")

        print("[high 4/6] verifying host not changed before flush")
        if TARGET_PATH_HIGH.read_text(encoding="utf-8") != "before-high\n":
            fail("host content changed before high-level flush (unexpected)")

        print("[high 5/6] flushing named jail")
        run([str(suid_bin), "flush", "--name", HIGH_LEVEL_JAIL])

        print("[high 6/6] verifying host changed after flush")
        if TARGET_PATH_HIGH.read_text(encoding="utf-8") != "after-high\n":
            fail("host content was not updated by high-level flush")
        return True
    finally:
        subprocess.run(
            [str(suid_bin), "rm", "--name", HIGH_LEVEL_JAIL],
            check=False,
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


def main() -> int:
    atexit.register(cleanup)
    prepare_inputs()

    print("[1/3] building cowjail via cargo")
    run(
        [
            "cargo",
            "build",
            "--manifest-path",
            str(ROOT_DIR / "Cargo.toml"),
            "--bin",
            "cowjail",
        ],
        stdout=subprocess.DEVNULL,
    )

    print("[2/3] running low-level smoke")
    run_low_level_smoke()

    print("[3/3] running high-level smoke")
    high_level_ran = run_high_level_smoke()
    if high_level_ran:
        print("smoke test passed (low-level + high-level)")
    else:
        print("smoke test passed (low-level, high-level skipped)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
