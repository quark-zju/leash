#!/usr/bin/env python3

import atexit
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
WORK_DIR = Path(tempfile.mkdtemp(prefix="cowjail-e2e-", dir="/tmp"))
MOUNT_DIR = WORK_DIR / "mnt"
RECORD_PATH = WORK_DIR / "record.cjr"
PROFILE_PATH = WORK_DIR / "profile"
TARGET_PATH = WORK_DIR / "host.txt"
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


def main() -> int:
    global mount_proc
    atexit.register(cleanup)

    MOUNT_DIR.mkdir(parents=True, exist_ok=True)
    TARGET_PATH.write_text("before\n", encoding="utf-8")
    PROFILE_PATH.write_text(f"{WORK_DIR} rw\n/tmp ro\n", encoding="utf-8")

    print("[1/6] building cowjail via cargo")
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

    print("[2/6] starting low-level mount")
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
        fail("mount process exited before test write")

    print("[3/6] writing through mounted view")
    mounted_target = MOUNT_DIR / TARGET_PATH.relative_to("/")
    mounted_target.write_text("after\n", encoding="utf-8")

    print("[4/6] verifying host not changed before flush")
    if TARGET_PATH.read_text(encoding="utf-8") != "before\n":
        fail("host content changed before flush (unexpected)")

    print("[5/6] unmount and flush")
    run(["fusermount", "-u", str(MOUNT_DIR)])
    mount_proc.wait(timeout=5)
    mount_proc = None
    run(RUN_COWJAIL + ["_flush", "--record", str(RECORD_PATH)])

    print("[6/6] verifying host changed after flush")
    if TARGET_PATH.read_text(encoding="utf-8") != "after\n":
        fail("host content was not updated by flush")

    print("smoke test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
