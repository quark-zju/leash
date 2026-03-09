#!/usr/bin/env bash
set -euo pipefail

# Manual smoke test for cowjail mount/flush flow.
# Requirements:
# - Linux with FUSE support
# - fusermount available
# - current user can mount FUSE

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d /tmp/cowjail-e2e-XXXXXX)"
MNT="${WORK}/mnt"
RECORD="${WORK}/record.cjr"
PROFILE="${WORK}/profile"
TARGET="${WORK}/host.txt"
MOUNT_PID=""
RUN_COWJAIL=(cargo run --manifest-path "${ROOT_DIR}/Cargo.toml" --bin cowjail --)

cleanup() {
  set +e
  if [[ -n "${MOUNT_PID}" ]] && kill -0 "${MOUNT_PID}" 2>/dev/null; then
    fusermount -u "${MNT}" 2>/dev/null || true
    kill "${MOUNT_PID}" 2>/dev/null || true
    wait "${MOUNT_PID}" 2>/dev/null || true
  fi
  rm -rf "${WORK}"
}
trap cleanup EXIT

mkdir -p "${MNT}"
echo "before" > "${TARGET}"

cat > "${PROFILE}" <<PROFILE
/tmp ro
${WORK} rw
PROFILE

echo "[1/6] checking cowjail command path via cargo run"
"${RUN_COWJAIL[@]}" --help >/dev/null

echo "[2/6] starting mount"
"${RUN_COWJAIL[@]}" mount --profile "${PROFILE}" --record "${RECORD}" "${MNT}" &
MOUNT_PID="$!"
sleep 1

echo "[3/6] writing through mounted view"
echo "after" > "${MNT}${TARGET}"

echo "[4/6] verifying host not changed before flush"
if [[ "$(cat "${TARGET}")" != "before" ]]; then
  echo "host content changed before flush (unexpected)"
  exit 1
fi

echo "[5/6] unmount and flush"
fusermount -u "${MNT}"
wait "${MOUNT_PID}" || true
MOUNT_PID=""
"${RUN_COWJAIL[@]}" flush --record "${RECORD}"

echo "[6/6] verifying host changed after flush"
if [[ "$(cat "${TARGET}")" != "after" ]]; then
  echo "host content was not updated by flush"
  exit 1
fi

echo "smoke test passed"
