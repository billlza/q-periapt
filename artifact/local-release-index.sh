#!/bin/sh
# Build a local, hash-bound release index over already verified package artifacts.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd) || exit 2
cd "$ROOT" || exit 2

need() {
	if ! command -v "$1" >/dev/null 2>&1; then
		printf 'error: required tool not found: %s\n' "$1" >&2
		exit 2
	fi
}

need cargo
need git
need python3
need rustc

CHANNEL=${QPERIAPT_RELEASE_INDEX_CHANNEL:-release}
case "$CHANNEL" in
	release | diagnostic) ;;
	*)
		printf 'error: QPERIAPT_RELEASE_INDEX_CHANNEL must be release or diagnostic\n' >&2
		exit 2
		;;
esac
case "${QPERIAPT_ALLOW_DIRTY_RELEASE_INDEX:-0}" in
	0 | 1) ;;
	*)
		printf 'error: QPERIAPT_ALLOW_DIRTY_RELEASE_INDEX must be 0 or 1\n' >&2
		exit 2
		;;
esac
if [ "${QPERIAPT_ALLOW_DIRTY_RELEASE_INDEX:-0}" = "1" ]; then
	CHANNEL=diagnostic
fi

set -- python3 artifact/release_index.py emit --root "$ROOT" --channel "$CHANNEL"

if [ -n "${QPERIAPT_RELEASE_INDEX_OUT_DIR:-}" ]; then
	set -- "$@" --output-dir "$QPERIAPT_RELEASE_INDEX_OUT_DIR"
fi

if [ "${QPERIAPT_RELEASE_INDEX_INCLUDE_APPLE_MATRIX:-0}" = "1" ]; then
	if [ -z "${QPERIAPT_DEVICE_RESULT_DIR:-}" ]; then
		printf 'error: QPERIAPT_DEVICE_RESULT_DIR is required when QPERIAPT_RELEASE_INDEX_INCLUDE_APPLE_MATRIX=1\n' >&2
		exit 2
	fi
	set -- "$@" --apple-matrix-proof "${QPERIAPT_DEVICE_MATRIX_PROOF:-$QPERIAPT_DEVICE_RESULT_DIR/apple-device-matrix-proof.json}"
fi

if [ "${QPERIAPT_RELEASE_INDEX_INCLUDE_ANDROID_RUNTIME:-0}" = "1" ]; then
	set -- "$@" --android-proof "${QPERIAPT_ANDROID_DEVICE_PROOF:-$ROOT/target/qperiapt-android-device-smoke/proof/qperiapt-android-device-proof.json}"
fi

"$@"
