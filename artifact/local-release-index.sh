#!/bin/sh
# Build a local, hash-bound release index over already verified package artifacts.
set -eu
umask 077

ROOT=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd) || exit 2
cd "$ROOT" || exit 2
. "$ROOT/artifact/python-env.sh"

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
if [ "${QPERIAPT_RELEASE_INDEX_OUT_DIR+x}" = x ]; then
	printf 'error: QPERIAPT_RELEASE_INDEX_OUT_DIR is no longer supported; the local store is fixed\n' >&2
	exit 2
fi

for include_value in \
	"${QPERIAPT_RELEASE_INDEX_INCLUDE_APPLE_MATRIX:-0}" \
	"${QPERIAPT_RELEASE_INDEX_INCLUDE_ANDROID_RUNTIME:-0}"
do
	case "$include_value" in
		0 | 1) ;;
		*)
			printf 'error: local release proof selectors must be 0 or 1\n' >&2
			exit 2
			;;
	esac
done
if [ "${QPERIAPT_DEVICE_MATRIX_PROOF+x}" = x ] || \
	[ "${QPERIAPT_ANDROID_DEVICE_PROOF+x}" = x ]; then
	printf 'error: local release indexes do not accept caller-selected proof file paths\n' >&2
	exit 2
fi

set -- python3 artifact/release_index.py emit --channel "$CHANNEL"
if [ "${QPERIAPT_RELEASE_INDEX_INCLUDE_APPLE_MATRIX:-0}" = "1" ]; then
	if [ -z "${QPERIAPT_DEVICE_RESULT_DIR:-}" ]; then
		printf 'error: QPERIAPT_DEVICE_RESULT_DIR is required for an Apple matrix summary\n' >&2
		exit 2
	fi
	apple_run_directory=${QPERIAPT_DEVICE_RESULT_DIR%/}
	apple_run_leaf=${apple_run_directory##*/}
	if [ -z "$apple_run_leaf" ]; then
		printf 'error: QPERIAPT_DEVICE_RESULT_DIR lacks a run directory name\n' >&2
		exit 2
	fi
	set -- "$@" --apple-matrix-run "$apple_run_leaf"
fi
if [ "${QPERIAPT_RELEASE_INDEX_INCLUDE_ANDROID_RUNTIME:-0}" = "1" ]; then
	android_runtime_run=${QPERIAPT_ANDROID_RUNTIME_RUN:-}
	case "$android_runtime_run" in
		"" | *[!0-9a-f]*)
			printf 'error: QPERIAPT_ANDROID_RUNTIME_RUN must be 32 lowercase hex characters\n' >&2
			exit 2
			;;
	esac
	if [ "${#android_runtime_run}" -ne 32 ]; then
		printf 'error: QPERIAPT_ANDROID_RUNTIME_RUN must be 32 lowercase hex characters\n' >&2
		exit 2
	fi
	set -- "$@" --android-runtime-run "$android_runtime_run"
elif [ "${QPERIAPT_ANDROID_RUNTIME_RUN+x}" = x ]; then
	printf 'error: QPERIAPT_ANDROID_RUNTIME_RUN requires the Android runtime selector\n' >&2
	exit 2
fi

"$@"
