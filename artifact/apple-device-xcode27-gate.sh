#!/bin/sh
# Fail-closed Xcode 27 physical-device capture for the Apple Swift/C ABI proof lane.
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

need date
need python3
need xcodebuild

if [ -z "${QPERIAPT_DEVELOPER_DIR:-}" ]; then
	printf 'error: QPERIAPT_DEVELOPER_DIR is required for the Xcode 27 gate\n' >&2
	exit 2
fi
if [ -z "${DEVELOPMENT_TEAM:-}" ]; then
	printf 'error: DEVELOPMENT_TEAM is required for the Xcode 27 gate\n' >&2
	exit 2
fi
MATRIX_MODE=0
if [ -n "${QPERIAPT_IOS_DEVICE_MATRIX:-}" ] || [ "${QPERIAPT_REQUIRE_APPLE_DEVICE_MATRIX:-0}" = "1" ]; then
	MATRIX_MODE=1
fi
if [ "$MATRIX_MODE" = "1" ] && [ -n "${QPERIAPT_IOS_DEVICE_ID:-}" ]; then
	printf 'error: QPERIAPT_IOS_DEVICE_ID and matrix mode are mutually exclusive\n' >&2
	exit 2
fi
if [ "$MATRIX_MODE" = "0" ] && [ -z "${QPERIAPT_IOS_DEVICE_ID:-}" ]; then
	printf 'error: QPERIAPT_IOS_DEVICE_ID is required for the Xcode 27 gate\n' >&2
	exit 2
fi

DEVELOPER_DIR=$QPERIAPT_DEVELOPER_DIR
export DEVELOPER_DIR

XCODE_VERSION=$(xcodebuild -version | sed -n '1p')
XCODE_BUILD=$(xcodebuild -version | sed -n '2p')
case "$XCODE_VERSION" in
	Xcode\ 27|Xcode\ 27.*) ;;
	*)
		printf 'error: expected Xcode 27.x, got: %s\n' "$XCODE_VERSION" >&2
		exit 1
		;;
esac
if [ -n "${QPERIAPT_EXPECT_XCODE_BUILD:-}" ] && [ "$XCODE_BUILD" != "Build version $QPERIAPT_EXPECT_XCODE_BUILD" ]; then
	printf 'error: expected Xcode build %s, got: %s\n' "$QPERIAPT_EXPECT_XCODE_BUILD" "$XCODE_BUILD" >&2
	exit 1
fi

RUN_LABEL=$(date -u +%Y%m%dT%H%M%SZ)-$(python3 -c 'import secrets; print(secrets.token_hex(4))')
if [ -z "${QPERIAPT_DEVICE_RESULT_DIR:-}" ]; then
	if [ "$MATRIX_MODE" = "1" ]; then
		QPERIAPT_DEVICE_RESULT_DIR="$ROOT/artifact/device-runs/xcode27-matrix-$RUN_LABEL"
	else
		QPERIAPT_DEVICE_RESULT_DIR="$ROOT/artifact/device-runs/xcode27-$RUN_LABEL"
	fi
	export QPERIAPT_DEVICE_RESULT_DIR
fi
if [ -z "${QPERIAPT_DERIVED_DATA:-}" ]; then
	if [ "$MATRIX_MODE" = "1" ]; then
		QPERIAPT_DERIVED_DATA="$ROOT/target/apple-device-derived-xcode27-matrix-$RUN_LABEL"
	else
		QPERIAPT_DERIVED_DATA="$ROOT/target/apple-device-derived-xcode27-$RUN_LABEL"
	fi
	export QPERIAPT_DERIVED_DATA
fi

printf 'Q-Periapt Xcode 27 Apple-device gate\n'
printf 'xcode  : %s %s\n' "$XCODE_VERSION" "$XCODE_BUILD"
printf 'result : %s\n' "$QPERIAPT_DEVICE_RESULT_DIR"
printf 'derived: %s\n' "$QPERIAPT_DERIVED_DATA"
printf 'mode   : %s\n' "$([ "$MATRIX_MODE" = "1" ] && printf matrix || printf single)"

if [ "${QPERIAPT_ALLOW_DIRTY_APPLE_DEVICE:-0}" = "1" ]; then
	QPERIAPT_ALLOW_DIRTY_APPLE_DEVICE_PROOF=1
	export QPERIAPT_ALLOW_DIRTY_APPLE_DEVICE_PROOF
fi

if [ "$MATRIX_MODE" = "1" ]; then
	sh artifact/apple-device-matrix.sh
	printf 'APPLE_DEVICE_XCODE27_CAPTURE_PASS mode=matrix promotion=pending result_dir=%s\n' \
		"$QPERIAPT_DEVICE_RESULT_DIR"
else
	sh artifact/apple-device-smoke.sh
	printf 'APPLE_DEVICE_XCODE27_CAPTURE_PASS mode=single promotion=pending result_dir=%s\n' \
		"$QPERIAPT_DEVICE_RESULT_DIR"
fi
