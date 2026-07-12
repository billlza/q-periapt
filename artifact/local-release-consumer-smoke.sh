#!/bin/sh
# Consume the local release index like an external downstream C project.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd) || exit 2
cd "$ROOT" || exit 2
. "$ROOT/artifact/python-env.sh"

need() {
	if ! command -v "$1" >/dev/null 2>&1; then
		printf 'error: required tool not found: %s\n' "$1" >&2
		exit 2
	fi
}

need cc
need pkg-config
need python3

case "${QPERIAPT_ALLOW_DIAGNOSTIC_RELEASE_CONSUMER:-0}" in
	0 | 1) ;;
	*)
		printf 'error: QPERIAPT_ALLOW_DIAGNOSTIC_RELEASE_CONSUMER must be 0 or 1\n' >&2
		exit 2
		;;
esac

set -- python3 artifact/release_consumer_smoke.py --root "$ROOT"

if [ -n "${QPERIAPT_RELEASE_INDEX_PATH:-}" ]; then
	set -- "$@" --index "$QPERIAPT_RELEASE_INDEX_PATH"
fi

if [ -n "${QPERIAPT_RELEASE_CONSUMER_OUT_DIR:-}" ]; then
	set -- "$@" --out-dir "$QPERIAPT_RELEASE_CONSUMER_OUT_DIR"
fi

if [ "${QPERIAPT_ALLOW_DIAGNOSTIC_RELEASE_CONSUMER:-0}" = "1" ]; then
	set -- "$@" --allow-diagnostic
fi

"$@"
