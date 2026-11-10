#!/bin/sh
# Consume the local release index like an external downstream C project.
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
if [ "${QPERIAPT_RELEASE_INDEX_PATH+x}" = x ] || \
	[ "${QPERIAPT_RELEASE_CONSUMER_OUT_DIR+x}" = x ]; then
	printf 'error: caller-selected release index and consumer output paths are not supported\n' >&2
	exit 2
fi

set -- python3 artifact/release_consumer_smoke.py run

if [ "${QPERIAPT_ALLOW_DIAGNOSTIC_RELEASE_CONSUMER:-0}" = "1" ]; then
	set -- "$@" --channel diagnostic --allow-diagnostic
fi

"$@"
