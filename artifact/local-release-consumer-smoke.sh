#!/bin/sh
# Consume the local release index like an external downstream C project.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd) || exit 2
cd "$ROOT" || exit 2

need() {
	if ! command -v "$1" >/dev/null 2>&1; then
		printf 'error: required tool not found: %s\n' "$1" >&2
		exit 2
	fi
}

need cc
need pkg-config
need python3

set -- python3 artifact/release_consumer_smoke.py --root "$ROOT"

if [ -n "${QPERIAPT_RELEASE_INDEX_PATH:-}" ]; then
	set -- "$@" --index "$QPERIAPT_RELEASE_INDEX_PATH"
fi

if [ -n "${QPERIAPT_RELEASE_CONSUMER_OUT_DIR:-}" ]; then
	set -- "$@" --out-dir "$QPERIAPT_RELEASE_CONSUMER_OUT_DIR"
fi

"$@"
