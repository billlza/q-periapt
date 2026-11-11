#!/bin/sh
# One-shot hardened Python entrypoint for CI and documented operator commands.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd) || exit 2
cd "$ROOT" || exit 2
. "$ROOT/artifact/python-env.sh"

python3 "$@"
