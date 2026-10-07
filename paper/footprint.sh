#!/bin/sh
# =============================================================================
# Reproduce the artifact's binary footprint (C-ABI cdylib + WASM module) and write
# paper/footprint.csv. Footprint is PLATFORM-DEPENDENT (toolchain, target, libc, strip),
# so run this on the host you want numbers for — do not treat any single value as universal.
#
#     sh paper/footprint.sh
# =============================================================================
set -eu

fail() {
  echo "footprint: $*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

for command_name in awk cargo cp cut dirname mktemp mv rm rustc strip tee tr uname wasm-pack wc; do
  need "$command_name"
done

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd) || fail "cannot resolve repository root"
cd "$ROOT" || fail "cannot enter repository root: $ROOT"

TMP_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/qperiapt-footprint.XXXXXX") || fail "cannot create temporary directory"
trap 'rm -rf "$TMP_ROOT"' EXIT HUP INT TERM

HOST="$(uname -srm)"
RUSTC="$(rustc --version | cut -d' ' -f2)"
OUT="paper/footprint.csv"
OUT_TMP="$TMP_ROOT/footprint.csv"
kib() { awk -v bytes="$1" 'BEGIN { printf "%.1f", bytes / 1024 }'; }

require_file() {
  [ -f "$1" ] || fail "expected build artifact is missing: $1"
}

# ---- C-ABI cdylib, release + stripped (the default hybrid build) ------------
echo "building C-ABI cdylib (release)..."
cargo build --locked -p q-periapt-ffi --release

case "$(uname -s)" in
  Darwin)
    LIB="target/release/libq_periapt_ffi_abi2.dylib"
    STRIP_MODE="darwin"
    ;;
  Linux)
    LIB="target/release/libq_periapt_ffi_abi2.so"
    STRIP_MODE="linux"
    ;;
  *)
    fail "unsupported host for the shared-library footprint: $(uname -s)"
    ;;
esac

require_file "$LIB"
STRIPPED="$TMP_ROOT/q_periapt_ffi_stripped"
cp "$LIB" "$STRIPPED"
case "$STRIP_MODE" in
  darwin) strip -x "$STRIPPED" ;;
  linux) strip --strip-unneeded "$STRIPPED" ;;
esac
CABI=$(wc -c < "$STRIPPED" | tr -d ' ')

# ---- WASM modules (lean default vs opt-in signed-policy) --------------------
echo "building WASM modules (release)..."
WASM_LEAN_DIR="$TMP_ROOT/wasm-lean"
WASM_POLICY_DIR="$TMP_ROOT/wasm-signed-policy"
wasm-pack build crates/q-periapt-wasm --release --target web --out-dir "$WASM_LEAN_DIR" --no-pack --locked
require_file "$WASM_LEAN_DIR/q_periapt_wasm_bg.wasm"
WASM_LEAN=$(wc -c < "$WASM_LEAN_DIR/q_periapt_wasm_bg.wasm" | tr -d ' ')

wasm-pack build crates/q-periapt-wasm --release --target web --out-dir "$WASM_POLICY_DIR" --no-pack --locked --features signed-policy
require_file "$WASM_POLICY_DIR/q_periapt_wasm_bg.wasm"
WASM_POL=$(wc -c < "$WASM_POLICY_DIR/q_periapt_wasm_bg.wasm" | tr -d ' ')

{
  echo "# Q-Periapt binary footprint. PLATFORM-DEPENDENT — regenerate per host: sh paper/footprint.sh"
  echo "host,rustc,artifact,bytes,kib"
  echo "$HOST,$RUSTC,c-abi-cdylib-stripped,$CABI,$(kib "$CABI")"
  echo "$HOST,$RUSTC,wasm-lean-default,$WASM_LEAN,$(kib "$WASM_LEAN")"
  echo "$HOST,$RUSTC,wasm-signed-policy,$WASM_POL,$(kib "$WASM_POL")"
} > "$OUT_TMP"

mv "$OUT_TMP" "$OUT"
tee < "$OUT"
