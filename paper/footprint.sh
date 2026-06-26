#!/bin/sh
# =============================================================================
# Reproduce the artifact's binary footprint (C-ABI cdylib + WASM module) and write
# paper/footprint.csv. Footprint is PLATFORM-DEPENDENT (toolchain, target, libc, strip),
# so run this on the host you want numbers for — do not treat any single value as universal.
#
#     sh paper/footprint.sh
# =============================================================================
set -u
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd); cd "$ROOT"
HOST="$(uname -srm)"; RUSTC="$(rustc --version | cut -d' ' -f2)"
OUT="paper/footprint.csv"
kib() { awk "BEGIN{printf \"%.1f\", $1/1024}"; }

# ---- C-ABI cdylib, release + stripped (the default hybrid build) ------------
echo "building C-ABI cdylib (release)..."
cargo build -p q-periapt-ffi --release >/dev/null 2>&1
LIB=$(ls target/release/libq_periapt_ffi.dylib target/release/libq_periapt_ffi.so 2>/dev/null | head -1)
cp "$LIB" /tmp/qp_ffi_stripped
strip -x /tmp/qp_ffi_stripped 2>/dev/null || strip /tmp/qp_ffi_stripped 2>/dev/null || true
CABI=$(wc -c < /tmp/qp_ffi_stripped | tr -d ' ')

# ---- WASM modules (lean default vs opt-in signed-policy), needs wasm-pack ----
WASM_LEAN=""; WASM_POL=""
if command -v wasm-pack >/dev/null 2>&1; then
  echo "building WASM modules (release)..."
  wasm-pack build crates/q-periapt-wasm --release --target web --out-dir /tmp/qp_wasm_lean >/dev/null 2>&1 \
    && WASM_LEAN=$(wc -c < /tmp/qp_wasm_lean/q_periapt_wasm_bg.wasm | tr -d ' ')
  wasm-pack build crates/q-periapt-wasm --release --target web --out-dir /tmp/qp_wasm_pol -- --features signed-policy >/dev/null 2>&1 \
    && WASM_POL=$(wc -c < /tmp/qp_wasm_pol/q_periapt_wasm_bg.wasm | tr -d ' ')
else
  echo "(wasm-pack not found — skipping WASM sizes)"
fi

{
  echo "# Q-Periapt binary footprint. PLATFORM-DEPENDENT — regenerate per host: sh paper/footprint.sh"
  echo "host,rustc,artifact,bytes,kib"
  echo "$HOST,$RUSTC,c-abi-cdylib-stripped,$CABI,$(kib "$CABI")"
  [ -n "$WASM_LEAN" ] && echo "$HOST,$RUSTC,wasm-lean-default,$WASM_LEAN,$(kib "$WASM_LEAN")"
  [ -n "$WASM_POL" ]  && echo "$HOST,$RUSTC,wasm-signed-policy,$WASM_POL,$(kib "$WASM_POL")"
} | tee "$OUT"
