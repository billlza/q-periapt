#!/usr/bin/env sh
# Build the q-periapt-ffi cdylib and link bindings/c/smoke.c against it with the system C
# compiler, then run the C-ABI link smoke test. Works on macOS (clang) and Linux (gcc/clang).
# The MSVC/Windows equivalent is build-and-run.bat.
set -eu
cd "$(dirname "$0")/../.."

echo "[1/2] cargo build -p q-periapt-ffi --release"
cargo build -p q-periapt-ffi --release

INC="crates/q-periapt-ffi/include"
LIB="$(pwd)/target/release"
CC="${CC:-cc}"

echo "[2/2] $CC smoke.c -> link libq_periapt_ffi, then run"
# rpath embeds the cdylib location so the test runs without LD_LIBRARY_PATH/DYLD_LIBRARY_PATH.
"$CC" -std=c11 -Wall -Wextra bindings/c/smoke.c -I "$INC" \
    -L "$LIB" -lq_periapt_ffi -Wl,-rpath,"$LIB" -o "$LIB/c_smoke"
"$LIB/c_smoke"
