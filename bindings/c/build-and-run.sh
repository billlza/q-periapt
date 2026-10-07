#!/usr/bin/env sh
# Build the q-periapt-ffi cdylib and link bindings/c/smoke.c against it with the system C
# compiler, then run the C-ABI link smoke test. Works on macOS (clang) and Linux (gcc/clang).
# The MSVC/Windows equivalent is build-and-run.bat.
set -eu
cd "$(dirname "$0")/../.."

echo "[1/3] cargo build -p q-periapt-ffi --release"
cargo build -p q-periapt-ffi --release --locked

INC="crates/q-periapt-ffi/include"
LIB="$(pwd)/target/release"
CC="${CC:-cc}"

echo "[2/3] $CC legacy ABI 2 consumer -> link current libq_periapt_ffi_abi2, then run"
# rpath embeds the cdylib location so the test runs without LD_LIBRARY_PATH/DYLD_LIBRARY_PATH.
"$CC" -std=c11 -Wall -Wextra -Werror bindings/c/smoke.c \
    -I crates/q-periapt-ffi/abi/v0.1.5 \
    -L "$LIB" -lq_periapt_ffi_abi2 -Wl,-rpath,"$LIB" -o "$LIB/c_smoke"
"$LIB/c_smoke"

echo "[3/3] $CC owned SDK consumer -> link current libq_periapt_ffi_abi2, then run"
"$CC" -std=c11 -Wall -Wextra -Werror bindings/c/sdk_smoke.c -I "$INC" \
    -L "$LIB" -lq_periapt_ffi_abi2 -Wl,-rpath,"$LIB" -o "$LIB/c_sdk_smoke"
"$LIB/c_sdk_smoke"
