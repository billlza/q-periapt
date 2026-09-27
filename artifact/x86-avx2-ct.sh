#!/bin/sh
# Native Linux AVX2 qualification. Compilation or a portable fallback is not a pass.
set -eu
ROOT=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
cd "$ROOT"
test "$(uname -s)" = Linux
test "$(uname -m)" = x86_64
test "$(rustc -vV | sed -n 's/^host: //p')" = x86_64-unknown-linux-gnu
command -v valgrind >/dev/null
command -v sha256sum >/dev/null
BIN="$ROOT/target/release/ct_decaps_gap"
test -x "$BIN"
WORK=$(mktemp -d "$ROOT/target/x86-avx2-ct.XXXXXX")
printf 'AVX2_CT_EVIDENCE=%s\n' "$WORK"
export QPERIAPT_EXPECT_MLKEM_IMPLEMENTATION=mlkem-native-1.2.0/x86_64-native-arith+fips202-avx2
sha256sum "$BIN" > "$WORK/binary.sha256"
{
    uname -srm
    rustc -vV
    valgrind --version
    git rev-parse HEAD
    git status --porcelain
} > "$WORK/environment.txt"
for parameter in 512 768 1024; do
    control="$WORK/control-$parameter.log"
    probe="$WORK/probe-$parameter.log"
    set +e
    valgrind --error-exitcode=99 --leak-check=no --track-origins=yes \
        "$BIN" "$parameter" control > "$control" 2>&1
    control_rc=$?
    set -e
    if [ "$control_rc" -ne 99 ] || \
       ! grep -Eq 'ERROR SUMMARY: [1-9][0-9]* errors' "$control" || \
       ! grep -Fxq "MLKEM_ACTIVE_IMPLEMENTATION=$QPERIAPT_EXPECT_MLKEM_IMPLEMENTATION" "$control"; then
        cat "$control"
        printf 'error: AVX2 ML-KEM-%s negative control failed (status %s)\n' "$parameter" "$control_rc" >&2
        exit 1
    fi
    set +e
    valgrind --error-exitcode=97 --leak-check=no --track-origins=yes \
        "$BIN" "$parameter" probe > "$probe" 2>&1
    probe_rc=$?
    set -e
    if [ "$probe_rc" -ne 0 ] || \
       ! grep -Fq 'ERROR SUMMARY: 0 errors from 0 contexts' "$probe" || \
       ! grep -Fxq "MLKEM_ACTIVE_IMPLEMENTATION=$QPERIAPT_EXPECT_MLKEM_IMPLEMENTATION" "$probe"; then
        cat "$probe"
        printf 'error: AVX2 ML-KEM-%s genuine-secret probe failed (status %s)\n' "$parameter" "$probe_rc" >&2
        exit 1
    fi
done
sha256sum --check "$WORK/binary.sha256"
printf 'AVX2_BINARY_CT_PASS parameters=512,768,1024\n' | tee "$WORK/result.txt"
