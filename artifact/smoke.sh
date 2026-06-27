#!/bin/sh
# One-command reviewer smoke test for Q-Periapt — the minimal closed loop.
#
#   sh artifact/smoke.sh
#
# Requires only a Rust toolchain (cargo >= 1.85) and a C compiler (for the FFI link smoke).
# No Docker, wasm-pack, Node, or network beyond cargo's first dependency fetch. A few minutes.
#
# It exercises, end to end: the core composition unit tests; the shared/reference combiner
# vectors; the C-ABI face (cargo tests + a real C link-and-run); the WASM face's shared vector
# on the host; a real loopback TLS 1.3 handshake driven by the rustls hybrid group; and the
# EasyCrypt no-`admit` proof gate. Exits non-zero if any step fails.
#
# Expected per-step counts and provenance are in artifact/results.json; a frozen capture of one
# real run is in artifact/ci-snapshot.log.
set -u
cd "$(dirname "$0")/.." || exit 2 # repo root

pass=0
fail=0
step() {
	name="$1"
	shift
	printf '\n=== %s ===\n' "$name"
	if "$@"; then
		printf 'PASS: %s\n' "$name"
		pass=$((pass + 1))
	else
		printf 'FAIL: %s\n' "$name"
		fail=$((fail + 1))
	fi
}

printf 'Q-Periapt reviewer smoke test\n'
printf 'commit : %s\n' "$(git rev-parse HEAD 2>/dev/null || echo unknown)"
printf 'rustc  : %s\n' "$(rustc --version 2>/dev/null || echo MISSING)"
printf 'host   : %s\n' "$(uname -srm)"

step "core unit tests"             cargo test -p q-periapt-core
step "shared reference vectors"    cargo test -p q-periapt-backends
step "C-ABI tests (incl. aliasing)" cargo test -p q-periapt-ffi
step "WASM shared vector (host)"   cargo test -p q-periapt-wasm
step "rustls loopback handshake"   cargo test -p q-periapt-rustls --test handshake
step "C-ABI link-and-run smoke"    sh bindings/c/build-and-run.sh
step "EasyCrypt no-admit gate"     sh -c "! grep -rnE 'admit|sorry' --include='*.ec' formal/easycrypt/"

printf '\n================ SUMMARY ================\n'
printf '%d passed, %d failed\n' "$pass" "$fail"
if [ "$fail" -eq 0 ]; then
	printf 'ALL PASS\n'
else
	printf 'FAILURES PRESENT\n'
fi
exit "$fail"
