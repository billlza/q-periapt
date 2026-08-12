#!/bin/sh
# Fail-closed consumer-embedding gate for Q-Periapt.
#
# This is the closest current analogue to a "download, build, and use it" check:
# it verifies the Rust workspace, C ABI, generated headers, Swift package,
# Android AAR/JNI package, Kotlin/Panama binding, WASM face, and proof-to-byte
# manifest from one command.
# Physical Apple-device proof remains opt-in because it requires local signing
# and attached devices.
set -eu

# Capture the one permitted caller compiler selector before any child process,
# then remove caller and internal names from the exported environment. POSIX
# shell assignments retain an existing export attribute unless first unset.
unset wasm_compiler_input WASM_C_COMPILER compiler compiler_version compiler_targets java_version_output
wasm_compiler_input=${CC_wasm32_unknown_unknown:-}
unset CC_wasm32_unknown_unknown

ROOT=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd) || exit 2
cd "$ROOT" || exit 2
. "$ROOT/artifact/python-env.sh"

need() {
	if ! command -v "$1" >/dev/null 2>&1; then
		printf 'error: required tool not found: %s\n' "$1" >&2
		exit 2
	fi
}

require_java_22() {
	need java
	java_version_output=$(java -version 2>&1) || {
		printf 'error: Java could not report its version\n' >&2
		exit 2
	}
	if ! printf '%s\n' "$java_version_output" | python3 -c '
import re
import sys

text = sys.stdin.read()
match = re.search(r"version \"([0-9]+)(?:[._][0-9]+)?", text)
if not match:
    sample = text.splitlines()[0] if text else "empty"
    raise SystemExit("error: cannot parse Java version from: " + sample)
major = int(match.group(1))
if major < 22:
    raise SystemExit(f"error: Kotlin/Panama binding requires JDK >= 22, got Java {major}")
'; then
		unset java_version_output
		return 2
	fi
	unset java_version_output
}

require_wasm_clang() {
	compiler=$1
	if [ -z "$compiler" ]; then
		printf 'error: CC_wasm32_unknown_unknown must name an absolute upstream LLVM clang path with the wasm32 backend\n' >&2
		exit 2
	fi
	case "$compiler" in
		/*) ;;
		*)
			printf 'error: CC_wasm32_unknown_unknown must be an absolute path\n' >&2
			exit 2
			;;
	esac
	if [ ! -f "$compiler" ] || [ ! -x "$compiler" ]; then
		printf 'error: CC_wasm32_unknown_unknown must identify an executable compiler file\n' >&2
		exit 2
	fi
	compiler_version=$("$compiler" --version 2>&1) || {
		printf 'error: CC_wasm32_unknown_unknown could not report its version\n' >&2
		exit 2
	}
	if ! printf '%s\n' "$compiler_version" | grep -q 'clang version' || \
		printf '%s\n' "$compiler_version" | grep -q 'Apple clang version'; then
		printf 'error: CC_wasm32_unknown_unknown must select upstream LLVM clang, not Apple clang\n' >&2
		exit 2
	fi
	compiler_targets=$("$compiler" --print-targets 2>/dev/null) || {
		printf 'error: CC_wasm32_unknown_unknown could not report supported targets\n' >&2
		exit 2
	}
	if ! printf '%s\n' "$compiler_targets" | grep -Eq '^[[:space:]]*wasm32[[:space:]]+-'; then
		printf 'error: CC_wasm32_unknown_unknown compiler has no wasm32 backend\n' >&2
		exit 2
	fi
	printf 'wasm C compiler: %s\n' "$(printf '%s\n' "$compiler_version" | sed -n '1p')"
}

step() {
	name=$1
	shift
	printf '\n=== %s ===\n' "$name"
	"$@"
	printf 'PASS: %s\n' "$name"
}

wasm_binding_tests() {
	# Revalidate immediately before use so a tool-path change during the long
	# package gate fails closed instead of selecting unchecked compiler bytes.
	require_wasm_clang "$wasm_compiler_input" >/dev/null
	unset compiler compiler_version compiler_targets
	env CC_wasm32_unknown_unknown="$wasm_compiler_input" \
		wasm-pack test --node crates/q-periapt-wasm
}

swift_binding_tests() {
	swift_log=$(mktemp "$ROOT/target/qperiapt-swift-test.XXXXXX.log")
	set +e
	swift test --package-path bindings/swift -Xlinker "-L$ROOT/target/release" >"$swift_log" 2>&1
	rc=$?
	set -e
	cat "$swift_log"
	if [ "$rc" -ne 0 ]; then
		return "$rc"
	fi
	if ! grep -q 'Executed 2 tests, with 0 failures' "$swift_log"; then
		printf 'error: Swift XCTest count was not the expected 2 passing ABI2 product tests\n' >&2
		return 1
	fi
}

skip_swift=${QPERIAPT_EMBED_SKIP_SWIFT:-0}
skip_kotlin=${QPERIAPT_EMBED_SKIP_KOTLIN:-0}
skip_wasm=${QPERIAPT_EMBED_SKIP_WASM:-0}
require_device_matrix=${QPERIAPT_EMBED_REQUIRE_DEVICE_MATRIX:-0}
require_android_runtime=${QPERIAPT_EMBED_REQUIRE_ANDROID_RUNTIME:-0}
require_local_release_consumer=${QPERIAPT_EMBED_REQUIRE_LOCAL_RELEASE_CONSUMER:-0}

if [ "$skip_swift" = "1" ] || [ "$skip_kotlin" = "1" ] || [ "$skip_wasm" = "1" ]; then
	printf 'error: QPERIAPT_EMBED_SKIP_SWIFT/KOTLIN/WASM are not supported by the embedding readiness gate\n' >&2
	printf '       Run the individual language commands directly for partial diagnostics.\n' >&2
	exit 2
fi
case "$require_local_release_consumer" in
	0 | 1) ;;
	*)
		printf 'error: QPERIAPT_EMBED_REQUIRE_LOCAL_RELEASE_CONSUMER must be 0 or 1\n' >&2
		exit 2
		;;
esac

need cargo
need cbindgen
need cmake
need python3
need pkg-config
need shasum

need swift
need rustup
need xcodebuild
need lipo
need zip
need gradle
require_java_22
need wasm-pack
need node
require_wasm_clang "$wasm_compiler_input"
unset compiler compiler_version compiler_targets

printf 'Q-Periapt embedding readiness gate\n'
printf 'repo   : %s\n' "$ROOT"
printf 'commit : %s\n' "$(git rev-parse HEAD 2>/dev/null || printf unknown)"
printf 'rustc  : %s\n' "$(rustc --version 2>/dev/null || printf MISSING)"
printf 'host   : %s\n' "$(uname -srm)"

mkdir -p "$ROOT/target"
tmp_header=$(mktemp "$ROOT/target/qperiapt-header.XXXXXX.h")
cleanup() {
	rm -f "$tmp_header" "${swift_log:-}"
}
trap cleanup EXIT INT TERM

step "cargo metadata locked" sh -c "cargo metadata --locked --format-version 1 >/dev/null"
step "rustfmt" cargo fmt --all --check
step "clippy warnings denied" cargo clippy --workspace --all-targets --locked -- -D warnings
step "workspace tests locked" cargo test --workspace --locked
run_android_proof_tests() {
	PYTHONPATH=artifact python3 -m unittest artifact/test_android_device_proof.py
}
step "Android proof provenance tests" run_android_proof_tests
step "optional SLH-DSA backend tests" cargo test -p q-periapt-backends --features slh-dsa --locked
step "release C ABI build" cargo build -p q-periapt-ffi --release --locked

printf '\n=== generated C header freshness ===\n'
cbindgen --config crates/q-periapt-ffi/cbindgen.toml \
	--crate q-periapt-ffi \
	--output "$tmp_header"
cmp "$tmp_header" crates/q-periapt-ffi/include/q_periapt.h
cmp crates/q-periapt-ffi/include/q_periapt.h bindings/swift/Sources/CQPeriapt/q_periapt.h
printf 'PASS: generated C header freshness\n'

step "C ABI link-and-run smoke" sh bindings/c/build-and-run.sh
step "C ABI release archive smoke" sh artifact/c-package.sh

step "Swift binding tests" swift_binding_tests
step "Swift XCFramework binary consumer" sh artifact/swift-xcframework.sh
step "Android AAR/JNI packaging proof" sh artifact/android-aar.sh
step "Kotlin/Panama binding tests" gradle test --project-dir bindings/kotlin
step "WASM binding tests on Node" wasm_binding_tests

step "proof-to-byte manifest" env QPERIAPT_SKIP_SMOKE=1 sh artifact/proof-to-byte.sh

if [ "$require_local_release_consumer" = "1" ]; then
	step "local release index C consumer smoke" sh artifact/local-release-consumer-smoke.sh
else
	printf '\nNOTE: local release-index C consumer smoke not required by this run.\n'
	printf '      After sh artifact/local-release-index.sh, set QPERIAPT_EMBED_REQUIRE_LOCAL_RELEASE_CONSUMER=1 to require it.\n'
fi

if [ "$require_device_matrix" = "1" ]; then
	if [ -z "${QPERIAPT_DEVICE_RESULT_DIR:-}" ]; then
		printf 'error: QPERIAPT_DEVICE_RESULT_DIR is required when QPERIAPT_EMBED_REQUIRE_DEVICE_MATRIX=1\n' >&2
		exit 2
	fi
	step "physical Apple iPad+iPhone matrix proof" \
		env QPERIAPT_SKIP_SMOKE=1 QPERIAPT_REQUIRE_APPLE_DEVICE_MATRIX=1 \
		QPERIAPT_DEVICE_RESULT_DIR="$QPERIAPT_DEVICE_RESULT_DIR" \
		sh artifact/proof-to-byte.sh
else
	printf '\nNOTE: physical Apple iPad+iPhone matrix proof not required by this run.\n'
	printf '      Set QPERIAPT_EMBED_REQUIRE_DEVICE_MATRIX=1 and QPERIAPT_DEVICE_RESULT_DIR=<matrix-run-dir> to require it.\n'
fi

if [ "$require_android_runtime" = "1" ]; then
	if [ -z "${QPERIAPT_ANDROID_DEVICE_PROOF:-}" ]; then
		printf 'error: QPERIAPT_ANDROID_DEVICE_PROOF is required when QPERIAPT_EMBED_REQUIRE_ANDROID_RUNTIME=1\n' >&2
		exit 2
	fi
	step "Android emulator/physical runtime proof" \
		env QPERIAPT_SKIP_SMOKE=1 QPERIAPT_REQUIRE_ANDROID_RUNTIME=1 \
		QPERIAPT_ANDROID_DEVICE_PROOF="$QPERIAPT_ANDROID_DEVICE_PROOF" \
		sh artifact/proof-to-byte.sh
else
	printf '\nNOTE: Android emulator/physical runtime proof not required by this run.\n'
	printf '      Set QPERIAPT_EMBED_REQUIRE_ANDROID_RUNTIME=1 and QPERIAPT_ANDROID_DEVICE_PROOF=<reported immutable proof path> after running artifact/android-device-smoke.sh.\n'
fi

printf '\nEMBEDDING_READINESS_PASS\n'
