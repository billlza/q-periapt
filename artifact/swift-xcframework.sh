#!/bin/sh
# Build and verify the SwiftPM binaryTarget/XCFramework release surface.
#
# Ordinary invocation is the credential-free pre-publication gate. The dedicated
# swift-xcframework-release.sh wrapper may select the internal signed mode
# from a fixed detached source commit. Both paths prove an isolated SwiftPM consumer
# can import the wrapper without development linker flags or repo-local library paths.
set -eu

unset CDPATH
if [ "${GIT_DIR+x}" = "x" ] || \
	[ "${GIT_WORK_TREE+x}" = "x" ] || \
	[ "${GIT_COMMON_DIR+x}" = "x" ] || \
	[ "${GIT_INDEX_FILE+x}" = "x" ] || \
	[ "${GIT_OBJECT_DIRECTORY+x}" = "x" ] || \
	[ "${GIT_ALTERNATE_OBJECT_DIRECTORIES+x}" = "x" ] || \
	[ "${GIT_SHALLOW_FILE+x}" = "x" ] || \
	[ "${GIT_NAMESPACE+x}" = "x" ] || \
	[ "${GIT_REPLACE_REF_BASE+x}" = "x" ] || \
	[ "${GIT_CONFIG_SYSTEM+x}" = "x" ] || \
	[ "${GIT_CONFIG_GLOBAL+x}" = "x" ] || \
	[ "${GIT_CONFIG_NOSYSTEM+x}" = "x" ] || \
	[ "${GIT_CONFIG_COUNT+x}" = "x" ] || \
	[ "${GIT_CONFIG_PARAMETERS+x}" = "x" ] || \
	[ "${GIT_CEILING_DIRECTORIES+x}" = "x" ] || \
	[ "${GIT_DISCOVERY_ACROSS_FILESYSTEM+x}" = "x" ]; then
	printf 'error: Apple release tooling rejects Git repository/configuration environment overrides\n' >&2
	exit 2
fi
ROOT=$(cd -- "$(dirname "$0")/.." && pwd) || exit 2
cd "$ROOT" || exit 2
. "$ROOT/artifact/python-env.sh"

release_git() {
	/usr/bin/env -i \
		PATH=/usr/bin:/bin \
		LC_ALL=C \
		LANG=C \
		GIT_CONFIG_NOSYSTEM=1 \
		GIT_CONFIG_GLOBAL=/dev/null \
		GIT_CONFIG_SYSTEM=/dev/null \
		GIT_NO_REPLACE_OBJECTS=1 \
		GIT_OPTIONAL_LOCKS=0 \
		/usr/bin/git \
		-c "safe.directory=$ROOT" \
		-c core.fsmonitor=false \
		-c core.hooksPath=/dev/null \
		-c core.attributesFile=/dev/null \
		-c core.excludesFile=/dev/null \
		-C "$ROOT" \
		"$@"
}

if [ "$#" -ne 0 ]; then
	printf 'error: swift-xcframework.sh accepts no positional arguments\n' >&2
	exit 2
fi

APPLE_RELEASE_MODE=${QPERIAPT_INTERNAL_APPLE_RELEASE_MODE:-0}
case "$APPLE_RELEASE_MODE" in
	0) ;;
	1)
		if [ "${QPERIAPT_INTERNAL_APPLE_RELEASE_ENTRYPOINT:-}" != "swift-xcframework-release-v1" ]; then
			printf 'error: credentialed Apple mode is available only through artifact/swift-xcframework-release.sh\n' >&2
			exit 2
		fi
		;;
	*)
		printf 'error: invalid internal Apple release mode\n' >&2
		exit 2
		;;
esac

need() {
	if ! command -v "$1" >/dev/null 2>&1; then
		printf 'error: required tool not found: %s\n' "$1" >&2
		exit 2
	fi
}

require_under_target() {
	python3 - "$ROOT" "$1" "$2" <<'PY'
import pathlib
import sys

root = pathlib.Path(sys.argv[1]).resolve()
path = pathlib.Path(sys.argv[2]).resolve()
label = sys.argv[3]
target = (root / "target").resolve()
try:
    path.relative_to(target)
except ValueError as exc:
    raise SystemExit(f"error: {label} must be under {target}: {path}") from exc
if path == target:
    raise SystemExit(f"error: {label} must not be the target root itself: {path}")
PY
}

need cargo
need cbindgen
need git
need lipo
need python3
need rustc
need rustup
need shasum
need swift
need xcodebuild
need zip
if [ "$APPLE_RELEASE_MODE" = "1" ]; then
	need codesign
	need ditto
	need openssl
	if [ -z "${QPERIAPT_INTERNAL_APPLE_EXPECTED_TEAM_ID:-}" ] || \
			[ -z "${QPERIAPT_INTERNAL_APPLE_IDENTITY_SHA1:-}" ] || \
			[ -z "${QPERIAPT_INTERNAL_APPLE_CERTIFICATE_SHA256:-}" ] || \
			[ -z "${QPERIAPT_INTERNAL_APPLE_DURABILITY_ROOT:-}" ] || \
			[ -z "${QPERIAPT_INTERNAL_APPLE_SOURCE_COMMIT:-}" ]; then
			printf 'error: credentialed Apple release inputs are incomplete\n' >&2
			exit 2
		fi
fi

if [ "${QPERIAPT_SWIFT_XCFRAMEWORK_SKIP_VERIFY:-0}" = "1" ]; then
	printf 'error: QPERIAPT_SWIFT_XCFRAMEWORK_SKIP_VERIFY is not supported\n' >&2
	exit 2
fi

if [ "$APPLE_RELEASE_MODE" = "1" ] && [ "${QPERIAPT_ALLOW_DIRTY_SWIFT_XCFRAMEWORK:-0}" != "0" ]; then
	printf 'error: credentialed Apple distribution never permits dirty diagnostic mode\n' >&2
	exit 2
fi
if [ "${QPERIAPT_ALLOW_DIRTY_SWIFT_XCFRAMEWORK:-0}" != "1" ]; then
	if ! SOURCE_STATUS=$(release_git status --porcelain=v1); then
		printf 'error: unable to inspect the Swift XCFramework source worktree\n' >&2
		exit 2
	fi
	if [ -n "$SOURCE_STATUS" ]; then
		printf 'error: Swift XCFramework release gate requires a clean worktree; set QPERIAPT_ALLOW_DIRTY_SWIFT_XCFRAMEWORK=1 only for local diagnostics\n' >&2
		exit 2
	fi
fi

if ! SOURCE_COMMIT=$(release_git rev-parse HEAD); then
	printf 'error: unable to resolve the Swift XCFramework source commit\n' >&2
	exit 2
fi
assert_release_source_snapshot() {
	if [ "$APPLE_RELEASE_MODE" != "1" ]; then
		return
	fi
	if ! current_commit=$(release_git rev-parse HEAD); then
		printf 'error: unable to revalidate the Apple release source commit\n' >&2
		exit 1
	fi
	if ! current_toplevel=$(release_git rev-parse --show-toplevel) || \
		! current_common_git_dir=$(release_git rev-parse --path-format=absolute --git-common-dir); then
		printf 'error: unable to resolve the Apple release worktree identity\n' >&2
		exit 1
	fi
	if [ "$current_toplevel" != "$ROOT" ] || \
		[ "$current_common_git_dir" != "$QPERIAPT_INTERNAL_APPLE_DURABILITY_ROOT/.git" ]; then
		printf 'error: Apple release source is not the expected detached worktree\n' >&2
		exit 1
	fi
	if [ "$current_commit" != "$SOURCE_COMMIT" ] || \
		[ "$current_commit" != "$QPERIAPT_INTERNAL_APPLE_SOURCE_COMMIT" ]; then
		printf 'error: Apple release source commit changed during the release\n' >&2
		exit 1
	fi
	if ! current_status=$(release_git status --porcelain=v1 --untracked-files=normal); then
		printf 'error: unable to revalidate the Apple release source worktree\n' >&2
		exit 1
	fi
	if [ -n "$current_status" ]; then
		printf 'error: Apple release source worktree changed during the release\n' >&2
		exit 1
	fi
}
assert_release_source_snapshot

VERSION=$(cargo metadata --locked --format-version 1 --no-deps | python3 -c '
import json
import sys

metadata = json.load(sys.stdin)
for package in metadata["packages"]:
    if package["name"] == "q-periapt-ffi":
        print(package["version"])
        break
else:
    raise SystemExit("error: q-periapt-ffi package not found in cargo metadata")
')
if [ "$VERSION" != "0.1.0-alpha.2" ]; then
	printf 'error: Swift ABI2 package version mismatch: got %s, expected 0.1.0-alpha.2\n' "$VERSION" >&2
	exit 1
fi
RUST_HOST=$(rustc -vV | awk '/^host: / { print $2 }')
LLVM_NM="$(rustc --print sysroot)/lib/rustlib/$RUST_HOST/bin/llvm-nm"
if [ ! -x "$LLVM_NM" ]; then
	printf 'error: Rust toolchain llvm-nm not found: %s\n' "$LLVM_NM" >&2
	printf 'hint : rustup component add llvm-tools\n' >&2
	exit 2
fi

OUT_ROOT=${QPERIAPT_SWIFT_XCFRAMEWORK_OUT_DIR:-"$ROOT/target/qperiapt-swift-xcframework"}
require_under_target "$OUT_ROOT" "QPERIAPT_SWIFT_XCFRAMEWORK_OUT_DIR"

PACKAGE_NAME="q-periapt-swift-$VERSION"
WORK="$OUT_ROOT/work"
DIST="$OUT_ROOT/$PACKAGE_NAME"
HEADERS="$WORK/Headers"
LIBS="$WORK/libs"
XCFRAMEWORK="$DIST/CQPeriapt.xcframework"
ZIP_PATH="$DIST/CQPeriapt.xcframework.zip"
CONSUMER="$OUT_ROOT/consumer"
MANIFEST="$DIST/MANIFEST.json"
SHA256SUMS="$DIST/SHA256SUMS"
CONSUMER_LOG="$OUT_ROOT/swift-binary-consumer.log"
APPLE_CONSUMER_EVIDENCE="$OUT_ROOT/apple-consumer-evidence"
SIGNING_EVIDENCE="$WORK/apple-signing.json"
APPLE_DISTRIBUTION="$DIST/APPLE_DISTRIBUTION.json"
required_targets="aarch64-apple-darwin x86_64-apple-darwin aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios"
mkdir -p "$ROOT/target"
tmp_header=$(mktemp "$ROOT/target/qperiapt-swift-xcframework-header.XXXXXX.h")

# BEGIN_BUILD_TRAP_FUNCTIONS
cleanup() {
	rm -f "$tmp_header"
}
cleanup_signal() {
	signal_status=$1
	trap - EXIT INT TERM
	cleanup
	exit "$signal_status"
}
# END_BUILD_TRAP_FUNCTIONS
trap cleanup EXIT
trap 'cleanup_signal 130' INT
trap 'cleanup_signal 143' TERM

installed_targets=$(rustup target list --installed)
missing_targets=
for target in $required_targets; do
	if ! printf '%s\n' "$installed_targets" | grep -Fx "$target" >/dev/null 2>&1; then
		missing_targets="$missing_targets $target"
	fi
done
if [ -n "$missing_targets" ]; then
	printf 'error: missing Rust Apple release targets:%s\n' "$missing_targets" >&2
	printf 'hint : rustup target add%s\n' "$missing_targets" >&2
	exit 2
fi

printf 'Q-Periapt Swift XCFramework package\n'
printf 'version : %s\n' "$VERSION"
printf 'out     : %s\n' "$DIST"
printf 'rustc   : %s\n' "$(rustc --version)"
printf 'swift   : %s\n' "$(swift --version 2>&1 | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
printf 'xcode   : %s\n' "$(xcodebuild -version | tr '\n' ' ')"

printf '\n=== Generated C header freshness ===\n'
cbindgen --config crates/q-periapt-ffi/cbindgen.toml \
	--crate q-periapt-ffi \
	--output "$tmp_header"
cmp "$tmp_header" crates/q-periapt-ffi/include/q_periapt.h
cmp crates/q-periapt-ffi/include/q_periapt.h bindings/swift/Sources/CQPeriapt/q_periapt.h
printf 'PASS: generated C header freshness\n'

printf '\n=== Build Apple static libraries ===\n'
for target in $required_targets; do
	cargo build -p q-periapt-ffi --release --locked --target "$target"
	test -f "$ROOT/target/$target/release/libq_periapt_ffi_abi2.a" || {
		printf 'error: missing static library for %s\n' "$target" >&2
		exit 1
	}
done

rm -rf "$OUT_ROOT"
mkdir -p "$HEADERS" "$LIBS/macos" "$LIBS/ios" "$LIBS/ios-simulator" "$DIST" "$CONSUMER"
cp crates/q-periapt-ffi/include/q_periapt.h "$HEADERS/q_periapt.h"
cat >"$HEADERS/module.modulemap" <<'EOF'
module CQPeriapt {
    header "q_periapt.h"
    export *
}
EOF

printf '\n=== Assemble release slices ===\n'
lipo -create \
	"$ROOT/target/aarch64-apple-darwin/release/libq_periapt_ffi_abi2.a" \
	"$ROOT/target/x86_64-apple-darwin/release/libq_periapt_ffi_abi2.a" \
	-output "$LIBS/macos/libq_periapt_ffi_abi2.a"
cp "$ROOT/target/aarch64-apple-ios/release/libq_periapt_ffi_abi2.a" "$LIBS/ios/libq_periapt_ffi_abi2.a"
lipo -create \
	"$ROOT/target/aarch64-apple-ios-sim/release/libq_periapt_ffi_abi2.a" \
	"$ROOT/target/x86_64-apple-ios/release/libq_periapt_ffi_abi2.a" \
	-output "$LIBS/ios-simulator/libq_periapt_ffi_abi2.a"

lipo "$LIBS/macos/libq_periapt_ffi_abi2.a" -verify_arch arm64 x86_64
lipo "$LIBS/ios/libq_periapt_ffi_abi2.a" -verify_arch arm64
lipo "$LIBS/ios-simulator/libq_periapt_ffi_abi2.a" -verify_arch arm64 x86_64
EXPECTED_FFI_EXPORTS='q_periapt_abi_version
q_periapt_decapsulate
q_periapt_decision_from_signed_policy
q_periapt_encapsulate
q_periapt_fixed_suite_id
q_periapt_fixed_suite_id_len
q_periapt_generate_keypair
q_periapt_status_name
q_periapt_version'
for lib in "$LIBS/macos/libq_periapt_ffi_abi2.a" "$LIBS/ios/libq_periapt_ffi_abi2.a" "$LIBS/ios-simulator/libq_periapt_ffi_abi2.a"; do
	ffi_exports=$("$LLVM_NM" -g "$lib" 2>/dev/null | awk '{print $NF}' | sed 's/^_//' | grep -E '^q_periapt_[a-z0-9_]+$' | LC_ALL=C sort -u)
	if [ "$ffi_exports" != "$EXPECTED_FFI_EXPORTS" ]; then
		printf 'error: Apple static slice differs from the exact ABI2 public q_periapt_* namespace allowlist: %s\n' "$lib" >&2
		printf 'actual public namespace symbols:\n%s\n' "$ffi_exports" >&2
		exit 1
	fi
done
printf 'PASS: release slices\n'

printf '\n=== Create XCFramework ===\n'
xcodebuild -create-xcframework \
	-library "$LIBS/macos/libq_periapt_ffi_abi2.a" -headers "$HEADERS" \
	-library "$LIBS/ios/libq_periapt_ffi_abi2.a" -headers "$HEADERS" \
	-library "$LIBS/ios-simulator/libq_periapt_ffi_abi2.a" -headers "$HEADERS" \
	-output "$XCFRAMEWORK"
test -d "$XCFRAMEWORK" || {
	printf 'error: XCFramework was not created: %s\n' "$XCFRAMEWORK" >&2
	exit 1
}

python3 - "$XCFRAMEWORK" <<'PY'
import pathlib
import plistlib
import sys

xcframework = pathlib.Path(sys.argv[1])
info_path = xcframework / "Info.plist"
with info_path.open("rb") as fh:
    info = plistlib.load(fh)

libraries = info.get("AvailableLibraries")
if not isinstance(libraries, list):
    raise SystemExit("error: XCFramework Info.plist missing AvailableLibraries")
info["AvailableLibraries"] = sorted(
    libraries,
    key=lambda item: (
        item.get("SupportedPlatform") or "",
        item.get("SupportedPlatformVariant") or "",
        item.get("LibraryIdentifier") or "",
    ),
)
with info_path.open("wb") as fh:
    plistlib.dump(info, fh, fmt=plistlib.FMT_XML, sort_keys=True)
PY

python3 - "$XCFRAMEWORK" <<'PY'
import pathlib
import plistlib
import sys

xcframework = pathlib.Path(sys.argv[1])
with (xcframework / "Info.plist").open("rb") as fh:
    info = plistlib.load(fh)

libraries = info.get("AvailableLibraries")
if not isinstance(libraries, list):
    raise SystemExit("error: XCFramework Info.plist missing AvailableLibraries")

required = {
    ("macos", None): {"arm64", "x86_64"},
    ("ios", None): {"arm64"},
    ("ios", "simulator"): {"arm64", "x86_64"},
}
seen = {}
for lib in libraries:
    platform = lib.get("SupportedPlatform")
    variant = lib.get("SupportedPlatformVariant")
    archs = set(lib.get("SupportedArchitectures") or [])
    library_path = lib.get("LibraryPath")
    headers_path = lib.get("HeadersPath")
    identifier = lib.get("LibraryIdentifier")
    if not identifier or not library_path or not headers_path:
        raise SystemExit(f"error: incomplete XCFramework library entry: {lib}")
    if library_path != "libq_periapt_ffi_abi2.a":
        raise SystemExit(f"error: unexpected ABI2 library basename for {identifier}: {library_path}")
    key = (platform, variant)
    seen[key] = archs
    if not (xcframework / identifier / library_path).is_file():
        raise SystemExit(f"error: library path missing for {identifier}: {library_path}")
    if not (xcframework / identifier / headers_path / "q_periapt.h").is_file():
        raise SystemExit(f"error: q_periapt.h missing for {identifier}")
    if not (xcframework / identifier / headers_path / "module.modulemap").is_file():
        raise SystemExit(f"error: module.modulemap missing for {identifier}")

for key, archs in required.items():
    if seen.get(key) != archs:
        raise SystemExit(f"error: XCFramework slice {key} has archs {sorted(seen.get(key, set()))}, expected {sorted(archs)}")
print("SWIFT_XCFRAMEWORK_INFO_PASS")
PY

if [ "$APPLE_RELEASE_MODE" = "1" ]; then
	printf '\n=== Developer ID-sign XCFramework ===\n'
	assert_release_source_snapshot
	SLICE_HASHES_BEFORE="$WORK/apple-slices-before.sha256"
	SLICE_HASHES_AFTER="$WORK/apple-slices-after.sha256"
	CODESIGN_DISPLAY="$WORK/apple-codesign-display.txt"
	CERTIFICATE_PREFIX="$WORK/apple-signing-certificate-"
	(
		cd "$XCFRAMEWORK"
		find . -type f -name '*.a' -print | LC_ALL=C sort | xargs shasum -a 256
	) >"$SLICE_HASHES_BEFORE"

	codesign --timestamp \
		--sign "$QPERIAPT_INTERNAL_APPLE_IDENTITY_SHA1" \
		"$XCFRAMEWORK"
	codesign --verify --strict --verbose=4 "$XCFRAMEWORK"
	codesign --display --verbose=4 \
		--extract-certificates="$CERTIFICATE_PREFIX" \
		"$XCFRAMEWORK" >"$CODESIGN_DISPLAY" 2>&1
	test -f "${CERTIFICATE_PREFIX}0" || {
		printf 'error: codesign did not extract the leaf signing certificate\n' >&2
		exit 1
	}
	chmod 600 "$CODESIGN_DISPLAY" "${CERTIFICATE_PREFIX}"*

	(
		cd "$XCFRAMEWORK"
		find . -type f -name '*.a' -print | LC_ALL=C sort | xargs shasum -a 256
	) >"$SLICE_HASHES_AFTER"
	cmp "$SLICE_HASHES_BEFORE" "$SLICE_HASHES_AFTER"

	PYTHONPATH=artifact python3 artifact/apple_distribution.py signing-evidence \
		--xcframework "$XCFRAMEWORK" \
		--codesign-display "$CODESIGN_DISPLAY" \
		--certificate "${CERTIFICATE_PREFIX}0" \
		--expected-team-id "$QPERIAPT_INTERNAL_APPLE_EXPECTED_TEAM_ID" \
		--expected-identity-sha1 "$QPERIAPT_INTERNAL_APPLE_IDENTITY_SHA1" \
		--expected-certificate-sha256 "$QPERIAPT_INTERNAL_APPLE_CERTIFICATE_SHA256" \
		--output "$SIGNING_EVIDENCE"
	printf 'SWIFT_XCFRAMEWORK_CODESIGN_PASS\n'
fi

printf '\n=== Zip XCFramework ===\n'
find "$XCFRAMEWORK" -exec touch -h -t 200001010000 {} +
if [ "$APPLE_RELEASE_MODE" = "1" ]; then
	codesign --verify --strict --verbose=4 "$XCFRAMEWORK"
fi
rm -f "$ZIP_PATH"
(cd "$DIST" && find "CQPeriapt.xcframework" -print | LC_ALL=C sort | zip -q -X "CQPeriapt.xcframework.zip" -@)
test -f "$ZIP_PATH" || {
	printf 'error: missing XCFramework zip: %s\n' "$ZIP_PATH" >&2
	exit 1
}
if [ "$APPLE_RELEASE_MODE" = "1" ]; then
	PYTHONPATH=artifact python3 artifact/apple_distribution.py validate-zip \
		--artifact "$ZIP_PATH" --require-signature
else
	PYTHONPATH=artifact python3 artifact/apple_distribution.py validate-zip \
		--artifact "$ZIP_PATH"
fi

if [ "$APPLE_RELEASE_MODE" = "1" ]; then
	ZIP_VERIFY="$WORK/zip-verify"
	mkdir -p "$ZIP_VERIFY"
	ditto -x -k "$ZIP_PATH" "$ZIP_VERIFY"
	codesign --verify --strict --verbose=4 "$ZIP_VERIFY/CQPeriapt.xcframework"
fi

SWIFTPM_CHECKSUM=$(swift package compute-checksum "$ZIP_PATH")

printf '\n=== Generate isolated SwiftPM binary consumer ===\n'
mkdir -p \
	"$CONSUMER/Binaries" \
	"$CONSUMER/Sources/QPeriaptHybrid" \
	"$CONSUMER/Sources/QPeriaptLinkProbe" \
	"$CONSUMER/Tests/QPeriaptHybridBinaryConsumerTests/Resources"
CONSUMER_XCFRAMEWORK="$XCFRAMEWORK"
if [ "$APPLE_RELEASE_MODE" = "1" ]; then
	CONSUMER_XCFRAMEWORK="$ZIP_VERIFY/CQPeriapt.xcframework"
fi
cp -R "$CONSUMER_XCFRAMEWORK" "$CONSUMER/Binaries/CQPeriapt.xcframework"
cp bindings/swift/Sources/QPeriaptHybrid/QPeriaptHybrid.swift "$CONSUMER/Sources/QPeriaptHybrid/QPeriaptHybrid.swift"
cp bindings/swift/BinaryConsumerFixture/Sources/QPeriaptLinkProbe/main.swift \
	"$CONSUMER/Sources/QPeriaptLinkProbe/main.swift"
cp bindings/signed-policy-vectors.json "$CONSUMER/Tests/QPeriaptHybridBinaryConsumerTests/Resources/signed-policy-vectors.json"
cat >"$CONSUMER/Package.swift" <<'EOF'
// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "QPeriaptBinaryConsumer",
    platforms: [
        .macOS(.v13),
        .iOS(.v16)
    ],
    products: [
        .library(name: "QPeriaptHybrid", targets: ["QPeriaptHybrid"]),
        .executable(name: "QPeriaptLinkProbe", targets: ["QPeriaptLinkProbe"])
    ],
    targets: [
        .binaryTarget(name: "CQPeriapt", path: "Binaries/CQPeriapt.xcframework"),
        .target(name: "QPeriaptHybrid", dependencies: ["CQPeriapt"]),
        .executableTarget(name: "QPeriaptLinkProbe", dependencies: ["QPeriaptHybrid"]),
        .testTarget(
            name: "QPeriaptHybridBinaryConsumerTests",
            dependencies: ["QPeriaptHybrid"],
            resources: [.copy("Resources")]
        ),
    ]
)
EOF
cp bindings/swift/BinaryConsumerFixture/Tests/QPeriaptHybridBinaryConsumerTests/QPeriaptHybridBinaryConsumerTests.swift \
	"$CONSUMER/Tests/QPeriaptHybridBinaryConsumerTests/QPeriaptHybridBinaryConsumerTests.swift"

if grep -R -nE 'unsafeFlags|\.\./\.\./target/release|target/release/libq_periapt_ffi' "$CONSUMER/Package.swift" "$CONSUMER/Sources" >/dev/null 2>&1; then
	printf 'error: generated binary consumer contains source-tree linker leakage\n' >&2
	exit 1
fi

set +e
swift test --package-path "$CONSUMER" >"$CONSUMER_LOG" 2>&1
consumer_rc=$?
set -e
cat "$CONSUMER_LOG"
if [ "$consumer_rc" -ne 0 ]; then
	printf 'error: Swift binary consumer test failed (exit=%s); see %s\n' "$consumer_rc" "$CONSUMER_LOG" >&2
	exit 1
fi
if grep -Eiq '(^|[^A-Za-z])(warning|error):' "$CONSUMER_LOG"; then
	printf 'error: Swift binary consumer log contains warning/error diagnostics; see %s\n' "$CONSUMER_LOG" >&2
	exit 1
fi
if ! grep -q 'Executed 3 tests, with 0 failures' "$CONSUMER_LOG"; then
	printf 'error: Swift binary consumer XCTest count was not the expected 3 passing tests\n' >&2
	exit 1
fi
if grep -R -nE 'unsafeFlags|\.\./\.\./target/release|target/release/libq_periapt_ffi' \
	"$CONSUMER/Package.swift" "$CONSUMER/Sources" "$CONSUMER/Tests" >/dev/null 2>&1; then
	printf 'error: generated binary consumer leaked development linker path after build\n' >&2
	exit 1
fi
printf 'SWIFT_BINARY_CONSUMER_PASS\n'

printf '\n=== Link exact XCFramework ZIP in iOS consumers ===\n'
QPERIAPT_INTERNAL_REQUIRE_DUAL_MACOS_RUNTIME="$APPLE_RELEASE_MODE" \
sh artifact/swift-xcframework-consumer-check.sh \
	"$CONSUMER" "$APPLE_CONSUMER_EVIDENCE" "$CONSUMER_XCFRAMEWORK"


if [ "$APPLE_RELEASE_MODE" = "1" ]; then
	printf '\n=== Apple static SDK distribution evidence ===\n'
	assert_release_source_snapshot
	PYTHONPATH=artifact python3 artifact/apple_distribution.py apple-distribution-evidence \
		--artifact "$ZIP_PATH" \
		--source-commit "$SOURCE_COMMIT" \
		--swiftpm-checksum "$SWIFTPM_CHECKSUM" \
		--signing-evidence "$SIGNING_EVIDENCE" \
		--output "$APPLE_DISTRIBUTION"
	PYTHONPATH=artifact python3 artifact/apple_distribution.py validate-zip \
		--artifact "$ZIP_PATH" --require-signature
	assert_release_source_snapshot
	printf 'SWIFT_XCFRAMEWORK_SIGNED_STATIC_DISTRIBUTION_PASS\n'
fi

printf '\n=== Release manifest ===\n'
assert_release_source_snapshot
python3 - "$ROOT" "$DIST" "$VERSION" "$SWIFTPM_CHECKSUM" "$required_targets" "$MANIFEST" "$APPLE_RELEASE_MODE" "$APPLE_DISTRIBUTION" "$SOURCE_COMMIT" "$CONSUMER_LOG" "$APPLE_CONSUMER_EVIDENCE" <<'PY'
import hashlib
import json
import pathlib
import re
import subprocess
import sys

root = pathlib.Path(sys.argv[1]).resolve()
dist = pathlib.Path(sys.argv[2]).resolve()
version = sys.argv[3]
swiftpm_checksum = sys.argv[4]
targets = sys.argv[5].split()
manifest_path = pathlib.Path(sys.argv[6]).resolve()
apple_release_mode = sys.argv[7] == "1"
apple_distribution_path = pathlib.Path(sys.argv[8]).resolve()
source_commit = sys.argv[9]
consumer_log = pathlib.Path(sys.argv[10]).resolve()
apple_consumer_evidence = pathlib.Path(sys.argv[11]).resolve()

def sha(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def run(args):
    return subprocess.check_output(args, cwd=root, stderr=subprocess.STDOUT, text=True).strip()

def run_git(args):
    environment = {
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C",
        "LANG": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
    }
    command = [
        "/usr/bin/git",
        "-c",
        f"safe.directory={root}",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.attributesFile=/dev/null",
        "-c",
        "core.excludesFile=/dev/null",
        "-C",
        str(root),
        *args,
    ]
    return subprocess.check_output(
        command,
        cwd=root,
        env=environment,
        stderr=subprocess.STDOUT,
        text=True,
    ).strip()

if not re.fullmatch(r"[0-9a-f]{40}", source_commit):
    raise SystemExit("error: Swift manifest source commit is not canonical")
if run_git(["rev-parse", "HEAD"]) != source_commit:
    raise SystemExit("error: Swift manifest source commit differs from repository HEAD")
git_dirty = bool(
    run_git(
        [
            "status",
            "--porcelain=v1",
            "--untracked-files=normal",
        ]
    )
)
if apple_release_mode and git_dirty:
    raise SystemExit("error: credentialed Apple manifest cannot record a dirty source tree")

contract = root / "crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json"
contract_document = json.loads(contract.read_text(encoding="utf-8"))
export_names = sorted(entry["name"] for entry in contract_document["abi"]["exports"])
if len(export_names) != 9 or len(set(export_names)) != 9:
    raise SystemExit("error: Swift manifest requires the exact 9-symbol ABI2 export set")
exports_digest = hashlib.sha256(("\n".join(export_names) + "\n").encode("utf-8")).hexdigest()

manifest = {
    "schema_version": 3,
    "kind": "qperiapt.swift_xcframework_manifest",
    "package": "q-periapt-swift",
    "version": version,
    "type": "swiftpm-binaryTarget-xcframework",
    "git_commit": source_commit,
    "git_dirty": git_dirty,
    "toolchain": {
        "rustc": run(["rustc", "--version"]),
        "swift": run(["swift", "--version"]).replace("\n", " "),
        "xcode": run(["xcodebuild", "-version"]).splitlines(),
    },
    "targets": targets,
    "abi": {
        "major": 2,
        "contract_path": contract.relative_to(root).as_posix(),
        "contract_sha256": sha(contract),
        "exports_sha256": exports_digest,
        "export_count": len(export_names),
        "platform": "apple-xcframework",
        "runtime_identity": {
            "container": "CQPeriapt.xcframework",
            "linkage": "static",
            "slice_library": "libq_periapt_ffi_abi2.a",
            "targets": targets,
        },
        "shared_filename": "CQPeriapt.xcframework",
        "static_filename": "libq_periapt_ffi_abi2.a",
    },
    "artifacts": {
        "xcframework_zip": {
            "path": "CQPeriapt.xcframework.zip",
            "sha256": sha(dist / "CQPeriapt.xcframework.zip"),
            "swiftpm_checksum": swiftpm_checksum,
        },
        "xcframework_info_plist_sha256": sha(dist / "CQPeriapt.xcframework" / "Info.plist"),
    },
    "consumer_verification": {
        "macos_runtime_tests": {
            "executed": 3,
            "failures": 0,
            "warning_or_error_diagnostics": 0,
            "log_sha256": sha(consumer_log),
        },
        "macos_universal_link": {
            "platform": "MACOS",
            "architectures": ["arm64", "x86_64"],
            "deployment_target": "13.0",
            "warning_or_error_diagnostics": 0,
            "logs_sha256": {
                "arm64": sha(
                    apple_consumer_evidence / "MACOS_UNIVERSAL-arm64.log"
                ),
                "x86_64": sha(
                    apple_consumer_evidence / "MACOS_UNIVERSAL-x86_64.log"
                ),
            },
        },
        "ios_device_link": {
            "platform": "IOS",
            "architectures": ["arm64"],
            "deployment_target": "16.0",
            "warning_or_error_diagnostics": 0,
            "log_sha256": sha(apple_consumer_evidence / "IOS_DEVICE.log"),
        },
        "ios_simulator_link": {
            "platform": "IOSSIMULATOR",
            "architectures": ["arm64", "x86_64"],
            "deployment_target": "16.0",
            "warning_or_error_diagnostics": 0,
            "log_sha256": sha(apple_consumer_evidence / "IOS_SIMULATOR.log"),
        },
    },
    "source_inputs": {
        "q_periapt_header_sha256": sha(root / "crates/q-periapt-ffi/include/q_periapt.h"),
        "swift_vendored_header_sha256": sha(root / "bindings/swift/Sources/CQPeriapt/q_periapt.h"),
        "swift_wrapper_sha256": sha(root / "bindings/swift/Sources/QPeriaptHybrid/QPeriaptHybrid.swift"),
        "c_abi_contract_sha256": sha(root / "crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json"),
        "signed_policy_vectors_sha256": sha(root / "bindings/signed-policy-vectors.json"),
        "script_sha256": sha(root / "artifact/swift-xcframework.sh"),
        "consumer_check_script_sha256": sha(
            root / "artifact/swift-xcframework-consumer-check.sh"
        ),
        "binary_consumer_link_probe_sha256": sha(
            root
            / "bindings/swift/BinaryConsumerFixture/Sources/QPeriaptLinkProbe/main.swift"
        ),
        "binary_consumer_tests_sha256": sha(
            root
            / "bindings/swift/BinaryConsumerFixture/Tests/QPeriaptHybridBinaryConsumerTests/QPeriaptHybridBinaryConsumerTests.swift"
        ),
    },
    "public_release_boundary": {
        "contains_raw_device_proof": False,
        "contains_mobileprovision": False,
        "contains_device_udid": False,
        "requires_clean_tree_for_release": True,
        "distribution_signed": apple_release_mode,
        "notarization_applicability": "not_applicable_static_sdk_payload",
        "notarized": False,
        "stapled": False,
        "consumer_distribution_responsibilities": {
            "macos": {
                "requires_final_app_signing": True,
                "requires_final_app_notarization": True,
            },
            "ios": {
                "requires_final_app_signing_and_provisioning": True,
                "sdk_notarization_applicable": False,
            },
        },
    },
}
if apple_release_mode:
    distribution = json.loads(apple_distribution_path.read_text(encoding="utf-8"))
    if distribution.get("kind") != "qperiapt.apple_static_xcframework_distribution":
        raise SystemExit("error: Apple distribution evidence has the wrong kind")
    if distribution.get("source_commit") != source_commit:
        raise SystemExit("error: Apple distribution evidence source commit mismatch")
    if distribution.get("artifact") != {
        "path": "CQPeriapt.xcframework.zip",
        "size": (dist / "CQPeriapt.xcframework.zip").stat().st_size,
        "sha256": sha(dist / "CQPeriapt.xcframework.zip"),
        "swiftpm_checksum": swiftpm_checksum,
    }:
        raise SystemExit("error: Apple distribution evidence artifact binding mismatch")
    if distribution.get("notarization") != {
        "applicability": "not_applicable_static_sdk_payload",
        "submission_performed": False,
        "ticket_expected": False,
        "ticket_generated": False,
        "notarized": False,
        "stapled": False,
        "reason_code": "static_xcframework_contains_no_standalone_executable_or_notarizable_bundle",
    }:
        raise SystemExit("error: Apple distribution evidence has unsafe notarization semantics")
    manifest["artifacts"]["apple_distribution_evidence"] = {
        "path": "APPLE_DISTRIBUTION.json",
        "sha256": sha(apple_distribution_path),
    }
    manifest["consumer_verification"]["macos_dual_arch_runtime"] = {
        "executed_architectures": ["arm64", "x86_64"],
        "warning_or_error_diagnostics": 0,
        "log_sha256": sha(
            apple_consumer_evidence / "MACOS_UNIVERSAL-runtime.log"
        ),
    }
    manifest["source_inputs"]["apple_distribution_verifier_sha256"] = sha(
        root / "artifact/apple_distribution.py"
    )
    manifest["source_inputs"]["apple_release_script_sha256"] = sha(
        root / "artifact/swift-xcframework-release.sh"
    )
    manifest["source_inputs"]["swift_remote_consumer_script_sha256"] = sha(
        root / "artifact/swift-xcframework-remote-consumer.sh"
    )
manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

(
	cd "$DIST"
	{
		shasum -a 256 "CQPeriapt.xcframework.zip"
		if [ "$APPLE_RELEASE_MODE" = "1" ]; then
			shasum -a 256 "APPLE_DISTRIBUTION.json"
		fi
		shasum -a 256 "MANIFEST.json"
	} >"$SHA256SUMS"
	shasum -c "$SHA256SUMS"
)

python3 - "$MANIFEST" <<'PY'
import json
import pathlib
import re
import sys

manifest = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
text = json.dumps(manifest, sort_keys=True)
bad = re.compile(
    r"(/Users/|/home/|BEGIN .*PRIVATE KEY|AKIA[0-9A-Z]{16}|"
    r"(?:api|auth|access|secret)[_-]?token\s*[:=]|password\s*[:=]|"
    r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{16,})",
    re.IGNORECASE,
)
if bad.search(text):
    raise SystemExit("error: manifest contains sensitive or nonportable values")
if manifest["public_release_boundary"]["contains_raw_device_proof"]:
    raise SystemExit("error: raw device proof must not be included in Swift binary release")
print("SWIFT_XCFRAMEWORK_MANIFEST_PASS")
PY

assert_release_source_snapshot

printf '\nSWIFT_XCFRAMEWORK_PACKAGE_PASS checksum=%s path=%s\n' "$SWIFTPM_CHECKSUM" "$ZIP_PATH"
