#!/bin/sh
# Re-download and independently verify the immutable alpha.2 Apple release set.
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
	printf 'error: remote consumer rejects Git repository/configuration environment overrides\n' >&2
	exit 2
fi
ROOT=$(cd -- "$(dirname "$0")/.." && pwd) || exit 2
cd "$ROOT" || exit 2

remote_git() {
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
	printf 'error: swift-xcframework-remote-consumer.sh accepts no positional arguments\n' >&2
	exit 2
fi

for tool in /usr/bin/codesign /usr/bin/cmp /usr/bin/curl /usr/bin/ditto \
	/usr/bin/git /usr/bin/swift /usr/bin/wc; do
	if [ ! -x "$tool" ]; then
		printf 'error: required remote-consumer tool is unavailable: %s\n' "$tool" >&2
		exit 2
	fi
done

VERSION="0.1.0-alpha.2"
RELEASE_BASE="https://github.com/billlza/q-periapt/releases/download/v$VERSION"
ZIP_URL="$RELEASE_BASE/CQPeriapt.xcframework.zip"
APPLE_DISTRIBUTION_URL="$RELEASE_BASE/APPLE_DISTRIBUTION.json"
MANIFEST_URL="$RELEASE_BASE/MANIFEST.json"
SHA256SUMS_URL="$RELEASE_BASE/SHA256SUMS"
URL=${QPERIAPT_SWIFT_BINARY_URL:-}
CHECKSUM=${QPERIAPT_SWIFT_BINARY_CHECKSUM:-}
EXPECTED_ZIP_SHA256=${QPERIAPT_SWIFT_BINARY_SHA256:-}
EXPECTED_APPLE_DISTRIBUTION_SHA256=${QPERIAPT_SWIFT_BINARY_APPLE_DISTRIBUTION_SHA256:-}
EXPECTED_MANIFEST_SHA256=${QPERIAPT_SWIFT_BINARY_MANIFEST_SHA256:-}
EXPECTED_SHA256SUMS_SHA256=${QPERIAPT_SWIFT_BINARY_SHA256SUMS_SHA256:-}
ARTIFACT_SOURCE_COMMIT=${QPERIAPT_SWIFT_BINARY_SOURCE_COMMIT:-}

if [ "$URL" != "$ZIP_URL" ]; then
	printf 'error: remote consumer URL must equal the immutable alpha.2 release asset URL\n' >&2
	exit 2
fi
require_lower_hex() {
	value=$1
	length=$2
	label=$3
	case "$value" in
		*[!0-9a-f]*|'')
			printf 'error: %s must be lowercase hexadecimal\n' "$label" >&2
			exit 2
			;;
	esac
	if [ "${#value}" -ne "$length" ]; then
		printf 'error: %s has the wrong length\n' "$label" >&2
		exit 2
	fi
}
require_lower_hex "$CHECKSUM" 64 "SwiftPM checksum"
require_lower_hex "$EXPECTED_ZIP_SHA256" 64 "ZIP SHA-256"
require_lower_hex "$EXPECTED_APPLE_DISTRIBUTION_SHA256" 64 "APPLE_DISTRIBUTION.json SHA-256"
require_lower_hex "$EXPECTED_MANIFEST_SHA256" 64 "MANIFEST.json SHA-256"
require_lower_hex "$EXPECTED_SHA256SUMS_SHA256" 64 "SHA256SUMS SHA-256"
require_lower_hex "$ARTIFACT_SOURCE_COMMIT" 40 "artifact source commit"

VERIFIER_COMMIT=$(remote_git rev-parse --verify "HEAD^{commit}") || {
	printf 'error: cannot resolve the remote-consumer verifier commit\n' >&2
	exit 2
}
require_lower_hex "$VERIFIER_COMMIT" 40 "verifier commit"
if ! remote_git cat-file -e "$ARTIFACT_SOURCE_COMMIT^{commit}"; then
	printf 'error: artifact source commit is unavailable: %s\n' "$ARTIFACT_SOURCE_COMMIT" >&2
	exit 2
fi

ARTIFACT_INPUTS='bindings/swift/Sources/QPeriaptHybrid/QPeriaptHybrid.swift
bindings/swift/BinaryConsumerFixture/Sources/QPeriaptLinkProbe/main.swift
bindings/swift/BinaryConsumerFixture/Tests/QPeriaptHybridBinaryConsumerTests/QPeriaptHybridBinaryConsumerTests.swift
bindings/signed-policy-vectors.json
crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json'
VERIFIER_INPUTS='artifact/swift-xcframework-remote-consumer.sh
artifact/apple_distribution.py
artifact/evidence_io.py
artifact/swift-xcframework-consumer-check.sh
artifact/python-env.sh
artifact/python_bootstrap.py
artifact/results.json'

OUT="$ROOT/target/qperiapt-swift-remote-consumer"
LOCK_DIR="$ROOT/target/.qperiapt-swift-remote-consumer.lock"
ARTIFACT_SNAPSHOT="$OUT/artifact-source-inputs"
VERIFIER_SNAPSHOT="$OUT/verifier-inputs"
RELEASE_ASSETS="$OUT/release-assets"
SNAPSHOT_TARGET="$VERIFIER_SNAPSHOT/target"
REMOTE_ZIP="$RELEASE_ASSETS/CQPeriapt.xcframework.zip"
REMOTE_EXTRACT="$SNAPSHOT_TARGET/extracted"
CONSUMER="$SNAPSHOT_TARGET/consumer"
APPLE_CONSUMER_EVIDENCE="$SNAPSHOT_TARGET/apple-consumer-evidence"
LOG="$OUT/swift-url-binary-consumer.log"
MAX_SOURCE_BLOB_BYTES=4194304
MAX_TEXT_ASSET_BYTES=262144
MAX_ZIP_ASSET_BYTES=536870912

cleanup_remote_state() {
	/bin/rm -f "$RELEASE_ASSETS"/*.part 2>/dev/null || :
	/bin/rm -rf "$ARTIFACT_SNAPSHOT" "$VERIFIER_SNAPSHOT"
	/bin/rmdir "$LOCK_DIR" 2>/dev/null || :
}
if [ -L "$ROOT/target" ] || { [ -e "$ROOT/target" ] && [ ! -d "$ROOT/target" ]; }; then
	printf 'error: remote-consumer target root must be a non-symlink directory\n' >&2
	exit 2
fi
if [ ! -d "$ROOT/target" ]; then
	/bin/mkdir -m 700 "$ROOT/target" || {
		printf 'error: cannot create the remote-consumer target root\n' >&2
		exit 2
	}
fi
if ! /bin/mkdir -m 700 "$LOCK_DIR"; then
	printf 'error: another remote-consumer verification owns the release lock\n' >&2
	exit 2
fi
trap cleanup_remote_state EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

/bin/rm -rf "$OUT"
/bin/mkdir -m 700 "$OUT"
/bin/mkdir -m 700 "$ARTIFACT_SNAPSHOT" "$VERIFIER_SNAPSHOT" "$RELEASE_ASSETS"

materialize_source_input() {
	commit=$1
	snapshot_root=$2
	relative=$3
	destination="$snapshot_root/$relative"
	if ! entry=$(remote_git ls-tree "$commit" -- "$relative"); then
		printf 'error: cannot inspect tracked remote-consumer input: %s\n' "$relative" >&2
		exit 1
	fi
	tab=$(printf '\t')
	IFS="$tab" read -r metadata tree_path <<EOF
$entry
EOF
	IFS=' ' read -r object_mode object_type expected_blob extra <<EOF
$metadata
EOF
	if [ "$object_mode" != "100644" ] || [ "$object_type" != "blob" ] || \
		[ -z "$expected_blob" ] || [ -n "$extra" ] || [ "$tree_path" != "$relative" ]; then
		printf 'error: remote-consumer input is not one regular tracked file: %s\n' "$relative" >&2
		exit 1
	fi
	if ! declared_size=$(remote_git cat-file -s "$expected_blob"); then
		printf 'error: cannot inspect remote-consumer input size: %s\n' "$relative" >&2
		exit 1
	fi
	case "$declared_size" in
		*[!0-9]*|'')
			printf 'error: remote-consumer input has a noncanonical size: %s\n' "$relative" >&2
			exit 1
			;;
	esac
	if [ "$declared_size" -le 0 ] || [ "$declared_size" -gt "$MAX_SOURCE_BLOB_BYTES" ]; then
		printf 'error: remote-consumer input exceeds the bounded contract: %s\n' "$relative" >&2
		exit 1
	fi
	/bin/mkdir -p "$(/usr/bin/dirname "$destination")"
	part="$destination.part"
	if ! (
		umask 077
		set -C
		exec 3>"$part"
		remote_git cat-file blob "$expected_blob" >&3
	); then
		printf 'error: cannot exclusively materialize remote-consumer input: %s\n' "$relative" >&2
		exit 1
	fi
	actual_size=$(/usr/bin/wc -c <"$part" | /usr/bin/tr -d '[:space:]')
	if [ "$actual_size" != "$declared_size" ]; then
		printf 'error: materialized remote-consumer input size mismatch: %s\n' "$relative" >&2
		exit 1
	fi
	actual_blob=$(remote_git hash-object --no-filters "$part")
	if [ "$actual_blob" != "$expected_blob" ]; then
		printf 'error: materialized remote-consumer input hash mismatch: %s\n' "$relative" >&2
		exit 1
	fi
	/bin/chmod 600 "$part"
	/bin/mv "$part" "$destination"
}

for relative in $ARTIFACT_INPUTS; do
	materialize_source_input "$ARTIFACT_SOURCE_COMMIT" "$ARTIFACT_SNAPSHOT" "$relative"
done
for relative in $VERIFIER_INPUTS; do
	materialize_source_input "$VERIFIER_COMMIT" "$VERIFIER_SNAPSHOT" "$relative"
done
if ! /usr/bin/cmp "$ROOT/artifact/swift-xcframework-remote-consumer.sh" \
	"$VERIFIER_SNAPSHOT/artifact/swift-xcframework-remote-consumer.sh"; then
	printf 'error: running remote consumer does not match the verifier commit\n' >&2
	exit 1
fi
snapshot_python() (
	ROOT="$VERIFIER_SNAPSHOT"
	cd "$VERIFIER_SNAPSHOT"
	. "$VERIFIER_SNAPSHOT/artifact/python-env.sh"
	python3 "$@"
)

validate_effective_url() {
	effective_url=$1
	snapshot_python - "$effective_url" <<'PY'
import sys
import urllib.parse

raw = sys.argv[1]
if any(ord(character) < 32 or ord(character) == 127 for character in raw):
    raise SystemExit("error: release download effective URL contains control characters")
url = urllib.parse.urlsplit(raw)
allowed_hosts = {"github.com", "release-assets.githubusercontent.com"}
if url.scheme != "https" or url.hostname not in allowed_hosts:
    raise SystemExit("error: release download redirected to an unapproved HTTPS origin")
if url.username is not None or url.password is not None or url.port not in (None, 443):
    raise SystemExit("error: release download effective URL contains forbidden authority components")
PY
}

download_asset() {
	asset_url=$1
	destination=$2
	maximum=$3
	label=$4
	part="$destination.part"
	if [ -e "$part" ] || [ -L "$part" ] || [ -e "$destination" ] || [ -L "$destination" ]; then
		printf 'error: release download path already exists for %s\n' "$label" >&2
		exit 1
	fi
	effective_url=$(
		/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C LANG=C \
			/usr/bin/curl -q --fail --location --silent --show-error \
			--proto '=https' --proto-redir '=https' --tlsv1.2 --max-redirs 5 \
			--connect-timeout 30 --max-time 900 --max-filesize "$maximum" \
			--speed-limit 1024 --speed-time 60 \
			--output "$part" --write-out '%{url_effective}' "$asset_url"
	) || {
		printf 'error: failed to download release asset: %s\n' "$label" >&2
		exit 1
	}
	validate_effective_url "$effective_url"
	if [ ! -f "$part" ] || [ -L "$part" ]; then
		printf 'error: release download did not produce a regular part file: %s\n' "$label" >&2
		exit 1
	fi
	/bin/chmod 600 "$part"
	/bin/mv "$part" "$destination"
}

download_asset "$ZIP_URL" "$REMOTE_ZIP" "$MAX_ZIP_ASSET_BYTES" "XCFramework ZIP"
download_asset "$APPLE_DISTRIBUTION_URL" "$RELEASE_ASSETS/APPLE_DISTRIBUTION.json" \
	"$MAX_TEXT_ASSET_BYTES" "APPLE_DISTRIBUTION.json"
download_asset "$MANIFEST_URL" "$RELEASE_ASSETS/MANIFEST.json" \
	"$MAX_TEXT_ASSET_BYTES" "MANIFEST.json"
download_asset "$SHA256SUMS_URL" "$RELEASE_ASSETS/SHA256SUMS" \
	"$MAX_TEXT_ASSET_BYTES" "SHA256SUMS"

verify_release_assets() {
	snapshot_python "$VERIFIER_SNAPSHOT/artifact/apple_distribution.py" \
		verify-release-assets \
		--release-directory "$RELEASE_ASSETS" \
		--results-manifest "$VERIFIER_SNAPSHOT/artifact/results.json" \
		--expected-source-commit "$ARTIFACT_SOURCE_COMMIT" \
		--expected-zip-sha256 "$EXPECTED_ZIP_SHA256" \
		--expected-apple-distribution-sha256 "$EXPECTED_APPLE_DISTRIBUTION_SHA256" \
		--expected-manifest-sha256 "$EXPECTED_MANIFEST_SHA256" \
		--expected-sha256sums-sha256 "$EXPECTED_SHA256SUMS_SHA256" \
		--expected-swiftpm-checksum "$CHECKSUM"
}

# This gate precedes every URL consumer or extractor.
verify_release_assets
ACTUAL_CHECKSUM=$(/usr/bin/swift package compute-checksum "$REMOTE_ZIP")
if [ "$ACTUAL_CHECKSUM" != "$CHECKSUM" ]; then
	printf 'error: downloaded SwiftPM checksum differs after release verification\n' >&2
	exit 1
fi

/bin/mkdir -p \
	"$REMOTE_EXTRACT" \
	"$CONSUMER/Sources/QPeriaptHybrid" \
	"$CONSUMER/Sources/QPeriaptLinkProbe" \
	"$CONSUMER/Tests/QPeriaptHybridBinaryConsumerTests/Resources"
/usr/bin/ditto -x -k "$REMOTE_ZIP" "$REMOTE_EXTRACT"
verify_release_assets
/usr/bin/codesign --verify --strict --verbose=4 \
	"$REMOTE_EXTRACT/CQPeriapt.xcframework"

/bin/cp "$ARTIFACT_SNAPSHOT/bindings/swift/Sources/QPeriaptHybrid/QPeriaptHybrid.swift" \
	"$CONSUMER/Sources/QPeriaptHybrid/QPeriaptHybrid.swift"
/bin/cp "$ARTIFACT_SNAPSHOT/bindings/swift/BinaryConsumerFixture/Sources/QPeriaptLinkProbe/main.swift" \
	"$CONSUMER/Sources/QPeriaptLinkProbe/main.swift"
/bin/cp "$ARTIFACT_SNAPSHOT/bindings/swift/BinaryConsumerFixture/Tests/QPeriaptHybridBinaryConsumerTests/QPeriaptHybridBinaryConsumerTests.swift" \
	"$CONSUMER/Tests/QPeriaptHybridBinaryConsumerTests/QPeriaptHybridBinaryConsumerTests.swift"
/bin/cp "$ARTIFACT_SNAPSHOT/bindings/signed-policy-vectors.json" \
	"$CONSUMER/Tests/QPeriaptHybridBinaryConsumerTests/Resources/signed-policy-vectors.json"
cat >"$CONSUMER/Package.swift" <<EOF
// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "QPeriaptRemoteBinaryConsumer",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        .library(name: "QPeriaptHybrid", targets: ["QPeriaptHybrid"]),
        .executable(name: "QPeriaptLinkProbe", targets: ["QPeriaptLinkProbe"])
    ],
    targets: [
        .binaryTarget(name: "CQPeriapt", url: "$URL", checksum: "$CHECKSUM"),
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
if ! /usr/bin/grep -Fq "url: \"$URL\"" "$CONSUMER/Package.swift" || \
	! /usr/bin/grep -Fq "checksum: \"$CHECKSUM\"" "$CONSUMER/Package.swift" || \
	/usr/bin/grep -Fq 'path:' "$CONSUMER/Package.swift"; then
	printf 'error: generated consumer is not exclusively URL/checksum pinned\n' >&2
	exit 1
fi

set +e
/usr/bin/swift test --package-path "$CONSUMER" >"$LOG" 2>&1
consumer_rc=$?
set -e
/bin/cat "$LOG"
if [ "$consumer_rc" -ne 0 ]; then
	printf 'error: remote Swift URL binary consumer failed (exit=%s)\n' "$consumer_rc" >&2
	exit 1
fi
if /usr/bin/grep -Eiq '(^|[^A-Za-z])(warning|error):' "$LOG"; then
	printf 'error: remote Swift URL binary consumer emitted warning/error diagnostics\n' >&2
	exit 1
fi
if ! /usr/bin/grep -q 'Executed 3 tests, with 0 failures' "$LOG"; then
	printf 'error: remote Swift URL binary consumer did not execute exactly three passing tests\n' >&2
	exit 1
fi

# The check script is verifier code, while its ABI contract is an artifact input.
/bin/mkdir -p "$VERIFIER_SNAPSHOT/crates/q-periapt-ffi/abi"
/bin/cp "$ARTIFACT_SNAPSHOT/crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json" \
	"$VERIFIER_SNAPSHOT/crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json"
QPERIAPT_INTERNAL_REQUIRE_DUAL_MACOS_RUNTIME=0 \
/bin/sh "$VERIFIER_SNAPSHOT/artifact/swift-xcframework-consumer-check.sh" \
	"$CONSUMER" "$APPLE_CONSUMER_EVIDENCE" \
	"$REMOTE_EXTRACT/CQPeriapt.xcframework"

# Re-open and re-hash all four public assets after every downstream consumer.
verify_release_assets
/usr/bin/codesign --verify --strict --verbose=4 \
	"$REMOTE_EXTRACT/CQPeriapt.xcframework"
/bin/rm -rf "$ARTIFACT_SNAPSHOT" "$VERIFIER_SNAPSHOT"
if [ -e "$ARTIFACT_SNAPSHOT" ] || [ -L "$ARTIFACT_SNAPSHOT" ] || \
	[ -e "$VERIFIER_SNAPSHOT" ] || [ -L "$VERIFIER_SNAPSHOT" ]; then
	printf 'error: remote-consumer source snapshot cleanup was incomplete\n' >&2
	exit 1
fi
printf 'SWIFT_REMOTE_BINARY_CONSUMER_PASS artifact_source_commit=%s verifier_commit=%s zip_sha256=%s apple_distribution_sha256=%s manifest_sha256=%s sha256sums_sha256=%s checksum=%s\n' \
	"$ARTIFACT_SOURCE_COMMIT" "$VERIFIER_COMMIT" "$EXPECTED_ZIP_SHA256" \
	"$EXPECTED_APPLE_DISTRIBUTION_SHA256" "$EXPECTED_MANIFEST_SHA256" \
	"$EXPECTED_SHA256SUMS_SHA256" "$ACTUAL_CHECKSUM"
