#!/bin/sh
# Re-download the immutable public alpha.2 asset and exercise a real URL binaryTarget.
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

need() {
	if ! command -v "$1" >/dev/null 2>&1; then
		printf 'error: required remote-consumer tool not found: %s\n' "$1" >&2
		exit 2
	fi
}

need codesign
need cmp
need curl
need ditto
need git
need shasum
need swift
need wc

VERSION="0.1.0-alpha.2"
EXPECTED_URL="https://github.com/billlza/q-periapt/releases/download/v$VERSION/CQPeriapt.xcframework.zip"
URL=${QPERIAPT_SWIFT_BINARY_URL:-}
CHECKSUM=${QPERIAPT_SWIFT_BINARY_CHECKSUM:-}
EXPECTED_SHA256=${QPERIAPT_SWIFT_BINARY_SHA256:-}
SOURCE_COMMIT=${QPERIAPT_SWIFT_BINARY_SOURCE_COMMIT:-}

if [ "$URL" != "$EXPECTED_URL" ]; then
	printf 'error: remote consumer URL must equal the immutable alpha.2 release asset URL\n' >&2
	exit 2
fi
case "$CHECKSUM" in
	*[!0-9a-f]*|'') printf 'error: SwiftPM checksum must be lowercase hexadecimal\n' >&2; exit 2 ;;
esac
case "$EXPECTED_SHA256" in
	*[!0-9a-f]*|'') printf 'error: ZIP SHA-256 must be lowercase hexadecimal\n' >&2; exit 2 ;;
esac
case "$SOURCE_COMMIT" in
	*[!0-9a-f]*|'') printf 'error: source commit must be lowercase hexadecimal\n' >&2; exit 2 ;;
esac
if [ "${#CHECKSUM}" -ne 64 ] || [ "${#EXPECTED_SHA256}" -ne 64 ] || \
	[ "${#SOURCE_COMMIT}" -ne 40 ]; then
	printf 'error: remote consumer checksum, SHA-256, or source commit has the wrong length\n' >&2
	exit 2
fi
if ! remote_git cat-file -e "$SOURCE_COMMIT^{commit}"; then
	printf 'error: source commit is not available in the local repository: %s\n' "$SOURCE_COMMIT" >&2
	exit 2
fi

TRACKED_CONSUMER_INPUTS='bindings/swift/Sources/QPeriaptHybrid/QPeriaptHybrid.swift
bindings/swift/BinaryConsumerFixture/Sources/QPeriaptLinkProbe/main.swift
bindings/swift/BinaryConsumerFixture/Tests/QPeriaptHybridBinaryConsumerTests/QPeriaptHybridBinaryConsumerTests.swift
bindings/signed-policy-vectors.json
artifact/swift-xcframework-remote-consumer.sh
artifact/apple_distribution.py
artifact/evidence_io.py
artifact/swift-xcframework-consumer-check.sh
artifact/python-env.sh
artifact/python_bootstrap.py
crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json'

OUT="$ROOT/target/qperiapt-swift-remote-consumer"
SOURCE_SNAPSHOT="$OUT/source-inputs"
SNAPSHOT_TARGET="$SOURCE_SNAPSHOT/target"
REMOTE_ZIP="$OUT/CQPeriapt.xcframework.zip"
REMOTE_ZIP_PART="$OUT/CQPeriapt.xcframework.zip.part"
REMOTE_EXTRACT="$SNAPSHOT_TARGET/extracted"
CONSUMER="$SNAPSHOT_TARGET/consumer"
APPLE_CONSUMER_EVIDENCE="$SNAPSHOT_TARGET/apple-consumer-evidence"
LOG="$OUT/swift-url-binary-consumer.log"
MAX_SOURCE_BLOB_BYTES=4194304

cleanup_remote_state() {
	rm -f "$REMOTE_ZIP_PART"
	rm -rf "$SOURCE_SNAPSHOT"
}
trap cleanup_remote_state EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

rm -rf "$OUT"
mkdir -p "$OUT"
mkdir -m 700 "$SOURCE_SNAPSHOT"
mkdir -p \
	"$REMOTE_EXTRACT" \
	"$CONSUMER/Sources/QPeriaptHybrid" \
	"$CONSUMER/Sources/QPeriaptLinkProbe" \
	"$CONSUMER/Tests/QPeriaptHybridBinaryConsumerTests/Resources"

materialize_source_input() {
	relative=$1
	destination="$SOURCE_SNAPSHOT/$relative"
	if ! entry=$(remote_git ls-tree "$SOURCE_COMMIT" -- "$relative"); then
		printf 'error: cannot inspect remote consumer source input: %s\n' "$relative" >&2
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
		printf 'error: remote consumer input is not one regular tracked file: %s\n' "$relative" >&2
		exit 1
	fi
	if ! declared_size=$(remote_git cat-file -s "$expected_blob"); then
		printf 'error: cannot inspect remote consumer input size: %s\n' "$relative" >&2
		exit 1
	fi
	case "$declared_size" in
		*[!0-9]*|'')
			printf 'error: remote consumer input has a noncanonical blob size: %s\n' "$relative" >&2
			exit 1
			;;
	esac
	if [ "$declared_size" -le 0 ] || [ "$declared_size" -gt "$MAX_SOURCE_BLOB_BYTES" ]; then
		printf 'error: remote consumer input blob size is outside the bounded contract: %s\n' "$relative" >&2
		exit 1
	fi
	mkdir -p "$(dirname "$destination")"
	part="$destination.part"
	if ! (
		umask 077
		set -C
		exec 3>"$part"
		remote_git cat-file blob "$expected_blob" >&3
	); then
		printf 'error: cannot exclusively materialize remote consumer input: %s\n' "$relative" >&2
		exit 1
	fi
	actual_size=$(wc -c <"$part" | tr -d '[:space:]')
	if [ "$actual_size" != "$declared_size" ]; then
		printf 'error: materialized remote consumer input size mismatch: %s\n' "$relative" >&2
		exit 1
	fi
	actual_blob=$(remote_git hash-object --no-filters "$part")
	if [ "$actual_blob" != "$expected_blob" ]; then
		printf 'error: materialized remote consumer input hash mismatch: %s\n' "$relative" >&2
		exit 1
	fi
	chmod 600 "$part"
	mv "$part" "$destination"
}

for relative in $TRACKED_CONSUMER_INPUTS; do
	materialize_source_input "$relative"
done
if ! cmp "$ROOT/artifact/swift-xcframework-remote-consumer.sh" \
	"$SOURCE_SNAPSHOT/artifact/swift-xcframework-remote-consumer.sh"; then
	printf 'error: running remote consumer does not match the source commit verifier\n' >&2
	exit 1
fi
snapshot_python() (
	ROOT="$SOURCE_SNAPSHOT"
	cd "$SOURCE_SNAPSHOT"
	. "$SOURCE_SNAPSHOT/artifact/python-env.sh"
	python3 "$@"
)
EFFECTIVE_URL=$(curl -q --fail --location --silent --show-error \
	--proto '=https' --proto-redir '=https' --tlsv1.2 \
	--connect-timeout 30 --max-time 900 --max-filesize 536870912 \
	--speed-limit 1024 --speed-time 60 \
	--output "$REMOTE_ZIP_PART" --write-out '%{url_effective}' "$URL")
snapshot_python - "$EFFECTIVE_URL" <<'PY'
import sys
import urllib.parse

url = urllib.parse.urlsplit(sys.argv[1])
allowed_hosts = {
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
}
if url.scheme != "https" or url.hostname not in allowed_hosts:
    raise SystemExit(f"error: release download redirected to an unapproved origin: {url.scheme}://{url.hostname}")
if url.username is not None or url.password is not None or url.port not in (None, 443):
    raise SystemExit("error: release download effective URL contains forbidden authority components")
PY
if [ ! -f "$REMOTE_ZIP_PART" ] || [ -L "$REMOTE_ZIP_PART" ]; then
	printf 'error: remote download did not produce a regular temporary ZIP\n' >&2
	exit 1
fi
ACTUAL_SHA256=$(shasum -a 256 "$REMOTE_ZIP_PART" | awk '{print $1}')
if [ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]; then
	printf 'error: downloaded XCFramework ZIP SHA-256 does not match release evidence\n' >&2
	exit 1
fi
ACTUAL_CHECKSUM=$(swift package compute-checksum "$REMOTE_ZIP_PART")
if [ "$ACTUAL_CHECKSUM" != "$CHECKSUM" ]; then
	printf 'error: downloaded XCFramework SwiftPM checksum does not match release evidence\n' >&2
	exit 1
fi
snapshot_python "$SOURCE_SNAPSHOT/artifact/apple_distribution.py" validate-zip \
	--artifact "$REMOTE_ZIP_PART" --require-signature
mv "$REMOTE_ZIP_PART" "$REMOTE_ZIP"
ditto -x -k "$REMOTE_ZIP" "$REMOTE_EXTRACT"
codesign --verify --strict --verbose=4 "$REMOTE_EXTRACT/CQPeriapt.xcframework"

cp "$SOURCE_SNAPSHOT/bindings/swift/Sources/QPeriaptHybrid/QPeriaptHybrid.swift" \
	"$CONSUMER/Sources/QPeriaptHybrid/QPeriaptHybrid.swift"
cp "$SOURCE_SNAPSHOT/bindings/swift/BinaryConsumerFixture/Sources/QPeriaptLinkProbe/main.swift" \
	"$CONSUMER/Sources/QPeriaptLinkProbe/main.swift"
cp "$SOURCE_SNAPSHOT/bindings/swift/BinaryConsumerFixture/Tests/QPeriaptHybridBinaryConsumerTests/QPeriaptHybridBinaryConsumerTests.swift" \
	"$CONSUMER/Tests/QPeriaptHybridBinaryConsumerTests/QPeriaptHybridBinaryConsumerTests.swift"
cp "$SOURCE_SNAPSHOT/bindings/signed-policy-vectors.json" \
	"$CONSUMER/Tests/QPeriaptHybridBinaryConsumerTests/Resources/signed-policy-vectors.json"
cat >"$CONSUMER/Package.swift" <<EOF
// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "QPeriaptRemoteBinaryConsumer",
    platforms: [
        .macOS(.v13),
        .iOS(.v16)
    ],
    products: [
        .library(name: "QPeriaptHybrid", targets: ["QPeriaptHybrid"]),
        .executable(name: "QPeriaptLinkProbe", targets: ["QPeriaptLinkProbe"])
    ],
    targets: [
        .binaryTarget(
            name: "CQPeriapt",
            url: "$URL",
            checksum: "$CHECKSUM"
        ),
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

if ! grep -Fq "url: \"$URL\"" "$CONSUMER/Package.swift" || \
	! grep -Fq "checksum: \"$CHECKSUM\"" "$CONSUMER/Package.swift" || \
	grep -Fq 'path:' "$CONSUMER/Package.swift"; then
	printf 'error: generated remote consumer is not exclusively pinned to the public URL/checksum\n' >&2
	exit 1
fi

set +e
swift test --package-path "$CONSUMER" >"$LOG" 2>&1
consumer_rc=$?
set -e
cat "$LOG"
if [ "$consumer_rc" -ne 0 ]; then
	printf 'error: remote Swift URL binary consumer failed (exit=%s)\n' "$consumer_rc" >&2
	exit 1
fi
if grep -Eiq '(^|[^A-Za-z])(warning|error):' "$LOG"; then
	printf 'error: remote Swift URL binary consumer emitted warning/error diagnostics\n' >&2
	exit 1
fi
if ! grep -q 'Executed 3 tests, with 0 failures' "$LOG"; then
	printf 'error: remote Swift URL binary consumer did not execute exactly three passing tests\n' >&2
	exit 1
fi
QPERIAPT_INTERNAL_REQUIRE_DUAL_MACOS_RUNTIME=0 \
sh "$SOURCE_SNAPSHOT/artifact/swift-xcframework-consumer-check.sh" \
	"$CONSUMER" "$APPLE_CONSUMER_EVIDENCE" "$REMOTE_EXTRACT/CQPeriapt.xcframework"
rm -rf "$SOURCE_SNAPSHOT"
if [ -e "$SOURCE_SNAPSHOT" ] || [ -L "$SOURCE_SNAPSHOT" ]; then
	printf 'error: remote consumer source snapshot cleanup was incomplete\n' >&2
	exit 1
fi
printf 'SWIFT_REMOTE_BINARY_CONSUMER_PASS source_commit=%s sha256=%s checksum=%s\n' \
	"$SOURCE_COMMIT" "$ACTUAL_SHA256" "$ACTUAL_CHECKSUM"
