#!/bin/sh
# Re-download the immutable public alpha.2 asset and exercise a real URL binaryTarget.
set -eu

unset CDPATH
ROOT=$(cd -- "$(dirname "$0")/.." && pwd) || exit 2
cd "$ROOT" || exit 2
. "$ROOT/artifact/python-env.sh"

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
need curl
need ditto
need git
need shasum
need swift

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
if ! git cat-file -e "$SOURCE_COMMIT^{commit}"; then
	printf 'error: source commit is not available in the local repository: %s\n' "$SOURCE_COMMIT" >&2
	exit 2
fi

SOURCE_WORKTREE="$ROOT/target/qperiapt-apple-release-worktrees/$SOURCE_COMMIT/source"
if [ ! -d "$SOURCE_WORKTREE" ]; then
	printf 'error: preserved source worktree is missing for commit %s\n' "$SOURCE_COMMIT" >&2
	exit 1
fi
if ! WORKTREE_COMMIT=$(git -C "$SOURCE_WORKTREE" rev-parse HEAD) || \
	! WORKTREE_STATUS=$(git -C "$SOURCE_WORKTREE" status --porcelain=v1 --untracked-files=normal); then
	printf 'error: cannot inspect the preserved source worktree\n' >&2
	exit 1
fi
if [ "$WORKTREE_COMMIT" != "$SOURCE_COMMIT" ] || [ -n "$WORKTREE_STATUS" ]; then
	printf 'error: preserved source worktree is not the exact clean source commit\n' >&2
	exit 1
fi
TRACKED_CONSUMER_INPUTS='bindings/swift/Sources/QPeriaptHybrid/QPeriaptHybrid.swift
bindings/swift/BinaryConsumerFixture/Sources/QPeriaptLinkProbe/main.swift
bindings/swift/BinaryConsumerFixture/Tests/QPeriaptHybridBinaryConsumerTests/QPeriaptHybridBinaryConsumerTests.swift
bindings/signed-policy-vectors.json'
for relative in $TRACKED_CONSUMER_INPUTS; do
	if ! git -C "$SOURCE_WORKTREE" ls-files --error-unmatch -- "$relative" >/dev/null 2>&1; then
		printf 'error: remote consumer input is not tracked by source commit: %s\n' "$relative" >&2
		exit 1
	fi
	input="$SOURCE_WORKTREE/$relative"
	if [ ! -f "$input" ] || [ -L "$input" ]; then
		printf 'error: remote consumer input is not a regular non-symlink file: %s\n' "$relative" >&2
		exit 1
	fi
done

OUT="$ROOT/target/qperiapt-swift-remote-consumer"
REMOTE_ZIP="$OUT/CQPeriapt.xcframework.zip"
REMOTE_ZIP_PART="$OUT/CQPeriapt.xcframework.zip.part"
REMOTE_EXTRACT="$OUT/extracted"
CONSUMER="$OUT/consumer"
LOG="$OUT/swift-url-binary-consumer.log"
rm -rf "$OUT"
mkdir -p \
	"$REMOTE_EXTRACT" \
	"$CONSUMER/Sources/QPeriaptHybrid" \
	"$CONSUMER/Sources/QPeriaptLinkProbe" \
	"$CONSUMER/Tests/QPeriaptHybridBinaryConsumerTests/Resources"
cleanup_remote_part() {
	rm -f "$REMOTE_ZIP_PART"
}
trap cleanup_remote_part EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
EFFECTIVE_URL=$(curl --fail --location --silent --show-error \
	--proto '=https' --proto-redir '=https' --tlsv1.2 \
	--output "$REMOTE_ZIP_PART" --write-out '%{url_effective}' "$URL")
python3 - "$EFFECTIVE_URL" <<'PY'
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
PYTHONPATH=artifact python3 artifact/apple_distribution.py validate-zip \
	--artifact "$REMOTE_ZIP_PART" --require-signature
mv "$REMOTE_ZIP_PART" "$REMOTE_ZIP"
ditto -x -k "$REMOTE_ZIP" "$REMOTE_EXTRACT"
codesign --verify --strict --verbose=4 "$REMOTE_EXTRACT/CQPeriapt.xcframework"

cp "$SOURCE_WORKTREE/bindings/swift/Sources/QPeriaptHybrid/QPeriaptHybrid.swift" \
	"$CONSUMER/Sources/QPeriaptHybrid/QPeriaptHybrid.swift"
cp "$SOURCE_WORKTREE/bindings/swift/BinaryConsumerFixture/Sources/QPeriaptLinkProbe/main.swift" \
	"$CONSUMER/Sources/QPeriaptLinkProbe/main.swift"
cp "$SOURCE_WORKTREE/bindings/swift/BinaryConsumerFixture/Tests/QPeriaptHybridBinaryConsumerTests/QPeriaptHybridBinaryConsumerTests.swift" \
	"$CONSUMER/Tests/QPeriaptHybridBinaryConsumerTests/QPeriaptHybridBinaryConsumerTests.swift"
cp "$SOURCE_WORKTREE/bindings/signed-policy-vectors.json" \
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
sh artifact/swift-xcframework-consumer-check.sh \
	"$CONSUMER" "$OUT/apple-consumer-evidence" "$REMOTE_EXTRACT/CQPeriapt.xcframework"
printf 'SWIFT_REMOTE_BINARY_CONSUMER_PASS source_commit=%s sha256=%s checksum=%s\n' \
	"$SOURCE_COMMIT" "$ACTUAL_SHA256" "$ACTUAL_CHECKSUM"
