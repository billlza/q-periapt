#!/bin/sh
# Re-download and independently verify the immutable 0.1.5 Apple release set.
set -eu
umask 077

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
		"$@" 2>/dev/null
}

if [ "$#" -ne 0 ]; then
	printf 'error: swift-xcframework-remote-consumer.sh accepts no positional arguments\n' >&2
	exit 2
fi

for tool in /usr/bin/awk /usr/bin/codesign /usr/bin/cmp /usr/bin/curl \
	/usr/bin/ditto /usr/bin/git /usr/bin/id /usr/bin/mktemp /usr/bin/shasum \
	/usr/bin/stat /usr/bin/swift /usr/bin/uname /usr/bin/wc; do
	if [ ! -x "$tool" ]; then
		printf 'error: required remote-consumer tool is unavailable: %s\n' "$tool" >&2
		exit 2
	fi
done

PRODUCT_VERSION="0.1.5"
RELEASE_TAG="v$PRODUCT_VERSION"
RELEASE_BASE="https://github.com/billlza/q-periapt/releases/download/$RELEASE_TAG"
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
	printf 'error: remote consumer URL must equal the immutable 0.1.5 release asset URL\n' >&2
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
RECOVERY_PENDING_COMMIT=${QPERIAPT_APPLE_VERIFIER_PENDING_COMMIT:-}
RECOVERY_VERIFIER_COMMIT=${QPERIAPT_APPLE_VERIFIER_COMMIT:-}
if [ -n "$RECOVERY_PENDING_COMMIT$RECOVERY_VERIFIER_COMMIT" ]; then
	require_lower_hex "$RECOVERY_PENDING_COMMIT" 40 "recovery pending commit"
	require_lower_hex "$RECOVERY_VERIFIER_COMMIT" 40 "recovery verifier commit"
	if [ "$RECOVERY_VERIFIER_COMMIT" != "$VERIFIER_COMMIT" ]; then
		printf 'error: recovery verifier pin differs from the current commit\n' >&2
		exit 2
	fi
fi
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
artifact/apple_stable_publication.py
artifact/apple_verifier_recovery.py
artifact/apple_distribution.py
artifact/apple_proof_contract.py
artifact/apple_publication_contract.py
artifact/bounded_process.py
artifact/claim_ledger.py
artifact/crates_io_publication_contract.py
artifact/evidence_io.py
artifact/git_provenance.py
artifact/platform_distribution_contract.py
artifact/platform_publication_contract.py
artifact/platform_release_contract.py
artifact/platform_stable_publication_contract.py
artifact/proof_manifest.py
artifact/publication_receipt_io.py
artifact/release_publication_contract.py
artifact/rust_package_handoff.py
artifact/rust_publish_contract.py
artifact/swift-xcframework-consumer-check.sh
artifact/python-env.sh
artifact/python_bootstrap.py
artifact/python-run.sh
artifact/results.json'

RUNS_ROOT="$ROOT/target/qperiapt-swift-remote-consumer-runs"
LOCK_DIR="$ROOT/target/.qperiapt-swift-remote-consumer.lock"
OUT=
ARTIFACT_SNAPSHOT=
VERIFIER_SNAPSHOT=
RELEASE_ASSETS=
LOCK_RELEASED=0
RECEIPT_COMMITTED=0
REMOTE_RECEIPT_RELATIVE=
REMOTE_RECEIPT_SHA256=
REMOTE_RECEIPT_VISIBILITY=
MAX_SOURCE_BLOB_BYTES=4194304
MAX_TEXT_ASSET_BYTES=262144
MAX_ZIP_ASSET_BYTES=536870912
MAX_PRIVATE_GATE_LOG_BYTES=1048576
MAX_SWIFT_TEST_LOG_BYTES=16777216
MAX_GATE_TIMEOUT_SECONDS=900

cleanup_remote_state() {
	primary_status=$?
	trap - EXIT INT TERM
	cleanup_failed=0
	if [ -n "$RELEASE_ASSETS" ]; then
		if ! /bin/rm -f "$RELEASE_ASSETS"/*.part 2>/dev/null; then
			printf 'error: remote-consumer part cleanup failed\n' >&2
			cleanup_failed=1
		fi
	fi
	if [ "$RECEIPT_COMMITTED" -eq 0 ] && \
		[ -n "$ARTIFACT_SNAPSHOT" ] && [ -n "$VERIFIER_SNAPSHOT" ]; then
		if ! /bin/rm -rf "$ARTIFACT_SNAPSHOT" "$VERIFIER_SNAPSHOT" 2>/dev/null; then
			printf 'error: remote-consumer snapshot cleanup failed\n' >&2
			cleanup_failed=1
		fi
	fi
	if [ "$RECEIPT_COMMITTED" -eq 0 ] && [ "$LOCK_RELEASED" -eq 0 ]; then
		if ! /bin/rmdir "$LOCK_DIR" 2>/dev/null; then
			printf 'error: remote-consumer lock cleanup failed\n' >&2
			cleanup_failed=1
		fi
	fi
	if [ "$cleanup_failed" -ne 0 ] && [ "$RECEIPT_COMMITTED" -eq 1 ]; then
		printf 'error: remote-consumer receipt committed but post-commit cleanup failed receipt_path=%s receipt_sha256=%s\n' \
			"$REMOTE_RECEIPT_RELATIVE" "$REMOTE_RECEIPT_SHA256" >&2
	fi
	if [ "$cleanup_failed" -ne 0 ] && [ "$primary_status" -eq 0 ]; then
		exit 125
	fi
	exit "$primary_status"
}
validate_private_directory() {
	directory=$1
	label=$2
	if [ ! -d "$directory" ] || [ -L "$directory" ]; then
		printf 'error: %s must be a non-symlink directory\n' "$label" >&2
		exit 2
	fi
	directory_identity=$(private_path_identity "$directory" directory) || {
		printf 'error: cannot inspect %s\n' "$label" >&2
		exit 2
	}
	if [ "$directory_identity" != "$(/usr/bin/id -u):700" ]; then
		printf 'error: %s must be an owned mode-0700 directory\n' "$label" >&2
		exit 2
	fi
}
private_path_identity() {
	identity_path=$1
	identity_kind=$2
	identity_kernel=$(/usr/bin/uname -s 2>/dev/null) || return 1
	case "$identity_kernel:$identity_kind" in
		Darwin:directory)
			/usr/bin/stat -f '%u:%Lp' "$identity_path" 2>/dev/null
			;;
		Darwin:file)
			/usr/bin/stat -f '%u:%Lp:%l' "$identity_path" 2>/dev/null
			;;
		Linux:directory)
			/usr/bin/stat -c '%u:%a' "$identity_path" 2>/dev/null
			;;
		Linux:file)
			/usr/bin/stat -c '%u:%a:%h' "$identity_path" 2>/dev/null
			;;
		*)
			return 1
			;;
	esac
}
capture_private_gate_log() {
	gate_log_leaf=$1
	gate_reason=$2
	gate_maximum_bytes=$3
	shift 3
	gate_log="$OUT/$gate_log_leaf"
	case "$gate_log_leaf" in
		*[!0-9A-Za-z._-]*|'')
			printf 'error: remote-consumer private gate log leaf is unsafe\n' >&2
			exit 2
			;;
	esac
	if [ -e "$gate_log" ] || [ -L "$gate_log" ]; then
		printf 'error: remote-consumer private gate log already exists reason=%s\n' \
			"$gate_reason" >&2
		exit 2
	fi
	set +e
	gate_marker=$(/bin/sh "$VERIFIER_SNAPSHOT/artifact/python-run.sh" \
		"$VERIFIER_SNAPSHOT/artifact/apple_stable_publication.py" \
		capture-remote-gate-log "$RUN_DIRECTORY_NAME" "$gate_log_leaf" \
		"$MAX_GATE_TIMEOUT_SECONDS" "$gate_maximum_bytes" -- "$@")
	gate_helper_status=$?
	set -e
	if [ "$gate_helper_status" -ne 0 ]; then
		printf 'error: remote-consumer private gate capture failed reason=%s\n' \
			"$gate_reason" >&2
		exit 2
	fi
	case "$gate_marker" in
		"REMOTE_CONSUMER_GATE_LOG_CAPTURED returncode="*" sha256="*) ;;
		*)
			printf 'error: remote-consumer private gate capture marker differs reason=%s\n' \
				"$gate_reason" >&2
			exit 2
			;;
	esac
	gate_values=${gate_marker#REMOTE_CONSUMER_GATE_LOG_CAPTURED returncode=}
	gate_status=${gate_values%% *}
	gate_sha256=${gate_values##* sha256=}
	if [ "$gate_values" != "$gate_status sha256=$gate_sha256" ]; then
		printf 'error: remote-consumer private gate capture marker is ambiguous reason=%s\n' \
			"$gate_reason" >&2
		exit 2
	fi
	case "$gate_status" in
		*[!0-9]*|'')
			printf 'error: remote-consumer private gate process status is malformed reason=%s\n' \
				"$gate_reason" >&2
			exit 2
			;;
	esac
	if [ "$gate_status" -gt 255 ]; then
		printf 'error: remote-consumer private gate process status is out of range reason=%s\n' \
			"$gate_reason" >&2
		exit 2
	fi
	require_lower_hex "$gate_sha256" 64 "remote-consumer private gate log SHA-256"
	if [ ! -f "$gate_log" ] || [ -L "$gate_log" ]; then
		printf 'error: remote-consumer private gate log metadata differs reason=%s\n' \
			"$gate_reason" >&2
		exit 2
	fi
	gate_identity=$(private_path_identity "$gate_log" file) || {
		printf 'error: cannot inspect remote-consumer private gate log reason=%s\n' \
			"$gate_reason" >&2
		exit 2
	}
	if [ "$gate_identity" != "$(/usr/bin/id -u):600:1" ]; then
		printf 'error: remote-consumer private gate log identity differs reason=%s\n' \
			"$gate_reason" >&2
		exit 2
	fi
	gate_size=$(/usr/bin/wc -c <"$gate_log" | /usr/bin/tr -d '[:space:]')
	case "$gate_size" in
		*[!0-9]*|'')
			printf 'error: remote-consumer private gate log size is malformed reason=%s\n' \
				"$gate_reason" >&2
			exit 2
			;;
	esac
	if [ "$gate_size" -gt "$gate_maximum_bytes" ]; then
		printf 'error: remote-consumer private gate log exceeded its bound reason=%s\n' \
			"$gate_reason" >&2
		exit 2
	fi
	gate_actual_sha256=$(
		/usr/bin/shasum -a 256 "$gate_log" | /usr/bin/awk '{print $1}'
	)
	require_lower_hex "$gate_actual_sha256" 64 "remote-consumer private gate log resample SHA-256"
	if [ "$gate_actual_sha256" != "$gate_sha256" ]; then
		printf 'error: remote-consumer private gate log changed after capture reason=%s\n' \
			"$gate_reason" >&2
		exit 2
	fi
}
run_private_gate() {
	gate_log_leaf=$1
	gate_reason=$2
	shift 2
	capture_private_gate_log "$gate_log_leaf" "$gate_reason" \
		"$MAX_PRIVATE_GATE_LOG_BYTES" "$@"
	if [ "$gate_status" -ne 0 ]; then
		printf 'error: remote-consumer private gate failed reason=%s private_log=target/qperiapt-swift-remote-consumer-runs/%s/%s log_sha256=%s\n' \
			"$gate_reason" "$RUN_DIRECTORY_NAME" "$gate_log_leaf" \
			"$gate_sha256" >&2
		exit 1
	fi
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

if [ -L "$RUNS_ROOT" ] || { [ -e "$RUNS_ROOT" ] && [ ! -d "$RUNS_ROOT" ]; }; then
	printf 'error: remote-consumer runs root must be a non-symlink directory\n' >&2
	exit 2
fi
if [ ! -d "$RUNS_ROOT" ]; then
	/bin/mkdir -m 700 "$RUNS_ROOT" || {
		printf 'error: cannot create the remote-consumer runs root\n' >&2
		exit 2
	}
fi
validate_private_directory "$RUNS_ROOT" "remote-consumer runs root"
OUT=$(/usr/bin/mktemp -d "$RUNS_ROOT/transaction.XXXXXXXX") || {
	printf 'error: cannot allocate a remote-consumer transaction\n' >&2
	exit 2
}
case "$OUT" in
	"$RUNS_ROOT"/transaction.*) ;;
	*)
		printf 'error: remote-consumer transaction escaped its fixed root\n' >&2
		exit 2
		;;
esac
/bin/chmod 700 "$OUT"
validate_private_directory "$OUT" "remote-consumer transaction"
RUN_DIRECTORY_NAME=${OUT##*/}
ARTIFACT_SNAPSHOT="$OUT/artifact-source-inputs"
VERIFIER_SNAPSHOT="$OUT/verifier-inputs"
RELEASE_ASSETS="$OUT/release-assets"
SNAPSHOT_TARGET="$VERIFIER_SNAPSHOT/target"
REMOTE_ZIP="$RELEASE_ASSETS/CQPeriapt.xcframework.zip"
REMOTE_EXTRACT="$SNAPSHOT_TARGET/extracted"
CONSUMER="$SNAPSHOT_TARGET/consumer"
APPLE_CONSUMER_EVIDENCE="$SNAPSHOT_TARGET/apple-consumer-evidence"
LOG="$OUT/swift-url-binary-consumer.log"
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
START_RESULTS_SHA256=$(
	/usr/bin/shasum -a 256 "$VERIFIER_SNAPSHOT/artifact/results.json" |
		/usr/bin/awk '{print $1}'
)
require_lower_hex "$START_RESULTS_SHA256" 64 "startup results SHA-256"
if [ -n "$RECOVERY_PENDING_COMMIT" ]; then
	/bin/sh "$VERIFIER_SNAPSHOT/artifact/python-run.sh" \
		"$VERIFIER_SNAPSHOT/artifact/apple_stable_publication.py" \
		verify-verifier-recovery "$RUN_DIRECTORY_NAME" "$START_RESULTS_SHA256" \
		"$RECOVERY_PENDING_COMMIT" "$RECOVERY_VERIFIER_COMMIT"
fi
if ! /usr/bin/cmp "$ROOT/artifact/swift-xcframework-remote-consumer.sh" \
	"$VERIFIER_SNAPSHOT/artifact/swift-xcframework-remote-consumer.sh"; then
	printf 'error: running remote consumer does not match the verifier commit\n' >&2
	exit 1
fi
validate_effective_url() {
	effective_url=$1
	/bin/sh "$VERIFIER_SNAPSHOT/artifact/python-run.sh" - "$effective_url" <<'PY'
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

verify_release_assets_private() {
	phase=$1
	run_private_gate "release-assets-$phase.log" \
		"release_assets_$phase" \
		/bin/sh \
		"$VERIFIER_SNAPSHOT/artifact/python-run.sh" \
		"$VERIFIER_SNAPSHOT/artifact/apple_stable_publication.py" \
		verify-release-assets \
		"$VERIFIER_SNAPSHOT/artifact/results.json" \
		"$RELEASE_ASSETS" \
		"$ARTIFACT_SOURCE_COMMIT" \
		"$EXPECTED_ZIP_SHA256" \
		"$EXPECTED_APPLE_DISTRIBUTION_SHA256" \
		"$EXPECTED_MANIFEST_SHA256" \
		"$EXPECTED_SHA256SUMS_SHA256" \
		"$CHECKSUM"
}

# This gate precedes every URL consumer or extractor.
verify_release_assets_private pre-url
CHECKSUM_VALUE="$OUT/swiftpm-checksum.txt"
run_private_gate "swiftpm-checksum.log" "swiftpm_checksum" \
	/bin/sh -c "
umask 077
set -C
/usr/bin/swift package compute-checksum \"\$2\" >\"\$1\"
" "swiftpm-checksum" "$CHECKSUM_VALUE" "$REMOTE_ZIP"
if [ ! -f "$CHECKSUM_VALUE" ] || [ -L "$CHECKSUM_VALUE" ]; then
	printf 'error: remote-consumer SwiftPM checksum value metadata differs\n' >&2
	exit 2
fi
/bin/chmod 600 "$CHECKSUM_VALUE"
CHECKSUM_VALUE_IDENTITY=$(private_path_identity "$CHECKSUM_VALUE" file) || {
	printf 'error: cannot inspect remote-consumer SwiftPM checksum value\n' >&2
	exit 2
}
if [ "$CHECKSUM_VALUE_IDENTITY" != "$(/usr/bin/id -u):600:1" ]; then
	printf 'error: remote-consumer SwiftPM checksum value identity differs\n' >&2
	exit 2
fi
CHECKSUM_VALUE_SIZE=$(/usr/bin/wc -c <"$CHECKSUM_VALUE" | /usr/bin/tr -d '[:space:]')
case "$CHECKSUM_VALUE_SIZE" in
	*[!0-9]*|'')
		printf 'error: remote-consumer SwiftPM checksum value size is malformed\n' >&2
		exit 2
		;;
esac
if [ "$CHECKSUM_VALUE_SIZE" -gt 128 ]; then
	printf 'error: remote-consumer SwiftPM checksum value exceeded its bound\n' >&2
	exit 2
fi
ACTUAL_CHECKSUM=$(/bin/cat "$CHECKSUM_VALUE" 2>/dev/null) || {
	printf 'error: cannot read remote-consumer SwiftPM checksum value\n' >&2
	exit 2
}
require_lower_hex "$ACTUAL_CHECKSUM" 64 "downloaded SwiftPM checksum"
if [ "$ACTUAL_CHECKSUM" != "$CHECKSUM" ]; then
	printf 'error: downloaded SwiftPM checksum differs after release verification\n' >&2
	exit 1
fi

/bin/mkdir -p \
	"$REMOTE_EXTRACT" \
	"$CONSUMER/Sources/QPeriaptHybrid" \
	"$CONSUMER/Sources/QPeriaptLinkProbe" \
	"$CONSUMER/Tests/QPeriaptHybridBinaryConsumerTests/Resources"
run_private_gate "ditto-extract.log" "ditto_extract" \
	/usr/bin/ditto -x -k "$REMOTE_ZIP" "$REMOTE_EXTRACT"
verify_release_assets_private post-extract
run_private_gate "codesign-post-extract.log" "codesign_post_extract" \
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

capture_private_gate_log "$REMOTE_CONSUMER_LOG_NAME" \
	"swift_url_binary_consumer" "$MAX_SWIFT_TEST_LOG_BYTES" \
	/usr/bin/swift test --package-path "$CONSUMER"
consumer_rc=$gate_status
PRIVATE_LOG_RELATIVE="target/qperiapt-swift-remote-consumer-runs/$RUN_DIRECTORY_NAME/swift-url-binary-consumer.log"
PRIVATE_LOG_SHA256=$gate_sha256
if [ "$consumer_rc" -ne 0 ]; then
	printf 'error: remote Swift URL binary consumer failed reason=process_exit private_log=%s log_sha256=%s\n' \
		"$PRIVATE_LOG_RELATIVE" "$PRIVATE_LOG_SHA256" >&2
	exit 1
fi
if /usr/bin/grep -Eiq '(^|[^A-Za-z])(warning|error):' "$LOG"; then
	printf 'error: remote Swift URL binary consumer failed reason=diagnostic private_log=%s log_sha256=%s\n' \
		"$PRIVATE_LOG_RELATIVE" "$PRIVATE_LOG_SHA256" >&2
	exit 1
fi
if ! /usr/bin/grep -q 'Executed 3 tests, with 0 failures' "$LOG"; then
	printf 'error: remote Swift URL binary consumer failed reason=test_count private_log=%s log_sha256=%s\n' \
		"$PRIVATE_LOG_RELATIVE" "$PRIVATE_LOG_SHA256" >&2
	exit 1
fi

# The check script is verifier code, while its ABI contract is an artifact input.
/bin/mkdir -p "$VERIFIER_SNAPSHOT/crates/q-periapt-ffi/abi"
/bin/cp "$ARTIFACT_SNAPSHOT/crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json" \
	"$VERIFIER_SNAPSHOT/crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json"
run_private_gate "consumer-check.log" "consumer_check" \
	/usr/bin/env QPERIAPT_INTERNAL_REQUIRE_DUAL_MACOS_RUNTIME=0 \
	/bin/sh "$VERIFIER_SNAPSHOT/artifact/swift-xcframework-consumer-check.sh" \
	"$CONSUMER" "$APPLE_CONSUMER_EVIDENCE" \
	"$REMOTE_EXTRACT/CQPeriapt.xcframework"

# Re-open and re-hash all four public assets after every downstream consumer.
verify_release_assets_private post-consumer
run_private_gate "codesign-pre-receipt.log" "codesign_pre_receipt" \
	/usr/bin/codesign --verify --strict --verbose=4 \
	"$REMOTE_EXTRACT/CQPeriapt.xcframework"
REMOTE_RECEIPT_RELATIVE="target/qperiapt-swift-remote-consumer-runs/$RUN_DIRECTORY_NAME/apple-remote-consumer-receipt.json"
set -- emit-remote-consumer "$RUN_DIRECTORY_NAME" "$START_RESULTS_SHA256"
if [ -n "$RECOVERY_PENDING_COMMIT" ]; then
	set -- "$@" --verifier-recovery "$RECOVERY_PENDING_COMMIT" "$RECOVERY_VERIFIER_COMMIT"
fi
set +e
REMOTE_RECEIPT_MARKER=$(/bin/sh "$VERIFIER_SNAPSHOT/artifact/python-run.sh" \
	"$VERIFIER_SNAPSHOT/artifact/apple_stable_publication.py" \
	"$@")
receipt_status=$?
set -e
if [ "$receipt_status" -ne 0 ]; then
	case "$receipt_status:$REMOTE_RECEIPT_MARKER" in
		125:"PUBLICATION_RECEIPT_COMMITTED_ERROR visibility=committed leaf=apple-remote-consumer-receipt.json sha256="*)
			REMOTE_RECEIPT_VISIBILITY=committed
			;;
		125:"PUBLICATION_RECEIPT_COMMITTED_ERROR visibility=indeterminate leaf=apple-remote-consumer-receipt.json sha256="*)
			REMOTE_RECEIPT_VISIBILITY=indeterminate
			;;
	esac
	case "$REMOTE_RECEIPT_VISIBILITY" in
		committed|indeterminate)
			RECEIPT_COMMITTED=1
			REMOTE_RECEIPT_SHA256=${REMOTE_RECEIPT_MARKER##* sha256=}
			require_lower_hex "$REMOTE_RECEIPT_SHA256" 64 \
				"intended remote-consumer receipt SHA-256"
			if [ "$REMOTE_RECEIPT_VISIBILITY" = committed ]; then
				printf 'error: remote-consumer receipt committed with incomplete durability; preserving transaction intended_receipt_path=%s intended_receipt_sha256=%s\n' \
					"$REMOTE_RECEIPT_RELATIVE" "$REMOTE_RECEIPT_SHA256" >&2
			else
				printf 'error: remote-consumer receipt visibility indeterminate; preserving transaction intended_receipt_path=%s intended_receipt_sha256=%s\n' \
					"$REMOTE_RECEIPT_RELATIVE" "$REMOTE_RECEIPT_SHA256" >&2
			fi
			exit 125
			;;
	esac
	printf 'error: remote-consumer receipt emission failed\n' >&2
	exit 1
fi
RECEIPT_COMMITTED=1
REMOTE_RECEIPT_SHA256=${REMOTE_RECEIPT_MARKER##* sha256=}
require_lower_hex "$REMOTE_RECEIPT_SHA256" 64 "remote-consumer receipt SHA-256"
EXPECTED_REMOTE_RECEIPT_MARKER="APPLE_REMOTE_CONSUMER_RECEIPT_PASS path=$REMOTE_RECEIPT_RELATIVE sha256=$REMOTE_RECEIPT_SHA256"
if [ "$REMOTE_RECEIPT_MARKER" != "$EXPECTED_REMOTE_RECEIPT_MARKER" ]; then
	printf 'error: remote-consumer receipt marker differs\n' >&2
	exit 1
fi
if ! /bin/rm -rf "$ARTIFACT_SNAPSHOT" "$VERIFIER_SNAPSHOT" 2>/dev/null; then
	printf 'error: remote-consumer snapshot cleanup failed\n' >&2
	printf 'error: remote-consumer receipt committed but post-commit cleanup failed receipt_path=%s receipt_sha256=%s\n' \
		"$REMOTE_RECEIPT_RELATIVE" "$REMOTE_RECEIPT_SHA256" >&2
	exit 125
fi
if [ -e "$ARTIFACT_SNAPSHOT" ] || [ -L "$ARTIFACT_SNAPSHOT" ] || \
	[ -e "$VERIFIER_SNAPSHOT" ] || [ -L "$VERIFIER_SNAPSHOT" ]; then
	printf 'error: remote-consumer source snapshot cleanup was incomplete\n' >&2
	printf 'error: remote-consumer receipt committed but post-commit cleanup failed receipt_path=%s receipt_sha256=%s\n' \
		"$REMOTE_RECEIPT_RELATIVE" "$REMOTE_RECEIPT_SHA256" >&2
	exit 125
fi
if ! /bin/rmdir "$LOCK_DIR" 2>/dev/null; then
	printf 'error: remote-consumer lock cleanup failed\n' >&2
	printf 'error: remote-consumer receipt committed but post-commit cleanup failed receipt_path=%s receipt_sha256=%s\n' \
		"$REMOTE_RECEIPT_RELATIVE" "$REMOTE_RECEIPT_SHA256" >&2
	exit 125
fi
LOCK_RELEASED=1
trap - EXIT INT TERM
printf '%s\n' "$REMOTE_RECEIPT_MARKER"
printf 'SWIFT_REMOTE_BINARY_CONSUMER_PASS artifact_source_commit=%s verifier_commit=%s zip_sha256=%s apple_distribution_sha256=%s manifest_sha256=%s sha256sums_sha256=%s checksum=%s receipt_path=%s receipt_sha256=%s\n' \
	"$ARTIFACT_SOURCE_COMMIT" "$VERIFIER_COMMIT" "$EXPECTED_ZIP_SHA256" \
	"$EXPECTED_APPLE_DISTRIBUTION_SHA256" "$EXPECTED_MANIFEST_SHA256" \
	"$EXPECTED_SHA256SUMS_SHA256" "$ACTUAL_CHECKSUM" \
	"$REMOTE_RECEIPT_RELATIVE" "$REMOTE_RECEIPT_SHA256"
