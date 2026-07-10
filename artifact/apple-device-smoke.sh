#!/bin/sh
# Mac + physical iOS/iPadOS device proof-to-byte smoke for the Swift/C ABI face.
#
# This script is fail-closed about evidence boundaries:
# - macOS SwiftPM tests prove the Mac native binding only.
# - iOS build proves the aarch64-apple-ios Rust staticlib and Swift app compile for a real device.
# - iOS launch proves the app executed on the attached physical device and printed
#   QPERIAPT_DEVICE_PASS run-id=<nonce>. Simulator output is never accepted as a substitute.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd) || exit 2
cd "$ROOT" || exit 2

if [ -n "${QPERIAPT_DEVELOPER_DIR:-}" ]; then
	DEVELOPER_DIR=$QPERIAPT_DEVELOPER_DIR
	export DEVELOPER_DIR
fi

DEVICE_ID=${QPERIAPT_IOS_DEVICE_ID:-${1:-}}
BUNDLE_ID=${QPERIAPT_IOS_BUNDLE_ID:-dev.qperiapt.DeviceRunner}
CODE_SIGN_STYLE_VALUE=${QPERIAPT_CODE_SIGN_STYLE:-Automatic}
MIN_PROFILE_VALID_DAYS=${QPERIAPT_MIN_PROFILE_VALID_DAYS:-30}
DERIVED_DATA=${QPERIAPT_DERIVED_DATA:-"$ROOT/target/apple-device-derived"}
RESULT_DIR=${QPERIAPT_DEVICE_RESULT_DIR:-"$ROOT/artifact/device-runs"}
DEVICE_PROOF_MAX_AGE_SECONDS=${QPERIAPT_DEVICE_PROOF_MAX_AGE_SECONDS:-86400}
DEVICE_ARTIFACT_PREFIX=${QPERIAPT_DEVICE_ARTIFACT_PREFIX:-ipad}
DEVICE_LABEL=${QPERIAPT_DEVICE_LABEL:-$DEVICE_ARTIFACT_PREFIX}
EXPECTED_DEVICE_TYPE=${QPERIAPT_EXPECT_DEVICE_TYPE:-}
ALLOW_DIRTY_APPLE_DEVICE=${QPERIAPT_ALLOW_DIRTY_APPLE_DEVICE:-0}
PROJECT_DIR="$ROOT/bindings/apple-device"
PROJECT="$PROJECT_DIR/QPeriaptAppleDevice.xcodeproj"
APP="$DERIVED_DATA/Build/Products/Debug-iphoneos/QPeriaptDeviceRunner.app"
ALLOW_PROVISIONING_UPDATES=${QPERIAPT_ALLOW_PROVISIONING_UPDATES:-0}
ALLOW_PROVISIONING_DEVICE_REGISTRATION=${QPERIAPT_ALLOW_PROVISIONING_DEVICE_REGISTRATION:-0}
case "$ALLOW_PROVISIONING_UPDATES" in
	0 | 1) ;;
	*)
		printf 'error: QPERIAPT_ALLOW_PROVISIONING_UPDATES must be 0 or 1\n' >&2
		exit 2
		;;
esac
case "$ALLOW_PROVISIONING_DEVICE_REGISTRATION" in
	0 | 1) ;;
	*)
		printf 'error: QPERIAPT_ALLOW_PROVISIONING_DEVICE_REGISTRATION must be 0 or 1\n' >&2
		exit 2
		;;
esac
if [ "$ALLOW_PROVISIONING_UPDATES" = "1" ]; then
	printf 'note: QPERIAPT_ALLOW_PROVISIONING_UPDATES=1 lets Xcode create/update development profiles for DEVELOPMENT_TEAM=%s\n' "${DEVELOPMENT_TEAM:-<unset>}"
	if [ "$ALLOW_PROVISIONING_DEVICE_REGISTRATION" = "1" ]; then
		printf 'note: QPERIAPT_ALLOW_PROVISIONING_DEVICE_REGISTRATION=1 lets Xcode register the selected device if needed\n'
	fi
elif [ "$ALLOW_PROVISIONING_DEVICE_REGISTRATION" = "1" ]; then
	printf 'error: QPERIAPT_ALLOW_PROVISIONING_DEVICE_REGISTRATION=1 requires QPERIAPT_ALLOW_PROVISIONING_UPDATES=1\n' >&2
	exit 2
fi

need() {
	if ! command -v "$1" >/dev/null 2>&1; then
		printf 'error: required tool not found: %s\n' "$1" >&2
		exit 2
	fi
}

pick_device() {
	xcrun devicectl list devices --json-output - 2>/dev/null | python3 -c '
import json
import sys

data = json.load(sys.stdin)
matches = []
for dev in data.get("result", {}).get("devices", []):
    props = dev.get("properties", {})
    hardware = props.get("hardware", {})
    state = props.get("state", {})
    connection = props.get("connection", {})
    if hardware.get("platform") != "iOS":
        continue
    if hardware.get("reality") != "physical":
        continue
    if hardware.get("deviceType") not in ("iPad", "iPhone"):
        continue
    if state.get("bootState") != "booted":
        continue
    if connection.get("state") != "connected":
        continue
    udid = hardware.get("udid")
    if udid:
        matches.append(udid)
if len(matches) == 1:
    print(matches[0])
'
}

need cargo
need codesign
need git
need xcodebuild
need xcodegen
need xcrun
need otool
need python3
need security

if [ -z "${DEVELOPMENT_TEAM:-}" ]; then
	printf 'error: DEVELOPMENT_TEAM is required for the physical Apple-device proof lane\n' >&2
	exit 2
fi
case "$ALLOW_DIRTY_APPLE_DEVICE" in
	0 | 1) ;;
	*)
		printf 'error: QPERIAPT_ALLOW_DIRTY_APPLE_DEVICE must be 0 or 1\n' >&2
		exit 2
		;;
esac
if [ -n "$(git status --porcelain=v1 --untracked-files=all)" ]; then
	if [ "$ALLOW_DIRTY_APPLE_DEVICE" != "1" ]; then
		printf 'error: Apple device proof requires a clean source tree; set QPERIAPT_ALLOW_DIRTY_APPLE_DEVICE=1 for local diagnostics only\n' >&2
		exit 2
	fi
	printf 'note: QPERIAPT_ALLOW_DIRTY_APPLE_DEVICE=1 records diagnostic-only dirty-source Apple proof\n'
fi
python3 - "$ROOT" "$DERIVED_DATA" "$RESULT_DIR" "$BUNDLE_ID" "$DEVICE_ID" "$DEVELOPMENT_TEAM" "$DEVICE_LABEL" "$DEVICE_ARTIFACT_PREFIX" "$EXPECTED_DEVICE_TYPE" "$MIN_PROFILE_VALID_DAYS" "$DEVICE_PROOF_MAX_AGE_SECONDS" <<'PY'
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1]).resolve()
derived = pathlib.Path(sys.argv[2]).resolve()
result = pathlib.Path(sys.argv[3]).resolve()
bundle_id = sys.argv[4]
device_id = sys.argv[5]
team_id = sys.argv[6]
device_label = sys.argv[7]
artifact_prefix = sys.argv[8]
expected_device_type = sys.argv[9]
min_profile_valid_days = int(sys.argv[10])
max_age_seconds = int(sys.argv[11])
target_base = (root / "target").resolve()
result_base = (root / "artifact" / "device-runs").resolve()
max_age_limit = 7 * 24 * 60 * 60
max_profile_days = 366

def require_under(path: pathlib.Path, base: pathlib.Path, label: str, allow_base: bool = False) -> None:
    try:
        path.relative_to(base)
    except ValueError as exc:
        raise SystemExit(f"error: {label} must be under {base}: {path}") from exc
    if not allow_base and path == base:
        raise SystemExit(f"error: {label} must not be the base directory itself: {path}")

require_under(derived, target_base, "QPERIAPT_DERIVED_DATA")
require_under(result, result_base, "QPERIAPT_DEVICE_RESULT_DIR", allow_base=True)
if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{2,}", bundle_id):
    raise SystemExit(f"error: invalid QPERIAPT_IOS_BUNDLE_ID: {bundle_id}")
if device_id and not re.fullmatch(r"[A-Za-z0-9-]{8,128}", device_id):
    raise SystemExit(f"error: invalid QPERIAPT_IOS_DEVICE_ID: {device_id}")
if not re.fullmatch(r"[A-Z0-9]{10}", team_id):
    raise SystemExit(f"error: invalid DEVELOPMENT_TEAM: {team_id}")
if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}", device_label):
    raise SystemExit(f"error: invalid QPERIAPT_DEVICE_LABEL: {device_label}")
if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}", artifact_prefix):
    raise SystemExit(f"error: invalid QPERIAPT_DEVICE_ARTIFACT_PREFIX: {artifact_prefix}")
if expected_device_type and expected_device_type not in ("iPad", "iPhone"):
    raise SystemExit(f"error: invalid QPERIAPT_EXPECT_DEVICE_TYPE: {expected_device_type}")
if not 0 <= min_profile_valid_days <= max_profile_days:
    raise SystemExit(f"error: QPERIAPT_MIN_PROFILE_VALID_DAYS must be between 0 and {max_profile_days}: {min_profile_valid_days}")
if not 0 < max_age_seconds <= max_age_limit:
    raise SystemExit(f"error: QPERIAPT_DEVICE_PROOF_MAX_AGE_SECONDS must be between 1 and {max_age_limit}: {max_age_seconds}")
PY

RUN_ID=$(python3 -c 'import secrets; print(secrets.token_hex(16))')

if [ -z "$DEVICE_ID" ]; then
	DEVICE_ID=$(pick_device)
fi
if [ -z "$DEVICE_ID" ]; then
	printf 'error: no online physical iOS/iPadOS device found; set QPERIAPT_IOS_DEVICE_ID explicitly\n' >&2
	exit 2
fi
python3 - "$DEVICE_ID" <<'PY'
import re
import sys

device_id = sys.argv[1]
if not re.fullmatch(r"[A-Za-z0-9-]{8,128}", device_id):
    raise SystemExit(f"error: invalid resolved iOS device id: {device_id}")
PY
python3 artifact/apple_device_proof.py inspect-device \
	--device-id "$DEVICE_ID" \
	--expected-device-type "$EXPECTED_DEVICE_TYPE" >/dev/null
DEVICE_ID_SHA256_PREFIX=$(python3 - "$DEVICE_ID" <<'PY'
import hashlib
import sys

print(hashlib.sha256(sys.argv[1].encode("utf-8")).hexdigest()[:12])
PY
)

mkdir -p "$RESULT_DIR"

printf 'Q-Periapt Apple device smoke\n'
printf 'repo    : %s\n' "$ROOT"
printf 'label   : %s\n' "$DEVICE_LABEL"
printf 'device  : sha256:%s\n' "$DEVICE_ID_SHA256_PREFIX"
if [ -n "${DEVELOPER_DIR:-}" ]; then
	printf 'devdir  : %s\n' "$DEVELOPER_DIR"
fi
printf 'xcode   : %s\n' "$(xcodebuild -version | tr '\n' ' ')"
printf 'swift   : %s\n' "$(xcrun swift --version | sed -n '1p')"
printf 'rustc   : %s\n' "$(rustc --version)"
printf 'run-id  : %s\n' "$RUN_ID"
printf 'profile : min %s valid days remaining\n' "$MIN_PROFILE_VALID_DAYS"

printf '\n=== macOS native Swift binding ===\n'
cargo build -p q-periapt-ffi --release
xcrun swift test --package-path bindings/swift -Xlinker "-L$ROOT/target/release"

printf '\n=== iOS Rust staticlib ===\n'
cargo build -p q-periapt-ffi --release --target aarch64-apple-ios
test -f "$ROOT/target/aarch64-apple-ios/release/libq_periapt_ffi.a" || {
	printf 'error: missing iOS staticlib\n' >&2
	exit 1
}

printf '\n=== Generate Apple device project ===\n'
(cd "$PROJECT_DIR" && xcodegen generate)

printf '\n=== Build device runner for physical device ===\n'
BUILD_LOG="$RESULT_DIR/$DEVICE_ARTIFACT_PREFIX-build.log"
rm -rf "$DERIVED_DATA"
rm -rf "$RESULT_DIR/$DEVICE_ARTIFACT_PREFIX-build.xcresult"
rm -f "$BUILD_LOG"
set +e
set -- xcodebuild build
if [ "$ALLOW_PROVISIONING_UPDATES" = "1" ]; then
	set -- "$@" -allowProvisioningUpdates
	if [ "$ALLOW_PROVISIONING_DEVICE_REGISTRATION" = "1" ]; then
		set -- "$@" -allowProvisioningDeviceRegistration
	fi
fi
set -- "$@" \
	-project "$PROJECT" \
	-scheme QPeriaptDeviceRunner \
	-destination "platform=iOS,id=$DEVICE_ID" \
	-derivedDataPath "$DERIVED_DATA" \
	-resultBundlePath "$RESULT_DIR/$DEVICE_ARTIFACT_PREFIX-build.xcresult" \
	PRODUCT_BUNDLE_IDENTIFIER="$BUNDLE_ID" \
	CODE_SIGN_STYLE="$CODE_SIGN_STYLE_VALUE"
if [ "${DEVELOPMENT_TEAM+x}" = x ]; then
	set -- "$@" DEVELOPMENT_TEAM="$DEVELOPMENT_TEAM"
	if [ "${QPERIAPT_PROVISIONING_PROFILE_SPECIFIER+x}" = x ]; then
		set -- "$@" PROVISIONING_PROFILE_SPECIFIER="$QPERIAPT_PROVISIONING_PROFILE_SPECIFIER"
	fi
fi
"$@" >"$BUILD_LOG" 2>&1
build_rc=$?
set -e
cat "$BUILD_LOG"
if [ "$build_rc" -ne 0 ]; then
	printf 'error: Xcode device runner build failed (exit=%s); see %s\n' "$build_rc" "$BUILD_LOG" >&2
	exit 1
fi
if grep -Eiq '(^|[^A-Za-z])(warning|error):' "$BUILD_LOG"; then
	printf 'error: Xcode build log contains warning/error diagnostics; see %s\n' "$BUILD_LOG" >&2
	exit 1
fi

test -d "$APP" || {
	printf 'error: built app not found: %s\n' "$APP" >&2
	exit 1
}
ACTUAL_BUNDLE_ID=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$APP/Info.plist")
if [ "$ACTUAL_BUNDLE_ID" != "$BUNDLE_ID" ]; then
	printf 'error: built bundle id mismatch: got %s, expected %s\n' "$ACTUAL_BUNDLE_ID" "$BUNDLE_ID" >&2
	exit 1
fi

PROFILE_PLIST="$RESULT_DIR/$DEVICE_ARTIFACT_PREFIX-embedded-profile.plist"
ENTITLEMENTS_PLIST="$RESULT_DIR/$DEVICE_ARTIFACT_PREFIX-codesign-entitlements.plist"
LINKAGE="$RESULT_DIR/$DEVICE_ARTIFACT_PREFIX-otool-l.txt"
PROOF_JSON="$RESULT_DIR/$DEVICE_ARTIFACT_PREFIX-device-proof.json"
STATICLIB="$ROOT/target/aarch64-apple-ios/release/libq_periapt_ffi.a"
rm -f "$PROFILE_PLIST" "$ENTITLEMENTS_PLIST" "$LINKAGE" "$PROOF_JSON"
security cms -D -i "$APP/embedded.mobileprovision" >"$PROFILE_PLIST"
codesign -d --entitlements :- "$APP" >"$ENTITLEMENTS_PLIST" 2>/dev/null
otool -L "$APP/QPeriaptDeviceRunner" >"$LINKAGE"

printf '\n=== Install device runner ===\n'
xcrun devicectl device uninstall app --device "$DEVICE_ID" "$BUNDLE_ID"
xcrun devicectl device install app --device "$DEVICE_ID" "$APP"

printf '\n=== Launch device runner ===\n'
LOG="$RESULT_DIR/$DEVICE_ARTIFACT_PREFIX-device-launch.log"
DEVICE_RESULT="$RESULT_DIR/$DEVICE_ARTIFACT_PREFIX-device-result.txt"
DEVICE_RESULT_COPY="$RESULT_DIR/$DEVICE_ARTIFACT_PREFIX-device-result-copy.txt"
DEVICE_RESULT_UNIQUE_NAME="qperiapt-device-result-$RUN_ID.txt"
rm -f "$LOG"
rm -f "$DEVICE_RESULT"
rm -f "$DEVICE_RESULT_COPY"
set +e
xcrun devicectl device process launch \
	--device "$DEVICE_ID" \
	--terminate-existing \
	--console \
	--environment-variables "{\"QPERIAPT_DEVICE_RUN_ID\":\"$RUN_ID\"}" \
	"$BUNDLE_ID" >"$LOG" 2>&1
rc=$?
set -e
cat "$LOG"

if [ "$rc" -ne 0 ]; then
	printf 'error: device runner launch failed (exit=%s); see %s\n' "$rc" "$LOG" >&2
	exit 1
fi
if grep -q 'QPERIAPT_DEVICE_FAIL' "$LOG"; then
	printf 'error: device runner emitted failure; see %s\n' "$LOG" >&2
	exit 1
fi

printf '\n=== Fetch device result marker ===\n'
xcrun devicectl device copy from \
	--device "$DEVICE_ID" \
	--domain-type appDataContainer \
	--domain-identifier "$BUNDLE_ID" \
	--source "/Documents/$DEVICE_RESULT_UNIQUE_NAME" \
	--destination "$DEVICE_RESULT_COPY"
test -f "$DEVICE_RESULT_COPY" || {
	printf 'error: run-bound device result marker missing from copied app container: %s\n' "$DEVICE_RESULT_UNIQUE_NAME" >&2
	exit 1
}
cp "$DEVICE_RESULT_COPY" "$DEVICE_RESULT"
cat "$DEVICE_RESULT"

if grep -q 'QPERIAPT_DEVICE_FAIL' "$DEVICE_RESULT"; then
	printf 'error: device result marker is failure; see %s\n' "$DEVICE_RESULT" >&2
	exit 1
fi
PASS_COUNT=$(grep -cx "QPERIAPT_DEVICE_PASS run-id=$RUN_ID" "$DEVICE_RESULT" || true)
if [ "$PASS_COUNT" -ne 1 ]; then
	printf 'error: device result did not contain exactly one run-bound QPERIAPT_DEVICE_PASS; see %s\n' "$DEVICE_RESULT" >&2
	exit 1
fi
if grep -cx 'QPERIAPT_DEVICE_PASS' "$DEVICE_RESULT" >/dev/null 2>&1; then
	printf 'error: device result contains legacy bare QPERIAPT_DEVICE_PASS; see %s\n' "$DEVICE_RESULT" >&2
	exit 1
fi

printf '\n=== Validate device proof metadata ===\n'
python3 artifact/apple_device_proof.py emit \
	--root "$ROOT" \
	--app "$APP" \
	--bundle-id "$BUNDLE_ID" \
	--device-id "$DEVICE_ID" \
	--run-id "$RUN_ID" \
	--device-label "$DEVICE_LABEL" \
	--expected-device-type "$EXPECTED_DEVICE_TYPE" \
	--expected-team "${DEVELOPMENT_TEAM:-}" \
	--min-profile-valid-days "$MIN_PROFILE_VALID_DAYS" \
	--staticlib "$STATICLIB" \
	--build-log "$BUILD_LOG" \
	--launch-log "$LOG" \
	--device-result "$DEVICE_RESULT" \
	--profile-plist "$PROFILE_PLIST" \
	--entitlements-plist "$ENTITLEMENTS_PLIST" \
	--linkage "$LINKAGE" \
	--output "$PROOF_JSON"
if [ "$ALLOW_DIRTY_APPLE_DEVICE" = "1" ]; then
	python3 artifact/apple_device_proof.py verify \
		--root "$ROOT" \
		--proof "$PROOF_JSON" \
		--build-log "$BUILD_LOG" \
		--launch-log "$LOG" \
		--device-result "$DEVICE_RESULT" \
		--max-age-seconds "$DEVICE_PROOF_MAX_AGE_SECONDS" \
		--allow-dirty-proof
else
	python3 artifact/apple_device_proof.py verify \
		--root "$ROOT" \
		--proof "$PROOF_JSON" \
		--build-log "$BUILD_LOG" \
		--launch-log "$LOG" \
		--device-result "$DEVICE_RESULT" \
		--max-age-seconds "$DEVICE_PROOF_MAX_AGE_SECONDS"
fi

printf '\nALL PASS: macOS native + physical iOS/iPadOS device smoke\n'
