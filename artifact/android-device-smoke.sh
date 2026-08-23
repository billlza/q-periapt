#!/bin/sh
# Build, install, and run the Android AAR/JNI smoke on an adb device/emulator.
#
# This is a runtime proof gate, not a package-only gate. It installs a temporary
# debuggable APK that consumes the generated AAR, runs the Android Java facade on
# ART, and accepts only a run-bound PASS marker copied back from the app-private
# files directory.
set -eu
umask 077

unset CDPATH
ROOT=$(cd -- "$(dirname "$0")/.." && pwd) || exit 2
cd "$ROOT" || exit 2
. "$ROOT/artifact/python-env.sh"

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
need javac
need keytool
need python3

# Hold one host/account-scoped open-file-description lock for the whole lane.
# The stable private file serializes every checkout that can reach the same
# account-owned adb/emulator resources. Long-lived children validate and close
# descriptor 9 before exec so a killed shell releases the lane for recovery.
LANE_LOCK_PATH=$(PYTHONPATH=artifact python3 \
	artifact/android_bounded_command.py lane-lock-path)
exec 9<>"$LANE_LOCK_PATH"
if ! python3 - 9 "$LANE_LOCK_PATH" <<'PY'
import fcntl
import os
import stat
import sys

descriptor = int(sys.argv[1])
lock_path = os.path.realpath(sys.argv[2])
metadata = os.fstat(descriptor)
try:
    path_metadata = os.stat(lock_path, follow_symlinks=False)
except OSError as exc:
    raise SystemExit(f"error: cannot inspect Android evidence lane lock: {exc}") from exc
if (
    not stat.S_ISREG(metadata.st_mode)
    or not stat.S_ISREG(path_metadata.st_mode)
    or (metadata.st_dev, metadata.st_ino) != (path_metadata.st_dev, path_metadata.st_ino)
    or metadata.st_uid != os.geteuid()
    or metadata.st_nlink != 1
    or stat.S_IMODE(metadata.st_mode) != 0o600
):
    raise SystemExit("error: Android evidence lane lock identity or permissions changed")
try:
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError as exc:
    raise SystemExit("error: another Android evidence lane is already running") from exc
except OSError as exc:
    raise SystemExit(f"error: cannot acquire Android evidence lane lock: {exc}") from exc
PY
then
	printf 'error: cannot acquire the Android evidence lane lock\n' >&2
	exit 2
fi
PYTHONPATH=artifact python3 artifact/android_bounded_command.py \
	recover-owned-runtime

if [ "${QPERIAPT_ANDROID_DEVICE_SKIP_VERIFY:-0}" = "1" ]; then
	printf 'error: QPERIAPT_ANDROID_DEVICE_SKIP_VERIFY is not supported\n' >&2
	exit 2
fi

ANDROID_RELEASE_MODE=${QPERIAPT_ANDROID_RELEASE_MODE:-0}
ANDROID_RELEASE_BUILD_TOOLS=36.0.0
case "$ANDROID_RELEASE_MODE" in
	0 | 1) ;;
	*)
		printf 'error: QPERIAPT_ANDROID_RELEASE_MODE must be 0 or 1\n' >&2
		exit 2
		;;
esac
ANDROID_BOOT_AVD=${QPERIAPT_ANDROID_BOOT_AVD:-0}
ANDROID_KEEP_EMULATOR=${QPERIAPT_ANDROID_KEEP_EMULATOR:-0}
for boolean_value in "$ANDROID_BOOT_AVD" "$ANDROID_KEEP_EMULATOR"; do
	case "$boolean_value" in
		0 | 1) ;;
		*)
			printf 'error: QPERIAPT_ANDROID_BOOT_AVD and QPERIAPT_ANDROID_KEEP_EMULATOR must be 0 or 1\n' >&2
			exit 2
			;;
	esac
done
if [ "$ANDROID_KEEP_EMULATOR" = "1" ]; then
	printf 'error: QPERIAPT_ANDROID_KEEP_EMULATOR=1 is incompatible with publishable device evidence\n' >&2
	exit 2
fi
EXPECTED_DEVICE_KIND=${QPERIAPT_ANDROID_EXPECT_DEVICE_KIND:-any}
case "$EXPECTED_DEVICE_KIND" in
	any | emulator | physical) ;;
	*)
		printf 'error: QPERIAPT_ANDROID_EXPECT_DEVICE_KIND must be any, emulator, or physical\n' >&2
		exit 2
		;;
esac
if [ "${ANDROID_AVD_HOME+x}" = x ]; then
	printf 'error: ANDROID_AVD_HOME is controlled internally by the Android device evidence lane\n' >&2
	exit 2
fi
ANDROID_AVD_HOME=
if [ "$ANDROID_BOOT_AVD" = "1" ]; then
	if [ -n "${QPERIAPT_ANDROID_SERIAL:-}" ]; then
		printf 'error: QPERIAPT_ANDROID_SERIAL is forbidden when the script owns the proof AVD\n' >&2
		exit 2
	fi
	if [ "$EXPECTED_DEVICE_KIND" != "emulator" ]; then
		printf 'error: a script-owned proof AVD requires QPERIAPT_ANDROID_EXPECT_DEVICE_KIND=emulator\n' >&2
		exit 2
	fi
	if [ "${QPERIAPT_ANDROID_AVD+x}" = x ]; then
		printf 'error: QPERIAPT_ANDROID_AVD is code-selected and must not be supplied\n' >&2
		exit 2
	fi
	ANDROID_AVD_HOME=$(PYTHONPATH=artifact python3 \
		artifact/android_bounded_command.py avd-home-path)
	export ANDROID_AVD_HOME
	ANDROID_EMULATOR_PORT=${QPERIAPT_ANDROID_EMULATOR_PORT:-5584}
	case "$ANDROID_EMULATOR_PORT" in
		[0-9][0-9][0-9][0-9]) ;;
		*)
			printf 'error: QPERIAPT_ANDROID_EMULATOR_PORT must be an even integer from 5554 through 5584\n' >&2
			exit 2
			;;
	esac
	if [ "$ANDROID_EMULATOR_PORT" -lt 5554 ] || [ "$ANDROID_EMULATOR_PORT" -gt 5584 ] || [ $((ANDROID_EMULATOR_PORT % 2)) -ne 0 ]; then
		printf 'error: QPERIAPT_ANDROID_EMULATOR_PORT must be an even integer from 5554 through 5584\n' >&2
		exit 2
	fi
	EXPECTED_COMMAND_SERIAL="emulator-$ANDROID_EMULATOR_PORT"
else
	if [ -z "${QPERIAPT_ANDROID_SERIAL:-}" ]; then
		printf 'error: QPERIAPT_ANDROID_SERIAL is required for a physical Android device run\n' >&2
		exit 2
	fi
	if [ "$EXPECTED_DEVICE_KIND" != "physical" ]; then
		printf 'error: an external Android device requires QPERIAPT_ANDROID_EXPECT_DEVICE_KIND=physical\n' >&2
		exit 2
	fi
	case "$QPERIAPT_ANDROID_SERIAL" in
		*[!A-Za-z0-9._:-]*)
			printf 'error: QPERIAPT_ANDROID_SERIAL contains unsupported characters\n' >&2
			exit 2
			;;
	esac
	if [ "${#QPERIAPT_ANDROID_SERIAL}" -gt 128 ]; then
		printf 'error: QPERIAPT_ANDROID_SERIAL exceeds 128 characters\n' >&2
		exit 2
	fi
	EXPECTED_COMMAND_SERIAL=$QPERIAPT_ANDROID_SERIAL
fi
EXPECTED_DEVICE_ABI=${QPERIAPT_ANDROID_EXPECT_ABI:-}
case "$EXPECTED_DEVICE_ABI" in
	"" | arm64-v8a | x86_64 | armeabi-v7a | x86) ;;
	*)
		printf 'error: invalid QPERIAPT_ANDROID_EXPECT_ABI: %s\n' "$EXPECTED_DEVICE_ABI" >&2
		exit 2
		;;
esac
EXPECTED_PAGE_SIZE=${QPERIAPT_ANDROID_EXPECT_PAGE_SIZE:-}
case "$EXPECTED_PAGE_SIZE" in
	"" | 4096 | 16384) ;;
	*)
		printf 'error: QPERIAPT_ANDROID_EXPECT_PAGE_SIZE must be 4096 or 16384\n' >&2
		exit 2
		;;
esac
EXPECTED_DEVICE_SDK=${QPERIAPT_ANDROID_EXPECT_SDK:-}
case "$EXPECTED_DEVICE_SDK" in
	"" | [1-9] | [1-9][0-9] | [1-9][0-9][0-9]) ;;
	*)
		printf 'error: QPERIAPT_ANDROID_EXPECT_SDK must be a canonical integer between 1 and 999\n' >&2
		exit 2
		;;
esac
if [ "$ANDROID_RELEASE_MODE" = "1" ]; then
	if [ -z "$EXPECTED_DEVICE_ABI" ]; then
		printf 'error: Android release mode requires an explicit QPERIAPT_ANDROID_EXPECT_ABI\n' >&2
		exit 2
	fi
	if [ "${QPERIAPT_ALLOW_DIRTY_ANDROID_DEVICE:-0}" = "1" ]; then
		printf 'error: Android release mode cannot allow a dirty source tree\n' >&2
		exit 2
	fi
	# The canonical release profile pins the emulator's exact device shape;
	# a physical release capture keeps the collection discipline while the
	# hardware supplies its own page size and SDK.
	case "$EXPECTED_DEVICE_KIND" in
		emulator)
			if [ "$EXPECTED_PAGE_SIZE" != "16384" ]; then
				printf 'error: Android release emulator proof requires QPERIAPT_ANDROID_EXPECT_PAGE_SIZE=16384\n' >&2
				exit 2
			fi
			if [ "$EXPECTED_DEVICE_SDK" != "35" ]; then
				printf 'error: Android release emulator proof requires QPERIAPT_ANDROID_EXPECT_SDK=35\n' >&2
				exit 2
			fi
			if [ "$ANDROID_BOOT_AVD" != "1" ]; then
				printf 'error: Android release emulator proof requires QPERIAPT_ANDROID_BOOT_AVD=1\n' >&2
				exit 2
			fi
			;;
		physical)
			if [ "$ANDROID_BOOT_AVD" != "0" ]; then
				printf 'error: Android release physical-device proof cannot boot an AVD\n' >&2
				exit 2
			fi
			;;
		any)
			printf 'error: Android release mode requires an explicit QPERIAPT_ANDROID_EXPECT_DEVICE_KIND\n' >&2
			exit 2
			;;
	esac
fi

if [ "${QPERIAPT_ALLOW_DIRTY_ANDROID_DEVICE:-0}" != "1" ]; then
	SOURCE_TREE_DIRTY=$(PYTHONPATH=artifact python3 - "$ROOT" <<'PY'
import pathlib
import sys

from git_provenance import source_tree_dirty

print(int(source_tree_dirty(pathlib.Path(sys.argv[1]))))
PY
)
	if [ "$SOURCE_TREE_DIRTY" = "1" ]; then
		printf 'error: Android device runtime gate requires a clean worktree; set QPERIAPT_ALLOW_DIRTY_ANDROID_DEVICE=1 only for local diagnostics\n' >&2
		exit 2
	fi
fi

ANDROID_SDK=${QPERIAPT_ANDROID_SDK_ROOT:-${ANDROID_HOME:-${ANDROID_SDK_ROOT:-"$HOME/Library/Android/sdk"}}}
if [ ! -d "$ANDROID_SDK" ]; then
	printf 'error: Android SDK not found; set QPERIAPT_ANDROID_SDK_ROOT or ANDROID_HOME\n' >&2
	exit 2
fi

ANDROID_PLATFORM=${QPERIAPT_ANDROID_PLATFORM:-"$ANDROID_SDK/platforms/android-35"}
ANDROID_JAR="$ANDROID_PLATFORM/android.jar"
if [ ! -f "$ANDROID_JAR" ]; then
	printf 'error: Android platform is missing android.jar: %s\n' "$ANDROID_PLATFORM" >&2
	exit 2
fi

EXPECTED_RELEASE_BUILD_TOOLS="$ANDROID_SDK/build-tools/$ANDROID_RELEASE_BUILD_TOOLS"
ANDROID_BUILD_TOOLS=${QPERIAPT_ANDROID_BUILD_TOOLS:-"$ANDROID_SDK/build-tools/36.0.0"}
if [ "$ANDROID_RELEASE_MODE" = "1" ] && [ "$ANDROID_BUILD_TOOLS" != "$EXPECTED_RELEASE_BUILD_TOOLS" ]; then
	printf 'error: Android release mode requires build-tools %s at %s\n' "$ANDROID_RELEASE_BUILD_TOOLS" "$EXPECTED_RELEASE_BUILD_TOOLS" >&2
	exit 2
fi
AAPT2="$ANDROID_BUILD_TOOLS/aapt2"
APKSIGNER="$ANDROID_BUILD_TOOLS/apksigner"
D8="$ANDROID_BUILD_TOOLS/d8"
ZIPALIGN="$ANDROID_BUILD_TOOLS/zipalign"
for tool in "$AAPT2" "$APKSIGNER" "$D8" "$ZIPALIGN"; do
	if [ ! -x "$tool" ]; then
		printf 'error: required Android build-tool not executable: %s\n' "$tool" >&2
		exit 2
	fi
done

ANDROID_NDK=${QPERIAPT_ANDROID_NDK_HOME:-${ANDROID_NDK_HOME:-"$ANDROID_SDK/ndk/29.0.14206865"}}
if [ ! -d "$ANDROID_NDK" ]; then
	printf 'error: Android NDK r29 not found: %s\n' "$ANDROID_NDK" >&2
	exit 2
fi
NDK_REVISION=$(PYTHONPATH=artifact python3 artifact/android_elf.py verify-ndk --ndk "$ANDROID_NDK")
TOOLCHAIN=$(PYTHONPATH=artifact python3 artifact/android_elf.py find-toolchain --ndk "$ANDROID_NDK")
LLVM_NM="$TOOLCHAIN/bin/llvm-nm"
LLVM_READELF="$TOOLCHAIN/bin/llvm-readelf"
for tool in "$LLVM_NM" "$LLVM_READELF"; do
	if [ ! -x "$tool" ]; then
		printf 'error: required NDK r29 LLVM verifier not executable: %s\n' "$tool" >&2
		exit 2
	fi
done

if [ "${QPERIAPT_ADB+x}" = x ]; then
	printf 'error: QPERIAPT_ADB is not supported; select a fixed QPERIAPT_ANDROID_ADB_PROFILE\n' >&2
	exit 2
fi
ADB_PROFILE=${QPERIAPT_ANDROID_ADB_PROFILE:-auto}
if [ "$ANDROID_BOOT_AVD" = "1" ] && [ "$ADB_PROFILE" = "auto" ]; then
	printf 'error: a script-owned proof AVD requires an explicit fixed QPERIAPT_ANDROID_ADB_PROFILE\n' >&2
	exit 2
fi
ADB=$(PYTHONPATH=artifact python3 artifact/android_bounded_command.py adb-path \
	--adb-profile "$ADB_PROFILE")
if [ "$ADB" != "$ANDROID_SDK/platform-tools/adb" ]; then
	printf 'error: fixed adb profile differs from the selected Android SDK: %s != %s\n' \
		"$ADB" "$ANDROID_SDK/platform-tools/adb" >&2
	exit 2
fi
EMULATOR=${QPERIAPT_EMULATOR:-"$ANDROID_SDK/emulator/emulator"}
if [ "$ANDROID_RELEASE_MODE" = "1" ] && [ "${QPERIAPT_EMULATOR+x}" = x ]; then
	printf 'error: Android release mode does not allow an emulator executable override\n' >&2
	exit 2
fi
if [ ! -x "$ADB" ]; then
	printf 'error: adb not found: %s\n' "$ADB" >&2
	exit 2
fi
EMULATOR_BACKEND=
EMULATOR_BACKEND_DEVICE=
EMULATOR_BACKEND_INODE=
EMULATOR_BACKEND_SHA256=
if [ "$ANDROID_BOOT_AVD" = "1" ]; then
	if [ -z "$EXPECTED_DEVICE_ABI" ]; then
		printf 'error: a script-owned proof AVD requires an explicit QPERIAPT_ANDROID_EXPECT_ABI\n' >&2
		exit 2
	fi
	EMULATOR_BACKEND=$(python3 artifact/android_device_proof.py emulator-backend-path \
		--emulator "$EMULATOR" \
		--device-abi "$EXPECTED_DEVICE_ABI")
fi
if [ "${ADB_VENDOR_KEYS+x}" = x ]; then
	printf 'error: ADB_VENDOR_KEYS is not supported by the Android device evidence lane\n' >&2
	exit 2
fi
if [ "${ADB_SERVER_SOCKET+x}" = x ]; then
	printf 'error: ADB_SERVER_SOCKET is not supported by the Android device evidence lane\n' >&2
	exit 2
fi
if [ "${ANDROID_ADB_SERVER_ADDRESS+x}" = x ]; then
	printf 'error: ANDROID_ADB_SERVER_ADDRESS is not supported by the Android device evidence lane\n' >&2
	exit 2
fi
if [ "${ANDROID_ADB_SERVER_PORT+x}" = x ]; then
	printf 'error: ANDROID_ADB_SERVER_PORT is not supported by the Android device evidence lane\n' >&2
	exit 2
fi
if [ "${ADB_MDNS+x}" = x ]; then
	printf 'error: ADB_MDNS is controlled internally by the Android device evidence lane\n' >&2
	exit 2
fi
if [ "${ADB_MDNS_AUTO_CONNECT+x}" = x ]; then
	printf 'error: ADB_MDNS_AUTO_CONNECT is not supported by the Android device evidence lane\n' >&2
	exit 2
fi
if [ "${ADB_MDNS_OPENSCREEN+x}" = x ]; then
	printf 'error: ADB_MDNS_OPENSCREEN is not supported by the Android device evidence lane\n' >&2
	exit 2
fi
if [ "${ADB_USB+x}" = x ]; then
	printf 'error: ADB_USB is controlled internally by the Android device evidence lane\n' >&2
	exit 2
fi
if [ "${ADB_EMU+x}" = x ]; then
	printf 'error: ADB_EMU is controlled internally by the Android device evidence lane\n' >&2
	exit 2
fi
if [ "${ADB_REJECT_KILL_SERVER+x}" = x ]; then
	printf 'error: ADB_REJECT_KILL_SERVER is not supported by the Android device evidence lane\n' >&2
	exit 2
fi
if [ "${ADB_LOCAL_TRANSPORT_MAX_PORT+x}" = x ]; then
	printf 'error: ADB_LOCAL_TRANSPORT_MAX_PORT is controlled internally by the Android device evidence lane\n' >&2
	exit 2
fi
if [ "${ADB_OSX_USB_CLEAR_ENDPOINTS+x}" = x ]; then
	printf 'error: ADB_OSX_USB_CLEAR_ENDPOINTS is not supported by the Android device evidence lane\n' >&2
	exit 2
fi
if [ "${ANDROID_ADB_LOG_PATH+x}" = x ]; then
	printf 'error: ANDROID_ADB_LOG_PATH is not supported by the Android device evidence lane\n' >&2
	exit 2
fi
if [ "${ADB_TRACE+x}" = x ]; then
	printf 'error: ADB_TRACE is not supported by the Android device evidence lane\n' >&2
	exit 2
fi
if [ "${ADB_INSTALL_DEFAULT_INCREMENTAL+x}" = x ]; then
	printf 'error: ADB_INSTALL_DEFAULT_INCREMENTAL is not supported by the Android device evidence lane\n' >&2
	exit 2
fi
if [ "${ADB_LIBUSB+x}" = x ]; then
	printf 'error: ADB_LIBUSB is not supported by the Android device evidence lane\n' >&2
	exit 2
fi
if [ "${ADB_LIBUSB_START_DETACHED+x}" = x ]; then
	printf 'error: ADB_LIBUSB_START_DETACHED is not supported by the Android device evidence lane\n' >&2
	exit 2
fi
python3 artifact/android_device_proof.py verify-adb-identity \
	--home-directory "$HOME"
if [ "$ANDROID_BOOT_AVD" = "1" ]; then
	ANDROID_AVD_NAME=$(PYTHONPATH=artifact python3 \
		artifact/android_bounded_command.py runtime-avd-name \
		--adb-profile "$ADB_PROFILE" \
		--device-abi "$EXPECTED_DEVICE_ABI")
	python3 artifact/android_device_proof.py verify-avd-home \
		--avd-home "$ANDROID_AVD_HOME" \
		--adb-profile "$ADB_PROFILE" \
		--device-abi "$EXPECTED_DEVICE_ABI" >/dev/null
fi

android_command() {
	operation=$1
	shift
	PYTHONPATH=artifact python3 artifact/android_bounded_command.py invoke \
		"$operation" --run-id "$RUN_ID" "$@"
}

monotonic_seconds() {
	python3 - <<'PY'
import time

print(time.monotonic_ns() // 1_000_000_000)
PY
}

monotonic_deadline() {
	duration_seconds=$1
	now_seconds=$(monotonic_seconds) || return 1
	printf '%s\n' "$((now_seconds + duration_seconds))"
}

remaining_bounded_timeout() {
	deadline_seconds=$1
	maximum_seconds=$2
	now_seconds=$(monotonic_seconds) || return 1
	remaining_seconds=$((deadline_seconds - now_seconds))
	if [ "$remaining_seconds" -le 0 ]; then
		return 1
	fi
	if [ "$remaining_seconds" -gt "$maximum_seconds" ]; then
		remaining_seconds=$maximum_seconds
	fi
	printf '%s\n' "$remaining_seconds"
}

assert_default_adb_server_absent() {
	python3 artifact/android_device_proof.py assert-default-adb-server-absent >/dev/null
}

private_adb_process_active() {
	if [ -z "${ADB_PRIVATE_SERVER_PID:-}" ] || ! kill -0 "$ADB_PRIVATE_SERVER_PID" 2>/dev/null; then
		return 1
	fi
	if private_adb_process_state=$(/bin/ps -o stat= -p "$ADB_PRIVATE_SERVER_PID" 2>/dev/null); then
		case "$private_adb_process_state" in
			"" | *Z*) return 1 ;;
		esac
	fi
	return 0
}

wait_for_private_adb_exit() {
	wait_duration_seconds=$1
	private_adb_cleanup_deadline=$(monotonic_deadline "$wait_duration_seconds") || return 1
	while private_adb_process_active; do
		remaining_bounded_timeout "$private_adb_cleanup_deadline" 1 >/dev/null || break
		sleep 0.2
	done
	! private_adb_process_active
}

stop_private_adb_server() {
	if [ "${ADB_PRIVATE_SERVER_CLEANUP_ARMED:-0}" != "1" ]; then
		return 0
	fi
	if [ -z "${ADB_PRIVATE_SERVER_DIRECTORY:-}" ] || \
		[ -z "${ADB_PRIVATE_SERVER_SOCKET_PATH:-}" ] || \
		[ -z "${ADB_PRIVATE_SERVER_SOCKET_SPEC:-}" ]; then
		printf 'error: private adb server cleanup lacks its directory capability\n' >&2
		return 1
	fi
	if [ "${ANDROID_RUNTIME_RECOVERY_ARMED:-0}" != "1" ]; then
		if [ -n "${ADB_PRIVATE_SERVER_PID:-}" ] || \
			[ -e "$ADB_PRIVATE_SERVER_SOCKET_PATH" ] || \
			[ -L "$ADB_PRIVATE_SERVER_SOCKET_PATH" ]; then
			printf 'error: pre-receipt private adb cleanup found unexpected live state\n' >&2
			return 1
		fi
		if ! python3 - "$ADB_PRIVATE_SERVER_DIRECTORY" <<'PY'
import os
import pathlib
import stat
import sys

directory = pathlib.Path(sys.argv[1])
metadata = directory.lstat()
if (
    not stat.S_ISDIR(metadata.st_mode)
    or directory.is_symlink()
    or metadata.st_uid != os.geteuid()
    or stat.S_IMODE(metadata.st_mode) != 0o700
    or any(directory.iterdir())
):
    raise SystemExit("pre-receipt private adb directory is not exact and empty")
directory.rmdir()
PY
		then
			printf 'error: cannot remove the exact pre-receipt private adb directory\n' >&2
			return 1
		fi
		ADB_PRIVATE_SERVER_CLEANUP_ARMED=0
		return 0
	fi
	if ! PYTHONPATH=artifact python3 artifact/android_bounded_command.py \
		request-owned-adb-stop --run-id "$RUN_ID"; then
		printf 'error: receipt-bound private adb server cleanup failed\n' >&2
		return 1
	fi
	ADB_PROTOCOL_STOP_REQUESTED=1
	if [ -n "${ADB_PRIVATE_SERVER_PID:-}" ]; then
		if ! wait_for_private_adb_exit 15; then
			printf 'error: owned adb server did not stop after its protocol request\n' >&2
			return 1
		fi
		set +e
		wait "$ADB_PRIVATE_SERVER_PID" >/dev/null 2>&1
		private_adb_wait_status=$?
		set -e
		if [ "$private_adb_wait_status" -ne 0 ]; then
			printf 'error: owned adb server exited unexpectedly with status %s\n' \
				"$private_adb_wait_status" >&2
			return 1
		fi
		ADB_PRIVATE_SERVER_PID=
	fi
	if ! PYTHONPATH=artifact python3 artifact/android_bounded_command.py \
		finalize-owned-adb-stop --run-id "$RUN_ID"; then
		printf 'error: receipt-bound private adb server finalization failed\n' >&2
		return 1
	fi
	ADB_PRIVATE_SERVER_CLEANUP_ARMED=0
	return 0
}

cleanup_android_command_capability() {
	if [ "${ANDROID_COMMAND_CAPABILITY_ARMED:-0}" != "1" ]; then
		return 0
	fi
	if ! PYTHONPATH=artifact python3 artifact/android_bounded_command.py destroy-capability \
		--run-id "$RUN_ID" \
		--missing-ok; then
		printf 'error: failed to remove the private Android command capability\n' >&2
		return 1
	fi
	ANDROID_COMMAND_CAPABILITY_ARMED=0
	return 0
}

RUN_ID=$(python3 - <<'PY'
import secrets
print(secrets.token_hex(16))
PY
)
OUT_ROOT="$ROOT/target/qperiapt-android-device-smoke-runs/$RUN_ID"
WORK="$OUT_ROOT/work"
DIST="$OUT_ROOT/proof"
PACKAGE_OBSERVATION_LOG="$DIST/adb-package-state-observation.log"
PACKAGE="dev.qperiapt.androidsmoke"
RESULT_TXT="$DIST/qperiapt-android-device-result.txt"
RESULT_JSON="$DIST/qperiapt-android-device-result.json"
PROOF_JSON="$DIST/qperiapt-android-device-proof.json"
PROOF_STAGING="$WORK/qperiapt-android-device-proof.json.pending"
EVIDENCE_BUNDLE="$DIST/qperiapt-android-runtime-evidence-v2.zip"
installed_apk="$WORK/installed-smoke-base.apk"
SOURCE_TREE_SHA256=$(python3 - "$ROOT" <<'PY'
import pathlib
import sys

from artifact.claim_ledger import canonical_tree_digest, repository_paths

root = pathlib.Path(sys.argv[1]).resolve()
print(canonical_tree_digest(root, repository_paths(root)))
PY
)

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
if [ "$VERSION" != "0.1.3" ]; then
	printf 'error: Android ABI2 device-smoke version mismatch: got %s, expected 0.1.3\n' "$VERSION" >&2
	exit 1
fi

EXISTING_AAR=${QPERIAPT_ANDROID_EXISTING_AAR:-}
EXISTING_AAR_MANIFEST=${QPERIAPT_ANDROID_EXISTING_AAR_MANIFEST:-}
EXPECTED_AAR_SHA256=${QPERIAPT_ANDROID_EXPECTED_AAR_SHA256:-}
EXPECTED_AAR_MANIFEST_SHA256=${QPERIAPT_ANDROID_EXPECTED_AAR_MANIFEST_SHA256:-}
USE_EXISTING_AAR=0
if [ -n "$EXISTING_AAR" ] || [ -n "$EXISTING_AAR_MANIFEST" ] || [ -n "$EXPECTED_AAR_SHA256" ] || [ -n "$EXPECTED_AAR_MANIFEST_SHA256" ]; then
	if [ -z "$EXISTING_AAR" ] || [ -z "$EXISTING_AAR_MANIFEST" ] || [ -z "$EXPECTED_AAR_SHA256" ] || [ -z "$EXPECTED_AAR_MANIFEST_SHA256" ]; then
		printf 'error: existing-AAR mode requires QPERIAPT_ANDROID_EXISTING_AAR, QPERIAPT_ANDROID_EXISTING_AAR_MANIFEST, QPERIAPT_ANDROID_EXPECTED_AAR_SHA256, and QPERIAPT_ANDROID_EXPECTED_AAR_MANIFEST_SHA256 together\n' >&2
		exit 2
	fi
	USE_EXISTING_AAR=1
	AAR_PATH=$EXISTING_AAR
	AAR_MANIFEST=$EXISTING_AAR_MANIFEST
	require_under_target "$AAR_PATH" "QPERIAPT_ANDROID_EXISTING_AAR"
	require_under_target "$AAR_MANIFEST" "QPERIAPT_ANDROID_EXISTING_AAR_MANIFEST"
else
	if [ "$ANDROID_RELEASE_MODE" = "1" ]; then
		printf 'error: Android release mode requires an explicit hash-bound existing AAR and manifest; rebuilding or fallback is forbidden\n' >&2
		exit 2
	fi
	if [ "${QPERIAPT_ALLOW_DIRTY_ANDROID_DEVICE:-0}" = "1" ]; then
		QPERIAPT_ALLOW_DIRTY_ANDROID_AAR=1 sh artifact/android-aar.sh
	else
		sh artifact/android-aar.sh
	fi
	AAR_DIST="$ROOT/target/qperiapt-android-aar/q-periapt-android-$VERSION"
	AAR_PATH="$AAR_DIST/q-periapt-android-$VERSION.aar"
	AAR_MANIFEST="$AAR_DIST/MANIFEST.json"
fi

python3 - "$OUT_ROOT" "$AAR_PATH" "$AAR_MANIFEST" <<'PY'
import pathlib
import sys

output = pathlib.Path(sys.argv[1]).resolve()
for raw_path in sys.argv[2:]:
    path = pathlib.Path(raw_path).resolve()
    try:
        path.relative_to(output)
    except ValueError:
        continue
    raise SystemExit(f"error: selected AAR input must not be inside the removable device-smoke output: {path}")
PY

created_out_root=$(PYTHONPATH=artifact python3 artifact/android_bounded_command.py \
	create-run --run-id "$RUN_ID")
if [ "$created_out_root" != "$OUT_ROOT" ]; then
	printf 'error: created Android run root differs from this run identity: %s\n' \
		"$created_out_root" >&2
	exit 2
fi
safe_unzip_dir="$WORK/aar"

set -- --manifest "$AAR_MANIFEST"
if [ "$USE_EXISTING_AAR" = "1" ]; then
	set -- "$@" \
		--expected-aar-sha256 "$EXPECTED_AAR_SHA256" \
		--expected-manifest-sha256 "$EXPECTED_AAR_MANIFEST_SHA256"
fi
if [ "$ANDROID_RELEASE_MODE" = "1" ]; then
	set -- "$@" --require-release-manifest
fi
PYTHONPATH=artifact python3 artifact/android_elf.py verify-aar \
	--aar "$AAR_PATH" \
	--llvm-nm "$LLVM_NM" \
	--llvm-readelf "$LLVM_READELF" \
	--forbid-text "$ROOT" \
	--source-root "$ROOT" \
	--extract-to "$safe_unzip_dir" \
	"$@"

printf 'Q-Periapt Android device runtime smoke\n'
printf 'run-id   : %s\n' "$RUN_ID"
printf 'aar      : %s\n' "$AAR_PATH"
printf 'manifest : %s\n' "$AAR_MANIFEST"
printf 'ndk-rev  : %s\n' "$NDK_REVISION"
printf 'release  : %s\n' "$ANDROID_RELEASE_MODE"
printf 'out      : %s\n' "$DIST"
printf 'platform : %s\n' "$ANDROID_PLATFORM"
printf 'buildtools: %s\n' "$ANDROID_BUILD_TOOLS"

test -f "$safe_unzip_dir/classes.jar" || {
	printf 'error: AAR missing classes.jar\n' >&2
	exit 1
}

SRC="$WORK/src"
CLASSES="$WORK/classes"
DEX="$WORK/dex"
APK_ROOT="$WORK/apk-root"
ASSETS="$WORK/assets"
mkdir -p "$SRC/dev/qperiapt/androidsmoke" "$CLASSES" "$DEX" "$APK_ROOT/lib" "$ASSETS"
cp bindings/signed-policy-vectors.json "$ASSETS/signed-policy-vectors.json"
for abi_dir in "$safe_unzip_dir"/jni/*; do
	[ -d "$abi_dir" ] || continue
	abi=$(basename "$abi_dir")
	mkdir -p "$APK_ROOT/lib/$abi"
	cp "$abi_dir"/*.so "$APK_ROOT/lib/$abi/"
done

cat >"$WORK/AndroidManifest.xml" <<'EOF'
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="dev.qperiapt.androidsmoke">
    <uses-sdk android:minSdkVersion="23" />
    <application
        android:debuggable="true"
        android:extractNativeLibs="true"
        android:label="QPeriaptSmoke"
        android:theme="@android:style/Theme.NoDisplay">
        <activity
            android:name=".QPeriaptSmokeActivity"
            android:exported="true" />
    </application>
</manifest>
EOF

cat >"$SRC/dev/qperiapt/androidsmoke/QPeriaptSmokeActivity.java" <<'EOF'
package dev.qperiapt.androidsmoke;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import dev.qperiapt.android.QPeriaptAndroid;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.json.JSONObject;

public final class QPeriaptSmokeActivity extends Activity {
    private static final String TAG = "QPeriaptSmoke";
    private static final String RESULT_TXT = "qperiapt-android-device-result.txt";
    private static final String RESULT_JSON = "qperiapt-android-device-result.json";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        String runId = getIntent().getStringExtra("qperiapt_run_id");
        if (runId == null || !runId.matches("[0-9a-f]{32}")) {
            runId = "invalid-run-id";
        }
        List<String> passed = new ArrayList<String>();
        try {
            runtimeMetadataMatches(passed);
            signedPolicyDecisionIsExactAndFailClosed(passed);
            osRandomPolicyRoundtripAndWipes(passed);
            writeResult(runId, true, passed, null);
            Log.i(TAG, "QPERIAPT_ANDROID_DEVICE_PASS run-id=" + runId + " tests=" + passed.size());
        } catch (Throwable t) {
            try {
                writeResult(runId, false, passed, t);
            } catch (Throwable ignored) {
                Log.e(TAG, "failed to write result", ignored);
            }
            Log.e(TAG, "QPERIAPT_ANDROID_DEVICE_FAIL run-id=" + runId, t);
        } finally {
            finish();
        }
    }

    private void runtimeMetadataMatches(List<String> passed) {
        expect(QPeriaptAndroid.runtimeAbiVersion() == QPeriaptAndroid.ABI_VERSION, "ABI mismatch");
        expect("0.1.3".equals(QPeriaptAndroid.runtimeVersion()), "version mismatch");
        assertBytes("ML-KEM-768+X25519".getBytes(StandardCharsets.UTF_8), QPeriaptAndroid.fixedSuiteId(), "suite id");
        expect(QPeriaptAndroid.fixedSuiteIdLen() == "ML-KEM-768+X25519".length(), "suite len");
        expect(QPeriaptAndroid.MAX_SIGNED_POLICY_BYTES == 65536, "signed policy limit");
        expect(QPeriaptAndroid.MAX_APPLICATION_CONTEXT_BYTES == 65536, "application context limit");
        expect("ERR_POLICY".equals(QPeriaptAndroid.statusName(-3)), "status -3");
        expect("UNKNOWN_STATUS".equals(QPeriaptAndroid.statusName(12345)), "unknown status");
        passed.add("runtimeMetadataMatches");
    }

    private void signedPolicyDecisionIsExactAndFailClosed(List<String> passed) throws Exception {
        String json = asset("signed-policy-vectors.json");
        byte[] policyToml = stringField(json, "policy_toml").getBytes(StandardCharsets.UTF_8);
        byte[] signature = hex(field(json, "signature"));
        byte[] verificationKey = hex(field(json, "verification_key"));
        byte expected = (byte) intField(json, "selected_profile_code");
        QPeriaptAndroid.PolicyDecision decision = QPeriaptAndroid.decisionFromSignedPolicy(
                policyToml,
                signature,
                verificationKey
        );
        expect(decision.profile() == expected, "signed policy selected profile mismatch");
        expect(decision.suiteCode() == QPeriaptAndroid.SUITE_MLKEM768_X25519,
                "signed policy selected suite mismatch");
        expect(decision.policyVersion() == intField(json, "policy_version"),
                "signed policy selected version mismatch");
        assertBytes(hex(field(json, "policy_digest")), decision.policyDigest(),
                "exact signed policy digest");
        QPeriaptAndroid.PolicyDecision reapplied = QPeriaptAndroid.decisionFromSignedPolicy(
                policyToml,
                signature,
                verificationKey,
                decision.trustedState()
        );
        assertBytes(decision.policyDigest(), reapplied.policyDigest(), "reapplied policy digest");
        try {
            QPeriaptAndroid.decisionFromSignedPolicy(
                    policyToml, signature, verificationKey, new byte[] {0, 0, 0, 2});
            throw new AssertionError("legacy ABI1 version-only state was accepted");
        } catch (IllegalArgumentException expectedLegacyStateFailure) {
            // ABI1 has no exact policy digest and therefore cannot be migrated automatically.
        }
        try {
            QPeriaptAndroid.decisionFromSignedPolicy(
                    new byte[QPeriaptAndroid.MAX_SIGNED_POLICY_BYTES], signature, verificationKey);
            throw new AssertionError("maximum-size invalid policy unexpectedly verified");
        } catch (QPeriaptAndroid.QPeriaptException expectedPolicyFailure) {
            // The exact boundary reached native verification rather than the facade size guard.
        }
        try {
            QPeriaptAndroid.decisionFromSignedPolicy(
                    new byte[QPeriaptAndroid.MAX_SIGNED_POLICY_BYTES + 1], signature, verificationKey);
            throw new AssertionError("oversized policy reached native verification");
        } catch (IllegalArgumentException expectedSizeFailure) {
            // The Java facade rejects before JNI copies the policy.
        }
        byte[] newerState = decision.trustedState();
        newerState[0] = 0;
        newerState[1] = 0;
        newerState[2] = 0;
        newerState[3] = (byte) intField(json, "last_trusted_version_reject");
        try {
            QPeriaptAndroid.decisionFromSignedPolicy(
                    policyToml,
                    signature,
                    verificationKey,
                    newerState
            );
            throw new AssertionError("rollback policy was accepted");
        } catch (QPeriaptAndroid.QPeriaptException err) {
            expect(err.code() == -3, "rollback rc=" + err.code());
        }
        byte[] tampered = signature.clone();
        int tamperByte = (int) intField(json, "tamper_signature_byte");
        tampered[tamperByte] = (byte) (tampered[tamperByte] ^ 1);
        try {
            QPeriaptAndroid.decisionFromSignedPolicy(policyToml, tampered, verificationKey);
            throw new AssertionError("tampered policy signature was accepted");
        } catch (QPeriaptAndroid.QPeriaptException err) {
            expect(err.code() == -3, "tamper rc=" + err.code());
        }
        passed.add("signedPolicyDecisionIsExactAndFailClosed");
    }

    private void osRandomPolicyRoundtripAndWipes(List<String> passed) throws Exception {
        String json = asset("signed-policy-vectors.json");
        QPeriaptAndroid.PolicyDecision decision = QPeriaptAndroid.decisionFromSignedPolicy(
                stringField(json, "policy_toml").getBytes(StandardCharsets.UTF_8),
                hex(field(json, "signature")),
                hex(field(json, "verification_key")));
        byte[] applicationContext = "android-device-policy-context".getBytes(StandardCharsets.UTF_8);

        QPeriaptAndroid.KeyPairResult keys = QPeriaptAndroid.generateKeypair(decision);
        try (keys) {
            byte[] skPq = keys.skPq();
            byte[] skTrad = keys.skTrad();
            byte[] encapsulatedSecret = null;
            byte[] decapsulatedSecret = null;
            byte[] wrongContextSecret = null;
            try {
                try (QPeriaptAndroid.EncapsulationResult maximumContext =
                                QPeriaptAndroid.encapsulate(
                                        decision,
                                        keys.pkPq(),
                                        keys.pkTrad(),
                                        fill(QPeriaptAndroid.MAX_APPLICATION_CONTEXT_BYTES, 1))) {
                    byte[] maximumSecret = maximumContext.takeSecret();
                    QPeriaptAndroid.wipe(maximumSecret);
                    assertWiped(maximumSecret, "maximum application-context secret");
                }
                try {
                    QPeriaptAndroid.encapsulate(
                            decision,
                            keys.pkPq(),
                            keys.pkTrad(),
                            new byte[QPeriaptAndroid.MAX_APPLICATION_CONTEXT_BYTES + 1]);
                    throw new AssertionError("oversized application context reached JNI");
                } catch (IllegalArgumentException expectedSizeFailure) {
                    // The Java facade rejects before JNI copies the context.
                }
                try (QPeriaptAndroid.EncapsulationResult encapsulation =
                                QPeriaptAndroid.encapsulate(
                                        decision, keys.pkPq(), keys.pkTrad(), applicationContext)) {
                    encapsulatedSecret = encapsulation.takeSecret();
                    try {
                        encapsulation.secret();
                        throw new AssertionError("transferred encapsulation secret remained readable");
                    } catch (IllegalStateException expectedClosedResult) {
                        // takeSecret transfers the sole binding-owned secret and closes the result.
                    }
                    decapsulatedSecret = QPeriaptAndroid.decapsulate(
                            decision,
                            skPq,
                            encapsulation.ctPq(),
                            keys.pkPq(),
                            skTrad,
                            encapsulation.ctTrad(),
                            keys.pkTrad(),
                            applicationContext);
                    assertBytes(encapsulatedSecret, decapsulatedSecret,
                            "OS-random policy-bound roundtrip");
                    wrongContextSecret = QPeriaptAndroid.decapsulate(
                            decision,
                            skPq,
                            encapsulation.ctPq(),
                            keys.pkPq(),
                            skTrad,
                            encapsulation.ctTrad(),
                            keys.pkTrad(),
                            "wrong-context".getBytes(StandardCharsets.UTF_8));
                    expect(!bytesEqual(decapsulatedSecret, wrongContextSecret),
                            "application context was not committed");
                }
            } finally {
                QPeriaptAndroid.wipe(skPq);
                QPeriaptAndroid.wipe(skTrad);
                if (encapsulatedSecret != null) {
                    QPeriaptAndroid.wipe(encapsulatedSecret);
                }
                if (decapsulatedSecret != null) {
                    QPeriaptAndroid.wipe(decapsulatedSecret);
                }
                if (wrongContextSecret != null) {
                    QPeriaptAndroid.wipe(wrongContextSecret);
                }
            }
            assertWiped(skPq, "ML-KEM secret key");
            assertWiped(skTrad, "X25519 secret key");
            if (encapsulatedSecret != null) {
                assertWiped(encapsulatedSecret, "encapsulated secret");
            }
            if (decapsulatedSecret != null) {
                assertWiped(decapsulatedSecret, "decapsulated secret");
            }
            if (wrongContextSecret != null) {
                assertWiped(wrongContextSecret, "wrong-context secret");
            }
        }
        try {
            keys.skPq();
            throw new AssertionError("closed key-pair secrets remained readable");
        } catch (IllegalStateException expectedClosedKeys) {
            // close wipes the binding-owned key buffers and seals their accessors.
        }

        try {
            QPeriaptAndroid.decisionFromSignedPolicy(
                    new byte[0], new byte[0], new byte[0], new byte[1]);
            throw new AssertionError("malformed lastTrustedState was accepted");
        } catch (IllegalArgumentException expectedMalformedState) {
            // Malformed state never reaches native verification.
        }
        passed.add("osRandomPolicyRoundtripAndWipes");
    }

    private void writeResult(String runId, boolean ok, List<String> passed, Throwable failure) throws Exception {
        String marker = (ok ? "QPERIAPT_ANDROID_DEVICE_PASS" : "QPERIAPT_ANDROID_DEVICE_FAIL")
                + " run-id=" + runId + " tests=" + passed.size() + "\n";
        FileOutputStream txt = openFileOutput(RESULT_TXT, MODE_PRIVATE);
        try {
            txt.write(marker.getBytes(StandardCharsets.UTF_8));
        } finally {
            txt.close();
        }
        StringBuilder json = new StringBuilder();
        json.append("{\n");
        json.append("  \"schema\": 1,\n");
        json.append("  \"status\": \"").append(ok ? "pass" : "fail").append("\",\n");
        json.append("  \"run_id\": \"").append(escape(runId)).append("\",\n");
        json.append("  \"test_count\": ").append(passed.size()).append(",\n");
        json.append("  \"passed_tests\": [");
        for (int i = 0; i < passed.size(); i++) {
            if (i > 0) {
                json.append(", ");
            }
            json.append("\"").append(escape(passed.get(i))).append("\"");
        }
        json.append("]");
        if (failure != null) {
            json.append(",\n  \"failure\": \"").append(escape(failure.getClass().getName() + ": " + failure.getMessage())).append("\"");
        }
        json.append("\n}\n");
        FileOutputStream out = openFileOutput(RESULT_JSON, MODE_PRIVATE);
        try {
            out.write(json.toString().getBytes(StandardCharsets.UTF_8));
        } finally {
            out.close();
        }
    }

    private String asset(String name) throws Exception {
        InputStream in = getAssets().open(name);
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            while (true) {
                int n = in.read(buf);
                if (n < 0) {
                    break;
                }
                out.write(buf, 0, n);
            }
            return new String(out.toByteArray(), StandardCharsets.UTF_8);
        } finally {
            in.close();
        }
    }

    private static byte[] hex(String text) {
        if ((text.length() & 1) != 0) {
            throw new IllegalArgumentException("odd hex length");
        }
        byte[] out = new byte[text.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(text.charAt(i * 2), 16);
            int lo = Character.digit(text.charAt(i * 2 + 1), 16);
            if (hi < 0 || lo < 0) {
                throw new IllegalArgumentException("invalid hex");
            }
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    private static String field(String json, String name) throws Exception {
        return new JSONObject(json).getString(name);
    }

    private static long intField(String json, String name) throws Exception {
        return new JSONObject(json).getLong(name);
    }

    private static String stringField(String json, String name) throws Exception {
        return new JSONObject(json).getString(name);
    }

    private static byte[] fill(int len, int value) {
        byte[] out = new byte[len];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) value;
        }
        return out;
    }

    private static void assertBytes(byte[] expected, byte[] got, String label) {
        if (expected.length != got.length) {
            throw new AssertionError(label + " length mismatch");
        }
        for (int i = 0; i < expected.length; i++) {
            if (expected[i] != got[i]) {
                throw new AssertionError(label + " mismatch at byte " + i);
            }
        }
    }

    private static void assertWiped(byte[] value, String label) {
        for (int i = 0; i < value.length; i++) {
            if (value[i] != 0) {
                throw new AssertionError(label + " was not wiped at byte " + i);
            }
        }
    }

    private static boolean bytesEqual(byte[] left, byte[] right) {
        if (left.length != right.length) {
            return false;
        }
        int difference = 0;
        for (int i = 0; i < left.length; i++) {
            difference |= left[i] ^ right[i];
        }
        return difference == 0;
    }

    private static void expect(boolean condition, String label) {
        if (!condition) {
            throw new AssertionError(label);
        }
    }

    private static String escape(String text) {
        if (text == null) {
            return "";
        }
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < text.length(); i++) {
            char ch = text.charAt(i);
            switch (ch) {
                case '\\':
                    out.append("\\\\");
                    break;
                case '"':
                    out.append("\\\"");
                    break;
                case '\n':
                    out.append("\\n");
                    break;
                case '\r':
                    out.append("\\r");
                    break;
                case '\t':
                    out.append("\\t");
                    break;
                default:
                    if (ch < 0x20) {
                        out.append(String.format("\\u%04x", (int) ch));
                    } else {
                        out.append(ch);
                    }
                    break;
            }
        }
        return out.toString();
    }
}
EOF

APP_SOURCES="$WORK/app-sources.txt"
APP_CLASSES_JAR="$WORK/app-classes.jar"
BASE_APK="$WORK/base.apk"
UNSIGNED_APK="$WORK/unsigned.apk"
ALIGNED_APK="$WORK/aligned.apk"
SIGNED_APK="$DIST/qperiapt-android-smoke.apk"
KEYSTORE="$WORK/qperiapt-android-smoke.p12"
EXPECTED_MARKER="QPERIAPT_ANDROID_DEVICE_PASS run-id=$RUN_ID tests=3"

emulator_process_active() {
	if ! kill -0 "$EMULATOR_PID" 2>/dev/null; then
		return 1
	fi
	if emulator_process_state=$(/bin/ps -o stat= -p "$EMULATOR_PID" 2>/dev/null); then
		case "$emulator_process_state" in
			"" | *Z*) return 1 ;;
		esac
	fi
	return 0
}

stop_emulator_process() {
	if [ -z "${EMULATOR_PID:-}" ]; then
		printf 'error: emulator cleanup lacks the child process identifier\n' >&2
		return 1
	fi

	emulator_cleanup_deadline=$(monotonic_deadline 20) || return 1
	while emulator_process_active && \
		remaining_bounded_timeout "$emulator_cleanup_deadline" 1 >/dev/null; do
		sleep 0.2
	done
	if emulator_process_active; then
		printf 'error: temporary Android emulator did not stop; refusing unsafe PID signalling (pid=%s)\n' \
			"$EMULATOR_PID" >&2
		return 1
	fi

	if wait "$EMULATOR_PID" >/dev/null 2>&1; then
		emulator_wait_status=0
	else
		emulator_wait_status=$?
	fi
	if [ "$emulator_wait_status" -ne 0 ]; then
		printf 'error: temporary Android emulator exited unexpectedly with status %s\n' "$emulator_wait_status" >&2
		return 1
	fi
	EMULATOR_PID=
	EMULATOR_STARTED=0
	return 0
}

capture_owned_emulator_listeners() {
	capture_timeout_seconds=$1
	if [ -z "${EMULATOR_PID:-}" ] || [ -z "${ANDROID_EMULATOR_PORT:-}" ]; then
		printf 'error: emulator listener inspection lacks its owned identity\n' >&2
		return 1
	fi
	if [ -z "${EMULATOR_PROCESS_IDENTITY:-}" ]; then
		printf 'error: emulator listener inspection lacks its process identity\n' >&2
		return 1
	fi
	if ! emulator_process_active; then
		return 1
	fi
	EMULATOR_ADB_PORT=$((ANDROID_EMULATOR_PORT + 1))
	EMULATOR_LISTENER_PENDING="$WORK/emulator-listeners.txt.pending"
	if ! captured_emulator_identity=$(PYTHONPATH=artifact python3 \
		artifact/android_bounded_command.py \
		capture-emulator-listeners \
		--run-id "$RUN_ID" \
		--timeout-seconds "$capture_timeout_seconds" 2>/dev/null); then
		return 1
	fi
	captured_emulator_pid=${captured_emulator_identity%%:*}
	if [ "$captured_emulator_identity" != "$EMULATOR_PROCESS_IDENTITY" ] || \
		[ "$captured_emulator_pid" != "$EMULATOR_PID" ]; then
		printf 'error: emulator listener capture returned a different child identity\n' >&2
		return 1
	fi
	if ! python3 artifact/android_device_proof.py verify-owned-emulator-listeners \
		--lsof-output "$EMULATOR_LISTENER_PENDING" \
		--expected-pid "$EMULATOR_PID" \
		--console-port "$ANDROID_EMULATOR_PORT" \
		--adb-port "$EMULATOR_ADB_PORT" >/dev/null; then
		return 1
	fi
}

wait_for_owned_emulator_listeners() {
	wait_seconds=$1
	emulator_listener_deadline=$(monotonic_deadline "$wait_seconds") || return 1
	while emulator_process_active; do
		listener_attempt_timeout=$(remaining_bounded_timeout \
			"$emulator_listener_deadline" 5) || break
		if capture_owned_emulator_listeners "$listener_attempt_timeout" 2>/dev/null; then
			if ! mv "$EMULATOR_LISTENER_PENDING" "$DIST/emulator-listeners.txt"; then
				printf 'error: cannot preserve owned emulator listener evidence\n' >&2
				return 2
			fi
			return 0
		fi
		sleep 0.2
	done
	printf 'error: owned emulator did not expose its fixed console and adb listeners\n' >&2
	return 1
}

register_owned_emulator() {
	registration_attempt=$1
	registration_deadline=$2
	listener_timeout_seconds=$(remaining_bounded_timeout \
		"$registration_deadline" 5) || return 1
	if ! emulator_process_active || ! \
		capture_owned_emulator_listeners "$listener_timeout_seconds"; then
		printf 'error: refusing emulator registration without fresh listener ownership\n' >&2
		return 1
	fi
	registration_timeout_seconds=$(remaining_bounded_timeout \
		"$registration_deadline" 10) || return 1
	registration_output="$WORK/adb-emulator-registration-attempt-$registration_attempt.txt.pending"
	registration_error="$WORK/adb-emulator-registration-attempt-$registration_attempt.err.pending"
	if ! android_command register-emulator --timeout-seconds "$registration_timeout_seconds" \
		>"$registration_output" 2>"$registration_error"; then
		return 1
	fi
	if [ -s "$registration_error" ]; then
		printf 'error: owned emulator registration emitted diagnostics\n' >&2
		return 1
	fi
	if ! rm -f -- "$registration_error"; then
		printf 'error: cannot remove empty emulator registration diagnostics\n' >&2
		return 2
	fi
	listener_timeout_seconds=$(remaining_bounded_timeout \
		"$registration_deadline" 5) || return 1
	if ! emulator_process_active || ! \
		capture_owned_emulator_listeners "$listener_timeout_seconds"; then
		printf 'error: emulator identity changed after registration\n' >&2
		return 1
	fi
	if ! mv "$registration_output" "$DIST/adb-emulator-registration.txt"; then
		printf 'error: cannot preserve emulator registration evidence\n' >&2
		return 2
	fi
}

wait_for_owned_emulator_registration() {
	wait_seconds=$1
	emulator_registration_deadline=$(monotonic_deadline "$wait_seconds") || return 1
	registration_attempt=0
	while emulator_process_active; do
		remaining_bounded_timeout "$emulator_registration_deadline" 1 \
			>/dev/null || break
		registration_attempt=$((registration_attempt + 1))
		if register_owned_emulator "$registration_attempt" \
			"$emulator_registration_deadline"; then
			return 0
		else
			registration_status=$?
		fi
		if [ "$registration_status" -eq 2 ]; then
			return 2
		fi
		sleep 0.5
	done
	printf 'error: private adb server could not register the owned emulator\n' >&2
	return 1
}

request_owned_emulator_shutdown() {
	if ! emulator_process_active; then
		printf 'error: owned emulator exited before its required protocol shutdown\n' >&2
		return 1
	fi
	if ! PYTHONPATH=artifact python3 artifact/android_bounded_command.py \
		request-owned-emulator-stop --run-id "$RUN_ID" >/dev/null; then
		printf 'error: authenticated owned-emulator console shutdown failed\n' >&2
		return 1
	fi
	EMULATOR_PROTOCOL_STOP_REQUESTED=1
}

query_package_state() {
	package_query_timeout_seconds=${1:-15}
	package_query_output=${2:-"$DIST/adb-package-query.txt"}
	package_query_error=${3:-"$DIST/adb-package-query.err"}
	if android_command package-state \
		--timeout-seconds "$package_query_timeout_seconds" \
		>"$package_query_output" 2>"$package_query_error"; then
		package_query_status=0
	else
		package_query_status=$?
	fi
	if [ "$package_query_status" -ne 0 ]; then
		printf 'error: cannot query the Android smoke package state\n' >&2
		return "$package_query_status"
	fi
	if ! package_state=$(/bin/cat -- "$package_query_output"); then
		printf 'error: cannot read the typed Android package state\n' >&2
		return 2
	fi
	if ! package_query_size=$(wc -c <"$package_query_output"); then
		printf 'error: cannot measure the typed Android package state\n' >&2
		return 2
	fi
	if [ "$package_query_size" -ne $((${#package_state} + 1)) ]; then
		printf 'error: typed Android package state is not one exact line\n' >&2
		return 2
	fi
	case "$package_state" in
		absent | present | retryable:query-nonzero | retryable:query-timeout | retryable:device-unavailable)
			printf '%s\n' "$package_state"
			;;
		*)
			printf 'error: Android package-state adapter returned an unexpected token\n' >&2
			return 2
			;;
	esac
}

observe_preinstall_package_absence() {
	preinstall_deadline=$(monotonic_deadline 45) || return 1
	preinstall_attempt=0
	preinstall_consecutive_absent=0
	while preinstall_query_timeout=$(remaining_bounded_timeout \
		"$preinstall_deadline" 5); do
		preinstall_attempt=$((preinstall_attempt + 1))
		preinstall_output="$DIST/adb-package-query-preinstall-attempt-$preinstall_attempt.txt"
		preinstall_error="$DIST/adb-package-query-preinstall-attempt-$preinstall_attempt.err"
		preinstall_observer_error="$DIST/adb-package-query-preinstall-attempt-$preinstall_attempt.observer.err"
		package_state=
		if package_state=$(query_package_state \
			"$preinstall_query_timeout" \
			"$preinstall_output" \
			"$preinstall_error" 2>>"$preinstall_observer_error"); then
			package_query_status=0
		else
			package_query_status=$?
		fi
		case "$package_query_status:$package_state" in
			0:absent)
				preinstall_consecutive_absent=$((preinstall_consecutive_absent + 1))
				printf 'phase=preinstall invocation=1 attempt=%s state=absent consecutive=%s\n' \
					"$preinstall_attempt" "$preinstall_consecutive_absent" \
					>>"$PACKAGE_OBSERVATION_LOG"
				if [ "$preinstall_consecutive_absent" -eq 3 ]; then
					return 0
				fi
				;;
			0:present)
				printf 'phase=preinstall invocation=1 attempt=%s state=present consecutive=0\n' \
					"$preinstall_attempt" >>"$PACKAGE_OBSERVATION_LOG"
				printf 'error: refusing to replace a pre-existing Android package: %s\n' \
					"$PACKAGE" >&2
				return 1
				;;
			0:retryable:query-nonzero | 0:retryable:query-timeout | 0:retryable:device-unavailable)
				preinstall_consecutive_absent=0
				preinstall_reason=${package_state#retryable:}
				printf 'phase=preinstall invocation=1 attempt=%s state=retryable reason=%s consecutive=0\n' \
					"$preinstall_attempt" "$preinstall_reason" \
					>>"$PACKAGE_OBSERVATION_LOG"
				;;
			0:* | *:*)
				printf 'phase=preinstall invocation=1 attempt=%s state=structural-error exit=%s consecutive=0\n' \
					"$preinstall_attempt" "$package_query_status" \
					>>"$PACKAGE_OBSERVATION_LOG"
				printf 'error: Android preinstall package observation failed structurally\n' >&2
				return 2
				;;
		esac
		if remaining_bounded_timeout "$preinstall_deadline" 1 >/dev/null; then
			sleep 1
		fi
	done
	printf 'error: Android package absence did not stabilize within 45 seconds; see %s\n' \
		"$PACKAGE_OBSERVATION_LOG" >&2
	return 1
}

remove_installed_apk_copy() {
	if [ -e "$installed_apk" ] && ! rm -f -- "$installed_apk"; then
		printf 'error: failed to remove the temporary installed-APK copy\n' >&2
		return 1
	fi
}

apk_file_identity() {
	PYTHONPATH=artifact python3 - "$1" <<'PY'
import pathlib
import sys

from evidence_io import read_regular_snapshot

snapshot = read_regular_snapshot(
    pathlib.Path(sys.argv[1]),
    maximum=512 * 1024 * 1024,
    label="Android smoke APK",
)
print(f"{snapshot.size}:{snapshot.sha256}")
PY
}

verify_observed_installed_apk_signer() {
	installed_signer_output="$DIST/installed-apksigner-verify.txt"
	if ! rm -f -- "$installed_signer_output"; then
		printf 'error: cannot reset installed-APK signer diagnostics\n' >&2
		return 2
	fi
	if ! installed_apk_identity=$(apk_file_identity "$installed_apk"); then
		remove_installed_apk_copy || return 2
		return 2
	fi
	if [ "$installed_apk_identity" != "$SIGNED_APK_IDENTITY" ]; then
		printf 'error: observed Android smoke APK copy changed before signer verification\n' >&2
		remove_installed_apk_copy || return 2
		return 2
	fi
	if ! chmod 600 "$installed_apk"; then
		printf 'error: cannot protect the temporary installed-APK copy\n' >&2
		remove_installed_apk_copy || return 2
		return 2
	fi
	if ! "$APKSIGNER" verify --min-sdk-version 23 --print-certs \
		"$installed_apk" >"$installed_signer_output" 2>&1; then
		printf 'error: installed Android smoke APK signature verification failed\n' >&2
		remove_installed_apk_copy || return 2
		return 2
	fi
	if ! installed_signer_sha256=$(PYTHONPATH=artifact python3 artifact/android_device_proof.py signer-sha256 \
		--apksigner-output "$installed_signer_output"); then
		remove_installed_apk_copy || return 2
		return 2
	fi
	remove_installed_apk_copy || return 2
	if [ "$installed_signer_sha256" != "$EXPECTED_APK_SIGNER_SHA256" ]; then
		printf 'error: installed Android package signer does not match this run; refusing to uninstall it\n' >&2
		return 2
	fi
}

observe_installed_package_sample() {
	ownership_timeout=$1
	ownership_phase=$2
	ownership_invocation=$3
	ownership_attempt=$4
	case "$ownership_phase:$ownership_invocation" in
		postinstall:1) ownership_file_phase=postinstall ;;
		cleanup:[1-9] | cleanup:[1-9][0-9]*)
			ownership_file_phase="cleanup-$ownership_invocation"
			;;
		*)
			printf 'error: invalid Android package ownership phase\n' >&2
			return 2
			;;
	esac
	ownership_output="$DIST/adb-package-$ownership_file_phase-attempt-$ownership_attempt.txt"
	ownership_error="$DIST/adb-package-$ownership_file_phase-attempt-$ownership_attempt.err"
	OWNERSHIP_SAMPLE_STATE=
	OWNERSHIP_SAMPLE_PATH_SHA256=
	OWNERSHIP_SAMPLE_RETRY_REASON=
	if android_command observe-installed-apk \
		--timeout-seconds "$ownership_timeout" \
		>"$ownership_output" 2>"$ownership_error"; then
		ownership_status=0
	else
		ownership_status=$?
	fi
	if [ "$ownership_status" -ne 0 ]; then
		printf 'phase=%s invocation=%s attempt=%s state=structural-error exit=%s consecutive=0\n' \
			"$ownership_phase" "$ownership_invocation" "$ownership_attempt" \
			"$ownership_status" >>"$PACKAGE_OBSERVATION_LOG"
		remove_installed_apk_copy || return 2
		printf 'error: Android package ownership observation failed structurally; see %s\n' \
			"$ownership_error" >&2
		return 2
	fi
	if ! ownership_result=$(/bin/cat -- "$ownership_output"); then
		printf 'error: cannot read the typed Android package ownership observation\n' >&2
		remove_installed_apk_copy || return 2
		return 2
	fi
	if ! ownership_result_size=$(wc -c <"$ownership_output"); then
		printf 'error: cannot measure the typed Android package ownership observation\n' >&2
		remove_installed_apk_copy || return 2
		return 2
	fi
	if [ "$ownership_result_size" -ne $((${#ownership_result} + 1)) ]; then
		printf 'error: typed Android package ownership observation is not one exact line\n' >&2
		remove_installed_apk_copy || return 2
		return 2
	fi
	case "$ownership_result" in
		exact:*)
			ownership_path_sha256=${ownership_result#exact:}
			case "$ownership_path_sha256" in
				*[!0-9a-f]* | "")
					printf 'error: Android package ownership observation returned a malformed path digest\n' >&2
					remove_installed_apk_copy || return 2
					return 2
					;;
			esac
			if [ "${#ownership_path_sha256}" -ne 64 ]; then
				printf 'error: Android package ownership path digest has the wrong length\n' >&2
				remove_installed_apk_copy || return 2
				return 2
			fi
			OWNERSHIP_SAMPLE_STATE=exact
			OWNERSHIP_SAMPLE_PATH_SHA256=$ownership_path_sha256
			;;
		retryable:*)
			ownership_reason=${ownership_result#retryable:}
			case "$ownership_reason" in
				package-unavailable | pull-failed | path-changed | bytes-mismatch | deadline-exhausted) ;;
				*)
					printf 'error: Android package ownership observation returned a malformed retry reason\n' >&2
					remove_installed_apk_copy || return 2
					return 2
					;;
			esac
			OWNERSHIP_SAMPLE_STATE=retryable
			OWNERSHIP_SAMPLE_RETRY_REASON=$ownership_reason
			remove_installed_apk_copy || return 2
			;;
		*)
			printf 'error: Android package ownership observation returned an unexpected result\n' >&2
			remove_installed_apk_copy || return 2
			return 2
			;;
	esac
}

observe_owned_installed_package() {
	ownership_deadline=$1
	ownership_phase=$2
	ownership_invocation=$3
	ownership_attempt=0
	ownership_consecutive_exact=0
	ownership_previous_path_sha256=
	while ownership_timeout=$(remaining_bounded_timeout "$ownership_deadline" 15); do
		ownership_attempt=$((ownership_attempt + 1))
		if observe_installed_package_sample "$ownership_timeout" \
			"$ownership_phase" "$ownership_invocation" "$ownership_attempt"; then
			:
		else
			ownership_sample_status=$?
			return "$ownership_sample_status"
		fi
		case "$OWNERSHIP_SAMPLE_STATE" in
			exact)
				if [ "$OWNERSHIP_SAMPLE_PATH_SHA256" = "$ownership_previous_path_sha256" ]; then
					ownership_consecutive_exact=$((ownership_consecutive_exact + 1))
				else
					ownership_consecutive_exact=1
					ownership_previous_path_sha256=$OWNERSHIP_SAMPLE_PATH_SHA256
				fi
				printf 'phase=%s invocation=%s attempt=%s state=exact path_sha256=%s consecutive=%s\n' \
					"$ownership_phase" "$ownership_invocation" "$ownership_attempt" \
					"$OWNERSHIP_SAMPLE_PATH_SHA256" "$ownership_consecutive_exact" \
					>>"$PACKAGE_OBSERVATION_LOG"
				if [ "$ownership_consecutive_exact" -eq 2 ]; then
					if verify_observed_installed_apk_signer; then
						return 0
					else
						ownership_signer_status=$?
					fi
					return "$ownership_signer_status"
				fi
				remove_installed_apk_copy || return 2
				;;
			retryable)
				ownership_transport_recovery_eligible=0
				if [ "$ownership_phase" = "postinstall" ] && \
					[ "$ownership_invocation" = "1" ] && \
					[ "$OWNERSHIP_SAMPLE_RETRY_REASON" = "package-unavailable" ] && \
					[ "$ownership_consecutive_exact" -eq 1 ] && \
					[ "$ANDROID_BOOT_AVD" = "1" ] && [ "$DEVICE_KIND" = "emulator" ] && \
					[ "$EMULATOR_STARTED" = "1" ] && \
					[ "$ANDROID_EMULATOR_TRANSPORT_RECOVERY_ATTEMPTED" = "0" ]; then
					ownership_transport_recovery_eligible=1
				fi
				ownership_consecutive_exact=0
				ownership_previous_path_sha256=
				printf 'phase=%s invocation=%s attempt=%s state=retryable reason=%s consecutive=0\n' \
					"$ownership_phase" "$ownership_invocation" "$ownership_attempt" \
					"$OWNERSHIP_SAMPLE_RETRY_REASON" >>"$PACKAGE_OBSERVATION_LOG"
				if [ "$ownership_transport_recovery_eligible" = "1" ] && \
					recovery_timeout=$(remaining_bounded_timeout "$ownership_deadline" 15); then
					ANDROID_EMULATOR_TRANSPORT_RECOVERY_ATTEMPTED=1
					if attempt_owned_emulator_transport_recovery postinstall \
						"$recovery_timeout" "$ownership_invocation" "$ownership_attempt"; then
						continue
					else
						ownership_recovery_status=$?
					fi
					case "$ownership_recovery_status" in
						1) ;;
						2 | 129 | 130 | 143) return "$ownership_recovery_status" ;;
						*) return 2 ;;
					esac
				fi
				;;
			*)
				printf 'error: Android package ownership sample lacks a typed state\n' >&2
				remove_installed_apk_copy || return 2
				return 2
				;;
		esac
		if remaining_bounded_timeout "$ownership_deadline" 1 >/dev/null; then
			sleep 1
		fi
	done
	remove_installed_apk_copy || return 2
	printf 'error: Android package ownership did not converge within its total deadline; see %s\n' \
		"$PACKAGE_OBSERVATION_LOG" >&2
	return 1
}

attempt_owned_emulator_transport_recovery() {
	recovery_phase=$1
	recovery_timeout=$2
	recovery_invocation=$3
	recovery_attempt=$4
	recovery_phase_valid=0
	case "$recovery_phase" in
		postinstall)
			if [ "$recovery_invocation" = "1" ]; then
				recovery_phase_valid=1
			fi
			;;
		cleanup)
			case "$recovery_invocation" in
				"" | 0* | *[!0-9]*) ;;
				*) recovery_phase_valid=1 ;;
			esac
			;;
	esac
	recovery_attempt_valid=0
	case "$recovery_attempt" in
		"" | 0* | *[!0-9]*) ;;
		*) recovery_attempt_valid=1 ;;
	esac
	recovery_timeout_valid=0
	case "$recovery_timeout" in
		"" | 0* | *[!0-9]*) ;;
		*)
			if [ "$recovery_timeout" -le 15 ]; then
				recovery_timeout_valid=1
			fi
			;;
	esac
	if [ "$recovery_phase_valid" != "1" ] || \
		[ "$recovery_attempt_valid" != "1" ] || \
		[ "$recovery_timeout_valid" != "1" ]; then
		printf 'error: invalid Android emulator transport recovery parameters\n' >&2
		return 2
	fi
	if [ "$ANDROID_BOOT_AVD" != "1" ] || [ "$DEVICE_KIND" != "emulator" ] || \
		[ "$EMULATOR_STARTED" != "1" ]; then
		printf 'error: refusing Android transport recovery outside the script-owned emulator lane\n' >&2
		return 2
	fi
	recovery_file_leaf="adb-emulator-transport-recovery-$recovery_phase-$recovery_invocation-$recovery_attempt"
	recovery_file_prefix="$WORK/$recovery_file_leaf"
	recovery_output="$recovery_file_prefix.txt"
	recovery_error="$recovery_file_prefix.err"
	if android_command recover-emulator-transport \
		--timeout-seconds "$recovery_timeout" \
		>"$recovery_output" 2>"$recovery_error"; then
		recovery_status=0
	else
		recovery_status=$?
	fi
	if [ "$recovery_status" -ne 0 ]; then
		printf 'phase=%s invocation=%s attempt=%s transport-recovery=structural-error exit=%s\n' \
			"$recovery_phase" "$recovery_invocation" "$recovery_attempt" "$recovery_status" \
			>>"$PACKAGE_OBSERVATION_LOG"
		case "$recovery_status" in
			129 | 130 | 143) return "$recovery_status" ;;
			*) return 2 ;;
		esac
	fi
	if [ -s "$recovery_error" ]; then
		printf 'error: successful Android emulator transport recovery emitted diagnostics\n' >&2
		return 2
	fi
	if ! recovery_result=$(/bin/cat -- "$recovery_output"); then
		printf 'error: cannot read the typed Android emulator transport recovery result\n' >&2
		return 2
	fi
	if ! recovery_result_size=$(wc -c <"$recovery_output"); then
		printf 'error: cannot measure the typed Android emulator transport recovery result\n' >&2
		return 2
	fi
	if [ "$recovery_result_size" -ne $((${#recovery_result} + 1)) ]; then
		printf 'error: typed Android emulator transport recovery result is not one exact line\n' >&2
		return 2
	fi
	case "$recovery_result" in
		recovered | race-device)
			printf 'phase=%s invocation=%s attempt=%s transport-recovery=%s\n' \
				"$recovery_phase" "$recovery_invocation" "$recovery_attempt" "$recovery_result" \
				>>"$PACKAGE_OBSERVATION_LOG"
			return 0
			;;
		retryable:transport-inconclusive | retryable:registration-failed | retryable:post-state-unavailable)
			recovery_reason=${recovery_result#retryable:}
			printf 'phase=%s invocation=%s attempt=%s transport-recovery=retryable reason=%s\n' \
				"$recovery_phase" "$recovery_invocation" "$recovery_attempt" "$recovery_reason" \
				>>"$PACKAGE_OBSERVATION_LOG"
			return 1
			;;
		*)
			printf 'error: Android emulator transport recovery returned an unexpected token\n' >&2
			return 2
			;;
	esac
}

cleanup_android_app() {
	if [ "${ANDROID_APP_CLEANUP_ARMED:-0}" != "1" ]; then
		return 0
	fi
	ANDROID_APP_CLEANUP_INVOCATION=$((ANDROID_APP_CLEANUP_INVOCATION + 1))
	cleanup_invocation=$ANDROID_APP_CLEANUP_INVOCATION
	cleanup_deadline=$(monotonic_deadline 45) || return 1
	required_absent_observations=3
	if [ "${ANDROID_APP_INSTALL_CONFIRMED:-0}" != "1" ]; then
		required_absent_observations=8
	fi
	attempt=0
	absent_observations=0
	cleanup_ownership_consecutive_exact=0
	cleanup_ownership_previous_path_sha256=
	while cleanup_query_timeout=$(remaining_bounded_timeout "$cleanup_deadline" 5); do
		attempt=$((attempt + 1))
		cleanup_query_output="$DIST/adb-package-query-cleanup-$cleanup_invocation-attempt-$attempt.txt"
		cleanup_query_error="$DIST/adb-package-query-cleanup-$cleanup_invocation-attempt-$attempt.err"
		cleanup_observer_error="$DIST/adb-package-query-cleanup-$cleanup_invocation-attempt-$attempt.observer.err"
		package_state=
		if package_state=$(query_package_state \
			"$cleanup_query_timeout" \
			"$cleanup_query_output" "$cleanup_query_error" \
			2>>"$cleanup_observer_error"); then
			cleanup_query_status=0
		else
			cleanup_query_status=$?
		fi
		case "$cleanup_query_status:$package_state" in
			0:absent)
				cleanup_ownership_consecutive_exact=0
				cleanup_ownership_previous_path_sha256=
				remove_installed_apk_copy || return 2
				absent_observations=$((absent_observations + 1))
				printf 'phase=cleanup invocation=%s attempt=%s state=absent consecutive=%s\n' \
					"$cleanup_invocation" "$attempt" "$absent_observations" \
					>>"$PACKAGE_OBSERVATION_LOG"
				if [ "$absent_observations" -ge "$required_absent_observations" ]; then
					ANDROID_APP_CLEANUP_ARMED=0
					return 0
				fi
				;;
			0:present)
				absent_observations=0
				printf 'phase=cleanup invocation=%s attempt=%s state=present consecutive=0\n' \
					"$cleanup_invocation" "$attempt" >>"$PACKAGE_OBSERVATION_LOG"
				if [ "$ANDROID_APP_UNINSTALL_REQUESTED" = "1" ]; then
					cleanup_ownership_consecutive_exact=0
					cleanup_ownership_previous_path_sha256=
					remove_installed_apk_copy || return 2
					printf 'phase=cleanup invocation=%s attempt=%s uninstall=still-present-after-request\n' \
						"$cleanup_invocation" "$attempt" >>"$PACKAGE_OBSERVATION_LOG"
				else
					if ! cleanup_ownership_timeout=$(remaining_bounded_timeout \
						"$cleanup_deadline" 15); then
						printf 'error: Android cleanup deadline expired before ownership observation\n' >&2
						return 1
					fi
					if observe_installed_package_sample "$cleanup_ownership_timeout" \
						cleanup "$cleanup_invocation" "$attempt"; then
						:
					else
						cleanup_ownership_sample_status=$?
						return "$cleanup_ownership_sample_status"
					fi
					case "$OWNERSHIP_SAMPLE_STATE" in
						exact)
							if [ "$OWNERSHIP_SAMPLE_PATH_SHA256" = \
								"$cleanup_ownership_previous_path_sha256" ]; then
								cleanup_ownership_consecutive_exact=$((cleanup_ownership_consecutive_exact + 1))
							else
								cleanup_ownership_consecutive_exact=1
								cleanup_ownership_previous_path_sha256=$OWNERSHIP_SAMPLE_PATH_SHA256
							fi
							printf 'phase=cleanup invocation=%s attempt=%s state=exact path_sha256=%s consecutive=%s\n' \
								"$cleanup_invocation" "$attempt" \
								"$OWNERSHIP_SAMPLE_PATH_SHA256" \
								"$cleanup_ownership_consecutive_exact" \
								>>"$PACKAGE_OBSERVATION_LOG"
							if [ "$cleanup_ownership_consecutive_exact" -lt 2 ]; then
								remove_installed_apk_copy || return 2
							elif verify_observed_installed_apk_signer; then
								:
							else
								cleanup_ownership_signer_status=$?
								return "$cleanup_ownership_signer_status"
							fi
							;;
						retryable)
							cleanup_ownership_consecutive_exact=0
							cleanup_ownership_previous_path_sha256=
							printf 'phase=cleanup invocation=%s attempt=%s state=retryable reason=%s consecutive=0\n' \
								"$cleanup_invocation" "$attempt" \
								"$OWNERSHIP_SAMPLE_RETRY_REASON" \
								>>"$PACKAGE_OBSERVATION_LOG"
							;;
						*)
							printf 'error: Android cleanup ownership sample lacks a typed state\n' >&2
							remove_installed_apk_copy || return 2
							return 2
							;;
					esac
					if [ "$cleanup_ownership_consecutive_exact" -eq 2 ]; then
						ANDROID_APP_INSTALL_CONFIRMED=1
						required_absent_observations=3
						if ! uninstall_timeout=$(remaining_bounded_timeout "$cleanup_deadline" 60); then
							printf 'error: Android cleanup deadline expired before owned uninstall\n' >&2
							return 1
						fi
						if ! android_command uninstall-app \
							--timeout-seconds "$uninstall_timeout" \
							>>"$DIST/adb-uninstall-cleanup.log" 2>&1; then
							printf 'phase=cleanup invocation=%s attempt=%s uninstall=unknown-or-failed\n' \
								"$cleanup_invocation" "$attempt" >>"$PACKAGE_OBSERVATION_LOG"
						else
							printf 'phase=cleanup invocation=%s attempt=%s uninstall=request-returned-zero\n' \
								"$cleanup_invocation" "$attempt" >>"$PACKAGE_OBSERVATION_LOG"
						fi
						ANDROID_APP_UNINSTALL_REQUESTED=1
					fi
				fi
				;;
			0:retryable:device-unavailable)
				absent_observations=0
				cleanup_ownership_consecutive_exact=0
				cleanup_ownership_previous_path_sha256=
				remove_installed_apk_copy || return 2
				printf 'phase=cleanup invocation=%s attempt=%s state=retryable reason=device-unavailable consecutive=0\n' \
					"$cleanup_invocation" "$attempt" >>"$PACKAGE_OBSERVATION_LOG"
				if [ "$ANDROID_BOOT_AVD" = "1" ] && [ "$DEVICE_KIND" = "emulator" ] && \
					[ "$EMULATOR_STARTED" = "1" ] && \
					[ "$ANDROID_EMULATOR_TRANSPORT_RECOVERY_ATTEMPTED" = "0" ] && \
					recovery_timeout=$(remaining_bounded_timeout "$cleanup_deadline" 15); then
					ANDROID_EMULATOR_TRANSPORT_RECOVERY_ATTEMPTED=1
					if attempt_owned_emulator_transport_recovery cleanup \
						"$recovery_timeout" "$cleanup_invocation" "$attempt"; then
						absent_observations=0
						cleanup_ownership_consecutive_exact=0
						cleanup_ownership_previous_path_sha256=
						remove_installed_apk_copy || return 2
						continue
					else
						recovery_attempt_status=$?
					fi
					case "$recovery_attempt_status" in
						1) ;;
						2 | 129 | 130 | 143) return "$recovery_attempt_status" ;;
						*) return 2 ;;
					esac
				fi
				;;
			0:retryable:query-nonzero | 0:retryable:query-timeout)
				absent_observations=0
				cleanup_ownership_consecutive_exact=0
				cleanup_ownership_previous_path_sha256=
				remove_installed_apk_copy || return 2
				cleanup_retry_reason=${package_state#retryable:}
				printf 'phase=cleanup invocation=%s attempt=%s state=retryable reason=%s consecutive=0\n' \
					"$cleanup_invocation" "$attempt" "$cleanup_retry_reason" \
					>>"$PACKAGE_OBSERVATION_LOG"
				;;
			0:* | *:*)
				remove_installed_apk_copy || return 2
				printf 'phase=cleanup invocation=%s attempt=%s state=structural-error exit=%s consecutive=0\n' \
					"$cleanup_invocation" "$attempt" "$cleanup_query_status" \
					>>"$PACKAGE_OBSERVATION_LOG"
				printf 'error: Android cleanup package observation failed structurally; see %s\n' \
					"$cleanup_observer_error" >&2
				return 2
				;;
		esac
		if remaining_bounded_timeout "$cleanup_deadline" 1 >/dev/null; then
			sleep 1
		fi
	done
	remove_installed_apk_copy || return 2
	printf 'error: Android app cleanup outcome is unresolved for device sha256:%s; see %s\n' \
		"${SERIAL_SHA256_PREFIX:-unavailable}" "$PACKAGE_OBSERVATION_LOG" >&2
	return 1
}

cleanup_unconfirmed_proof() {
	proof_artifact_cleanup_status=0
	if [ "${ANDROID_PROOF_EVIDENCE_CONFIRMED:-0}" != "1" ]; then
		for proof_artifact in "$PROOF_STAGING" "$PROOF_JSON" "$EVIDENCE_BUNDLE"; do
			if { [ -e "$proof_artifact" ] || [ -L "$proof_artifact" ]; } && \
				! rm -f -- "$proof_artifact"; then
				printf 'error: failed to remove unconfirmed Android proof artifact: %s\n' \
					"$proof_artifact" >&2
				proof_artifact_cleanup_status=1
			fi
			done
	fi
	return "$proof_artifact_cleanup_status"
}

cleanup_runtime() {
	primary_exit_status=$1
	runtime_internal_cleanup_status=0
	record_runtime_cleanup_failure() {
		cleanup_failure_status=$1
		if [ "$runtime_internal_cleanup_status" -eq 0 ]; then
			runtime_internal_cleanup_status=$cleanup_failure_status
		fi
	}
	if [ "${ANDROID_RUNTIME_RECOVERY_PRESERVE:-0}" = "1" ]; then
		printf 'error: preserving Android runtime recovery state after an unresolved server startup handoff\n' >&2
		return 1
	fi
	if [ -n "${KEYSTORE:-}" ] && [ -e "$KEYSTORE" ]; then
		if ! rm -f -- "$KEYSTORE"; then
			printf 'error: failed to remove temporary Android smoke keystore: %s\n' "$KEYSTORE" >&2
			record_runtime_cleanup_failure 1
		fi
	fi
	if [ "${ANDROID_APP_CLEANUP_ARMED:-0}" = "1" ]; then
		if [ -z "${ADB:-}" ] || [ -z "${SERIAL:-}" ]; then
			printf 'error: installed Android smoke app cleanup lacks adb or device identity\n' >&2
			record_runtime_cleanup_failure 1
		else
			if cleanup_android_app; then
				:
			else
				app_cleanup_status=$?
				record_runtime_cleanup_failure "$app_cleanup_status"
			fi
		fi
	fi
	if [ "${EMULATOR_STARTED:-0}" = "1" ]; then
		if ! request_owned_emulator_shutdown; then
			printf 'error: failed to request shutdown of the temporary Android emulator\n' >&2
			record_runtime_cleanup_failure 1
		fi
		if stop_emulator_process; then
			EMULATOR_STARTED=0
		else
			record_runtime_cleanup_failure 1
		fi
	fi
	if [ "${ADB_PRIVATE_SERVER_CLEANUP_ARMED:-0}" = "1" ]; then
		if [ "${EMULATOR_STARTED:-0}" = "1" ]; then
			printf 'error: preserving private adb recovery state because emulator cleanup is unresolved\n' >&2
			record_runtime_cleanup_failure 1
		else
			stop_private_adb_server || record_runtime_cleanup_failure 1
		fi
	fi
	if [ "${ANDROID_COMMAND_CAPABILITY_ARMED:-0}" = "1" ]; then
		if [ "${ADB_PRIVATE_SERVER_CLEANUP_ARMED:-0}" = "1" ]; then
			printf 'error: preserving the Android command capability because private adb cleanup is unresolved\n' >&2
			record_runtime_cleanup_failure 1
		else
			cleanup_android_command_capability || record_runtime_cleanup_failure 1
		fi
	fi
	if [ "${ANDROID_RUNTIME_RECOVERY_ARMED:-0}" = "1" ] && \
		[ "${EMULATOR_STARTED:-0}" != "1" ] && \
		[ "${ADB_PRIVATE_SERVER_CLEANUP_ARMED:-0}" != "1" ] && \
		[ "${ANDROID_COMMAND_CAPABILITY_ARMED:-0}" != "1" ]; then
		if [ "${ADB_PROTOCOL_STOP_REQUESTED:-0}" != "1" ] || \
			{ [ "$ANDROID_BOOT_AVD" = "1" ] && \
			[ "${EMULATOR_PROTOCOL_STOP_REQUESTED:-0}" != "1" ]; }; then
			printf 'error: refusing runtime retirement without every required protocol shutdown\n' >&2
			record_runtime_cleanup_failure 1
		else
			retirement_exit_status=$primary_exit_status
			if [ "$retirement_exit_status" -eq 0 ] && \
				[ "$runtime_internal_cleanup_status" -ne 0 ]; then
				retirement_exit_status=$runtime_internal_cleanup_status
			fi
			if [ "$retirement_exit_status" -eq 0 ]; then
				set -- retire-stopped-runtime --run-id "$RUN_ID"
				retirement_label=completed
			else
				set -- retire-failed-runtime --run-id "$RUN_ID" \
					--primary-exit-status "$retirement_exit_status"
				retirement_label=failed
			fi
			if ! PYTHONPATH=artifact python3 artifact/android_bounded_command.py "$@"; then
				printf 'error: failed to retire the %s Android runtime recovery receipt\n' \
					"$retirement_label" >&2
				record_runtime_cleanup_failure 1
			else
				ANDROID_RUNTIME_RECOVERY_ARMED=0
			fi
		fi
	fi
	if [ "$runtime_internal_cleanup_status" -eq 0 ]; then
		ANDROID_RUNTIME_CLEANUP_COMPLETED=1
	fi
	return "$runtime_internal_cleanup_status"
}

cleanup_runtime_with_deferred_signals() {
	ANDROID_CLEANUP_SIGNAL=0
	trap 'ANDROID_CLEANUP_SIGNAL=129' HUP
	trap 'ANDROID_CLEANUP_SIGNAL=130' INT
	trap 'ANDROID_CLEANUP_SIGNAL=143' TERM
	deferred_runtime_cleanup_status=0
	cleanup_runtime 0 || deferred_runtime_cleanup_status=$?
	trap 'exit 129' HUP
	trap 'exit 130' INT
	trap 'exit 143' TERM
	return "$deferred_runtime_cleanup_status"
}

cleanup_exit() {
	exit_status=$?
	trap - EXIT
	ANDROID_EXIT_CLEANUP_SIGNAL=0
	trap 'ANDROID_EXIT_CLEANUP_SIGNAL=129' HUP
	trap 'ANDROID_EXIT_CLEANUP_SIGNAL=130' INT
	trap 'ANDROID_EXIT_CLEANUP_SIGNAL=143' TERM
	exit_runtime_cleanup_status=0
	cleanup_runtime "$exit_status" || exit_runtime_cleanup_status=$?
	exit_proof_cleanup_status=0
	cleanup_unconfirmed_proof || exit_proof_cleanup_status=$?
	trap - HUP INT TERM
	if [ "$ANDROID_EXIT_CLEANUP_SIGNAL" -ne 0 ]; then
		exit_status=$ANDROID_EXIT_CLEANUP_SIGNAL
	elif [ "$exit_status" -eq 0 ] && [ "$exit_runtime_cleanup_status" -ne 0 ]; then
		exit_status=$exit_runtime_cleanup_status
	elif [ "$exit_status" -eq 0 ] && [ "$exit_proof_cleanup_status" -ne 0 ]; then
		exit_status=$exit_proof_cleanup_status
	fi
	exit "$exit_status"
}

ANDROID_APP_CLEANUP_ARMED=0
ANDROID_APP_INSTALL_CONFIRMED=0
ANDROID_APP_CLEANUP_INVOCATION=0
ANDROID_APP_UNINSTALL_REQUESTED=0
ANDROID_EMULATOR_TRANSPORT_RECOVERY_ATTEMPTED=0
ADB_PRIVATE_SERVER_CLEANUP_ARMED=0
ADB_PRIVATE_SERVER_DIRECTORY=
ADB_PRIVATE_SERVER_SOCKET_NONCE=
ADB_PRIVATE_SERVER_SOCKET_PATH=
ADB_PRIVATE_SERVER_SOCKET_SPEC=
ADB_PRIVATE_SERVER_PID=
ADB_PROTOCOL_STOP_REQUESTED=0
EMULATOR_PROTOCOL_STOP_REQUESTED=0
ANDROID_COMMAND_CAPABILITY_ARMED=0
ANDROID_RUNTIME_RECOVERY_ARMED=0
ANDROID_RUNTIME_RECOVERY_PRESERVE=0
ANDROID_RUNTIME_CLEANUP_COMPLETED=0
ANDROID_PROOF_EVIDENCE_CONFIRMED=0
trap cleanup_exit EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
TARGET_SDK=$(python3 - "$ANDROID_PLATFORM" <<'PY'
import pathlib
import re
import sys

name = pathlib.Path(sys.argv[1]).name
match = re.search(r"android-(\d+)", name)
if not match:
    raise SystemExit(f"error: cannot derive target SDK from Android platform name: {name}")
print(match.group(1))
PY
)

printf '\n=== Build temporary Android smoke APK ===\n'
find "$SRC" -name '*.java' -print | LC_ALL=C sort >"$APP_SOURCES"
test -s "$APP_SOURCES" || {
	printf 'error: no Android smoke Java sources generated\n' >&2
	exit 1
}
javac --release 11 -Xlint:all -Werror \
	-cp "$ANDROID_JAR:$safe_unzip_dir/classes.jar" \
	-d "$CLASSES" \
	@"$APP_SOURCES"
python3 - "$CLASSES" "$APP_CLASSES_JAR" <<'PY'
import pathlib
import sys
import zipfile

classes = pathlib.Path(sys.argv[1])
out = pathlib.Path(sys.argv[2])
epoch = (2000, 1, 1, 0, 0, 0)
with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
    for path in sorted(p for p in classes.rglob("*") if p.is_file()):
        rel = path.relative_to(classes).as_posix()
        info = zipfile.ZipInfo(rel, epoch)
        info.external_attr = 0o100644 << 16
        zf.writestr(info, path.read_bytes())
PY
"$D8" --min-api 23 --lib "$ANDROID_JAR" --output "$DEX" \
	"$safe_unzip_dir/classes.jar" "$APP_CLASSES_JAR"
test -f "$DEX/classes.dex" || {
	printf 'error: d8 did not produce classes.dex for smoke APK\n' >&2
	exit 1
}
"$AAPT2" link \
	--manifest "$WORK/AndroidManifest.xml" \
	-I "$ANDROID_JAR" \
	-A "$ASSETS" \
	--min-sdk-version 23 \
	--target-sdk-version "$TARGET_SDK" \
	--version-code 1 \
	--version-name "$VERSION" \
	-o "$BASE_APK"
test -f "$BASE_APK" || {
	printf 'error: aapt2 did not produce base APK\n' >&2
	exit 1
}
python3 - "$BASE_APK" "$DEX/classes.dex" "$APK_ROOT" "$UNSIGNED_APK" <<'PY'
import pathlib
import stat
import sys
import zipfile

base = pathlib.Path(sys.argv[1])
dex = pathlib.Path(sys.argv[2])
apk_root = pathlib.Path(sys.argv[3])
out = pathlib.Path(sys.argv[4])
epoch = (2000, 1, 1, 0, 0, 0)
seen = set()
with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as dst:
    with zipfile.ZipFile(base) as src:
        for info in src.infolist():
            name = info.filename
            if name in seen:
                raise SystemExit(f"error: duplicate APK entry from aapt2: {name}")
            parts = pathlib.PurePosixPath(name).parts
            if name.startswith("/") or name.startswith("\\") or ".." in parts:
                raise SystemExit(f"error: unsafe APK entry from aapt2: {name}")
            mode = (info.external_attr >> 16) & 0o777777
            if stat.S_ISLNK(mode) or stat.S_ISCHR(mode) or stat.S_ISBLK(mode) or stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode):
                raise SystemExit(f"error: unsafe APK file type from aapt2 for {name}: {oct(mode)}")
            entry = zipfile.ZipInfo(name, epoch)
            entry.external_attr = 0o100644 << 16
            dst.writestr(entry, src.read(info))
            seen.add(name)
    for name, path in [("classes.dex", dex)]:
        if name in seen:
            raise SystemExit(f"error: duplicate generated APK entry: {name}")
        entry = zipfile.ZipInfo(name, epoch)
        entry.external_attr = 0o100644 << 16
        dst.writestr(entry, path.read_bytes())
        seen.add(name)
    for path in sorted(p for p in apk_root.rglob("*") if p.is_file()):
        rel = path.relative_to(apk_root).as_posix()
        parts = pathlib.PurePosixPath(rel).parts
        if rel.startswith("/") or rel.startswith("\\") or ".." in parts:
            raise SystemExit(f"error: unsafe staged APK entry: {rel}")
        if rel in seen:
            raise SystemExit(f"error: duplicate staged APK entry: {rel}")
        entry = zipfile.ZipInfo(rel, epoch)
        entry.external_attr = 0o100644 << 16
        dst.writestr(entry, path.read_bytes())
        seen.add(rel)
required = {
    "AndroidManifest.xml",
    "classes.dex",
    "lib/arm64-v8a/libq_periapt_ffi_abi2.so",
    "lib/arm64-v8a/libqperiapt_jni_abi2.so",
    "lib/x86_64/libq_periapt_ffi_abi2.so",
    "lib/x86_64/libqperiapt_jni_abi2.so",
    "lib/armeabi-v7a/libq_periapt_ffi_abi2.so",
    "lib/armeabi-v7a/libqperiapt_jni_abi2.so",
    "lib/x86/libq_periapt_ffi_abi2.so",
    "lib/x86/libqperiapt_jni_abi2.so",
    "assets/signed-policy-vectors.json",
}
with zipfile.ZipFile(out) as zf:
    names = set(zf.namelist())
missing = sorted(required - names)
if missing:
    raise SystemExit("error: smoke APK missing required entries: " + ", ".join(missing))
legacy = sorted(
    name for name in names
    if name.endswith("/libq_periapt_ffi.so") or name.endswith("/libqperiapt_jni.so")
)
if legacy:
    raise SystemExit("error: smoke APK contains legacy ABI1 native names: " + ", ".join(legacy))
PY
"$ZIPALIGN" -f -P 16 4 "$UNSIGNED_APK" "$ALIGNED_APK"
keytool -genkeypair \
	-storetype PKCS12 \
	-keystore "$KEYSTORE" \
	-storepass android \
	-keypass android \
	-alias qperiapt-android-smoke \
	-dname "CN=QPeriapt Android Smoke,O=QPeriapt,C=US" \
	-keyalg RSA \
	-keysize 2048 \
	-validity 30 \
	-noprompt \
	>"$DIST/keytool.log" 2>&1
"$APKSIGNER" sign \
	--ks "$KEYSTORE" \
	--ks-pass pass:android \
	--key-pass pass:android \
	--out "$SIGNED_APK" \
	"$ALIGNED_APK"
rm -f -- "$KEYSTORE"
KEYSTORE=
(
	cd "$DIST"
	"$APKSIGNER" verify --min-sdk-version 23 --print-certs "$(basename "$SIGNED_APK")"
) >"$DIST/apksigner-verify.txt"
EXPECTED_APK_SIGNER_SHA256=$(PYTHONPATH=artifact python3 artifact/android_device_proof.py signer-sha256 \
	--apksigner-output "$DIST/apksigner-verify.txt")
SIGNED_APK_IDENTITY=$(apk_file_identity "$SIGNED_APK")
case "$SIGNED_APK_IDENTITY" in
	*:*:*)
		printf 'error: malformed Android smoke APK identity\n' >&2
		exit 2
		;;
	*:*) ;;
	*)
		printf 'error: Android smoke APK identity is missing its separator\n' >&2
		exit 2
		;;
esac
SIGNED_APK_BYTES=${SIGNED_APK_IDENTITY%%:*}
case "$SIGNED_APK_BYTES" in
	[1-9] | [1-9][0-9]*) ;;
	*)
		printf 'error: Android smoke APK byte length is not canonical\n' >&2
		exit 2
		;;
esac
(
	cd "$DIST"
	"$ZIPALIGN" -c -P 16 -v 4 "$(basename "$SIGNED_APK")"
) >"$DIST/zipalign-verify.txt"
printf 'PASS: temporary Android smoke APK built and signed\n'

adb_devices() {
	if ! devices_output=$(android_command list-devices); then
		printf 'error: cannot enumerate Android devices\n' >&2
		return 1
	fi
	printf '%s\n' "$devices_output" | awk '$2 == "device" { print $1 }'
}

redact_serials() {
	python3 -c '
import hashlib
import sys

for line in sys.stdin:
    serial = line.strip()
    if serial:
        digest = hashlib.sha256(serial.encode("utf-8")).hexdigest()[:12]
        print(f"sha256:{digest}")
'
}

capture_app_logcat() {
	raw_logcat="$DIST/logcat-raw.txt"
	if ! android_command capture-logcat; then
		printf 'error: failed to capture the run-bounded Android smoke log\n' >&2
		return 1
	fi
	PYTHONPATH=artifact python3 - "$raw_logcat" "$RUN_ID" <<'PY'
import pathlib
import sys

from evidence_io import read_regular_snapshot

path = pathlib.Path(sys.argv[1])
run_id = sys.argv[2]
snapshot = read_regular_snapshot(
    path,
    maximum=16 * 1024 * 1024,
    label="Android run-bounded logcat",
)
try:
    text = snapshot.data.decode("utf-8")
except UnicodeDecodeError as exc:
    raise SystemExit(f"error: Android run-bounded logcat is not UTF-8: {exc}") from exc
needle = f"run-id={run_id}"
for line in text.splitlines():
    if line.startswith("--------- beginning of ") or needle in line:
        print(line)
PY
}

select_serial_or_empty() {
	set +e
	selected=$(choose_device_serial)
	rc=$?
	set -e
	case "$rc" in
		0)
			printf '%s\n' "$selected"
			;;
		1)
			printf '\n'
			;;
		*)
			exit "$rc"
			;;
	esac
}

choose_device_serial() {
	if [ -n "${QPERIAPT_ANDROID_SERIAL:-}" ]; then
		printf '%s\n' "$QPERIAPT_ANDROID_SERIAL"
		return
	fi
	if ! devices=$(adb_devices); then
		exit 2
	fi
	count=$(printf '%s\n' "$devices" | sed '/^$/d' | wc -l | tr -d ' ')
	if [ "$count" = "0" ]; then
		return 1
	fi
	printf 'error: refusing automatic Android device selection; set QPERIAPT_ANDROID_SERIAL for a physical run or detach devices before booting the owned AVD\n' >&2
	printf '%s\n' "$devices" | redact_serials >&2
	exit 2
}

printf '\n=== Select Android runtime device ===\n'
assert_default_adb_server_absent
ADB_PRIVATE_DIRECTORY_SIGNAL=0
trap 'ADB_PRIVATE_DIRECTORY_SIGNAL=129' HUP
trap 'ADB_PRIVATE_DIRECTORY_SIGNAL=130' INT
trap 'ADB_PRIVATE_DIRECTORY_SIGNAL=143' TERM
if ADB_PRIVATE_SERVER_DIRECTORY=$(/usr/bin/mktemp -d /tmp/qperiapt-adb.XXXXXXXX); then
	ADB_PRIVATE_SERVER_SOCKET_NONCE=${ADB_PRIVATE_SERVER_DIRECTORY##*.}
	ADB_PRIVATE_SERVER_SOCKET_PATH="$ADB_PRIVATE_SERVER_DIRECTORY/adb.sock"
	ADB_PRIVATE_SERVER_SOCKET_SPEC="localfilesystem:$ADB_PRIVATE_SERVER_SOCKET_PATH"
	ADB_PRIVATE_VENDOR_KEY="$HOME/.android/adbkey"
	ADB_PRIVATE_SERVER_CLEANUP_ARMED=1
	private_adb_directory_status=0
else
	private_adb_directory_status=$?
fi
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
if [ "$private_adb_directory_status" -ne 0 ]; then
	printf 'error: cannot create private adb server directory\n' >&2
	exit "$private_adb_directory_status"
fi
if [ "$ADB_PRIVATE_DIRECTORY_SIGNAL" -ne 0 ]; then
	exit "$ADB_PRIVATE_DIRECTORY_SIGNAL"
fi
/bin/chmod 0700 "$ADB_PRIVATE_SERVER_DIRECTORY"
python3 artifact/android_device_proof.py verify-private-adb-socket \
	--directory "$ADB_PRIVATE_SERVER_DIRECTORY" \
	--state absent >/dev/null
export ADB_SERVER_SOCKET="$ADB_PRIVATE_SERVER_SOCKET_SPEC"
export ADB_VENDOR_KEYS="$ADB_PRIVATE_VENDOR_KEY"
export ADB_MDNS=0
export ADB_MDNS_AUTO_CONNECT=0
export ADB_LOCAL_TRANSPORT_MAX_PORT=5585
if [ "$EXPECTED_DEVICE_KIND" = "physical" ]; then
	export ADB_USB=1
else
	export ADB_USB=0
fi
# The owned emulator is registered explicitly only after its child identity and
# fixed listeners are verified.  The private server must not auto-scan ports.
export ADB_EMU=0
SIGNED_APK_SHA256=${SIGNED_APK_IDENTITY#*:}
ANDROID_CAPABILITY_CREATE_SIGNAL=0
trap 'ANDROID_CAPABILITY_CREATE_SIGNAL=129' HUP
trap 'ANDROID_CAPABILITY_CREATE_SIGNAL=130' INT
trap 'ANDROID_CAPABILITY_CREATE_SIGNAL=143' TERM
ANDROID_COMMAND_CAPABILITY_ARMED=1
if PYTHONPATH=artifact python3 artifact/android_bounded_command.py create-capability \
	--adb-profile "$ADB_PROFILE" \
	--socket-nonce "$ADB_PRIVATE_SERVER_SOCKET_NONCE" \
	--device-kind "$EXPECTED_DEVICE_KIND" \
	--expected-serial "$EXPECTED_COMMAND_SERIAL" \
	--run-id "$RUN_ID" \
	--signed-apk-size "$SIGNED_APK_BYTES" \
	--signed-apk-sha256 "$SIGNED_APK_SHA256"; then
	android_capability_create_status=0
else
	android_capability_create_status=$?
fi
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
if [ "$android_capability_create_status" -ne 0 ]; then
	exit "$android_capability_create_status"
fi
if [ "$ANDROID_CAPABILITY_CREATE_SIGNAL" -ne 0 ]; then
	exit "$ANDROID_CAPABILITY_CREATE_SIGNAL"
fi
PYTHONPATH=artifact python3 artifact/android_bounded_command.py \
	create-runtime-recovery --run-id "$RUN_ID"
ANDROID_RUNTIME_RECOVERY_ARMED=1
ADB_SNAPSHOT=$(PYTHONPATH=artifact python3 artifact/android_bounded_command.py \
	capability-adb-path --run-id "$RUN_ID")
if [ "$ADB_SNAPSHOT" != "$WORK/adb-$RUN_ID" ]; then
	printf 'error: private adb snapshot path differs from this run identity: %s\n' \
		"$ADB_SNAPSHOT" >&2
	exit 2
fi
ADB_PRIVATE_SERVER_PYTHON_CACHE="$ADB_PRIVATE_SERVER_DIRECTORY/python-cache"
if [ -e "$ADB_PRIVATE_SERVER_PYTHON_CACHE" ] || [ -L "$ADB_PRIVATE_SERVER_PYTHON_CACHE" ]; then
	printf 'error: private adb Python cache path already exists\n' >&2
	exit 2
fi
ADB_SERVER_START_SIGNAL=0
trap 'ADB_SERVER_START_SIGNAL=129' HUP
trap 'ADB_SERVER_START_SIGNAL=130' INT
trap 'ADB_SERVER_START_SIGNAL=143' TERM

# The hardened python3 shell function owns a cleanup wrapper process.  This
# long-lived exec path must instead launch the already-validated interpreter
# directly so $! remains the PID that Python later execs into adb.
"$QPERIAPT_PYTHON" -I -S -B -X "pycache_prefix=$ADB_PRIVATE_SERVER_PYTHON_CACHE" \
	"$QPERIAPT_PYTHON_BOOTSTRAP" artifact/android_bounded_command.py server-nodaemon \
	--run-id "$RUN_ID" \
	>"$DIST/adb-server.log" 2>&1 &
ADB_PRIVATE_SERVER_PID=$!
# The owned child inherited its lane-specific transport scanners at spawn. All
# subsequent clients disable scanners so an auto-started replacement is inert.
export ADB_USB=0
export ADB_EMU=0
printf 'private-adb: pid=%s socket=%s\n' \
	"$ADB_PRIVATE_SERVER_PID" "$ADB_PRIVATE_SERVER_SOCKET_PATH" >&2
set +e
ADB_SERVER_START_IDENTITY=$(PYTHONPATH=artifact python3 \
	artifact/android_bounded_command.py wait-owned-adb-server-start \
	--run-id "$RUN_ID" \
	--timeout-seconds 15 \
	2>"$DIST/adb-server-start-handshake.err")
ADB_SERVER_START_HANDSHAKE_STATUS=$?
set -e

if [ "$ADB_SERVER_START_HANDSHAKE_STATUS" -eq 0 ]; then
	ADB_SERVER_START_PID=${ADB_SERVER_START_IDENTITY%%:*}
	if [ "$ADB_SERVER_START_PID" != "$ADB_PRIVATE_SERVER_PID" ]; then
		printf 'error: private adb receipt advanced for a different child\n' >&2
		ADB_SERVER_START_HANDSHAKE_STATUS=2
	fi
fi
if [ "$ADB_SERVER_START_HANDSHAKE_STATUS" -ne 0 ]; then
	ANDROID_RUNTIME_RECOVERY_PRESERVE=1
fi
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
if [ "$ADB_SERVER_START_HANDSHAKE_STATUS" -ne 0 ]; then
	printf 'error: private adb child did not durably advance its recovery receipt; preserving recovery state\n' >&2
	if [ "$ADB_SERVER_START_SIGNAL" -ne 0 ]; then
		exit "$ADB_SERVER_START_SIGNAL"
	fi
	exit "$ADB_SERVER_START_HANDSHAKE_STATUS"
fi
if [ "$ADB_SERVER_START_SIGNAL" -ne 0 ]; then
	exit "$ADB_SERVER_START_SIGNAL"
fi
ADB_PRIVATE_SERVER_READY_DEADLINE=$(monotonic_deadline 15)
while [ ! -S "$ADB_PRIVATE_SERVER_SOCKET_PATH" ] && \
	private_adb_process_active && \
	remaining_bounded_timeout "$ADB_PRIVATE_SERVER_READY_DEADLINE" 1 >/dev/null; do
	sleep 0.1
done
if [ -e "$ADB_PRIVATE_SERVER_PYTHON_CACHE" ] || [ -L "$ADB_PRIVATE_SERVER_PYTHON_CACHE" ]; then
	printf 'error: private adb Python cache path appeared during server launch\n' >&2
	exit 2
fi
python3 artifact/android_device_proof.py verify-private-adb-socket \
	--directory "$ADB_PRIVATE_SERVER_DIRECTORY" \
	--state present >/dev/null
ADB_LISTENER_INITIAL="$DIST/adb-listener-initial.txt"
android_command lsof-initial
ADB_PRIVATE_SERVER_PROCESS_IDENTITY=$(python3 artifact/android_device_proof.py verify-adb-listener \
	--lsof-output "$ADB_LISTENER_INITIAL" \
	--run-id "$RUN_ID" \
	--adb "$ADB_SNAPSHOT" \
	--expected-endpoint "$ADB_PRIVATE_SERVER_SOCKET_PATH" \
	--expected-pid "$ADB_PRIVATE_SERVER_PID" \
	--expected-server-socket "$ADB_PRIVATE_SERVER_SOCKET_SPEC" \
	--expected-vendor-keys "$ADB_PRIVATE_VENDOR_KEY" \
	--expected-mdns 0 \
	--expected-transport-kind "$EXPECTED_DEVICE_KIND")
if [ "$ADB_PRIVATE_SERVER_PROCESS_IDENTITY" != "$ADB_SERVER_START_IDENTITY" ]; then
	printf 'error: private adb listener identity differs from its startup receipt\n' >&2
	exit 2
fi
PYTHONPATH=artifact python3 artifact/android_bounded_command.py \
	seal-private-adb-directory --run-id "$RUN_ID" >/dev/null
ADB_SERVER_STATUS_BEFORE="$DIST/adb-server-status-before.txt"
android_command server-status-before
python3 artifact/android_device_proof.py verify-adb-server-status \
	--status "$ADB_SERVER_STATUS_BEFORE" \
	--adb "$ADB_SNAPSHOT" \
	--home-directory "$HOME"
ADB_LISTENER_BEFORE="$DIST/adb-listener-before.txt"
android_command lsof-before
ADB_LISTENER_IDENTITY=$(python3 artifact/android_device_proof.py verify-adb-listener \
	--lsof-output "$ADB_LISTENER_BEFORE" \
	--run-id "$RUN_ID" \
	--adb "$ADB_SNAPSHOT" \
	--expected-endpoint "$ADB_PRIVATE_SERVER_SOCKET_PATH" \
	--expected-pid "$ADB_PRIVATE_SERVER_PID" \
	--expected-identity "$ADB_PRIVATE_SERVER_PROCESS_IDENTITY" \
	--expected-server-socket "$ADB_PRIVATE_SERVER_SOCKET_SPEC" \
	--expected-vendor-keys "$ADB_PRIVATE_VENDOR_KEY" \
	--expected-mdns 0 \
	--expected-transport-kind "$EXPECTED_DEVICE_KIND")
EMULATOR_STARTED=0
EMULATOR_PROCESS_IDENTITY=
SERIAL=$(select_serial_or_empty)
if [ "$ANDROID_BOOT_AVD" = "1" ]; then
	if [ -n "$SERIAL" ]; then
		printf 'error: refusing to boot a proof AVD while another adb device is already online\n' >&2
		exit 2
	fi
	EXPECTED_EMULATOR_SERIAL=$EXPECTED_COMMAND_SERIAL
	if [ ! -x "$EMULATOR" ]; then
		printf 'error: Android emulator not found: %s\n' "$EMULATOR" >&2
		exit 2
	fi
	printf 'boot-avd : %s\n' "$ANDROID_AVD_NAME"
	EMULATOR_PYTHON_CACHE="$WORK/emulator-python-cache"
	if [ -e "$EMULATOR_PYTHON_CACHE" ] || [ -L "$EMULATOR_PYTHON_CACHE" ]; then
		printf 'error: owned emulator Python cache path already exists\n' >&2
		exit 2
	fi
	EMULATOR_START_SIGNAL=0
	trap 'EMULATOR_START_SIGNAL=129' HUP
	trap 'EMULATOR_START_SIGNAL=130' INT
	trap 'EMULATOR_START_SIGNAL=143' TERM
	"$QPERIAPT_PYTHON" -I -S -B -X "pycache_prefix=$EMULATOR_PYTHON_CACHE" \
		"$QPERIAPT_PYTHON_BOOTSTRAP" artifact/android_bounded_command.py \
		emulator-nodaemon \
		--run-id "$RUN_ID" \
		--device-abi "$EXPECTED_DEVICE_ABI" \
		>"$DIST/emulator.log" 2>&1 &
	EMULATOR_PID=$!
	EMULATOR_STARTED=1
	trap 'exit 129' HUP
	trap 'exit 130' INT
	trap 'exit 143' TERM
	if [ "$EMULATOR_START_SIGNAL" -ne 0 ]; then
		exit "$EMULATOR_START_SIGNAL"
	fi
	EMULATOR_PROCESS_IDENTITY=$(PYTHONPATH=artifact python3 \
		artifact/android_bounded_command.py wait-owned-emulator-backend \
		--run-id "$RUN_ID" \
		--timeout-seconds 10)
	EMULATOR_RECEIPT_PID=${EMULATOR_PROCESS_IDENTITY%%:*}
	if [ "$EMULATOR_RECEIPT_PID" != "$EMULATOR_PID" ]; then
		printf 'error: emulator receipt advanced for a different child\n' >&2
		exit 2
	fi
	EMULATOR_BACKEND_FILE_IDENTITY=$(PYTHONPATH=artifact python3 \
		artifact/android_bounded_command.py owned-emulator-backend-identity \
		--run-id "$RUN_ID")
	EMULATOR_BACKEND_DEVICE=${EMULATOR_BACKEND_FILE_IDENTITY%%:*}
	EMULATOR_BACKEND_IDENTITY_REMAINDER=${EMULATOR_BACKEND_FILE_IDENTITY#*:}
	EMULATOR_BACKEND_INODE=${EMULATOR_BACKEND_IDENTITY_REMAINDER%%:*}
	EMULATOR_BACKEND_SHA256=${EMULATOR_BACKEND_IDENTITY_REMAINDER#*:}
	if [ -e "$EMULATOR_PYTHON_CACHE" ] || [ -L "$EMULATOR_PYTHON_CACHE" ]; then
		printf 'error: owned emulator Python cache path appeared during launch\n' >&2
		exit 2
	fi
	if ! wait_for_owned_emulator_listeners 90; then
		exit 1
	fi
	if ! wait_for_owned_emulator_registration 30; then
		exit 1
	fi
	ADB_SERVER_STATUS_REGISTERED="$DIST/adb-server-status-registered.txt"
	android_command server-status-registered
	python3 artifact/android_device_proof.py verify-adb-server-status \
		--status "$ADB_SERVER_STATUS_REGISTERED" \
		--adb "$ADB_SNAPSHOT" \
		--home-directory "$HOME"
	ADB_LISTENER_REGISTERED="$DIST/adb-listener-registered.txt"
	android_command lsof-registered
	python3 artifact/android_device_proof.py verify-adb-listener \
		--lsof-output "$ADB_LISTENER_REGISTERED" \
		--run-id "$RUN_ID" \
		--adb "$ADB_SNAPSHOT" \
		--expected-endpoint "$ADB_PRIVATE_SERVER_SOCKET_PATH" \
		--expected-pid "$ADB_PRIVATE_SERVER_PID" \
		--expected-identity "$ADB_LISTENER_IDENTITY" \
		--expected-server-socket "$ADB_PRIVATE_SERVER_SOCKET_SPEC" \
		--expected-vendor-keys "$ADB_PRIVATE_VENDOR_KEY" \
		--expected-mdns 0 \
		--expected-transport-kind "$EXPECTED_DEVICE_KIND" >/dev/null
	PYTHONPATH=artifact python3 artifact/android_bounded_command.py \
		record-owned-emulator-routing --run-id "$RUN_ID" >/dev/null
	PYTHONPATH=artifact python3 artifact/android_bounded_command.py \
		record-adb-isolation-checkpoint \
		--run-id "$RUN_ID" \
		--checkpoint emulator_post_registration >/dev/null
	EMULATOR_ADB_DEADLINE=$(monotonic_deadline 90)
	while emulator_attempt_timeout=$(remaining_bounded_timeout "$EMULATOR_ADB_DEADLINE" 10); do
		if ! emulator_process_active; then
			printf 'error: temporary Android emulator exited before its bound adb serial became available\n' >&2
			exit 1
		fi
		if emulator_state=$(android_command device-state \
			--timeout-seconds "$emulator_attempt_timeout" 2>/dev/null) \
			&& [ "$emulator_state" = "device" ]; then
			SERIAL=$EXPECTED_EMULATOR_SERIAL
			break
		fi
		if remaining_bounded_timeout "$EMULATOR_ADB_DEADLINE" 1 >/dev/null; then
			sleep 1
		fi
	done
	if [ -z "$SERIAL" ]; then
		if ! "$EMULATOR" -accel-check >"$DIST/emulator-accel-check.log" 2>&1; then
			printf 'note: emulator acceleration diagnostic also failed; see %s\n' "$DIST/emulator-accel-check.log" >&2
		fi
		printf 'error: emulator did not appear in adb devices within 90 seconds\n' >&2
		exit 1
	fi
fi
if [ -z "$SERIAL" ]; then
	printf 'error: no Android adb device available\n' >&2
	printf 'hint : set an explicit physical serial/kind, or run with QPERIAPT_ANDROID_BOOT_AVD=1 QPERIAPT_ANDROID_EXPECT_DEVICE_KIND=emulator QPERIAPT_ANDROID_EXPECT_ABI=<abi>; the AVD name is code-selected from the fixed profile and ABI\n' >&2
	exit 2
fi
if ! authorized_state=$(android_command device-state 2>"$DIST/adb-authorization.err"); then
	printf 'error: target Android device was not already authorized; do not accept a new authorization prompt during proof\n' >&2
	exit 2
fi
if [ "$authorized_state" != "device" ]; then
	printf 'error: target Android device state is not authorized/device: %s\n' "$authorized_state" >&2
	exit 2
fi
SERIAL_SHA256_PREFIX=$(python3 - "$SERIAL" <<'PY'
import hashlib
import sys

print(hashlib.sha256(sys.argv[1].encode("utf-8")).hexdigest()[:12])
PY
)

BOOT_COMPLETION_DEADLINE=$(monotonic_deadline 120)
booted=
while boot_attempt_timeout=$(remaining_bounded_timeout "$BOOT_COMPLETION_DEADLINE" 15); do
	booted=$(android_command boot-completed \
		--timeout-seconds "$boot_attempt_timeout" | tr -d '\r')
	if [ "$booted" = "1" ]; then
		break
	fi
	if remaining_bounded_timeout "$BOOT_COMPLETION_DEADLINE" 1 >/dev/null; then
		sleep 1
	fi
done
if [ "$booted" != "1" ]; then
	printf 'error: Android device did not complete boot within 120 seconds: sha256:%s\n' "$SERIAL_SHA256_PREFIX" >&2
	exit 1
fi
qemu=$(android_command qemu-kind | tr -d '\r')
if [ "$qemu" = "1" ]; then
	DEVICE_KIND=emulator
else
	DEVICE_KIND=physical
fi
if [ "$ANDROID_RELEASE_MODE" = "1" ] && [ "$DEVICE_KIND" = "emulator" ] && [ "$EMULATOR_STARTED" != "1" ]; then
	printf 'error: Android release emulator proof must use the script-started cold-boot AVD\n' >&2
	exit 2
fi
case "$EXPECTED_DEVICE_KIND" in
	any) ;;
	emulator | physical)
		if [ "$EXPECTED_DEVICE_KIND" != "$DEVICE_KIND" ]; then
			printf 'error: Android device kind mismatch: expected %s, got %s\n' "$EXPECTED_DEVICE_KIND" "$DEVICE_KIND" >&2
			exit 1
		fi
		;;
esac
if [ "$DEVICE_KIND" = "physical" ]; then
	DEVICE_DEVPATH_FILE="$DIST/adb-device-devpath.txt"
	android_command device-devpath
	DEVICE_TRANSPORT=$(PYTHONPATH=artifact python3 - "$DEVICE_DEVPATH_FILE" <<'PY'
import pathlib
import re
import sys

from evidence_io import read_regular_snapshot

snapshot = read_regular_snapshot(
    pathlib.Path(sys.argv[1]), maximum=4096, label="Android adb device path"
)
try:
    value = snapshot.data.decode("utf-8").replace("\r", "").removesuffix("\n")
except UnicodeDecodeError as exc:
    raise SystemExit(f"error: Android adb device path is not UTF-8: {exc}") from exc
if re.fullmatch(r"usb:[A-Za-z0-9._:/-]{1,512}", value) is None:
    raise SystemExit(f"error: physical Android evidence requires one USB transport: {value!r}")
print("usb")
PY
	)
else
	DEVICE_TRANSPORT=emulator-local
fi
DEVICE_ABI=$(android_command device-abi | tr -d '\r\n ')
case "$DEVICE_ABI" in
	arm64-v8a | x86_64 | armeabi-v7a | x86) ;;
	*)
		printf 'error: unsupported or missing Android primary ABI from device: %s\n' "$DEVICE_ABI" >&2
		exit 1
		;;
esac
PAGE_SIZE=$(android_command page-size | tr -d '\r\n ')
case "$PAGE_SIZE" in
	4096 | 16384) ;;
	*)
		printf 'error: Android device PAGE_SIZE must be exactly 4096 or 16384, got %s\n' "$PAGE_SIZE" >&2
		exit 1
		;;
esac
DEVICE_SDK=$(android_command device-sdk | tr -d '\r\n ')
case "$DEVICE_SDK" in
	[1-9] | [1-9][0-9] | [1-9][0-9][0-9]) ;;
	*)
		printf 'error: Android device SDK must be a canonical integer between 1 and 999, got %s\n' "$DEVICE_SDK" >&2
		exit 1
		;;
esac
if [ -n "$EXPECTED_DEVICE_ABI" ] && [ "$DEVICE_ABI" != "$EXPECTED_DEVICE_ABI" ]; then
	printf 'error: Android device ABI mismatch: expected %s, got %s\n' "$EXPECTED_DEVICE_ABI" "$DEVICE_ABI" >&2
	exit 1
fi
if [ -n "$EXPECTED_PAGE_SIZE" ] && [ "$PAGE_SIZE" != "$EXPECTED_PAGE_SIZE" ]; then
	printf 'error: Android device PAGE_SIZE mismatch: expected %s, got %s\n' "$EXPECTED_PAGE_SIZE" "$PAGE_SIZE" >&2
	exit 1
fi
if [ -n "$EXPECTED_DEVICE_SDK" ] && [ "$DEVICE_SDK" != "$EXPECTED_DEVICE_SDK" ]; then
	printf 'error: Android device SDK mismatch: expected %s, got %s\n' "$EXPECTED_DEVICE_SDK" "$DEVICE_SDK" >&2
	exit 1
fi
printf 'serial   : sha256:%s\n' "$SERIAL_SHA256_PREFIX"
printf 'kind     : %s\n' "$DEVICE_KIND"
printf 'transport: %s\n' "$DEVICE_TRANSPORT"
printf 'abi      : %s\n' "$DEVICE_ABI"
printf 'page-size: %s\n' "$PAGE_SIZE"
printf 'sdk      : %s\n' "$DEVICE_SDK"

printf '\n=== Install and run Android runtime smoke ===\n'
if ! : >"$PACKAGE_OBSERVATION_LOG"; then
	printf 'error: cannot initialize the sanitized Android package observation journal\n' >&2
	exit 1
fi
if ! : >"$DIST/adb-uninstall-cleanup.log"; then
	printf 'error: cannot reset Android app cleanup log\n' >&2
	exit 1
fi
if observe_preinstall_package_absence; then
	:
else
	preinstall_observation_status=$?
	exit "$preinstall_observation_status"
fi
ANDROID_APP_CLEANUP_ARMED=1
if ! android_command install-apk >"$DIST/adb-install.log"; then
	printf 'error: Android smoke APK installation failed\n' >&2
	exit 1
fi
POSTINSTALL_OWNERSHIP_DEADLINE=$(monotonic_deadline 45)
if observe_owned_installed_package "$POSTINSTALL_OWNERSHIP_DEADLINE" postinstall 1; then
	:
else
	postinstall_ownership_status=$?
	printf 'error: installed Android smoke package ownership did not converge (exit=%s)\n' \
		"$postinstall_ownership_status" >&2
	exit "$postinstall_ownership_status"
fi
ANDROID_APP_INSTALL_CONFIRMED=1
if android_command device-time 2>"$DIST/adb-device-time.err"; then
	:
else
	device_time_status=$?
	printf 'error: Android runtime device-time capture failed (exit=%s); see %s\n' \
		"$device_time_status" "$DIST/adb-device-time.err" >&2
	exit 1
fi
LOGCAT_START_EPOCH=$(tr -d '\r\n ' <"$DIST/adb-device-time.txt")
python3 - "$LOGCAT_START_EPOCH" <<'PY'
import re
import sys

value = sys.argv[1]
if re.fullmatch(r"[1-9][0-9]{9,12}\.[0-9]{3}", value) is None:
    raise SystemExit(f"error: Android device returned a non-canonical logcat start time: {value}")
PY
if android_command force-stop >"$DIST/adb-force-stop.log" 2>&1; then
	:
else
	force_stop_status=$?
	printf 'error: Android runtime force-stop failed (exit=%s); see %s\n' \
		"$force_stop_status" "$DIST/adb-force-stop.log" >&2
	exit 1
fi
if android_command start-app >"$DIST/adb-start.log" 2>&1; then
	:
else
	start_app_status=$?
	printf 'error: Android runtime activity start failed (exit=%s); see %s\n' \
		"$start_app_status" "$DIST/adb-start.log" >&2
	exit 1
fi
RUNTIME_RESULT_DEADLINE=$(monotonic_deadline 90)
while result_attempt_timeout=$(remaining_bounded_timeout "$RUNTIME_RESULT_DEADLINE" 15); do
	set +e
	android_command read-result-text \
		--timeout-seconds "$result_attempt_timeout" 2>"$DIST/result-read.err"
	read_rc=$?
	set -e
	if [ "$read_rc" -eq 0 ]; then
		if grep -Fx "$EXPECTED_MARKER" "$RESULT_TXT.tmp" >/dev/null 2>&1; then
			mv "$RESULT_TXT.tmp" "$RESULT_TXT"
			break
		fi
		if grep -F "QPERIAPT_ANDROID_DEVICE_FAIL run-id=$RUN_ID" "$RESULT_TXT.tmp" >/dev/null 2>&1; then
			mv "$RESULT_TXT.tmp" "$RESULT_TXT"
			android_command read-result-json 2>"$DIST/result-json-read.err"
			capture_app_logcat >"$DIST/logcat.txt"
			printf 'error: Android runtime smoke reported failure; see %s and %s\n' "$RESULT_JSON" "$DIST/logcat.txt" >&2
			exit 1
		fi
	fi
	if remaining_bounded_timeout "$RUNTIME_RESULT_DEADLINE" 1 >/dev/null; then
		sleep 1
	fi
done
rm -f "$RESULT_TXT.tmp"
test -f "$RESULT_TXT" || {
	capture_app_logcat >"$DIST/logcat.txt"
	printf 'error: did not receive Android runtime PASS marker within 90 seconds; see %s\n' "$DIST/logcat.txt" >&2
	exit 1
}
android_command read-result-json
capture_app_logcat >"$DIST/logcat.txt"
if grep -E 'QPERIAPT_ANDROID_DEVICE_FAIL|FATAL EXCEPTION|JNI DETECTED ERROR|UnsatisfiedLinkError|NoSuchMethodError|NoClassDefFoundError|SIGSEGV|signal 11' "$DIST/logcat.txt" >/dev/null 2>&1; then
	printf 'error: Android logcat contains a runtime failure marker; see %s\n' "$DIST/logcat.txt" >&2
	exit 1
fi
if cleanup_android_app; then
	:
else
	app_cleanup_status=$?
	printf 'error: run-owned Android smoke app cleanup failed\n' >&2
	exit "$app_cleanup_status"
fi

PYTHONPATH=artifact python3 - "$RESULT_TXT" "$RESULT_JSON" "$RUN_ID" <<'PY'
import pathlib
import sys

from evidence_io import load_json_object_snapshot

txt = pathlib.Path(sys.argv[1]).read_text()
payload = load_json_object_snapshot(
    pathlib.Path(sys.argv[2]), label="Android device result"
).value
run_id = sys.argv[3]
expected_tests = [
    "runtimeMetadataMatches",
    "signedPolicyDecisionIsExactAndFailClosed",
    "osRandomPolicyRoundtripAndWipes",
]
expected_marker = f"QPERIAPT_ANDROID_DEVICE_PASS run-id={run_id} tests={len(expected_tests)}\n"
if txt != expected_marker:
    raise SystemExit(f"error: unexpected Android result marker: {txt!r}")
if payload.get("schema") != 1:
    raise SystemExit("error: unexpected Android result schema")
if payload.get("status") != "pass":
    raise SystemExit(f"error: Android result status is not pass: {payload.get('status')}")
if payload.get("run_id") != run_id:
    raise SystemExit("error: Android result run_id mismatch")
if payload.get("test_count") != len(expected_tests):
    raise SystemExit("error: Android result test_count mismatch")
if payload.get("passed_tests") != expected_tests:
    raise SystemExit("error: Android result passed_tests mismatch")
PY
printf 'PASS: Android runtime smoke returned run-bound marker\n'

printf '\n=== Capture final Android runtime metadata ===\n'
if [ "$DEVICE_KIND" = "physical" ]; then
	android_command device-devpath
fi
FINAL_DEVICE_ABI=$(android_command device-abi | tr -d '\r')
FINAL_PAGE_SIZE=$(android_command page-size | tr -d '\r')
FINAL_DEVICE_SDK=$(android_command device-sdk | tr -d '\r')
DEVICE_MANUFACTURER=$(android_command device-manufacturer | tr -d '\r')
DEVICE_MODEL=$(android_command device-model | tr -d '\r')
DEVICE_RELEASE=$(android_command device-release | tr -d '\r')
DEVICE_FINGERPRINT=$(android_command device-fingerprint | tr -d '\r')
ADB_VERSION=$(android_command adb-version | sed -n '1p' | tr -d '\r')
emit_android_runtime_proof() {
python3 - "$ROOT" "$RUN_ID" "$SERIAL" "$DEVICE_KIND" "$AAR_PATH" "$AAR_MANIFEST" "$SIGNED_APK" "$RESULT_TXT" "$RESULT_JSON" "$DIST/logcat.txt" "$PROOF_STAGING" "$PROOF_JSON" "$ANDROID_PLATFORM" "$ANDROID_BUILD_TOOLS" "$safe_unzip_dir" "$SOURCE_TREE_SHA256" "$DEVICE_ABI" "$PAGE_SIZE" "$DEVICE_SDK" "$NDK_REVISION" "$ANDROID_RELEASE_MODE" "$APKSIGNER" "$ZIPALIGN" "$FINAL_DEVICE_ABI" "$FINAL_PAGE_SIZE" "$FINAL_DEVICE_SDK" "$DEVICE_MANUFACTURER" "$DEVICE_MODEL" "$DEVICE_RELEASE" "$DEVICE_FINGERPRINT" "$ADB_VERSION" "$EMULATOR_BACKEND" "${ANDROID_EMULATOR_PORT:-}" "$EMULATOR_PROCESS_IDENTITY" "$ADB_LISTENER_IDENTITY" "$DIST/emulator-listeners.txt" "$DIST/adb-emulator-registration.txt" "${ADB_SERVER_STATUS_REGISTERED:-}" "${ADB_LISTENER_REGISTERED:-}" "$EMULATOR_BACKEND_DEVICE" "$EMULATOR_BACKEND_INODE" "$EMULATOR_BACKEND_SHA256" <<'PY'
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import sys

from artifact.android_device_proof import build_emulator_control_receipt
from artifact.android_emulator_control import (
    ADB_ISOLATION_CHECKPOINT_LEAVES,
    EMULATOR_ROUTING_RECEIPT_LEAF,
    AdbIsolationCheckpoint,
)
from artifact.claim_ledger import canonical_tree_digest, repository_paths
from artifact.evidence_io import load_json_object_snapshot, read_regular_snapshot
from artifact.git_provenance import git_commit, source_tree_dirty

root = pathlib.Path(sys.argv[1])
run_id = sys.argv[2]
serial = sys.argv[3]
device_kind = sys.argv[4]
aar = pathlib.Path(sys.argv[5])
aar_manifest = pathlib.Path(sys.argv[6])
apk = pathlib.Path(sys.argv[7])
result_txt = pathlib.Path(sys.argv[8])
result_json = pathlib.Path(sys.argv[9])
logcat = pathlib.Path(sys.argv[10])
proof = pathlib.Path(sys.argv[11])
proof_destination = pathlib.Path(sys.argv[12])
android_platform = pathlib.Path(sys.argv[13])
android_build_tools = pathlib.Path(sys.argv[14])
aar_extract = pathlib.Path(sys.argv[15])
source_tree_sha256 = sys.argv[16]
device_abi = sys.argv[17]
page_size = int(sys.argv[18])
device_sdk = int(sys.argv[19])
ndk_revision = sys.argv[20]
release_mode = sys.argv[21] == "1"
apksigner = pathlib.Path(sys.argv[22]).resolve()
zipalign = pathlib.Path(sys.argv[23]).resolve()
final_device_abi = sys.argv[24]
final_page_size_text = sys.argv[25]
final_device_sdk_text = sys.argv[26]
device_manufacturer = sys.argv[27]
device_model = sys.argv[28]
device_release = sys.argv[29]
device_fingerprint = sys.argv[30]
adb_version = sys.argv[31]
emulator_backend = pathlib.Path(sys.argv[32]) if sys.argv[32] else None
emulator_console_port = int(sys.argv[33]) if sys.argv[33] else None
emulator_process_identity = sys.argv[34]
private_adb_identity = sys.argv[35]
emulator_listener_path = pathlib.Path(sys.argv[36])
emulator_registration_path = pathlib.Path(sys.argv[37])
registered_adb_status_path = pathlib.Path(sys.argv[38]) if sys.argv[38] else None
registered_adb_listener_path = pathlib.Path(sys.argv[39]) if sys.argv[39] else None
emulator_backend_device = int(sys.argv[40]) if sys.argv[40] else None
emulator_backend_inode = int(sys.argv[41]) if sys.argv[41] else None
emulator_backend_sha256 = sys.argv[42] if sys.argv[42] else None

def sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def bounded_text(value: str, label: str, maximum_bytes: int = 4096) -> str:
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise SystemExit(f"error: {label} is not Unicode scalar text: {exc}") from exc
    if not value or len(encoded) > maximum_bytes:
        raise SystemExit(f"error: {label} is empty or oversized")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise SystemExit(f"error: {label} contains a control character")
    return value

def sha_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()

if device_kind == "physical":
    devpath_snapshot = read_regular_snapshot(
        proof_destination.parent / "adb-device-devpath.txt",
        maximum=4096,
        label="final Android adb device path",
    )
    try:
        final_devpath = devpath_snapshot.data.decode("utf-8").replace("\r", "").strip()
    except UnicodeDecodeError as exc:
        raise SystemExit(f"error: final Android transport is not UTF-8: {exc}") from exc
    if re.fullmatch(r"usb:[A-Za-z0-9._:/-]{1,512}", final_devpath) is None:
        raise SystemExit("error: physical Android transport changed before proof staging")
if final_device_abi != device_abi:
    raise SystemExit("error: Android device ABI changed while producing runtime proof")
if re.fullmatch(r"(?:4096|16384)", final_page_size_text) is None:
    raise SystemExit("error: Android device PAGE_SIZE became non-canonical")
if int(final_page_size_text) != page_size:
    raise SystemExit("error: Android device PAGE_SIZE changed while producing runtime proof")
if re.fullmatch(r"[1-9][0-9]{0,2}", final_device_sdk_text) is None:
    raise SystemExit(f"error: Android device SDK became invalid while producing runtime proof: {final_device_sdk_text!r}")
if int(final_device_sdk_text) != device_sdk:
    raise SystemExit("error: Android device SDK changed while producing runtime proof")
device_manufacturer = bounded_text(device_manufacturer, "Android manufacturer")
device_model = bounded_text(device_model, "Android model")
device_release = bounded_text(device_release, "Android release")
device_fingerprint = bounded_text(device_fingerprint, "Android fingerprint")
adb_version = bounded_text(adb_version, "adb version", 1024)

emulator_control = None
if device_kind == "emulator":
    if emulator_backend is None or registered_adb_status_path is None or registered_adb_listener_path is None:
        raise SystemExit("error: emulator proof lacks its verified control-plane inputs")
    if emulator_console_port is None:
        raise SystemExit("error: emulator proof lacks its fixed console port")
    emulator_control = build_emulator_control_receipt(
        backend_path=emulator_backend,
        backend_device=emulator_backend_device,
        backend_inode=emulator_backend_inode,
        backend_sha256=emulator_backend_sha256,
        device_abi=device_abi,
        console_port=emulator_console_port,
        process_identity=emulator_process_identity,
        listener_snapshot_path=emulator_listener_path,
        registration_response_path=emulator_registration_path,
        private_adb_identity=private_adb_identity,
        private_adb_status_path=registered_adb_status_path,
        private_adb_listener_path=registered_adb_listener_path,
        routing_receipt_path=proof_destination.parent / EMULATOR_ROUTING_RECEIPT_LEAF,
        adb_isolation_receipt_paths={
            checkpoint: proof_destination.parent
            / ADB_ISOLATION_CHECKPOINT_LEAVES[checkpoint]
            for checkpoint in AdbIsolationCheckpoint
        },
        run_id=run_id,
    )
elif any(
    (
        emulator_backend is not None,
        emulator_backend_device is not None,
        emulator_backend_inode is not None,
        emulator_backend_sha256 is not None,
        bool(emulator_process_identity),
        registered_adb_status_path is not None,
        registered_adb_listener_path is not None,
    )
):
    raise SystemExit("error: physical proof unexpectedly received emulator control-plane inputs")

target_sdk_match = re.search(r"android-(\d+)", android_platform.name)
if not target_sdk_match:
    raise SystemExit(f"error: cannot derive target SDK from Android platform name: {android_platform.name}")

native = {}
for abi_dir in sorted((aar_extract / "jni").iterdir()):
    if not abi_dir.is_dir():
        continue
    native[abi_dir.name] = {
        "ffi_so_sha256": sha256(abi_dir / "libq_periapt_ffi_abi2.so"),
        "jni_so_sha256": sha256(abi_dir / "libqperiapt_jni_abi2.so"),
    }

result_payload = load_json_object_snapshot(
    result_json, label="Android device result"
).value
current_source_tree_sha256 = canonical_tree_digest(root, repository_paths(root))
if current_source_tree_sha256 != source_tree_sha256:
    raise SystemExit(
        "error: canonical execution-input tree changed while Android runtime proof was running: "
        f"got {current_source_tree_sha256}, expected {source_tree_sha256}"
    )
source_paths = {
    "bounded_process": root / "artifact/bounded_process.py",
    "android_emulator_control": root / "artifact/android_emulator_control.py",
    "process_identity": root / "artifact/process_identity.py",
    "android_runtime_state": root / "artifact/android_runtime_state.py",
    "android_runtime_state_tests": root / "artifact/test_android_runtime_state.py",
    "android_bounded_command": root / "artifact/android_bounded_command.py",
    "android_bounded_command_tests": root / "artifact/test_android_bounded_command.py",
    "android_device_smoke_script": root / "artifact/android-device-smoke.sh",
    "android_device_proof": root / "artifact/android_device_proof.py",
    "proof_to_byte": root / "artifact/proof-to-byte.sh",
    "android_aar_script": root / "artifact/android-aar.sh",
    "android_elf_verifier": root / "artifact/android_elf.py",
    "release_binary_scan": root / "artifact/release_binary_scan.py",
    "third_party_license_collector": root / "artifact/third_party_licenses.py",
    "deterministic_archive": root / "artifact/deterministic_archive.py",
    "platform_release_contract": root / "artifact/platform_release_contract.py",
    "android_facade": root / "bindings/android/src/main/java/dev/qperiapt/android/QPeriaptAndroid.java",
    "android_jni_adapter": root / "bindings/android/jni/qperiapt_jni.c",
    "c_abi_contract": root / "crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json",
    "signed_policy_vectors": root / "bindings/signed-policy-vectors.json",
}

def rel(path: pathlib.Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()

proof_paths = {
    "aar": rel(aar),
    "aar_manifest": rel(aar_manifest),
    "smoke_apk": rel(apk),
    "apksigner_verify": rel(proof_destination.parent / "apksigner-verify.txt"),
    "zipalign_verify": rel(proof_destination.parent / "zipalign-verify.txt"),
    "result_txt": rel(result_txt),
    "result_json": rel(result_json),
    "logcat": rel(logcat),
}
if device_kind == "emulator":
    proof_paths.update(
        {
            "adb_isolation_emulator_pre_exec": rel(
                proof_destination.parent
                / ADB_ISOLATION_CHECKPOINT_LEAVES[
                    AdbIsolationCheckpoint.EMULATOR_PRE_EXEC
                ]
            ),
            "adb_isolation_emulator_post_registration": rel(
                proof_destination.parent
                / ADB_ISOLATION_CHECKPOINT_LEAVES[
                    AdbIsolationCheckpoint.EMULATOR_POST_REGISTRATION
                ]
            ),
            "adb_isolation_runtime_pre_cleanup": rel(
                proof_destination.parent
                / ADB_ISOLATION_CHECKPOINT_LEAVES[
                    AdbIsolationCheckpoint.RUNTIME_PRE_CLEANUP
                ]
            ),
            "adb_isolation_runtime_post_cleanup": rel(
                proof_destination.parent
                / ADB_ISOLATION_CHECKPOINT_LEAVES[
                    AdbIsolationCheckpoint.RUNTIME_POST_CLEANUP
                ]
            ),
            "emulator_routing": rel(
                proof_destination.parent / EMULATOR_ROUTING_RECEIPT_LEAF
            ),
        }
    )

payload = {
    "schema": 6,
    "generated_at": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
    "git_commit": git_commit(root),
    "source_tree_dirty": source_tree_dirty(root),
    "proof_source_tree_sha256": source_tree_sha256,
    "device_runtime_proof": True,
    "package_only": False,
    "release_candidate_mode": release_mode,
    "run_id": run_id,
    "package": "dev.qperiapt.androidsmoke",
    "paths": proof_paths,
    "device": {
        "kind": device_kind,
        "serial_sha256_prefix": sha_text(serial)[:12],
        "raw_serial_recorded": False,
        "manufacturer": device_manufacturer,
        "model": device_model,
        "abi": device_abi,
        "page_size": page_size,
        "sdk": device_sdk,
        "release": device_release,
        "fingerprint_sha256_prefix": sha_text(device_fingerprint)[:12],
    },
    "emulator_control": emulator_control,
    "android": {
        "platform": android_platform.name,
        "build_tools": android_build_tools.name,
        "ndk": ndk_revision,
        "native_page_alignment": 16384,
        "min_sdk": 23,
        "target_sdk": int(target_sdk_match.group(1)),
        "adb_version": adb_version,
        "apksigner_sha256": sha256(apksigner),
        "zipalign_sha256": sha256(zipalign),
    },
    "abi": {
        "major": 2,
        "contract_path": "crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json",
        "contract_sha256": sha256(root / "crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json"),
        "runtime_library": "libq_periapt_ffi_abi2.so",
        "jni_library": "libqperiapt_jni_abi2.so",
        "legacy_library_names_present": False,
    },
    "result": {
        "marker_sha256": sha256(result_txt),
        "json_sha256": sha256(result_json),
        "status": result_payload.get("status"),
        "test_count": result_payload.get("test_count"),
        "passed_tests": result_payload.get("passed_tests"),
    },
    "artifacts": {
        "aar_sha256": sha256(aar),
        "aar_manifest_sha256": sha256(aar_manifest),
        "smoke_apk_sha256": sha256(apk),
        "apksigner_verify_sha256": sha256(
            proof_destination.parent / "apksigner-verify.txt"
        ),
        "zipalign_verify_sha256": sha256(
            proof_destination.parent / "zipalign-verify.txt"
        ),
        "logcat_sha256": sha256(logcat),
        "native": native,
    },
    "source_hashes": {name + "_sha256": sha256(path) for name, path in source_paths.items()},
}
encoded_proof = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
descriptor = os.open(proof, flags, 0o600)
with os.fdopen(descriptor, "wb") as proof_file:
    proof_file.write(encoded_proof)
    proof_file.flush()
    os.fsync(proof_file.fileno())
PY
}
ADB_SERVER_STATUS_AFTER="$DIST/adb-server-status-after.txt"
android_command server-status-after
python3 artifact/android_device_proof.py verify-adb-server-status \
	--status "$ADB_SERVER_STATUS_AFTER" \
	--adb "$ADB_SNAPSHOT" \
	--home-directory "$HOME"
ADB_LISTENER_AFTER="$DIST/adb-listener-after.txt"
android_command lsof-after
python3 artifact/android_device_proof.py verify-adb-listener \
	--lsof-output "$ADB_LISTENER_AFTER" \
	--run-id "$RUN_ID" \
	--adb "$ADB_SNAPSHOT" \
	--expected-endpoint "$ADB_PRIVATE_SERVER_SOCKET_PATH" \
	--expected-pid "$ADB_PRIVATE_SERVER_PID" \
	--expected-identity "$ADB_LISTENER_IDENTITY" \
	--expected-server-socket "$ADB_PRIVATE_SERVER_SOCKET_SPEC" \
	--expected-vendor-keys "$ADB_PRIVATE_VENDOR_KEY" \
	--expected-mdns 0 \
	--expected-transport-kind "$EXPECTED_DEVICE_KIND" >/dev/null
assert_default_adb_server_absent
if [ "$DEVICE_KIND" = "emulator" ]; then
	PYTHONPATH=artifact python3 artifact/android_bounded_command.py \
		record-adb-isolation-checkpoint \
		--run-id "$RUN_ID" \
		--checkpoint runtime_pre_cleanup >/dev/null
fi
if cleanup_runtime_with_deferred_signals; then
	runtime_cleanup_status=0
else
	runtime_cleanup_status=$?
fi
if [ "$ANDROID_CLEANUP_SIGNAL" -ne 0 ]; then
	exit "$ANDROID_CLEANUP_SIGNAL"
fi
if [ "$runtime_cleanup_status" -ne 0 ]; then
	printf 'error: Android runtime cleanup failed before proof publication\n' >&2
	exit "$runtime_cleanup_status"
fi
if [ "$ANDROID_RUNTIME_CLEANUP_COMPLETED" != "1" ]; then
	printf 'error: Android runtime cleanup did not reach its confirmation point\n' >&2
	exit 1
fi
assert_default_adb_server_absent
printf '\n=== Emit Android runtime proof ===\n'
emit_android_runtime_proof
python3 artifact/android_device_proof.py publish-staged-proof \
	--staging "$PROOF_STAGING" \
	--destination "$PROOF_JSON"
python3 -m json.tool "$PROOF_JSON" >/dev/null
if [ "${QPERIAPT_ALLOW_DIRTY_ANDROID_DEVICE:-0}" = "1" ]; then
	set -- --allow-dirty-proof
else
	set --
fi
set -- "$@" --expected-device-abi "$DEVICE_ABI" --expected-page-size "$PAGE_SIZE" --expected-device-sdk "$DEVICE_SDK"
if [ "$ANDROID_RELEASE_MODE" = "1" ]; then
	set -- "$@" --require-release-mode
fi
PYTHONPATH=artifact python3 artifact/android_device_proof.py verify \
	--root "$ROOT" \
	--proof "$PROOF_JSON" \
	--expected-device-kind "$DEVICE_KIND" \
	"$@"
PYTHONPATH=artifact python3 artifact/android_device_proof.py create-bundle \
	--root "$ROOT" \
	--proof "$PROOF_JSON" \
	--output "$EVIDENCE_BUNDLE" \
	--llvm-nm "$LLVM_NM" \
	--llvm-readelf "$LLVM_READELF" \
	--apksigner "$APKSIGNER" \
	--zipalign "$ZIPALIGN" \
	--forbid-text "$SERIAL" \
	--expected-device-kind "$DEVICE_KIND" \
	"$@"
if [ "$ANDROID_RUNTIME_CLEANUP_COMPLETED" != "1" ]; then
	printf 'error: refusing to confirm Android evidence before runtime cleanup\n' >&2
	exit 1
fi
ANDROID_PROOF_EVIDENCE_CONFIRMED=1
printf 'Proof    : %s\n' "$PROOF_JSON"
printf 'Bundle   : %s\n' "$EVIDENCE_BUNDLE"
printf '\nANDROID_DEVICE_RUNTIME_PASS proof=%s bundle=%s\n' "$PROOF_JSON" "$EVIDENCE_BUNDLE"
