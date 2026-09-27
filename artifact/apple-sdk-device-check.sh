#!/bin/sh
# Host workload execution and iOS executable linkage only. No device/signing proof.
set -eu
umask 077
ROOT=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd) || exit 2
cd "$ROOT" || exit 2
. "$ROOT/artifact/python-env.sh"

if [ "$#" -ne 0 ]; then
	printf 'error: apple-sdk-device-check accepts no arguments\n' >&2
	exit 2
fi
OUT="$ROOT/target/apple-sdk-device-check"
if [ -e "$OUT" ] || [ -L "$OUT" ]; then
	printf 'error: refusing to replace a prior SDK device-check attempt: %s\n' "$OUT" >&2
	exit 2
fi
mkdir -p "$ROOT/target"
mkdir "$OUT"
python3 - "$OUT/Fixtures.bundle" <<'PY'
import pathlib
import plistlib
import shutil
import sys

bundle = pathlib.Path(sys.argv[1])
bundle.mkdir()
for name in ("signed-policy-vectors", "sdk-policy-revocation-vectors", "sdk-policy-update-vectors"):
    shutil.copyfile(pathlib.Path("bindings") / f"{name}.json", bundle / f"{name}.json")
(bundle / "Info.plist").write_bytes(plistlib.dumps({
    "CFBundleIdentifier": "dev.qperiapt.SDKHostFixtures", "CFBundlePackageType": "BNDL",
}))
PY

cargo build --locked --release -p q-periapt-ffi --target-dir "$ROOT/target" >"$OUT/host-native.log" 2>&1
IPHONEOS_DEPLOYMENT_TARGET=16.0 cargo build --locked --release -p q-periapt-ffi \
	--target-dir "$ROOT/target" --target aarch64-apple-ios >"$OUT/ios-native.log" 2>&1

set -- -parse-as-library -D QPERIAPT_SDK_DEVICE \
	-strict-concurrency=complete -warnings-as-errors \
	-I bindings/swift/Sources/CQPeriapt \
	bindings/swift/Sources/QPeriaptHybrid/QPeriaptHybrid.swift \
	bindings/swift/Sources/QPeriaptSDK/QPeriaptSDK.swift \
	bindings/apple-device/Sources/QPeriaptDeviceRunner/DeviceSmoke.swift \
	bindings/apple-device/Sources/QPeriaptDeviceRunner/SDKDeviceSmoke.swift
xcrun swiftc "$@" bindings/apple-device/HostProbe.swift \
	-L "$ROOT/target/release" -lq_periapt_ffi_abi2 -o "$OUT/host-probe" >"$OUT/host-build.log" 2>&1
DYLD_LIBRARY_PATH="$ROOT/target/release" "$OUT/host-probe" "$OUT/Fixtures.bundle" >"$OUT/host-run.log" 2>&1
xcrun --sdk iphoneos swiftc "$@" -target arm64-apple-ios16.0 \
	-sdk "$(xcrun --sdk iphoneos --show-sdk-path)" \
	bindings/apple-device/Sources/QPeriaptDeviceRunner/main.swift \
	"$ROOT/target/aarch64-apple-ios/release/libq_periapt_ffi_abi2.a" \
	-framework Security -o "$OUT/ios-runner" >"$OUT/ios-build.log" 2>&1
PYTHONPATH=artifact python3 - "$OUT" <<'PY'
import pathlib
import sys

from apple_device_proof import require_clean_build_log
from apple_sdk_device_contract import SDK_TESTS

out = pathlib.Path(sys.argv[1])
for name in ("host-native", "ios-native", "host-build", "ios-build"):
    require_clean_build_log(out / f"{name}.log")
expected = f"HOST_SDK_DEVICE_SUITE_PASS tests={','.join(SDK_TESTS)}\n"
if (out / "host-run.log").read_text() != expected:
    raise SystemExit("error: host workload did not complete its exact SDK suite")
print("APPLE_SDK_HOST_WORKLOAD_AND_IOS_COMPILE_PASS physical_device_qualified=false")
PY
