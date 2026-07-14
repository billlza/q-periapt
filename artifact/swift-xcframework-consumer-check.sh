#!/bin/sh
# Compile, link, and validate the generated SwiftPM consumer across every Apple slice.
set -eu

unset CDPATH
ROOT=$(cd -- "$(dirname "$0")/.." && pwd) || exit 2
cd "$ROOT" || exit 2
. "$ROOT/artifact/python-env.sh"

if [ "$#" -lt 3 ] || [ "$#" -gt 4 ]; then
	printf 'error: usage: swift-xcframework-consumer-check.sh PACKAGE_DIR EVIDENCE_DIR XCFRAMEWORK [--validate-only]\n' >&2
	exit 2
fi

PACKAGE_DIR=$1
EVIDENCE_DIR=$2
XCFRAMEWORK=$3
MODE=${4:-build}
REQUIRE_DUAL_MACOS_RUNTIME=${QPERIAPT_INTERNAL_REQUIRE_DUAL_MACOS_RUNTIME:-0}
for absolute_path in "$PACKAGE_DIR" "$EVIDENCE_DIR" "$XCFRAMEWORK"; do
	case "$absolute_path" in
		/*) ;;
		*)
			printf 'error: Apple consumer-check paths must be absolute: %s\n' "$absolute_path" >&2
			exit 2
			;;
	esac
done
case "$MODE" in
	build|--validate-only) ;;
	*)
		printf 'error: invalid Apple consumer-check mode: %s\n' "$MODE" >&2
		exit 2
		;;
esac
case "$REQUIRE_DUAL_MACOS_RUNTIME" in
	0|1) ;;
	*)
		printf 'error: invalid internal dual-architecture macOS runtime policy\n' >&2
		exit 2
		;;
esac

need() {
	if ! command -v "$1" >/dev/null 2>&1; then
		printf 'error: required Apple consumer-check tool not found: %s\n' "$1" >&2
		exit 2
	fi
}

need arch
need cmp
need lipo
need nm
need python3
need swift
need xcodebuild
need xcrun

python3 - "$ROOT" "$PACKAGE_DIR" "$EVIDENCE_DIR" "$XCFRAMEWORK" "$MODE" <<'PY'
import pathlib
import sys

root = pathlib.Path(sys.argv[1]).resolve()
package = pathlib.Path(sys.argv[2]).resolve()
evidence = pathlib.Path(sys.argv[3]).resolve()
xcframework = pathlib.Path(sys.argv[4]).resolve()
mode = sys.argv[5]
target = (root / "target").resolve()
if not package.is_dir() or not (package / "Package.swift").is_file():
    raise SystemExit(f"error: generated Swift consumer package is incomplete: {package}")
if not xcframework.is_dir() or not (xcframework / "Info.plist").is_file():
    raise SystemExit(f"error: expected XCFramework is incomplete: {xcframework}")
for label, path in (("package", package), ("evidence", evidence), ("XCFramework", xcframework)):
    try:
        path.relative_to(target)
    except ValueError as exc:
        raise SystemExit(f"error: Apple consumer {label} path must be under {target}: {path}") from exc
if mode == "build" and evidence.exists():
    raise SystemExit(f"error: Apple consumer evidence directory already exists: {evidence}")
if mode == "--validate-only" and not evidence.is_dir():
    raise SystemExit(f"error: preserved Apple consumer evidence directory is missing: {evidence}")
PY

if [ "$MODE" = "build" ]; then
	mkdir -p "$EVIDENCE_DIR"
fi

EXPECTED_SYMBOLS=$(python3 - "$ROOT/crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json" <<'PY'
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
names = sorted(item["name"] for item in document["abi"]["exports"])
if len(names) != 9 or len(set(names)) != 9:
    raise SystemExit("error: Apple consumer gate requires the exact nine-symbol ABI2 contract")
print("\n".join(names))
PY
)

validate_probe() (
	gate=$1
	arch=$2
	probe=$3
	expected_platform=$4
	expected_minos=$5
	if [ ! -f "$probe" ]; then
		printf 'error: %s link gate lacks its %s final executable\n' "$gate" "$arch" >&2
		exit 1
	fi
	if [ "$(lipo -archs "$probe")" != "$arch" ]; then
		printf 'error: %s final executable has the wrong architecture: %s\n' \
			"$gate" "$(lipo -archs "$probe")" >&2
		exit 1
	fi
	if nm -u "$probe" | grep -F '_q_periapt_' >/dev/null 2>&1; then
		printf 'error: %s/%s link probe retains unresolved Q-Periapt symbols\n' \
			"$gate" "$arch" >&2
		exit 1
	fi
	actual_symbols=$(nm -gU "$probe" | awk '$3 ~ /^_q_periapt_/ { sub(/^_/, "", $3); print $3 }' | LC_ALL=C sort)
	if [ "$actual_symbols" != "$EXPECTED_SYMBOLS" ]; then
		printf 'error: %s/%s link probe does not contain the exact ABI2 symbol set\n' \
			"$gate" "$arch" >&2
		exit 1
	fi
	build_version=$(xcrun vtool -show-build "$probe")
	if [ "$(printf '%s\n' "$build_version" | grep -Fxc " platform $expected_platform")" -ne 1 ] || \
		[ "$(printf '%s\n' "$build_version" | grep -Fxc "    minos $expected_minos")" -ne 1 ]; then
		printf 'error: %s/%s link probe has the wrong Apple platform or deployment target\n' \
			"$gate" "$arch" >&2
		exit 1
	fi
)

run_macos_link_gate() (
	gate=MACOS_UNIVERSAL
	expected="$XCFRAMEWORK/macos-arm64_x86_64/libq_periapt_ffi_abi2.a"
	if [ ! -f "$expected" ]; then
		printf 'error: macOS XCFramework slice is missing\n' >&2
		exit 1
	fi
	runtime_log="$EVIDENCE_DIR/$gate-runtime.log"
	if [ "$MODE" = "build" ] && [ "$REQUIRE_DUAL_MACOS_RUNTIME" = "1" ]; then
		: >"$runtime_log"
	elif [ "$MODE" = "--validate-only" ] && \
		[ "$REQUIRE_DUAL_MACOS_RUNTIME" = "1" ] && [ ! -f "$runtime_log" ]; then
		printf 'error: macOS dual-architecture runtime evidence is missing\n' >&2
		exit 1
	fi

	for arch in arm64 x86_64; do
		triple="${arch}-apple-macosx13.0"
		scratch="$EVIDENCE_DIR/$gate-$arch-build"
		log="$EVIDENCE_DIR/$gate-$arch.log"
		if [ "$MODE" = "build" ]; then
			set +e
			swift build \
				--package-path "$PACKAGE_DIR" \
				--scratch-path "$scratch" \
				--triple "$triple" >"$log" 2>&1
			rc=$?
			set -e
			if [ "$rc" -ne 0 ]; then
				cat "$log"
				printf 'error: macOS %s SwiftPM final-link gate failed (exit=%s)\n' \
					"$arch" "$rc" >&2
				exit 1
			fi
		fi
		if [ ! -f "$log" ] || grep -Eiq '(^|[^A-Za-z])(warning|error):' "$log"; then
			[ ! -f "$log" ] || cat "$log"
			printf 'error: macOS %s SwiftPM link log is missing or warning-bearing\n' \
				"$arch" >&2
			exit 1
		fi
		if [ "$(grep -Fc 'Copying libq_periapt_ffi_abi2.a' "$log")" -ne 1 ] || \
			[ "$(grep -Fc 'Linking QPeriaptLinkProbe' "$log")" -ne 1 ] || \
			[ "$(grep -Fc 'Build complete!' "$log")" -ne 1 ]; then
			printf 'error: macOS %s SwiftPM log lacks exact copy/link/success evidence\n' \
				"$arch" >&2
			exit 1
		fi
		product="$scratch/${arch}-apple-macosx/debug"
		selected="$product/libq_periapt_ffi_abi2.a"
		if [ ! -f "$selected" ] || ! cmp "$expected" "$selected"; then
			printf 'error: macOS %s SwiftPM-selected library differs from the XCFramework slice\n' \
				"$arch" >&2
			exit 1
		fi
		probe="$product/QPeriaptLinkProbe"
		validate_probe "$gate" "$arch" "$probe" MACOS 13.0
		if [ "$REQUIRE_DUAL_MACOS_RUNTIME" = "1" ]; then
			set +e
			runtime_output=$(arch "-$arch" "$probe" 2>&1)
			runtime_rc=$?
			set -e
			if [ "$runtime_rc" -ne 0 ] || [ -n "$runtime_output" ]; then
				printf '%s\n' "$runtime_output" >&2
				printf 'error: macOS link probe failed or emitted output for architecture %s\n' \
					"$arch" >&2
				exit 1
			fi
			if [ "$MODE" = "build" ]; then
				printf 'SWIFT_XCFRAMEWORK_MACOS_RUNTIME_PASS arch=%s\n' "$arch" >>"$runtime_log"
			fi
		fi
	done

	if [ "$REQUIRE_DUAL_MACOS_RUNTIME" = "1" ]; then
		expected_runtime_markers='SWIFT_XCFRAMEWORK_MACOS_RUNTIME_PASS arch=arm64
SWIFT_XCFRAMEWORK_MACOS_RUNTIME_PASS arch=x86_64'
		if [ "$(cat "$runtime_log")" != "$expected_runtime_markers" ]; then
			printf 'error: macOS dual-architecture runtime evidence is incomplete or noncanonical\n' >&2
			exit 1
		fi
	fi
	printf 'SWIFT_XCFRAMEWORK_MACOS_UNIVERSAL_LINK_PASS arches=arm64 x86_64\n'
)

run_ios_link_gate() (
	gate=$1
	destination=$2
	platform_suffix=$3
	expected_arches=$4
	derived="$EVIDENCE_DIR/$gate-derived"
	log="$EVIDENCE_DIR/$gate.log"

	if [ "$MODE" = "build" ]; then
		set +e
		(
			cd "$PACKAGE_DIR"
			xcodebuild \
				-scheme QPeriaptLinkProbe \
				-destination "$destination" \
				-derivedDataPath "$derived" \
				CODE_SIGNING_ALLOWED=NO \
				"ARCHS=$expected_arches" \
				ONLY_ACTIVE_ARCH=NO \
				build
		) >"$log" 2>&1
		rc=$?
		set -e
		if [ "$rc" -ne 0 ]; then
			cat "$log"
			printf 'error: %s XCFramework consumer link gate failed (exit=%s)\n' "$gate" "$rc" >&2
			exit 1
		fi
	fi
	if [ ! -f "$log" ]; then
		printf 'error: %s XCFramework consumer link log is missing\n' "$gate" >&2
		exit 1
	fi
	if grep -Eiq '(^|[^A-Za-z])(warning|error):' "$log"; then
		cat "$log"
		printf 'error: %s XCFramework consumer link gate emitted warning/error diagnostics\n' "$gate" >&2
		exit 1
	fi
	if [ "$(grep -Fc '** BUILD SUCCEEDED **' "$log")" -ne 1 ] || \
		[ "$(grep -Fc -- '-lq_periapt_ffi_abi2' "$log")" -lt 1 ]; then
		printf 'error: %s link log lacks XCFramework processing, ABI2 linkage, or success evidence\n' "$gate" >&2
		exit 1
	fi
	case "$platform_suffix" in
		iphoneos)
			[ "$(grep -Ec '^ProcessXCFramework .*CQPeriapt\.xcframework .*Debug-iphoneos/libq_periapt_ffi_abi2\.a ios$' "$log")" -eq 1 ] || {
				printf 'error: iOS device gate did not select the device XCFramework slice\n' >&2
				exit 1
			}
			product_dir="$derived/Build/Products/Debug-iphoneos"
			expected="$XCFRAMEWORK/ios-arm64/libq_periapt_ffi_abi2.a"
			expected_platform=IOS
			expected_minos=16.0
			;;
		iphonesimulator)
			[ "$(grep -Ec '^ProcessXCFramework .*CQPeriapt\.xcframework .*Debug-iphonesimulator/libq_periapt_ffi_abi2\.a ios simulator$' "$log")" -eq 1 ] || {
				printf 'error: iOS simulator gate did not select the simulator XCFramework slice\n' >&2
				exit 1
			}
			product_dir="$derived/Build/Products/Debug-iphonesimulator"
			expected="$XCFRAMEWORK/ios-arm64_x86_64-simulator/libq_periapt_ffi_abi2.a"
			expected_platform=IOSSIMULATOR
			expected_minos=16.0
			;;
		*)
			printf 'error: unsupported iOS link-gate platform suffix: %s\n' "$platform_suffix" >&2
			exit 2
			;;
	esac
	processed="$product_dir/libq_periapt_ffi_abi2.a"
	if [ ! -f "$processed" ] || [ ! -f "$expected" ] || ! cmp "$expected" "$processed"; then
		printf 'error: %s Xcode-selected library is not the exact expected XCFramework slice\n' "$gate" >&2
		exit 1
	fi

	probe="$product_dir/QPeriaptLinkProbe"
	if [ ! -f "$probe" ]; then
		printf 'error: %s link gate did not produce its final executable\n' "$gate" >&2
		exit 1
	fi
	actual_arches=$(lipo -archs "$probe")
	expected_arch_count=$(printf '%s\n' "$expected_arches" | awk '{print NF}')
	actual_arch_count=$(printf '%s\n' "$actual_arches" | awk '{print NF}')
	if [ "$actual_arch_count" -ne "$expected_arch_count" ]; then
		printf 'error: %s link probe has an unexpected architecture set: %s\n' \
			"$gate" "$actual_arches" >&2
		exit 1
	fi
	for arch in $expected_arches; do
		case " $actual_arches " in
			*" $arch "*) ;;
			*)
				printf 'error: %s link probe lacks expected architecture %s: %s\n' \
					"$gate" "$arch" "$actual_arches" >&2
				exit 1
				;;
		esac
		thin="$EVIDENCE_DIR/$gate-$arch"
		if [ "$MODE" = "build" ]; then
			if [ "$expected_arch_count" -eq 1 ]; then
				cp "$probe" "$thin"
			else
				lipo "$probe" -thin "$arch" -output "$thin"
			fi
		fi
		validate_probe "$gate" "$arch" "$thin" "$expected_platform" "$expected_minos"
	done
	printf 'SWIFT_XCFRAMEWORK_%s_LINK_PASS arches=%s\n' "$gate" "$actual_arches"
)

run_macos_link_gate
run_ios_link_gate IOS_DEVICE 'generic/platform=iOS' iphoneos 'arm64'
run_ios_link_gate IOS_SIMULATOR 'generic/platform=iOS Simulator' iphonesimulator 'arm64 x86_64'
