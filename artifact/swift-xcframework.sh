#!/bin/sh
# Build and verify the SwiftPM binaryTarget/XCFramework release surface.
#
# This is a pre-publication gate. It proves an isolated SwiftPM consumer can import
# the Swift wrapper through a binary CQPeriapt XCFramework, without the development
# package's unsafe relative linker flags or repo-local target/release path.
set -eu

unset CDPATH
ROOT=$(cd -- "$(dirname "$0")/.." && pwd) || exit 2
cd "$ROOT" || exit 2

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

if [ "${QPERIAPT_SWIFT_XCFRAMEWORK_SKIP_VERIFY:-0}" = "1" ]; then
	printf 'error: QPERIAPT_SWIFT_XCFRAMEWORK_SKIP_VERIFY is not supported\n' >&2
	exit 2
fi

if [ "${QPERIAPT_ALLOW_DIRTY_SWIFT_XCFRAMEWORK:-0}" != "1" ]; then
	if [ -n "$(git status --porcelain=v1)" ]; then
		printf 'error: Swift XCFramework release gate requires a clean worktree; set QPERIAPT_ALLOW_DIRTY_SWIFT_XCFRAMEWORK=1 only for local diagnostics\n' >&2
		exit 2
	fi
fi

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
RUST_HOST=$(rustc -vV | awk '/^host: / { print $2 }')
LLVM_NM="$(rustc --print sysroot)/lib/rustlib/$RUST_HOST/bin/llvm-nm"
if [ ! -x "$LLVM_NM" ]; then
	printf 'error: Rust toolchain llvm-nm not found: %s\n' "$LLVM_NM" >&2
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
tmp_header=$(mktemp "$ROOT/target/qperiapt-swift-xcframework-header.XXXXXX.h")

cleanup() {
	rm -f "$tmp_header"
}
trap cleanup EXIT INT TERM

required_targets="aarch64-apple-darwin x86_64-apple-darwin aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios"
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
	test -f "$ROOT/target/$target/release/libq_periapt_ffi.a" || {
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
	"$ROOT/target/aarch64-apple-darwin/release/libq_periapt_ffi.a" \
	"$ROOT/target/x86_64-apple-darwin/release/libq_periapt_ffi.a" \
	-output "$LIBS/macos/libq_periapt_ffi.a"
cp "$ROOT/target/aarch64-apple-ios/release/libq_periapt_ffi.a" "$LIBS/ios/libq_periapt_ffi.a"
lipo -create \
	"$ROOT/target/aarch64-apple-ios-sim/release/libq_periapt_ffi.a" \
	"$ROOT/target/x86_64-apple-ios/release/libq_periapt_ffi.a" \
	-output "$LIBS/ios-simulator/libq_periapt_ffi.a"

lipo "$LIBS/macos/libq_periapt_ffi.a" -verify_arch arm64 x86_64
lipo "$LIBS/ios/libq_periapt_ffi.a" -verify_arch arm64
lipo "$LIBS/ios-simulator/libq_periapt_ffi.a" -verify_arch arm64 x86_64
for lib in "$LIBS/macos/libq_periapt_ffi.a" "$LIBS/ios/libq_periapt_ffi.a" "$LIBS/ios-simulator/libq_periapt_ffi.a"; do
	if ! "$LLVM_NM" -g "$lib" 2>/dev/null | grep -E '(^| )_?q_periapt_abi_version$' >/dev/null 2>&1; then
		printf 'error: missing q_periapt_abi_version export in %s\n' "$lib" >&2
		exit 1
	fi
done
printf 'PASS: release slices\n'

printf '\n=== Create XCFramework ===\n'
xcodebuild -create-xcframework \
	-library "$LIBS/macos/libq_periapt_ffi.a" -headers "$HEADERS" \
	-library "$LIBS/ios/libq_periapt_ffi.a" -headers "$HEADERS" \
	-library "$LIBS/ios-simulator/libq_periapt_ffi.a" -headers "$HEADERS" \
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

printf '\n=== Zip XCFramework ===\n'
find "$XCFRAMEWORK" -exec touch -h -t 200001010000 {} +
rm -f "$ZIP_PATH"
(cd "$DIST" && find "CQPeriapt.xcframework" -print | LC_ALL=C sort | zip -q -X "CQPeriapt.xcframework.zip" -@)
test -f "$ZIP_PATH" || {
	printf 'error: missing XCFramework zip: %s\n' "$ZIP_PATH" >&2
	exit 1
}
python3 - "$ZIP_PATH" <<'PY'
import pathlib
import stat
import sys
import zipfile

zip_path = pathlib.Path(sys.argv[1])
seen = set()
with zipfile.ZipFile(zip_path) as archive:
    for info in archive.infolist():
        name = info.filename
        pure = pathlib.PurePosixPath(name)
        if name in seen:
            raise SystemExit(f"error: duplicate zip entry: {name}")
        seen.add(name)
        if name.startswith("/") or ".." in pure.parts:
            raise SystemExit(f"error: unsafe zip entry: {name}")
        if any(part in ("__MACOSX", ".DS_Store") for part in pure.parts):
            raise SystemExit(f"error: Apple metadata leaked into zip: {name}")
        mode = (info.external_attr >> 16) & 0o170000
        if mode in (stat.S_IFLNK, stat.S_IFCHR, stat.S_IFBLK, stat.S_IFIFO, stat.S_IFSOCK):
            raise SystemExit(f"error: unsupported zip entry type: {name}")
required = {
    "CQPeriapt.xcframework/Info.plist",
}
missing = required - seen
if missing:
    raise SystemExit(f"error: missing zip entries: {sorted(missing)}")
print("SWIFT_XCFRAMEWORK_ZIP_PASS")
PY

SWIFTPM_CHECKSUM=$(swift package compute-checksum "$ZIP_PATH")

printf '\n=== Generate isolated SwiftPM binary consumer ===\n'
mkdir -p "$CONSUMER/Binaries" "$CONSUMER/Sources/QPeriaptHybrid" "$CONSUMER/Tests/QPeriaptHybridBinaryConsumerTests/Resources"
cp -R "$XCFRAMEWORK" "$CONSUMER/Binaries/CQPeriapt.xcframework"
cp bindings/swift/Sources/QPeriaptHybrid/QPeriaptHybrid.swift "$CONSUMER/Sources/QPeriaptHybrid/QPeriaptHybrid.swift"
cp bindings/shared-test-vectors.json "$CONSUMER/Tests/QPeriaptHybridBinaryConsumerTests/Resources/shared-test-vectors.json"
cp bindings/contextbound-vectors.txt "$CONSUMER/Tests/QPeriaptHybridBinaryConsumerTests/Resources/contextbound-vectors.txt"
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
        .library(name: "QPeriaptHybrid", targets: ["QPeriaptHybrid"])
    ],
    targets: [
        .binaryTarget(name: "CQPeriapt", path: "Binaries/CQPeriapt.xcframework"),
        .target(name: "QPeriaptHybrid", dependencies: ["CQPeriapt"]),
        .testTarget(
            name: "QPeriaptHybridBinaryConsumerTests",
            dependencies: ["QPeriaptHybrid"],
            resources: [.copy("Resources")]
        ),
    ]
)
EOF
cat >"$CONSUMER/Tests/QPeriaptHybridBinaryConsumerTests/QPeriaptHybridBinaryConsumerTests.swift" <<'EOF'
import Foundation
import XCTest

@testable import QPeriaptHybrid

final class QPeriaptHybridBinaryConsumerTests: XCTestCase {
    func hex(_ s: String) -> [UInt8] {
        var out = [UInt8]()
        var i = s.startIndex
        while i < s.endIndex {
            let j = s.index(i, offsetBy: 2)
            out.append(UInt8(s[i..<j], radix: 16)!)
            i = j
        }
        return out
    }

    func resourceData(_ name: String) throws -> Data {
        guard let url = Bundle.module.url(
            forResource: name,
            withExtension: nil,
            subdirectory: "Resources"
        ) else {
            throw NSError(domain: "QPeriaptBinaryConsumerTests", code: 1)
        }
        return try Data(contentsOf: url)
    }

    func sharedVector() throws -> [String: Any] {
        let data = try resourceData("shared-test-vectors.json")
        return try JSONSerialization.jsonObject(with: data) as! [String: Any]
    }

    func signedPolicyVector() throws -> [String: Any] {
        let data = try resourceData("signed-policy-vectors.json")
        return try JSONSerialization.jsonObject(with: data) as! [String: Any]
    }

    func testRuntimeMetadataMatchesCompiledHeader() throws {
        XCTAssertEqual(QPeriaptHybrid.runtimeAbiVersion, QPeriaptHybrid.abiVersion)
        XCTAssertEqual(QPeriaptHybrid.runtimeVersion, "0.0.1")
        XCTAssertEqual(QPeriaptHybrid.fixedSuiteId, Array("ML-KEM-768+X25519".utf8))
        XCTAssertEqual(QPeriaptHybrid.fixedSuiteIdLen, "ML-KEM-768+X25519".utf8.count)
        XCTAssertEqual(QPeriaptHybrid.statusName(QPeriaptError.policyCode), "ERR_POLICY")
        XCTAssertEqual(QPeriaptHybrid.statusName(12345), "UNKNOWN_STATUS")
    }

    func testSharedVectorDecapsulates() throws {
        let v = try sharedVector()
        let secret = try QPeriaptHybrid.decapsulate(
            profile: .contextBound,
            suiteId: hex(v["suite_id"] as! String),
            policyVersion: UInt32(v["policy_version"] as! Int),
            skPq: hex(v["sk_pq"] as! String),
            ctPq: hex(v["ct_pq"] as! String),
            pkPq: hex(v["pk_pq"] as! String),
            skTrad: hex(v["sk_trad"] as! String),
            ctTrad: hex(v["ct_trad"] as! String),
            pkTrad: hex(v["pk_trad"] as! String),
            context: hex(v["context"] as! String))
        XCTAssertEqual(secret, hex(v["secret"] as! String))
    }

    func testSharedVectorEncapsulates() throws {
        let v = try sharedVector()
        let enc = try QPeriaptHybrid.encapsulate(
            profile: .contextBound,
            suiteId: hex(v["suite_id"] as! String),
            policyVersion: UInt32(v["policy_version"] as! Int),
            pkPq: hex(v["pk_pq"] as! String),
            pkTrad: hex(v["pk_trad"] as! String),
            context: hex(v["context"] as! String),
            randPq: hex(v["rand_pq"] as! String),
            randTrad: hex(v["rand_trad"] as! String))
        XCTAssertEqual(enc.ctPq, hex(v["ct_pq"] as! String))
        XCTAssertEqual(enc.ctTrad, hex(v["ct_trad"] as! String))
        XCTAssertEqual(enc.secret, hex(v["secret"] as! String))
    }

    func testContextBoundRejectsEmptyContext() throws {
        let v = try sharedVector()
        XCTAssertThrowsError(try QPeriaptHybrid.encapsulate(
            profile: .contextBound,
            suiteId: hex(v["suite_id"] as! String),
            policyVersion: UInt32(v["policy_version"] as! Int),
            pkPq: hex(v["pk_pq"] as! String),
            pkTrad: hex(v["pk_trad"] as! String),
            context: [],
            randPq: hex(v["rand_pq"] as! String),
            randTrad: hex(v["rand_trad"] as! String))) { error in
                XCTAssertEqual((error as? QPeriaptError)?.code, QPeriaptError.lengthCode)
        }
    }

    func testCompatXWingSeedKeypairRoundtrip() throws {
        let pq = try QPeriaptHybrid.mlkem768XWingKeypair(
            seed: [UInt8](repeating: 7, count: QPeriaptHybrid.mlkemXWingSeedLen))
        let x = try QPeriaptHybrid.x25519Keypair(
            secret: [UInt8](repeating: 9, count: QPeriaptHybrid.x25519Len))
        let enc = try QPeriaptHybrid.encapsulate(
            profile: .compatXWing,
            suiteId: Array("ML-KEM-768+X25519".utf8),
            policyVersion: 1,
            pkPq: pq.pk,
            pkTrad: x.pk,
            context: [],
            randPq: [UInt8](repeating: 3, count: 32),
            randTrad: [UInt8](repeating: 5, count: 32))
        let dec = try QPeriaptHybrid.decapsulate(
            profile: .compatXWing,
            suiteId: Array("ML-KEM-768+X25519".utf8),
            policyVersion: 1,
            skPq: pq.skSeed,
            ctPq: enc.ctPq,
            pkPq: pq.pk,
            skTrad: x.sk,
            ctTrad: enc.ctTrad,
            pkTrad: x.pk,
            context: [])
        XCTAssertEqual(enc.secret, dec)
    }

    func testCombineReferenceVectors() throws {
        let text = String(data: try resourceData("contextbound-vectors.txt"), encoding: .utf8)!
        var n = 0
        for line in text.split(separator: "\n") {
            let p = line.split(separator: " ")
            if p.count != 3 { continue }
            let profile = QPeriaptProfile(rawValue: UInt8(p[0])!)!
            let got = try QPeriaptHybrid.combine(profile: profile, input: hex(String(p[1])))
            XCTAssertEqual(got, hex(String(p[2])))
            n += 1
        }
        XCTAssertEqual(n, 6, "expected 6 reference vectors")
    }

    func testSignedPolicyVectorSelectsProfileAndRejectsRollbackAndTamper() throws {
        let v = try signedPolicyVector()
        XCTAssertEqual(v["algorithm"] as? String, "ML-DSA-65")
        let policyToml = Array((v["policy_toml"] as! String).utf8)
        let signature = hex(v["signature"] as! String)
        let verificationKey = hex(v["verification_key"] as! String)
        let expectedCode = UInt8(v["selected_profile_code"] as! Int)

        let profile = try QPeriaptHybrid.profileFromSignedPolicy(
            toml: policyToml,
            signature: signature,
            verificationKey: verificationKey,
            lastTrustedVersion: UInt32(v["last_trusted_version_accept"] as! Int))
        XCTAssertEqual(profile.rawValue, expectedCode)

        XCTAssertThrowsError(try QPeriaptHybrid.profileFromSignedPolicy(
            toml: policyToml,
            signature: signature,
            verificationKey: verificationKey,
            lastTrustedVersion: UInt32(v["last_trusted_version_reject"] as! Int))) { error in
                XCTAssertEqual((error as? QPeriaptError)?.code, QPeriaptError.policyCode)
        }

        var tampered = signature
        let tamperByte = v["tamper_signature_byte"] as! Int
        XCTAssertLessThan(tamperByte, tampered.count)
        tampered[tamperByte] ^= 1
        XCTAssertThrowsError(try QPeriaptHybrid.profileFromSignedPolicy(
            toml: policyToml,
            signature: tampered,
            verificationKey: verificationKey,
            lastTrustedVersion: 0)) { error in
                XCTAssertEqual((error as? QPeriaptError)?.code, QPeriaptError.policyCode)
        }
    }
}
EOF

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
if ! grep -q 'Executed 7 tests, with 0 failures' "$CONSUMER_LOG"; then
	printf 'error: Swift binary consumer XCTest count was not the expected 7 passing tests\n' >&2
	exit 1
fi
if grep -R -nE 'unsafeFlags|\.\./\.\./target/release|target/release/libq_periapt_ffi' "$CONSUMER" >/dev/null 2>&1; then
	printf 'error: generated binary consumer leaked development linker path after build\n' >&2
	exit 1
fi
printf 'SWIFT_BINARY_CONSUMER_PASS\n'

printf '\n=== Release manifest ===\n'
python3 - "$ROOT" "$DIST" "$VERSION" "$SWIFTPM_CHECKSUM" "$required_targets" "$MANIFEST" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

root = pathlib.Path(sys.argv[1]).resolve()
dist = pathlib.Path(sys.argv[2]).resolve()
version = sys.argv[3]
swiftpm_checksum = sys.argv[4]
targets = sys.argv[5].split()
manifest_path = pathlib.Path(sys.argv[6]).resolve()

def sha(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def run(args):
    return subprocess.check_output(args, cwd=root, stderr=subprocess.STDOUT, text=True).strip()

manifest = {
    "package": "q-periapt-swift",
    "version": version,
    "type": "swiftpm-binaryTarget-xcframework",
    "git_commit": run(["git", "rev-parse", "HEAD"]),
    "git_dirty": bool(run(["git", "status", "--porcelain=v1"])),
    "toolchain": {
        "rustc": run(["rustc", "--version"]),
        "swift": run(["swift", "--version"]).replace("\n", " "),
        "xcode": run(["xcodebuild", "-version"]).splitlines(),
    },
    "targets": targets,
    "artifacts": {
        "xcframework_zip": {
            "path": "CQPeriapt.xcframework.zip",
            "sha256": sha(dist / "CQPeriapt.xcframework.zip"),
            "swiftpm_checksum": swiftpm_checksum,
        },
        "xcframework_info_plist_sha256": sha(dist / "CQPeriapt.xcframework" / "Info.plist"),
    },
    "source_inputs": {
        "q_periapt_header_sha256": sha(root / "crates/q-periapt-ffi/include/q_periapt.h"),
        "swift_vendored_header_sha256": sha(root / "bindings/swift/Sources/CQPeriapt/q_periapt.h"),
        "swift_wrapper_sha256": sha(root / "bindings/swift/Sources/QPeriaptHybrid/QPeriaptHybrid.swift"),
        "shared_vectors_sha256": sha(root / "bindings/shared-test-vectors.json"),
        "contextbound_vectors_sha256": sha(root / "bindings/contextbound-vectors.txt"),
        "signed_policy_vectors_sha256": sha(root / "bindings/signed-policy-vectors.json"),
        "script_sha256": sha(root / "artifact/swift-xcframework.sh"),
    },
    "public_release_boundary": {
        "contains_raw_device_proof": False,
        "contains_mobileprovision": False,
        "contains_device_udid": False,
        "requires_clean_tree_for_release": True,
    },
}
manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

(
	cd "$DIST"
	{
		shasum -a 256 "CQPeriapt.xcframework.zip"
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

printf '\nSWIFT_XCFRAMEWORK_PACKAGE_PASS checksum=%s path=%s\n' "$SWIFTPM_CHECKSUM" "$ZIP_PATH"
