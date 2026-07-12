#!/bin/sh
# Build and verify a host C-ABI release archive for downstream consumers.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd) || exit 2
cd "$ROOT" || exit 2
. "$ROOT/artifact/python-env.sh"

need() {
	if ! command -v "$1" >/dev/null 2>&1; then
		printf 'error: required tool not found: %s\n' "$1" >&2
		exit 2
	fi
}

need cargo
need cbindgen
need cc
need cmake
need ctest
need pkg-config
need python3
need rustc
need shasum
need tar
need nm

if [ "${QPERIAPT_C_PACKAGE_SKIP_VERIFY:-0}" = "1" ]; then
	printf 'error: QPERIAPT_C_PACKAGE_SKIP_VERIFY is not supported by the release archive proof gate\n' >&2
	exit 2
fi

mkdir -p "$ROOT/target"
CARGO_TARGET_DIR="$ROOT/target"
export CARGO_TARGET_DIR
static_libs_log=$(mktemp "$ROOT/target/qperiapt-c-package-static-libs.XXXXXX.log")
tmp_cbom=$(mktemp "$ROOT/target/qperiapt-cbom.XXXXXX.json")
tmp_sbom=$(mktemp "$ROOT/target/qperiapt-sbom.XXXXXX.json")
ABI_MAJOR=2
ABI_COMPAT_VERSION=2.0.0
CONTRACT_SOURCE="$ROOT/crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json"
HEADER_SOURCE="$ROOT/crates/q-periapt-ffi/include/q_periapt.h"
FIXTURE_SOURCE="$ROOT/bindings/c/signed_policy_fixture.h"
VERSION=$(cargo metadata --locked --format-version 1 | python3 -c '
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
HOST=$(rustc -vV | awk '/^host: / { print $2 }')
PACKAGE_NAME="q-periapt-c-abi2-$VERSION-$HOST"
OUT_ROOT=${QPERIAPT_C_PACKAGE_OUT_DIR:-"$ROOT/target/qperiapt-c-abi2"}
PACKAGE_DIR="$OUT_ROOT/$PACKAGE_NAME"
ARCHIVE="$OUT_ROOT/$PACKAGE_NAME.tar.gz"
VERIFY_ROOT="$OUT_ROOT/verify-$PACKAGE_NAME"
tmp_header=$(mktemp "$ROOT/target/qperiapt-c-package-header.XXXXXX.h")
path_log=$(mktemp "$ROOT/target/qperiapt-c-package-paths.XXXXXX.log")

cleanup() {
	rm -f "$tmp_header" "$path_log" "$static_libs_log" "$tmp_cbom" "$tmp_sbom"
}
trap cleanup EXIT INT TERM

case "$(uname -s)" in
	Darwin)
		PLATFORM="macos"
		BUILD_SHARED_LIB="libq_periapt_ffi_abi2.dylib"
		SHARED_LIB="libq_periapt_ffi.2.dylib"
		RPATH_FLAG="-Wl,-rpath,"
		need otool
		;;
	Linux)
		PLATFORM="linux"
		BUILD_SHARED_LIB="libq_periapt_ffi_abi2.so"
		SHARED_LIB="libq_periapt_ffi.so.2"
		RPATH_FLAG="-Wl,-rpath,"
		need ldd
		need readelf
		;;
	*)
		printf 'error: C package script currently supports Darwin/Linux hosts, got %s\n' "$(uname -s)" >&2
	exit 2
		;;
esac
STATIC_LIB="libq_periapt_ffi_abi2.a"

inspect_dynamic_linkage() {
	binary=$1
	label=$2
	linkage="$VERIFY_ROOT/$label-linkage.txt"
	case "$(uname -s)" in
		Darwin)
			otool -L "$binary" >"$linkage"
			if ! grep -F "@rpath/$SHARED_LIB" "$linkage" >/dev/null 2>&1; then
				cat "$linkage" >&2
				printf 'error: dynamic consumer is not linked through @rpath/%s\n' "$SHARED_LIB" >&2
				exit 1
			fi
			;;
		Linux)
			ldd "$binary" >"$linkage"
			if ! grep -F "$SHARED_LIB" "$linkage" >/dev/null 2>&1; then
				cat "$linkage" >&2
				printf 'error: dynamic consumer is not linked to %s\n' "$SHARED_LIB" >&2
				exit 1
			fi
			;;
	esac
	if grep -F "$ROOT/target/release" "$linkage" >/dev/null 2>&1; then
		cat "$linkage" >&2
		printf 'error: dynamic consumer linkage references source-tree target/release\n' >&2
		exit 1
	fi
}

inspect_static_linkage() {
	binary=$1
	label=$2
	linkage="$VERIFY_ROOT/$label-linkage.txt"
	case "$(uname -s)" in
		Darwin)
			otool -L "$binary" >"$linkage"
			;;
		Linux)
			if ldd "$binary" >"$linkage" 2>&1; then
				:
			else
				ldd_status=$?
				if [ "$ldd_status" -ne 1 ] || ! grep -Eq 'not a dynamic executable|statically linked' "$linkage"; then
					cat "$linkage" >&2
					printf 'error: ldd failed unexpectedly for static consumer (exit %s)\n' "$ldd_status" >&2
					exit 1
				fi
			fi
			;;
	esac
	if grep -F "$SHARED_LIB" "$linkage" >/dev/null 2>&1; then
		cat "$linkage" >&2
		printf 'error: static consumer unexpectedly links to %s\n' "$SHARED_LIB" >&2
		exit 1
	fi
	if grep -F "$ROOT/target/release" "$linkage" >/dev/null 2>&1; then
		cat "$linkage" >&2
		printf 'error: static consumer linkage references source-tree target/release\n' >&2
		exit 1
	fi
}

validate_license_and_boms() {
	package_root=$1
	python3 - "$ROOT" "$package_root" <<'PY'
import json
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1]).resolve()
package_root = pathlib.Path(sys.argv[2]).resolve()

def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"error: {message}")

def read_text(rel: str) -> str:
    path = package_root / rel
    require(path.is_file(), f"missing package file: {rel}")
    return path.read_text(encoding="utf-8")

def load_json(rel: str):
    path = package_root / rel
    require(path.is_file(), f"missing package file: {rel}")
    return json.loads(path.read_text(encoding="utf-8"))

license_text = read_text("LICENSE")
apache_text = read_text("LICENSES/Apache-2.0.txt")
mit_text = read_text("LICENSES/MIT.txt")
require("Apache-2.0 OR MIT" in license_text, "LICENSE does not match workspace license expression")
require("Apache License" in apache_text and "Version 2.0, January 2004" in apache_text, "Apache license text is incomplete")
require("MIT License" in mit_text and "Permission is hereby granted" in mit_text, "MIT license text is incomplete")

bad_value = re.compile(
    r"(/Users/|/home/|/private/|[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}|BEGIN .*PRIVATE KEY|AKIA[0-9A-Z]{16}|(?:api|auth|access|secret)[_-]?token\s*[:=]|password\s*[:=])",
    re.IGNORECASE,
)
bad_keys = {"timestamp", "generated_at", "serialNumber"}

def walk(value, path: str) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            require(key not in bad_keys, f"non-reproducible BOM key at {path}/{key}")
            walk(child, f"{path}/{key}")
    elif isinstance(value, list):
        for idx, child in enumerate(value):
            walk(child, f"{path}/{idx}")
    elif isinstance(value, str):
        require(not bad_value.search(value), f"sensitive or nonportable BOM value at {path}: {value[:120]}")

def validate_cyclonedx(data, rel: str):
    require(data.get("bomFormat") == "CycloneDX", f"{rel} is not CycloneDX")
    require(data.get("specVersion") == "1.6", f"{rel} is not CycloneDX 1.6")
    require(isinstance(data.get("version"), int) and data["version"] > 0, f"{rel} version must be a positive integer")
    metadata = data.get("metadata")
    require(isinstance(metadata, dict), f"{rel} metadata missing")
    component = metadata.get("component")
    require(isinstance(component, dict) and component.get("name") == "q-periapt-hybrid-suite", f"{rel} component metadata mismatch")
    components = data.get("components")
    require(isinstance(components, list) and components, f"{rel} components missing")
    refs = [component.get("bom-ref") for component in components if isinstance(component, dict) and "bom-ref" in component]
    require(len(refs) == len(set(refs)), f"{rel} duplicate bom-ref")
    walk(data, rel)
    return components

cbom = load_json("share/q-periapt/bom/cbom.cdx.json")
sbom = load_json("share/q-periapt/bom/sbom.cdx.json")
cbom_components = validate_cyclonedx(cbom, "share/q-periapt/bom/cbom.cdx.json")
sbom_components = validate_cyclonedx(sbom, "share/q-periapt/bom/sbom.cdx.json")

expected_crypto = {
    "ML-KEM-768",
    "ML-KEM-1024",
    "X25519",
    "ML-DSA-65",
    "ML-DSA-87",
    "SLH-DSA-SHA2-256s",
    "SHA3-256",
    "SHAKE-256",
}
seen_crypto = set()
for component in cbom_components:
    require(component.get("type") == "cryptographic-asset", "CBOM component is not a cryptographic asset")
    name = component.get("name")
    seen_crypto.add(name)
    crypto = component.get("cryptoProperties")
    require(isinstance(crypto, dict) and crypto.get("assetType") == "algorithm", f"CBOM cryptoProperties missing for {name}")
    algo = crypto.get("algorithmProperties")
    require(isinstance(algo, dict), f"CBOM algorithmProperties missing for {name}")
    require(isinstance(algo.get("primitive"), str) and algo["primitive"], f"CBOM primitive missing for {name}")
    require(algo.get("parameterSetIdentifier") == name, f"CBOM parameterSetIdentifier mismatch for {name}")
    require(isinstance(algo.get("cryptoFunctions"), list) and algo["cryptoFunctions"], f"CBOM cryptoFunctions missing for {name}")
    require(isinstance(algo.get("nistQuantumSecurityLevel"), int), f"CBOM NIST level missing for {name}")
require(
    seen_crypto == expected_crypto,
    "CBOM asset inventory mismatch: "
    f"missing={sorted(expected_crypto - seen_crypto)} "
    f"unexpected={sorted(seen_crypto - expected_crypto)}",
)

lock_components = []
name = version = None
in_package = False
for raw in (root / "Cargo.lock").read_text(encoding="utf-8").splitlines():
    line = raw.strip()
    if line == "[[package]]":
        if name and version:
            lock_components.append((name, version))
        name = version = None
        in_package = True
    elif in_package and line.startswith("name = "):
        name = line.removeprefix("name = ").strip('"')
    elif in_package and line.startswith("version = "):
        version = line.removeprefix("version = ").strip('"')
if name and version:
    lock_components.append((name, version))
expected_sbom = {(name, version, f"pkg:cargo/{name}@{version}") for name, version in lock_components}
actual_sbom = set()
for component in sbom_components:
    require(component.get("type") == "library", "SBOM component is not a library")
    name = component.get("name")
    version = component.get("version")
    purl = component.get("purl")
    bom_ref = component.get("bom-ref")
    require(isinstance(name, str) and name, "SBOM component name missing")
    require(isinstance(version, str) and version, f"SBOM component version missing for {name}")
    require(purl == f"pkg:cargo/{name}@{version}", f"SBOM purl mismatch for {name}")
    require(bom_ref == purl, f"SBOM bom-ref mismatch for {name}")
    actual_sbom.add((name, version, purl))
require(actual_sbom == expected_sbom, "SBOM components do not match Cargo.lock package set")
PY
}

python3 - "$ROOT" "$OUT_ROOT" "$PACKAGE_DIR" "$VERIFY_ROOT" <<'PY'
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1]).resolve()
target = (root / "target").resolve()
for raw, label in ((sys.argv[2], "QPERIAPT_C_PACKAGE_OUT_DIR"), (sys.argv[3], "package dir"), (sys.argv[4], "verify dir")):
    path = pathlib.Path(raw).resolve()
    try:
        path.relative_to(target)
    except ValueError as exc:
        raise SystemExit(f"error: {label} must be under {target}: {path}") from exc
    if path == target:
        raise SystemExit(f"error: {label} must not be the target root itself: {path}")
if not re.fullmatch(r"q-periapt-c-abi2-[0-9A-Za-z._+-]+-[0-9A-Za-z._+-]+", pathlib.Path(sys.argv[3]).name):
    raise SystemExit(f"error: unsafe package directory name: {pathlib.Path(sys.argv[3]).name}")
PY

printf 'Q-Periapt C ABI package\n'
printf 'version : %s\n' "$VERSION"
printf 'host    : %s\n' "$HOST"
printf 'out     : %s\n' "$OUT_ROOT"

printf '\n=== Frozen ABI 2 contract and generated header freshness ===\n'
test -f "$CONTRACT_SOURCE" || {
	printf 'error: missing ABI contract: %s\n' "$CONTRACT_SOURCE" >&2
	exit 1
}
test -f "$FIXTURE_SOURCE" || {
	printf 'error: missing signed-policy fixture: %s\n' "$FIXTURE_SOURCE" >&2
	exit 1
}
python3 artifact/c_abi_contract.py \
	--contract "$CONTRACT_SOURCE" \
	--header "$HEADER_SOURCE"
cbindgen --config crates/q-periapt-ffi/cbindgen.toml \
	--crate q-periapt-ffi \
	--output "$tmp_header"
cmp "$tmp_header" "$HEADER_SOURCE"
cmp "$HEADER_SOURCE" bindings/swift/Sources/CQPeriapt/q_periapt.h
CONTRACT_VERSION=$(python3 - "$CONTRACT_SOURCE" <<'PY'
import json
import pathlib
import sys

print(json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))["package"]["semver"])
PY
)
if [ "$VERSION" != "$CONTRACT_VERSION" ]; then
	printf 'error: Cargo package version %s differs from frozen ABI contract version %s\n' \
		"$VERSION" "$CONTRACT_VERSION" >&2
	exit 1
fi
printf 'PASS: ABI 2 source contract and generated header freshness\n'

printf '\n=== Build release C ABI ===\n'
cargo build -p q-periapt-ffi --release --locked
test -f "$ROOT/target/release/$STATIC_LIB" || {
	printf 'error: missing static library: %s\n' "$ROOT/target/release/$STATIC_LIB" >&2
	exit 1
}
test -f "$ROOT/target/release/$BUILD_SHARED_LIB" || {
	printf 'error: missing shared library: %s\n' "$ROOT/target/release/$BUILD_SHARED_LIB" >&2
	exit 1
}
if ! CARGO_TERM_COLOR=never cargo rustc -p q-periapt-ffi --release --locked --crate-type staticlib -- --print native-static-libs >"$static_libs_log" 2>&1; then
	cat "$static_libs_log" >&2
	printf 'error: failed to obtain q-periapt-ffi native static link libraries\n' >&2
	exit 1
fi
NATIVE_STATIC_LIBS=$(python3 - "$static_libs_log" "$(uname -s)" <<'PY'
import pathlib
import re
import shlex
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
platform = sys.argv[2]
# GitHub runners can force colored Cargo diagnostics even when output is redirected.
# Strip only well-formed ANSI CSI sequences, then reject any remaining escape byte;
# the native linker tokens below still pass through the strict allowlist.
ansi_csi = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
text = ansi_csi.sub("", text)
if "\x1b" in text:
    raise SystemExit("error: unsupported terminal escape in rustc native-static-libs output")
matches = re.findall(r"native-static-libs:\s*(.*)", text)
if not matches:
    raise SystemExit("error: rustc did not print native-static-libs for q-periapt-ffi")
tokens = shlex.split(matches[-1])
allowed_value_after = {"-framework", "-weak_framework"}
expect_value = False
for token in tokens:
    if expect_value:
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.+-]*", token):
            raise SystemExit(f"error: unsafe native static library token: {token}")
        expect_value = False
        continue
    if token in allowed_value_after:
        expect_value = True
        continue
    if not re.fullmatch(r"-l[A-Za-z0-9_.+-]+|-Wl,[A-Za-z0-9_.,@%+/=:-]+", token):
        raise SystemExit(f"error: unsafe native static library token: {token}")
if expect_value:
    raise SystemExit("error: native static library option missing value")
if platform == "Darwin":
    # AppleClang injects -lSystem itself; keeping rustc's copy makes ld warn
    # about a duplicate system library in every static consumer proof.
    tokens = [token for token in tokens if token != "-lSystem"]
print(" ".join(tokens))
PY
)
CMAKE_NATIVE_STATIC_LIBS=$(python3 - "$NATIVE_STATIC_LIBS" <<'PY'
import sys

tokens = sys.argv[1].split()
print(" ".join('"' + token.replace("\\", "\\\\").replace('"', '\\"') + '"' for token in tokens))
PY
)
printf 'native static libs: %s\n' "$NATIVE_STATIC_LIBS"

if [ "$PLATFORM" = "macos" ]; then
	# Mach-O compatibility/current versions cannot be set by install_name_tool.
	# Write all three ABI-major identity fields at link time, then have the
	# independent contract verifier read LC_ID_DYLIB from the packaged copy.
	cargo rustc -p q-periapt-ffi --release --locked --crate-type cdylib -- \
		-C "link-arg=-Wl,-install_name,@rpath/$SHARED_LIB" \
		-C "link-arg=-Wl,-compatibility_version,$ABI_COMPAT_VERSION" \
		-C "link-arg=-Wl,-current_version,$ABI_COMPAT_VERSION"
elif [ "$PLATFORM" = "linux" ]; then
	# Cargo has no stable manifest key for an ELF SONAME. Re-link this single
	# cdylib target with the frozen ABI-major SONAME and verify it below; merely
	# renaming an unversioned ELF file would create a false runtime identity.
	cargo rustc -p q-periapt-ffi --release --locked --crate-type cdylib -- \
		-C "link-arg=-Wl,-soname,$SHARED_LIB"
fi

for required_file in LICENSE LICENSES/Apache-2.0.txt LICENSES/MIT.txt; do
	test -f "$ROOT/$required_file" || {
		printf 'error: required license file missing: %s\n' "$required_file" >&2
		exit 1
	}
done

rm -rf "$PACKAGE_DIR" "$VERIFY_ROOT" "$ARCHIVE" "$ARCHIVE.sha256"
mkdir -p "$PACKAGE_DIR/include/qperiapt/abi2" \
	"$PACKAGE_DIR/lib/pkgconfig" \
	"$PACKAGE_DIR/lib/cmake/QPeriaptABI2" \
	"$PACKAGE_DIR/share/q-periapt/abi" \
	"$PACKAGE_DIR/share/q-periapt/bom" \
	"$PACKAGE_DIR/LICENSES"
cp "$HEADER_SOURCE" "$PACKAGE_DIR/include/qperiapt/abi2/q_periapt.h"
cp "$FIXTURE_SOURCE" "$PACKAGE_DIR/include/qperiapt/abi2/signed_policy_fixture.h"
cp "$CONTRACT_SOURCE" "$PACKAGE_DIR/share/q-periapt/abi/q-periapt-c-abi-v2.json"
cp "$ROOT/target/release/$STATIC_LIB" "$PACKAGE_DIR/lib/$STATIC_LIB"
cp "$ROOT/target/release/$BUILD_SHARED_LIB" "$PACKAGE_DIR/lib/$SHARED_LIB"
cp "$ROOT/bindings/c/smoke.c" "$PACKAGE_DIR/share/q-periapt/smoke.c"
cp "$ROOT/LICENSE" "$PACKAGE_DIR/LICENSE"
cp "$ROOT/LICENSES/Apache-2.0.txt" "$PACKAGE_DIR/LICENSES/Apache-2.0.txt"
cp "$ROOT/LICENSES/MIT.txt" "$PACKAGE_DIR/LICENSES/MIT.txt"
python3 artifact/c_abi_contract.py \
	--contract "$PACKAGE_DIR/share/q-periapt/abi/q-periapt-c-abi-v2.json" \
	--header "$PACKAGE_DIR/include/qperiapt/abi2/q_periapt.h" \
	--library "$PACKAGE_DIR/lib/$SHARED_LIB" \
	--platform "$PLATFORM"

cargo run --locked --quiet -p q-periapt-cli --bin qperiapt -- cbom >"$tmp_cbom"
cargo run --locked --quiet -p q-periapt-cli --bin qperiapt -- sbom --lock Cargo.lock >"$tmp_sbom"
cp "$tmp_cbom" "$PACKAGE_DIR/share/q-periapt/bom/cbom.cdx.json"
cp "$tmp_sbom" "$PACKAGE_DIR/share/q-periapt/bom/sbom.cdx.json"
validate_license_and_boms "$PACKAGE_DIR"

cat > "$PACKAGE_DIR/lib/pkgconfig/qperiapt-abi2.pc" <<EOF
prefix=\${pcfiledir}/../..
exec_prefix=\${prefix}
libdir=\${prefix}/lib
includedir=\${prefix}/include/qperiapt/abi2

Name: qperiapt-abi2
Description: Q-Periapt policy-gated C ABI 2 (ML-KEM-768 + X25519)
Version: $VERSION
Cflags: -I\${includedir}
Libs: \${libdir}/$SHARED_LIB ${RPATH_FLAG}\${libdir}
EOF

cat > "$PACKAGE_DIR/lib/pkgconfig/qperiapt-abi2-static.pc" <<EOF
prefix=\${pcfiledir}/../..
exec_prefix=\${prefix}
libdir=\${prefix}/lib
includedir=\${prefix}/include/qperiapt/abi2

Name: qperiapt-abi2-static
Description: Q-Periapt policy-gated C ABI 2 static library (ML-KEM-768 + X25519)
Version: $VERSION
Cflags: -I\${includedir}
Libs: \${libdir}/$STATIC_LIB
Libs.private: $NATIVE_STATIC_LIBS
EOF

cat > "$PACKAGE_DIR/lib/cmake/QPeriaptABI2/QPeriaptABI2Config.cmake" <<EOF
include_guard(GLOBAL)

if(NOT DEFINED QPeriaptABI2_FIND_VERSION OR
   NOT QPeriaptABI2_FIND_VERSION VERSION_EQUAL "$ABI_COMPAT_VERSION" OR
   NOT QPeriaptABI2_FIND_VERSION_EXACT)
  message(FATAL_ERROR
    "QPeriaptABI2 must be requested as find_package(QPeriaptABI2 $ABI_COMPAT_VERSION EXACT CONFIG REQUIRED)")
endif()

get_filename_component(_QPERIAPT_ABI2_PREFIX "\${CMAKE_CURRENT_LIST_DIR}/../../.." ABSOLUTE)
set(QPeriaptABI2_VERSION "$ABI_COMPAT_VERSION")
set(QPeriaptABI2_ABI_MAJOR "$ABI_MAJOR")
set(QPeriaptABI2_RELEASE_VERSION "$VERSION")
set(QPeriaptABI2_INCLUDE_DIR "\${_QPERIAPT_ABI2_PREFIX}/include/qperiapt/abi2")
set(QPeriaptABI2_LIBRARY "\${_QPERIAPT_ABI2_PREFIX}/lib/$SHARED_LIB")
set(QPeriaptABI2_STATIC_LIBRARY "\${_QPERIAPT_ABI2_PREFIX}/lib/$STATIC_LIB")
set(_QPERIAPT_ABI2_STATIC_NATIVE_LIBS $CMAKE_NATIVE_STATIC_LIBS)

if(NOT EXISTS "\${QPeriaptABI2_INCLUDE_DIR}/q_periapt.h")
  message(FATAL_ERROR "QPeriapt ABI 2 header not found: \${QPeriaptABI2_INCLUDE_DIR}/q_periapt.h")
endif()
if(NOT EXISTS "\${QPeriaptABI2_LIBRARY}")
  message(FATAL_ERROR "QPeriapt ABI 2 shared library not found: \${QPeriaptABI2_LIBRARY}")
endif()
if(NOT EXISTS "\${QPeriaptABI2_STATIC_LIBRARY}")
  message(FATAL_ERROR "QPeriapt ABI 2 static library not found: \${QPeriaptABI2_STATIC_LIBRARY}")
endif()

if(NOT TARGET QPeriaptABI2::qperiapt)
  add_library(QPeriaptABI2::qperiapt UNKNOWN IMPORTED)
  set_target_properties(QPeriaptABI2::qperiapt PROPERTIES
    IMPORTED_LOCATION "\${QPeriaptABI2_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "\${QPeriaptABI2_INCLUDE_DIR}"
  )
endif()

if(NOT TARGET QPeriaptABI2::qperiapt_static)
  add_library(QPeriaptABI2::qperiapt_static STATIC IMPORTED)
  set_target_properties(QPeriaptABI2::qperiapt_static PROPERTIES
    IMPORTED_LOCATION "\${QPeriaptABI2_STATIC_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "\${QPeriaptABI2_INCLUDE_DIR}"
  )
  if(_QPERIAPT_ABI2_STATIC_NATIVE_LIBS)
    set_property(TARGET QPeriaptABI2::qperiapt_static APPEND PROPERTY
      INTERFACE_LINK_LIBRARIES \${_QPERIAPT_ABI2_STATIC_NATIVE_LIBS})
  endif()
endif()
EOF

cat > "$PACKAGE_DIR/lib/cmake/QPeriaptABI2/QPeriaptABI2ConfigVersion.cmake" <<EOF
set(PACKAGE_VERSION "$ABI_COMPAT_VERSION")

if(PACKAGE_FIND_VERSION VERSION_EQUAL PACKAGE_VERSION)
  set(PACKAGE_VERSION_EXACT TRUE)
  set(PACKAGE_VERSION_COMPATIBLE TRUE)
else()
  set(PACKAGE_VERSION_COMPATIBLE FALSE)
  set(PACKAGE_VERSION_UNSUITABLE TRUE)
endif()
EOF

cat > "$PACKAGE_DIR/README.md" <<EOF
# Q-Periapt C ABI 2 — $VERSION ($HOST)

This archive contains the policy-gated Q-Periapt C ABI 2 for ML-KEM-768 + X25519.
The CMake ABI compatibility version is \`$ABI_COMPAT_VERSION\`; the full release
version is exposed as \`QPeriaptABI2_RELEASE_VERSION=$VERSION\`.

Contents:

- \`include/qperiapt/abi2/q_periapt.h\`
- \`include/qperiapt/abi2/signed_policy_fixture.h\` (public smoke-test material)
- \`lib/$STATIC_LIB\`
- \`lib/$SHARED_LIB\`
- \`lib/pkgconfig/qperiapt-abi2.pc\`
- \`lib/pkgconfig/qperiapt-abi2-static.pc\`
- \`lib/cmake/QPeriaptABI2/QPeriaptABI2Config.cmake\`
- \`lib/cmake/QPeriaptABI2/QPeriaptABI2ConfigVersion.cmake\`
- \`share/q-periapt/abi/q-periapt-c-abi-v2.json\`
- \`share/q-periapt/smoke.c\`
- \`share/q-periapt/bom/cbom.cdx.json\`
- \`share/q-periapt/bom/sbom.cdx.json\`
- \`LICENSE\`
- \`LICENSES/Apache-2.0.txt\`
- \`LICENSES/MIT.txt\`
- \`MANIFEST.json\` and \`SHA256SUMS\`

Verify checksums:

\`\`\`sh
shasum -a 256 -c SHA256SUMS
\`\`\`

Compile the bundled smoke with pkg-config:

\`\`\`sh
PKG_CONFIG_PATH="\$PWD/lib/pkgconfig" PKG_CONFIG_LIBDIR="\$PWD/lib/pkgconfig" \\
  pkg-config --cflags --libs qperiapt-abi2 > qperiapt-abi2.flags
cc -std=c11 -Wall -Wextra -Wpedantic -Werror share/q-periapt/smoke.c \\
  @qperiapt-abi2.flags \\
  -o c_smoke
./c_smoke
\`\`\`

Compile the bundled smoke with the static archive:

\`\`\`sh
PKG_CONFIG_PATH="\$PWD/lib/pkgconfig" PKG_CONFIG_LIBDIR="\$PWD/lib/pkgconfig" \\
  pkg-config --cflags --libs --static qperiapt-abi2-static > qperiapt-abi2-static.flags
cc -std=c11 -Wall -Wextra -Wpedantic -Werror share/q-periapt/smoke.c \\
  @qperiapt-abi2-static.flags \\
  -o c_static_smoke
./c_static_smoke
\`\`\`
EOF

if grep -R -n -F "$ROOT" \
	"$PACKAGE_DIR/lib/pkgconfig" \
	"$PACKAGE_DIR/lib/cmake" \
	"$PACKAGE_DIR/share/q-periapt" \
	"$PACKAGE_DIR/LICENSE" \
	"$PACKAGE_DIR/LICENSES" \
	"$PACKAGE_DIR/README.md" >"$path_log" 2>&1; then
	cat "$path_log" >&2
	printf 'error: package metadata contains source-tree path\n' >&2
	exit 1
fi
if grep -R -n -F "target/release" \
	"$PACKAGE_DIR/lib/pkgconfig" \
	"$PACKAGE_DIR/lib/cmake" \
	"$PACKAGE_DIR/share/q-periapt" \
	"$PACKAGE_DIR/README.md" >"$path_log" 2>&1; then
	cat "$path_log" >&2
	printf 'error: package metadata references target/release\n' >&2
	exit 1
fi

python3 - "$ROOT" "$PACKAGE_DIR" "$PACKAGE_NAME" "$VERSION" "$HOST" \
	"$PLATFORM" "$SHARED_LIB" "$STATIC_LIB" <<'PY'
import datetime as dt
import hashlib
import json
import pathlib
import stat
import subprocess
import sys

root = pathlib.Path(sys.argv[1]).resolve()
package_dir = pathlib.Path(sys.argv[2]).resolve()
package_name = sys.argv[3]
version = sys.argv[4]
host = sys.argv[5]
platform = sys.argv[6]
shared_filename = sys.argv[7]
static_filename = sys.argv[8]

def sha256(path: pathlib.Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()

def run(args: list[str]) -> str:
    try:
        return subprocess.check_output(args, cwd=root, text=True, stderr=subprocess.PIPE).strip()
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.strip() if exc.stderr else ""
        raise SystemExit(f"error: command failed for package manifest: {' '.join(args)} {stderr}") from exc

entries = []
for path in sorted(p for p in package_dir.rglob("*") if p.is_file() and p.name not in {"MANIFEST.json", "SHA256SUMS"}):
    rel = path.relative_to(package_dir).as_posix()
    st = path.stat()
    entries.append({
        "path": rel,
        "type": "file",
        "mode": oct(stat.S_IMODE(st.st_mode)),
        "sha256": sha256(path),
        "bytes": st.st_size,
    })

def tree_hash(rels: tuple[str, ...]) -> str:
    hasher = hashlib.sha256()
    seen = False
    for rel in rels:
        base = root / rel
        if base.is_file():
            candidates = [base]
        elif base.is_dir():
            candidates = sorted(p for p in base.rglob("*") if p.is_file())
        else:
            raise SystemExit(f"error: source input missing: {base}")
        for candidate in candidates:
            seen = True
            rel_name = candidate.resolve().relative_to(root).as_posix()
            hasher.update(rel_name.encode("utf-8"))
            hasher.update(b"\0")
            hasher.update(hashlib.sha256(candidate.read_bytes()).digest())
            hasher.update(b"\0")
    if not seen:
        raise SystemExit("error: source tree hash had no inputs")
    return hasher.hexdigest()

source_contract_rel = "crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json"
embedded_contract_rel = "share/q-periapt/abi/q-periapt-c-abi-v2.json"
source_contract_path = root / source_contract_rel
embedded_contract_path = package_dir / embedded_contract_rel
if sha256(source_contract_path) != sha256(embedded_contract_path):
    raise SystemExit("error: embedded ABI contract differs from repository trust root")
contract = json.loads(embedded_contract_path.read_text(encoding="utf-8"))
exports = sorted(item["name"] for item in contract["abi"]["exports"])
if len(exports) != 9 or len(exports) != len(set(exports)):
    raise SystemExit(f"error: ABI contract export count differs from frozen value: {len(exports)}")
# ABI export-set digest encoding: UTF-8 of sorted exact names, one per line,
# including the final LF. This is stable across JSON formatting and platforms.
exports_sha256 = hashlib.sha256(("\n".join(exports) + "\n").encode("utf-8")).hexdigest()
runtime_identity = contract["package"]["platforms"][platform]
if runtime_identity["shared_filename"] != shared_filename:
    raise SystemExit("error: packaged shared filename differs from ABI contract")
if runtime_identity["static_filename"] != static_filename:
    raise SystemExit("error: packaged static filename differs from ABI contract")

manifest = {
    "schema_version": 2,
    "package": package_name,
    "version": version,
    "host": host,
    "generated_at": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
    "git_commit": run(["git", "rev-parse", "HEAD"]),
    "git_dirty": bool(run(["git", "status", "--short"])),
    "rustc": run(["rustc", "--version"]),
    "cargo": run(["cargo", "--version"]),
    "abi": {
        "major": 2,
        "contract_path": source_contract_rel,
        "embedded_contract_path": embedded_contract_rel,
        "contract_sha256": sha256(embedded_contract_path),
        "exports_sha256": exports_sha256,
        "export_count": len(exports),
        "platform": platform,
        "runtime_identity": runtime_identity,
        "shared_filename": shared_filename,
        "static_filename": static_filename,
    },
    "source_inputs_sha256": {
        "cargo_lock": sha256(root / "Cargo.lock"),
        "c_package_script": sha256(root / "artifact" / "c-package.sh"),
        "c_abi_contract_script": sha256(root / "artifact" / "c_abi_contract.py"),
        "c_abi_contract": sha256(root / "crates" / "q-periapt-ffi" / "abi" / "q-periapt-c-abi-v2.json"),
        "c_smoke": sha256(root / "bindings" / "c" / "smoke.c"),
        "c_signed_policy_fixture": sha256(root / "bindings" / "c" / "signed_policy_fixture.h"),
        "license": sha256(root / "LICENSE"),
        "license_apache": sha256(root / "LICENSES" / "Apache-2.0.txt"),
        "license_mit": sha256(root / "LICENSES" / "MIT.txt"),
        "qperiapt_cli_cargo": sha256(root / "crates" / "q-periapt-cli" / "Cargo.toml"),
        "qperiapt_cli_lib": sha256(root / "crates" / "q-periapt-cli" / "src" / "lib.rs"),
        "qperiapt_cli_main": sha256(root / "crates" / "q-periapt-cli" / "src" / "main.rs"),
        "ffi_header": sha256(root / "crates" / "q-periapt-ffi" / "include" / "q_periapt.h"),
        "rust_workspace_build_inputs": tree_hash(("Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "crates")),
    },
    "files": entries,
}
manifest_path = package_dir / "MANIFEST.json"
manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
entries.append({"path": "MANIFEST.json", "sha256": sha256(manifest_path), "bytes": manifest_path.stat().st_size})

with (package_dir / "SHA256SUMS").open("w", encoding="utf-8") as handle:
    for entry in sorted(entries, key=lambda item: item["path"]):
        handle.write(f"{entry['sha256']}  {entry['path']}\n")
PY

printf '\n=== Archive package ===\n'
mkdir -p "$OUT_ROOT"
COPYFILE_DISABLE=1 tar -czf "$ARCHIVE" -C "$OUT_ROOT" "$PACKAGE_NAME"
shasum -a 256 "$ARCHIVE" > "$ARCHIVE.sha256"
printf 'C_ABI_PACKAGE_ARCHIVE=%s\n' "$ARCHIVE"

printf '\n=== Verify extracted package ===\n'
mkdir -p "$VERIFY_ROOT"
python3 - "$ARCHIVE" "$VERIFY_ROOT" "$PACKAGE_NAME" <<'PY'
import pathlib
import tarfile
import sys

archive = pathlib.Path(sys.argv[1]).resolve()
dest = pathlib.Path(sys.argv[2]).resolve()
package_name = sys.argv[3]
seen: set[str] = set()

with tarfile.open(archive, "r:gz") as tar:
    members = tar.getmembers()
    if not members:
        raise SystemExit("error: archive is empty")
    for member in members:
        name = member.name
        path = pathlib.PurePosixPath(name)
        if not name or path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
            raise SystemExit(f"error: unsafe archive entry path: {name}")
        if any(part.startswith("._") for part in path.parts):
            raise SystemExit(f"error: unsupported AppleDouble archive entry: {name}")
        if path.parts[0] != package_name:
            raise SystemExit(f"error: unexpected archive top-level entry: {name}")
        normalized = path.as_posix()
        if normalized in seen:
            raise SystemExit(f"error: duplicate archive entry: {name}")
        seen.add(normalized)
        if member.issym() or member.islnk() or member.isdev() or member.isfifo():
            raise SystemExit(f"error: unsupported archive entry type: {name}")
        if not (member.isdir() or member.isfile()):
            raise SystemExit(f"error: unsupported archive entry type: {name}")
    tar.extractall(dest)
PY
EXTRACTED="$VERIFY_ROOT/$PACKAGE_NAME"
test -d "$EXTRACTED" || {
	printf 'error: extracted package missing: %s\n' "$EXTRACTED" >&2
	exit 1
}
(cd "$EXTRACTED" && shasum -a 256 -c SHA256SUMS)
validate_license_and_boms "$EXTRACTED"
python3 - "$ROOT" "$EXTRACTED" <<'PY'
import hashlib
import json
import pathlib
import re
import sys

repo_root = pathlib.Path(sys.argv[1]).resolve()
root = pathlib.Path(sys.argv[2]).resolve()

def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"error: {message}")

manifest_path = root / "MANIFEST.json"
sums_path = root / "SHA256SUMS"
require(manifest_path.is_file(), "MANIFEST.json missing after extraction")
require(sums_path.is_file(), "SHA256SUMS missing after extraction")
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
require(manifest.get("schema_version") == 2, "unsupported MANIFEST schema")
files = manifest.get("files")
require(isinstance(files, list) and files, "MANIFEST files list missing")
source_inputs = manifest.get("source_inputs_sha256")
require(isinstance(source_inputs, dict), "MANIFEST source_inputs_sha256 missing")
abi = manifest.get("abi")
require(isinstance(abi, dict), "MANIFEST abi object missing")
require(set(abi) == {
    "major",
    "contract_path",
    "embedded_contract_path",
    "contract_sha256",
    "exports_sha256",
    "export_count",
    "platform",
    "runtime_identity",
    "shared_filename",
    "static_filename",
}, "MANIFEST abi keys differ from schema 2")
require(abi["major"] == 2, "MANIFEST ABI major is not 2")
require(abi["export_count"] == 9, "MANIFEST ABI export count is not 9")
require(abi["platform"] in {"macos", "linux"}, "MANIFEST ABI platform is unsupported")
require(abi["contract_path"] == "crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json", "MANIFEST repository contract path differs")
require(abi["embedded_contract_path"] == "share/q-periapt/abi/q-periapt-c-abi-v2.json", "MANIFEST embedded contract path differs")
require(re.fullmatch(r"[0-9a-f]{64}", abi["contract_sha256"] or "") is not None, "MANIFEST ABI contract hash is malformed")
require(re.fullmatch(r"[0-9a-f]{64}", abi["exports_sha256"] or "") is not None, "MANIFEST ABI exports hash is malformed")
require(isinstance(abi["runtime_identity"], dict), "MANIFEST runtime identity is not an object")

manifest_hashes = {}
for entry in files:
    require(isinstance(entry, dict), "MANIFEST file entry is not an object")
    rel = entry.get("path")
    digest = entry.get("sha256")
    require(isinstance(rel, str) and rel, "MANIFEST path missing")
    require(re.fullmatch(r"[0-9a-f]{64}", digest or ""), f"MANIFEST sha256 invalid for {rel}")
    require(not pathlib.PurePosixPath(rel).is_absolute(), f"MANIFEST absolute path: {rel}")
    require(".." not in pathlib.PurePosixPath(rel).parts, f"MANIFEST parent traversal path: {rel}")
    require(not any(part.startswith("._") for part in pathlib.PurePosixPath(rel).parts), f"MANIFEST AppleDouble path: {rel}")
    require(rel not in manifest_hashes, f"duplicate MANIFEST path: {rel}")
    manifest_hashes[rel] = digest

sum_hashes = {}
for line in sums_path.read_text(encoding="utf-8").splitlines():
    if not line:
        continue
    parts = line.split("  ", 1)
    require(len(parts) == 2, f"malformed SHA256SUMS line: {line}")
    digest, rel = parts
    require(re.fullmatch(r"[0-9a-f]{64}", digest), f"invalid SHA256SUMS digest for {rel}")
    require(rel not in sum_hashes, f"duplicate SHA256SUMS path: {rel}")
    sum_hashes[rel] = digest

actual_files = {
    path.relative_to(root).as_posix()
    for path in root.rglob("*")
    if path.is_file()
}
expected_actual = set(manifest_hashes) | {"MANIFEST.json", "SHA256SUMS"}
require(actual_files == expected_actual, f"archive file set mismatch extra={sorted(actual_files - expected_actual)} missing={sorted(expected_actual - actual_files)}")
expected_sums = set(manifest_hashes) | {"MANIFEST.json"}
require(set(sum_hashes) == expected_sums, f"SHA256SUMS path set mismatch extra={sorted(set(sum_hashes) - expected_sums)} missing={sorted(expected_sums - set(sum_hashes))}")

def sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

for rel, digest in manifest_hashes.items():
    require(sum_hashes[rel] == digest, f"MANIFEST/SHA256SUMS hash mismatch for {rel}")
    require(sha256(root / rel) == digest, f"file hash mismatch for {rel}")
require(sha256(manifest_path) == sum_hashes["MANIFEST.json"], "MANIFEST.json hash mismatch")
embedded_contract_path = root / abi["embedded_contract_path"]
require(embedded_contract_path.is_file(), "embedded ABI contract is missing")
require(sha256(embedded_contract_path) == abi["contract_sha256"], "embedded ABI contract hash mismatch")
source_contract_path = repo_root / abi["contract_path"]
require(source_contract_path.is_file(), "repository ABI contract is missing")
require(sha256(source_contract_path) == abi["contract_sha256"], "repository/embedded ABI contract hash mismatch")
contract = json.loads(embedded_contract_path.read_text(encoding="utf-8"))
require(contract["abi"]["major"] == 2, "embedded ABI contract major differs")
require(contract["package"]["semver"] == manifest.get("version"), "manifest version differs from ABI contract")
require(abi["runtime_identity"] == contract["package"]["platforms"][abi["platform"]], "MANIFEST runtime identity differs from ABI contract")
require(abi["shared_filename"] == abi["runtime_identity"]["shared_filename"], "MANIFEST shared filename differs from runtime identity")
require(abi["static_filename"] == abi["runtime_identity"]["static_filename"], "MANIFEST static filename differs from runtime identity")
exports = sorted(item["name"] for item in contract["abi"]["exports"])
require(len(exports) == 9 and len(exports) == len(set(exports)), "embedded ABI contract export count differs")
# Encoding is UTF-8 of sorted exact export names, one name per line, with a final LF.
exports_sha256 = hashlib.sha256(("\n".join(exports) + "\n").encode("utf-8")).hexdigest()
require(exports_sha256 == abi["exports_sha256"], "MANIFEST ABI export-set hash mismatch")
require((root / "lib" / abi["shared_filename"]).is_file(), "MANIFEST shared library is missing")
require((root / "lib" / abi["static_filename"]).is_file(), "MANIFEST static library is missing")
require((root / "include/qperiapt/abi2/q_periapt.h").is_file(), "ABI-major header path is missing")
require((root / "include/qperiapt/abi2/signed_policy_fixture.h").is_file(), "signed-policy fixture is missing")
for legacy in (
    "include/q_periapt.h",
    "lib/libq_periapt_ffi.dylib",
    "lib/libq_periapt_ffi.so",
    "lib/libq_periapt_ffi.a",
    "lib/libq_periapt_ffi_abi2.dylib",
    "lib/libq_periapt_ffi_abi2.so",
    "lib/pkgconfig/qperiapt.pc",
    "lib/pkgconfig/qperiapt-static.pc",
    "lib/cmake/QPeriapt/QPeriaptConfig.cmake",
):
    require(not (root / legacy).exists(), f"legacy/unversioned package path is present: {legacy}")
expected_source_files = {
    "cargo_lock": "Cargo.lock",
    "c_package_script": "artifact/c-package.sh",
    "c_abi_contract_script": "artifact/c_abi_contract.py",
    "c_abi_contract": "crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json",
    "c_smoke": "bindings/c/smoke.c",
    "c_signed_policy_fixture": "bindings/c/signed_policy_fixture.h",
    "ffi_header": "crates/q-periapt-ffi/include/q_periapt.h",
    "license": "LICENSE",
    "license_apache": "LICENSES/Apache-2.0.txt",
    "license_mit": "LICENSES/MIT.txt",
    "qperiapt_cli_cargo": "crates/q-periapt-cli/Cargo.toml",
    "qperiapt_cli_lib": "crates/q-periapt-cli/src/lib.rs",
    "qperiapt_cli_main": "crates/q-periapt-cli/src/main.rs",
}
for key, rel in expected_source_files.items():
    require(key in source_inputs, f"MANIFEST source input missing: {key}")
    require(source_inputs[key] == sha256(repo_root / rel), f"MANIFEST source input hash mismatch for {rel}")
PY

python3 artifact/c_abi_contract.py \
	--contract "$EXTRACTED/share/q-periapt/abi/q-periapt-c-abi-v2.json" \
	--header "$EXTRACTED/include/qperiapt/abi2/q_periapt.h" \
	--library "$EXTRACTED/lib/$SHARED_LIB" \
	--platform "$PLATFORM"

printf '\n=== Legacy package-name negative controls ===\n'
for legacy_module in qperiapt qperiapt-static; do
	if PKG_CONFIG_PATH="$EXTRACTED/lib/pkgconfig" \
		PKG_CONFIG_LIBDIR="$EXTRACTED/lib/pkgconfig" \
		pkg-config --exists "$legacy_module"; then
		printf 'error: legacy pkg-config module unexpectedly resolves: %s\n' "$legacy_module" >&2
		exit 1
	fi
done
printf 'PASS: legacy pkg-config modules do not resolve\n'

printf '\n=== pkg-config extracted consumer ===\n'
PKG_CONFIG_PATH="$EXTRACTED/lib/pkgconfig" \
	PKG_CONFIG_LIBDIR="$EXTRACTED/lib/pkgconfig" \
	pkg-config --cflags --libs qperiapt-abi2 > "$VERIFY_ROOT/pkgconfig-dynamic.flags"
PKG_DYNAMIC_VERSION=$(PKG_CONFIG_PATH="$EXTRACTED/lib/pkgconfig" \
	PKG_CONFIG_LIBDIR="$EXTRACTED/lib/pkgconfig" \
	pkg-config --modversion qperiapt-abi2)
if [ "$PKG_DYNAMIC_VERSION" != "$VERSION" ]; then
	printf 'error: dynamic pkg-config release version differs: %s\n' "$PKG_DYNAMIC_VERSION" >&2
	exit 1
fi
cc -std=c11 -Wall -Wextra -Wpedantic -Werror "$EXTRACTED/share/q-periapt/smoke.c" \
	@"$VERIFY_ROOT/pkgconfig-dynamic.flags" \
	-o "$VERIFY_ROOT/pkgconfig-smoke"
"$VERIFY_ROOT/pkgconfig-smoke"
inspect_dynamic_linkage "$VERIFY_ROOT/pkgconfig-smoke" "pkgconfig-smoke"

printf '\n=== pkg-config static extracted consumer ===\n'
PKG_CONFIG_PATH="$EXTRACTED/lib/pkgconfig" \
	PKG_CONFIG_LIBDIR="$EXTRACTED/lib/pkgconfig" \
	pkg-config --cflags --libs --static qperiapt-abi2-static > "$VERIFY_ROOT/pkgconfig-static.flags"
PKG_STATIC_VERSION=$(PKG_CONFIG_PATH="$EXTRACTED/lib/pkgconfig" \
	PKG_CONFIG_LIBDIR="$EXTRACTED/lib/pkgconfig" \
	pkg-config --modversion qperiapt-abi2-static)
if [ "$PKG_STATIC_VERSION" != "$VERSION" ]; then
	printf 'error: static pkg-config release version differs: %s\n' "$PKG_STATIC_VERSION" >&2
	exit 1
fi
cc -std=c11 -Wall -Wextra -Wpedantic -Werror "$EXTRACTED/share/q-periapt/smoke.c" \
	@"$VERIFY_ROOT/pkgconfig-static.flags" \
	-o "$VERIFY_ROOT/pkgconfig-static-smoke"
"$VERIFY_ROOT/pkgconfig-static-smoke"
inspect_static_linkage "$VERIFY_ROOT/pkgconfig-static-smoke" "pkgconfig-static-smoke"

printf '\n=== CMake extracted consumer ===\n'
CMAKE_SRC="$VERIFY_ROOT/cmake-consumer-src"
CMAKE_BUILD="$VERIFY_ROOT/cmake-consumer-build"
mkdir -p "$CMAKE_SRC"
cp "$EXTRACTED/share/q-periapt/smoke.c" "$CMAKE_SRC/smoke.c"
cat > "$CMAKE_SRC/CMakeLists.txt" <<'EOF'
cmake_minimum_required(VERSION 3.20)
project(QPeriaptCConsumer C)
find_package(QPeriaptABI2 2.0.0 EXACT REQUIRED CONFIG)
if(NOT QPeriaptABI2_RELEASE_VERSION STREQUAL EXPECTED_QPERIAPT_RELEASE_VERSION)
  message(FATAL_ERROR
    "QPeriapt ABI 2 release version mismatch: ${QPeriaptABI2_RELEASE_VERSION}")
endif()
add_executable(cmake-smoke smoke.c)
target_compile_features(cmake-smoke PRIVATE c_std_11)
target_compile_options(cmake-smoke PRIVATE -Wall -Wextra -Wpedantic)
target_link_libraries(cmake-smoke PRIVATE QPeriaptABI2::qperiapt)
add_executable(cmake-static-smoke smoke.c)
target_compile_features(cmake-static-smoke PRIVATE c_std_11)
target_compile_options(cmake-static-smoke PRIVATE -Wall -Wextra -Wpedantic)
target_link_libraries(cmake-static-smoke PRIVATE QPeriaptABI2::qperiapt_static)
enable_testing()
add_test(NAME qperiapt-cmake-smoke COMMAND cmake-smoke)
add_test(NAME qperiapt-cmake-static-smoke COMMAND cmake-static-smoke)
EOF
cmake -S "$CMAKE_SRC" -B "$CMAKE_BUILD" -DCMAKE_PREFIX_PATH="$EXTRACTED" \
	-DEXPECTED_QPERIAPT_RELEASE_VERSION="$VERSION" \
	-DCMAKE_BUILD_TYPE=Release -DCMAKE_COMPILE_WARNING_AS_ERROR=ON \
	-DCMAKE_FIND_PACKAGE_PREFER_CONFIG=ON \
	-DCMAKE_FIND_USE_PACKAGE_REGISTRY=OFF \
	-DCMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY=OFF
cmake --build "$CMAKE_BUILD"
ctest_list=$(ctest --test-dir "$CMAKE_BUILD" -N)
printf '%s\n' "$ctest_list"
if ! printf '%s\n' "$ctest_list" | grep -q 'Total Tests: 2'; then
	printf 'error: expected exactly two CMake smoke tests\n' >&2
	exit 1
fi
ctest --test-dir "$CMAKE_BUILD" --output-on-failure
inspect_dynamic_linkage "$CMAKE_BUILD/cmake-smoke" "cmake-smoke"
inspect_static_linkage "$CMAKE_BUILD/cmake-static-smoke" "cmake-static-smoke"

printf '\n=== Legacy CMake package negative control ===\n'
LEGACY_CMAKE_SRC="$VERIFY_ROOT/cmake-legacy-negative-src"
LEGACY_CMAKE_BUILD="$VERIFY_ROOT/cmake-legacy-negative-build"
mkdir -p "$LEGACY_CMAKE_SRC"
cat > "$LEGACY_CMAKE_SRC/CMakeLists.txt" <<'EOF'
cmake_minimum_required(VERSION 3.20)
project(QPeriaptLegacyNegative NONE)
find_package(QPeriapt CONFIG QUIET PATHS "${QPERIAPT_TEST_PREFIX}" NO_DEFAULT_PATH)
if(QPeriapt_FOUND)
  message(FATAL_ERROR "legacy QPeriapt CMake package unexpectedly resolved")
endif()
find_package(QPeriaptABI2 2.0.1 EXACT CONFIG QUIET
  PATHS "${QPERIAPT_TEST_PREFIX}" NO_DEFAULT_PATH)
if(QPeriaptABI2_FOUND)
  message(FATAL_ERROR "wrong QPeriaptABI2 compatibility version unexpectedly resolved")
endif()
EOF
cmake -S "$LEGACY_CMAKE_SRC" -B "$LEGACY_CMAKE_BUILD" \
	-DQPERIAPT_TEST_PREFIX="$EXTRACTED" \
	-DCMAKE_FIND_USE_PACKAGE_REGISTRY=OFF \
	-DCMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY=OFF
printf 'PASS: legacy CMake package and wrong ABI compatibility version do not resolve\n'

printf '\nC_ABI_PACKAGE_VERIFY_PASS\n'
