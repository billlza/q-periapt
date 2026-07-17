#!/bin/sh
# Build and verify the Android AAR/JNI release surface.
#
# This is a pre-publication packaging gate. It proves that an Android consumer can
# compile against a deterministic AAR containing Android ELF ABI slices and a JNI
# shim over the existing q-periapt-ffi C ABI. Runtime/device proof is intentionally
# separate: package-only output must not be described as Android device readiness.
set -eu

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

choose_highest_child() {
	python3 - "$1" "$2" <<'PY'
import pathlib
import re
import sys

base = pathlib.Path(sys.argv[1])
kind = sys.argv[2]
if not base.is_dir():
    raise SystemExit(f"error: missing {kind} directory: {base}")

def key(path: pathlib.Path):
    nums = [int(part) for part in re.findall(r"\d+", path.name)]
    return (nums, path.name)

candidates = sorted((p for p in base.iterdir() if p.is_dir()), key=key)
if not candidates:
    raise SystemExit(f"error: no {kind} candidates under {base}")
print(candidates[-1])
PY
}

need cargo
need cbindgen
need file
need git
need javac
need javap
need python3
need rustc
need rustup

if [ "${QPERIAPT_ANDROID_AAR_SKIP_VERIFY:-0}" = "1" ]; then
	printf 'error: QPERIAPT_ANDROID_AAR_SKIP_VERIFY is not supported\n' >&2
	exit 2
fi

SOURCE_PROVENANCE=$(python3 - "$ROOT" <<'PY'
import pathlib
import sys

from claim_ledger import LedgerError, canonical_tree_digest, repository_paths
from git_provenance import GitProvenanceError, inspect_worktree, run_git_text

root = pathlib.Path(sys.argv[1])
try:
    inspection = inspect_worktree(root)
    commit_epoch = run_git_text(root, ["show", "-s", "--format=%ct", "HEAD"])
    source_digest = canonical_tree_digest(root, repository_paths(root))
except (GitProvenanceError, LedgerError, OSError, UnicodeDecodeError) as exc:
    raise SystemExit(f"error: cannot establish Android AAR source provenance: {exc}") from exc
if not commit_epoch.isascii() or not commit_epoch.isdigit():
    raise SystemExit("error: Android source commit timestamp is malformed")
print(f"{inspection.commit}|{1 if inspection.dirty else 0}|{commit_epoch}|{source_digest}")
PY
)
OLD_IFS=$IFS
IFS='|'
read -r SOURCE_COMMIT SOURCE_DIRTY SOURCE_COMMIT_EPOCH SOURCE_TREE_SHA256 SOURCE_EXTRA <<EOF
$SOURCE_PROVENANCE
EOF
IFS=$OLD_IFS
if [ -n "$SOURCE_EXTRA" ]; then
	printf 'error: Android AAR source provenance output is malformed\n' >&2
	exit 2
fi
case "$SOURCE_DIRTY" in
	0 | 1) ;;
	*)
		printf 'error: Android AAR source dirty provenance is malformed\n' >&2
		exit 2
		;;
esac
case "$SOURCE_COMMIT_EPOCH" in
	'' | *[!0-9]*)
		printf 'error: Android AAR source timestamp is malformed\n' >&2
		exit 2
		;;
esac
case "$SOURCE_TREE_SHA256" in
	????????????????????????????????????????????????????????????????) ;;
	*)
		printf 'error: Android AAR source tree digest is malformed\n' >&2
		exit 2
		;;
esac
if [ "$SOURCE_DIRTY" = "1" ] && [ "${QPERIAPT_ALLOW_DIRTY_ANDROID_AAR:-0}" != "1" ]; then
	printf 'error: Android AAR release gate requires a clean worktree; set QPERIAPT_ALLOW_DIRTY_ANDROID_AAR=1 only for local diagnostics\n' >&2
	exit 2
fi
if [ "$SOURCE_DIRTY" = "1" ]; then
	printf 'DIRTY_ANDROID_AAR_DIAGNOSTIC_ONLY\n'
fi
if [ -n "${SOURCE_DATE_EPOCH:-}" ] && [ "$SOURCE_DATE_EPOCH" != "$SOURCE_COMMIT_EPOCH" ]; then
	printf 'error: SOURCE_DATE_EPOCH must equal the Android source HEAD commit epoch %s\n' "$SOURCE_COMMIT_EPOCH" >&2
	exit 2
fi
SOURCE_DATE_EPOCH=$SOURCE_COMMIT_EPOCH
if [ "$SOURCE_DATE_EPOCH" -gt 4294967295 ]; then
	printf 'error: Android AAR source epoch exceeds the supported deterministic range\n' >&2
	exit 2
fi
export SOURCE_DATE_EPOCH
EXPECTED_GIT_COMMIT=${QPERIAPT_EXPECTED_GIT_COMMIT:-}

assert_source_snapshot() {
	PYTHONPATH=artifact python3 artifact/android_elf.py verify-expected-commit \
		--expected "$EXPECTED_GIT_COMMIT" \
		--actual "$SOURCE_COMMIT" >/dev/null
	python3 - "$ROOT" "$SOURCE_COMMIT" "$SOURCE_DIRTY" "$SOURCE_COMMIT_EPOCH" "$SOURCE_TREE_SHA256" <<'PY'
import pathlib
import sys

from claim_ledger import LedgerError, canonical_tree_digest, repository_paths
from git_provenance import GitProvenanceError, inspect_worktree, run_git_text

root = pathlib.Path(sys.argv[1])
expected_commit = sys.argv[2]
expected_dirty = sys.argv[3] == "1"
expected_epoch = sys.argv[4]
expected_digest = sys.argv[5]
try:
    inspection = inspect_worktree(root)
    actual_epoch = run_git_text(root, ["show", "-s", "--format=%ct", "HEAD"])
    actual_digest = canonical_tree_digest(root, repository_paths(root))
except (GitProvenanceError, LedgerError, OSError, UnicodeDecodeError) as exc:
    raise SystemExit(f"error: cannot revalidate Android AAR source provenance: {exc}") from exc
if inspection.commit != expected_commit:
    raise SystemExit("error: Android AAR source commit changed during the build")
if inspection.dirty is not expected_dirty:
    raise SystemExit("error: Android AAR source dirty state changed during the build")
if actual_epoch != expected_epoch:
    raise SystemExit("error: Android AAR source commit epoch changed during the build")
if actual_digest != expected_digest:
    raise SystemExit("error: Android AAR source bytes changed during the build")
PY
}

assert_source_snapshot

ANDROID_SDK=${QPERIAPT_ANDROID_SDK_ROOT:-${ANDROID_HOME:-${ANDROID_SDK_ROOT:-"$HOME/Library/Android/sdk"}}}
if [ ! -d "$ANDROID_SDK" ]; then
	printf 'error: Android SDK not found; set QPERIAPT_ANDROID_SDK_ROOT or ANDROID_HOME\n' >&2
	exit 2
fi

ANDROID_NDK=${QPERIAPT_ANDROID_NDK_HOME:-${ANDROID_NDK_HOME:-}}
if [ -z "$ANDROID_NDK" ]; then
	ANDROID_NDK="$ANDROID_SDK/ndk/29.0.14206865"
fi
if [ ! -d "$ANDROID_NDK" ]; then
	printf 'error: Android NDK r29 not found: %s\n' "$ANDROID_NDK" >&2
	exit 2
fi
NDK_REVISION=$(PYTHONPATH=artifact python3 artifact/android_elf.py verify-ndk --ndk "$ANDROID_NDK")

ANDROID_PLATFORM=${QPERIAPT_ANDROID_PLATFORM:-$(choose_highest_child "$ANDROID_SDK/platforms" "Android platform")}
ANDROID_JAR="$ANDROID_PLATFORM/android.jar"
if [ ! -f "$ANDROID_JAR" ]; then
	printf 'error: Android platform is missing android.jar: %s\n' "$ANDROID_PLATFORM" >&2
	exit 2
fi

ANDROID_BUILD_TOOLS=${QPERIAPT_ANDROID_BUILD_TOOLS:-$(choose_highest_child "$ANDROID_SDK/build-tools" "Android build-tools")}
D8="$ANDROID_BUILD_TOOLS/d8"
if [ ! -x "$D8" ]; then
	printf 'error: Android build-tools d8 not found: %s\n' "$D8" >&2
	exit 2
fi

TOOLCHAIN=$(PYTHONPATH=artifact python3 artifact/android_elf.py find-toolchain --ndk "$ANDROID_NDK")

LLVM_AR="$TOOLCHAIN/bin/llvm-ar"
LLVM_NM="$TOOLCHAIN/bin/llvm-nm"
LLVM_READELF="$TOOLCHAIN/bin/llvm-readelf"
LLVM_STRIP="$TOOLCHAIN/bin/llvm-strip"
SYSROOT="$TOOLCHAIN/sysroot"
for tool in "$LLVM_AR" "$LLVM_NM" "$LLVM_READELF" "$LLVM_STRIP"; do
	if [ ! -x "$tool" ]; then
		printf 'error: required NDK LLVM tool not executable: %s\n' "$tool" >&2
		exit 2
	fi
done
if [ -z "${HOME:-}" ]; then
	printf 'error: HOME is required to remap private build paths from Android release binaries\n' >&2
	exit 2
fi
RUST_PATH_REMAP="--remap-path-prefix=$HOME=/qperiapt-build/user"
C_PATH_REMAP="-ffile-prefix-map=$HOME=/qperiapt-build/user -fdebug-prefix-map=$HOME=/qperiapt-build/user -fmacro-prefix-map=$HOME=/qperiapt-build/user"

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
if [ "$VERSION" != "0.1.0-alpha.2" ]; then
	printf 'error: Android ABI2 package version mismatch: got %s, expected 0.1.0-alpha.2\n' "$VERSION" >&2
	exit 1
fi

required_targets="aarch64-linux-android x86_64-linux-android armv7-linux-androideabi i686-linux-android"
installed_targets=$(rustup target list --installed)
missing_targets=
for target in $required_targets; do
	if ! printf '%s\n' "$installed_targets" | grep -Fx "$target" >/dev/null 2>&1; then
		missing_targets="$missing_targets $target"
	fi
done
if [ -n "$missing_targets" ]; then
	printf 'error: missing Rust Android release targets:%s\n' "$missing_targets" >&2
	printf 'hint : rustup target add%s\n' "$missing_targets" >&2
	exit 2
fi
RUSTC_VERSION=$(rustc --version)
CARGO_VERSION=$(cargo --version)
if [ "$RUSTC_VERSION" != "rustc 1.96.1 (31fca3adb 2026-06-26)" ]; then
	printf 'error: Android release package requires rustc 1.96.1: %s\n' "$RUSTC_VERSION" >&2
	exit 2
fi
if [ "$CARGO_VERSION" != "cargo 1.96.1 (356927216 2026-06-26)" ]; then
	printf 'error: Android release package requires cargo 1.96.1: %s\n' "$CARGO_VERSION" >&2
	exit 2
fi

OUT_ROOT=${QPERIAPT_ANDROID_AAR_OUT_DIR:-"$ROOT/target/qperiapt-android-aar"}
require_under_target "$OUT_ROOT" "QPERIAPT_ANDROID_AAR_OUT_DIR"

PACKAGE_NAME="q-periapt-android-$VERSION"
WORK="$OUT_ROOT/work"
DIST="$OUT_ROOT/$PACKAGE_NAME"
STAGE="$WORK/aar"
CLASSES="$WORK/classes"
DEX_OUT="$WORK/dex"
CONSUMER="$WORK/consumer"
CLASSES_JAR="$DIST/classes.jar"
AAR_PATH="$DIST/$PACKAGE_NAME.aar"
MANIFEST="$DIST/MANIFEST.json"
SHA256SUMS="$DIST/SHA256SUMS"
JAVA_SOURCES="$WORK/java-sources.txt"
# A clean checkout has no target directory yet; mktemp requires its template
# directory to exist before any build command has had a chance to create it.
mkdir -p "$ROOT/target"
tmp_header=$(mktemp "$ROOT/target/qperiapt-android-header.XXXXXX.h")

cleanup() {
	rm -f "$tmp_header"
}
trap cleanup EXIT INT TERM

printf 'Q-Periapt Android AAR/JNI package\n'
printf 'version  : %s\n' "$VERSION"
printf 'out      : %s\n' "$DIST"
printf 'sdk      : %s\n' "$ANDROID_SDK"
printf 'ndk      : %s\n' "$ANDROID_NDK"
printf 'ndk-rev  : %s\n' "$NDK_REVISION"
printf 'platform : %s\n' "$ANDROID_PLATFORM"
printf 'buildtools: %s\n' "$ANDROID_BUILD_TOOLS"
printf 'rustc    : %s\n' "$RUSTC_VERSION"
printf 'cargo    : %s\n' "$CARGO_VERSION"
printf 'javac    : %s\n' "$(javac -version 2>&1)"

printf '\n=== Generated C header freshness ===\n'
cbindgen --config crates/q-periapt-ffi/cbindgen.toml \
	--crate q-periapt-ffi \
	--output "$tmp_header"
cmp "$tmp_header" crates/q-periapt-ffi/include/q_periapt.h
printf 'PASS: generated C header freshness\n'

rm -rf "$OUT_ROOT"
mkdir -p "$STAGE/jni" "$CLASSES" "$DEX_OUT" "$CONSUMER/classes" "$DIST"

printf '\n=== Compile Android Java facade ===\n'
if grep -R "java.lang.foreign" bindings/android/src/main/java >/dev/null 2>&1; then
	printf 'error: Android facade must not depend on java.lang.foreign/Panama\n' >&2
	exit 1
fi
find bindings/android/src/main/java -name '*.java' -print | LC_ALL=C sort >"$JAVA_SOURCES"
test -s "$JAVA_SOURCES" || {
	printf 'error: no Android Java sources found\n' >&2
	exit 1
}
javac --release 11 -Xlint:all -Werror -cp "$ANDROID_JAR" -d "$CLASSES" @"$JAVA_SOURCES"
javap -classpath "$CLASSES" -s -p dev.qperiapt.android.QPeriaptAndroid >"$WORK/QPeriaptAndroid.javap"
python3 - "$WORK/QPeriaptAndroid.javap" "$ROOT/bindings/android/jni/qperiapt_jni.c" "$ROOT/bindings/android/src/main/java/dev/qperiapt/android/QPeriaptAndroid.java" <<'PY'
import pathlib
import re
import sys

javap = pathlib.Path(sys.argv[1]).read_text()
csrc = pathlib.Path(sys.argv[2]).read_text()
java_src = pathlib.Path(sys.argv[3]).read_text()
loader_names = re.findall(r'System\.loadLibrary\("([^"]+)"\)', java_src)
if loader_names != ["q_periapt_ffi_abi2", "qperiapt_jni_abi2"]:
    raise SystemExit(f"error: Android ABI2 loader names mismatch: {loader_names}")
expected = {
    "runtimeAbiVersionNative": "()I",
    "runtimeVersionNative": "()Ljava/lang/String;",
    "fixedSuiteIdNative": "()Ljava/lang/String;",
    "fixedSuiteIdLenNative": "()J",
    "statusNameNative": "(I)Ljava/lang/String;",
    "decisionFromSignedPolicyNative": "([B[B[B[B)[B",
    "generateKeypairNative": "([B[B[B[B[B)V",
    "encapsulateNative": "([B[B[B[B[B[B[B)V",
    "decapsulateNative": "([B[B[B[B[B[B[B[B[B)V",
}
for name, descriptor in expected.items():
    javap_pattern = re.compile(
        r"native\s+[\w.$\[\]/]+[\s\[\]]+\b" + re.escape(name) + r"\([^)]*\);\s+descriptor:\s+" + re.escape(descriptor),
        re.MULTILINE,
    )
    if not javap_pattern.search(javap):
        raise SystemExit(f"error: javap descriptor mismatch for {name}: expected {descriptor}")
    if f'{{"{name}", "{descriptor}",' not in csrc:
        raise SystemExit(f"error: JNI RegisterNatives table missing {name} {descriptor}")
print("ANDROID_JNI_SIGNATURES_PASS")
PY
python3 - "$CLASSES" "$CLASSES_JAR" <<'PY'
import pathlib
import zipfile
import sys

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
"$D8" --min-api 23 --lib "$ANDROID_JAR" --output "$DEX_OUT" "$CLASSES_JAR"
test -f "$DEX_OUT/classes.dex" || {
	printf 'error: d8 did not produce classes.dex\n' >&2
	exit 1
}
printf 'PASS: Java facade compile + dex conversion\n'

cat >"$STAGE/AndroidManifest.xml" <<'EOF'
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <uses-sdk android:minSdkVersion="23" />
</manifest>
EOF
cp "$CLASSES_JAR" "$STAGE/classes.jar"
touch "$STAGE/R.txt"
cat >"$STAGE/proguard.txt" <<'EOF'
-keepclasseswithmembernames class dev.qperiapt.android.QPeriaptAndroid {
    native <methods>;
}
EOF
mkdir -p "$STAGE/META-INF"
cp LICENSE "$STAGE/META-INF/LICENSE"
if [ -d LICENSES ]; then
	mkdir -p "$STAGE/META-INF/LICENSES"
	for license_file in LICENSES/*; do
		[ -f "$license_file" ] || continue
		cp "$license_file" "$STAGE/META-INF/LICENSES/$(basename "$license_file")"
	done
fi

printf '\n=== Build Android Rust FFI slices and JNI shim ===\n'
while IFS='|' read -r abi triple clang_name cargo_var cc_var ar_var; do
	clang="$TOOLCHAIN/bin/$clang_name"
	if [ ! -x "$clang" ]; then
		printf 'error: Android clang not found for %s: %s\n' "$abi" "$clang" >&2
		exit 2
	fi
	printf '\n--- %s (%s) ---\n' "$abi" "$triple"
	env "$cargo_var=$clang" "$cc_var=$clang" "$ar_var=$LLVM_AR" \
		CARGO_ENCODED_RUSTFLAGS="$RUST_PATH_REMAP" \
		CFLAGS="$C_PATH_REMAP" \
		cargo rustc -p q-periapt-ffi --release --locked --target "$triple" -- \
		-C link-arg=-Wl,--no-undefined \
		-C link-arg=-Wl,--fatal-warnings \
		-C link-arg=-Wl,-z,relro \
		-C link-arg=-Wl,-z,now \
		-C link-arg=-Wl,-z,max-page-size=16384 \
		-C link-arg=-Wl,-z,common-page-size=16384 \
		-C link-arg=-Wl,-soname,libq_periapt_ffi_abi2.so
	ffi_src="$ROOT/target/$triple/release/libq_periapt_ffi_abi2.so"
	test -f "$ffi_src" || {
		printf 'error: missing Rust Android cdylib: %s\n' "$ffi_src" >&2
		exit 1
	}
	abi_dir="$STAGE/jni/$abi"
	mkdir -p "$abi_dir"
	cp "$ffi_src" "$abi_dir/libq_periapt_ffi_abi2.so"
	"$LLVM_STRIP" --strip-unneeded "$abi_dir/libq_periapt_ffi_abi2.so"
	"$clang" \
		-shared \
		-fPIC \
		-O2 \
		-std=c11 \
		-Wall \
		-Wextra \
		-Werror \
		-fvisibility=hidden \
		-ffile-prefix-map="$HOME=/qperiapt-build/user" \
		-fdebug-prefix-map="$HOME=/qperiapt-build/user" \
		-fmacro-prefix-map="$HOME=/qperiapt-build/user" \
		-I "$SYSROOT/usr/include" \
		-I "$ROOT/crates/q-periapt-ffi/include" \
		"$ROOT/bindings/android/jni/qperiapt_jni.c" \
		-L "$ROOT/target/$triple/release" \
		-lq_periapt_ffi_abi2 \
		-Wl,--no-undefined \
		-Wl,--fatal-warnings \
		-Wl,-z,relro \
		-Wl,-z,now \
		-Wl,-z,max-page-size=16384 \
		-Wl,-z,common-page-size=16384 \
		-Wl,-soname,libqperiapt_jni_abi2.so \
		-o "$abi_dir/libqperiapt_jni_abi2.so"
	"$LLVM_STRIP" --strip-unneeded "$abi_dir/libqperiapt_jni_abi2.so"
	file "$abi_dir/libq_periapt_ffi_abi2.so" "$abi_dir/libqperiapt_jni_abi2.so"
done <<'EOF'
arm64-v8a|aarch64-linux-android|aarch64-linux-android23-clang|CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER|CC_aarch64_linux_android|AR_aarch64_linux_android
x86_64|x86_64-linux-android|x86_64-linux-android23-clang|CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER|CC_x86_64_linux_android|AR_x86_64_linux_android
armeabi-v7a|armv7-linux-androideabi|armv7a-linux-androideabi23-clang|CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER|CC_armv7_linux_androideabi|AR_armv7_linux_androideabi
x86|i686-linux-android|i686-linux-android23-clang|CARGO_TARGET_I686_LINUX_ANDROID_LINKER|CC_i686_linux_android|AR_i686_linux_android
EOF
PYTHONPATH=artifact python3 artifact/android_elf.py verify-tree \
	--root "$STAGE" \
	--llvm-nm "$LLVM_NM" \
	--llvm-readelf "$LLVM_READELF"
printf 'PASS: Android ABI slices, ELF hardening, 16 KiB alignment, dependencies, and exports\n'

printf '\n=== Collect production Rust dependency licenses ===\n'
PYTHONPATH=artifact python3 artifact/third_party_licenses.py create \
	--root "$ROOT" \
	--package-root "$STAGE/META-INF" \
	--target x86_64-linux-android
PYTHONPATH=artifact python3 artifact/third_party_licenses.py verify \
	--package-root "$STAGE/META-INF" \
	--expected-target x86_64-linux-android
LICENSE_MATRIX="$WORK/license-matrix"
mkdir -p "$LICENSE_MATRIX"
for license_target in aarch64-linux-android armv7-linux-androideabi i686-linux-android; do
	mkdir "$LICENSE_MATRIX/$license_target"
	PYTHONPATH=artifact python3 artifact/third_party_licenses.py create \
		--root "$ROOT" \
		--package-root "$LICENSE_MATRIX/$license_target" \
		--target "$license_target"
done
PYTHONPATH=artifact python3 - \
	"$STAGE/META-INF/THIRD_PARTY/rust/INVENTORY.json" \
	"$LICENSE_MATRIX/aarch64-linux-android/THIRD_PARTY/rust/INVENTORY.json" \
	"$LICENSE_MATRIX/armv7-linux-androideabi/THIRD_PARTY/rust/INVENTORY.json" \
	"$LICENSE_MATRIX/i686-linux-android/THIRD_PARTY/rust/INVENTORY.json" <<'PY'
import pathlib
import sys

from evidence_io import load_json_object_snapshot

inventories = [
    load_json_object_snapshot(pathlib.Path(raw), label="Android Rust license matrix").value
    for raw in sys.argv[1:]
]

def identities(inventory):
    return {
        (package["name"], package["version"], package["source"])
        for package in inventory["packages"]
    }

reference = identities(inventories[0])
union = set().union(*(identities(inventory) for inventory in inventories))
if reference != union:
    missing = sorted(union - reference)
    raise SystemExit(
        "error: x86_64 Android license closure is not a superset of all shipped ABI closures: "
        f"missing={missing}"
    )
print(f"ANDROID_RUST_LICENSE_TARGET_SUPERSET_PASS packages={len(reference)} targets=4")
PY
rm -rf "$LICENSE_MATRIX"
printf 'PASS: production Rust dependency license closure\n'

printf '\n=== Create deterministic AAR ===\n'
python3 - "$STAGE" "$AAR_PATH" <<'PY'
import pathlib
import zipfile
import sys

stage = pathlib.Path(sys.argv[1])
out = pathlib.Path(sys.argv[2])
epoch = (2000, 1, 1, 0, 0, 0)
with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
    for path in sorted(p for p in stage.rglob("*") if p.is_file()):
        rel = path.relative_to(stage).as_posix()
        info = zipfile.ZipInfo(rel, epoch)
        info.external_attr = 0o100644 << 16
        zf.writestr(info, path.read_bytes())
PY
test -f "$AAR_PATH" || {
	printf 'error: missing AAR: %s\n' "$AAR_PATH" >&2
	exit 1
}

PYTHONPATH=artifact python3 artifact/android_elf.py verify-aar \
	--aar "$AAR_PATH" \
	--llvm-nm "$LLVM_NM" \
	--llvm-readelf "$LLVM_READELF" \
	--forbid-text "$ROOT"
printf 'PASS: deterministic AAR exact-file/CRC/nested-JAR audit and extracted ELF re-verification\n'

printf '\n=== Isolated Java consumer compile ===\n'
cat >"$CONSUMER/Consumer.java" <<'EOF'
import dev.qperiapt.android.QPeriaptAndroid;

final class Consumer {
    private Consumer() {
    }

    static int compileOnlyContract() {
        byte[] suite = QPeriaptAndroid.fixedSuiteId();
        QPeriaptAndroid.PolicyDecision decision = QPeriaptAndroid.decisionFromSignedPolicy(
                new byte[0], new byte[0], new byte[0]);
        try (QPeriaptAndroid.KeyPairResult keyPair = QPeriaptAndroid.generateKeypair(decision)) {
            byte[] skPq = keyPair.skPq();
            byte[] skTrad = keyPair.skTrad();
            try (QPeriaptAndroid.EncapsulationResult encapsulation = QPeriaptAndroid.encapsulate(
                    decision, keyPair.pkPq(), keyPair.pkTrad(), new byte[] {1})) {
                byte[] encapsulatedSecret = encapsulation.takeSecret();
                byte[] decapsulatedSecret = QPeriaptAndroid.decapsulate(
                        decision,
                        skPq,
                        encapsulation.ctPq(),
                        keyPair.pkPq(),
                        skTrad,
                        encapsulation.ctTrad(),
                        keyPair.pkTrad(),
                        new byte[] {1});
                try {
                    Class<?> exceptionClass = QPeriaptAndroid.QPeriaptException.class;
                    return suite.length + keyPair.pkPq().length + encapsulatedSecret.length
                            + decapsulatedSecret.length + exceptionClass.getName().length();
                } finally {
                    QPeriaptAndroid.wipe(encapsulatedSecret);
                    QPeriaptAndroid.wipe(decapsulatedSecret);
                }
            } finally {
                QPeriaptAndroid.wipe(skPq);
                QPeriaptAndroid.wipe(skTrad);
            }
        }
    }
}
EOF
javac --release 11 -Xlint:all -Werror -cp "$ANDROID_JAR:$CLASSES_JAR" -d "$CONSUMER/classes" "$CONSUMER/Consumer.java"
printf 'PASS: isolated Java consumer compile\n'

assert_source_snapshot
printf '\n=== Emit manifest and checksums ===\n'
CURRENT_RUSTC_VERSION=$(rustc --version)
CURRENT_CARGO_VERSION=$(cargo --version)
if [ "$CURRENT_RUSTC_VERSION" != "$RUSTC_VERSION" ] || [ "$CURRENT_CARGO_VERSION" != "$CARGO_VERSION" ]; then
	printf 'error: Android Rust toolchain changed during release package construction\n' >&2
	exit 2
fi
python3 - "$ROOT" "$STAGE" "$AAR_PATH" "$CLASSES_JAR" "$MANIFEST" "$SHA256SUMS" "$ANDROID_PLATFORM" "$ANDROID_BUILD_TOOLS" "$VERSION" "$NDK_REVISION" "$SOURCE_COMMIT" "$SOURCE_DIRTY" "$SOURCE_COMMIT_EPOCH" "$SOURCE_TREE_SHA256" "$CURRENT_RUSTC_VERSION" "$CURRENT_CARGO_VERSION" <<'PY'
import datetime as dt
import hashlib
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
stage = pathlib.Path(sys.argv[2])
aar = pathlib.Path(sys.argv[3])
classes_jar = pathlib.Path(sys.argv[4])
manifest = pathlib.Path(sys.argv[5])
sha256sums = pathlib.Path(sys.argv[6])
android_platform = pathlib.Path(sys.argv[7])
android_build_tools = pathlib.Path(sys.argv[8])
version = sys.argv[9]
ndk_revision = sys.argv[10]
source_commit = sys.argv[11]
source_dirty = sys.argv[12] == "1"
source_date_epoch = int(sys.argv[13])
source_tree_sha256 = sys.argv[14]
rustc_version = sys.argv[15]
cargo_version = sys.argv[16]

def sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

abis = ["arm64-v8a", "x86_64", "armeabi-v7a", "x86"]
native = {}
for abi in abis:
    native[abi] = {
        "ffi_so_sha256": sha256(stage / "jni" / abi / "libq_periapt_ffi_abi2.so"),
        "jni_so_sha256": sha256(stage / "jni" / abi / "libqperiapt_jni_abi2.so"),
    }

contract = root / "crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json"
contract_document = json.loads(contract.read_text(encoding="utf-8"))
third_party_inventory_path = stage / "META-INF/THIRD_PARTY/rust/INVENTORY.json"
third_party_inventory = json.loads(third_party_inventory_path.read_text(encoding="utf-8"))
third_party_packages = third_party_inventory.get("packages")
if not isinstance(third_party_packages, list) or not third_party_packages:
    raise SystemExit("error: Android manifest requires a non-empty third-party Rust license inventory")
export_names = sorted(entry["name"] for entry in contract_document["abi"]["exports"])
if len(export_names) != 9 or len(set(export_names)) != 9:
    raise SystemExit("error: Android manifest requires the exact 9-symbol ABI2 export set")
exports_digest = hashlib.sha256(("\n".join(export_names) + "\n").encode("utf-8")).hexdigest()
payload = {
    "schema_version": 4,
    "kind": "qperiapt.android_aar_manifest",
    "package": aar.name,
    "version": version,
    "generated_at": dt.datetime.fromtimestamp(
        source_date_epoch, tz=dt.timezone.utc
    ).isoformat().replace("+00:00", "Z"),
    "source_date_epoch": source_date_epoch,
    "git_commit": source_commit,
    "git_dirty": source_dirty,
    "diagnostic_only": source_dirty,
    "source_tree_sha256": source_tree_sha256,
    "package_only": True,
    "device_runtime_proof": False,
    "boundary": "AAR/JNI packaging proof only; Android emulator or physical-device instrumentation is required before claiming Android runtime readiness.",
    "toolchain": {
        "cargo": cargo_version,
        "rustc": rustc_version,
    },
    "third_party": {
        "rust": {
            "covered_targets": [
                "aarch64-linux-android",
                "x86_64-linux-android",
                "armv7-linux-androideabi",
                "i686-linux-android",
            ],
            "inventory_path": "META-INF/THIRD_PARTY/rust/INVENTORY.json",
            "inventory_sha256": sha256(third_party_inventory_path),
            "package_count": len(third_party_packages),
            "target": "x86_64-linux-android",
        },
    },
    "abi": {
        "major": 2,
        "contract_path": contract.relative_to(root).as_posix(),
        "contract_sha256": sha256(contract),
        "exports_sha256": exports_digest,
        "export_count": len(export_names),
        "platform": "android-aar",
        "runtime_identity": {
            "abis": abis,
            "jni_library": "libqperiapt_jni_abi2.so",
            "loader_order": ["q_periapt_ffi_abi2", "qperiapt_jni_abi2"],
            "runtime_library": "libq_periapt_ffi_abi2.so",
        },
        "shared_filename": "libq_periapt_ffi_abi2.so",
        "static_filename": "not-shipped-abi2",
    },
    "android": {
        "sdk": "local-android-sdk",
        "ndk": ndk_revision,
        "platform": android_platform.name,
        "build_tools": android_build_tools.name,
        "min_sdk": 23,
        "native_page_alignment": 16384,
        "native_stripped": True,
        "abis": abis,
    },
    "artifacts": {
        "aar_sha256": sha256(aar),
        "classes_jar_sha256": sha256(classes_jar),
        "java_facade_sha256": sha256(root / "bindings/android/src/main/java/dev/qperiapt/android/QPeriaptAndroid.java"),
        "jni_adapter_sha256": sha256(root / "bindings/android/jni/qperiapt_jni.c"),
        "script_sha256": sha256(root / "artifact/android-aar.sh"),
        "elf_verifier_sha256": sha256(root / "artifact/android_elf.py"),
        "release_binary_scan_sha256": sha256(root / "artifact/release_binary_scan.py"),
        "third_party_license_collector_sha256": sha256(root / "artifact/third_party_licenses.py"),
        "native": native,
    },
}
manifest.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")

entries = [
    (aar.name, aar),
    (classes_jar.name, classes_jar),
    (manifest.name, manifest),
]
sha256sums.write_text("".join(f"{sha256(path)}  {name}\n" for name, path in entries))
PY
set -- --manifest "$MANIFEST"
if [ "${QPERIAPT_ALLOW_DIRTY_ANDROID_AAR:-0}" != "1" ]; then
	set -- "$@" --require-release-manifest
fi
PYTHONPATH=artifact python3 artifact/android_elf.py verify-aar \
	--aar "$AAR_PATH" \
	--llvm-nm "$LLVM_NM" \
	--llvm-readelf "$LLVM_READELF" \
	--forbid-text "$ROOT" \
	--source-root "$ROOT" \
	"$@"
assert_source_snapshot
printf 'PASS: manifest and checksums\n'

printf '\nAAR      : %s\n' "$AAR_PATH"
printf 'Manifest : %s\n' "$MANIFEST"
printf 'SHA256   : %s\n' "$SHA256SUMS"
printf '\nANDROID_AAR_PACKAGE_PASS\n'
