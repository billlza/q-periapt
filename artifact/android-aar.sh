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

if [ "${QPERIAPT_ALLOW_DIRTY_ANDROID_AAR:-0}" != "1" ]; then
	if [ -n "$(git status --porcelain=v1)" ]; then
		printf 'error: Android AAR release gate requires a clean worktree; set QPERIAPT_ALLOW_DIRTY_ANDROID_AAR=1 only for local diagnostics\n' >&2
		exit 2
	fi
fi

ANDROID_SDK=${QPERIAPT_ANDROID_SDK_ROOT:-${ANDROID_HOME:-${ANDROID_SDK_ROOT:-"$HOME/Library/Android/sdk"}}}
if [ ! -d "$ANDROID_SDK" ]; then
	printf 'error: Android SDK not found; set QPERIAPT_ANDROID_SDK_ROOT or ANDROID_HOME\n' >&2
	exit 2
fi

ANDROID_NDK=${QPERIAPT_ANDROID_NDK_HOME:-${ANDROID_NDK_HOME:-}}
if [ -z "$ANDROID_NDK" ]; then
	ANDROID_NDK=$(choose_highest_child "$ANDROID_SDK/ndk" "Android NDK")
fi
if [ ! -d "$ANDROID_NDK" ]; then
	printf 'error: Android NDK not found: %s\n' "$ANDROID_NDK" >&2
	exit 2
fi

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

TOOLCHAIN=$(python3 - "$ANDROID_NDK" <<'PY'
import pathlib
import sys

base = pathlib.Path(sys.argv[1]) / "toolchains" / "llvm" / "prebuilt"
if not base.is_dir():
    raise SystemExit(f"error: NDK LLVM prebuilt directory missing: {base}")
for candidate in sorted(base.iterdir()):
    if (candidate / "bin" / "llvm-readelf").is_file() and (candidate / "sysroot" / "usr" / "include" / "jni.h").is_file():
        print(candidate)
        break
else:
    raise SystemExit(f"error: no usable NDK LLVM prebuilt toolchain under {base}")
PY
)

LLVM_AR="$TOOLCHAIN/bin/llvm-ar"
LLVM_NM="$TOOLCHAIN/bin/llvm-nm"
LLVM_READELF="$TOOLCHAIN/bin/llvm-readelf"
SYSROOT="$TOOLCHAIN/sysroot"
for tool in "$LLVM_AR" "$LLVM_NM" "$LLVM_READELF"; do
	if [ ! -x "$tool" ]; then
		printf 'error: required NDK LLVM tool not executable: %s\n' "$tool" >&2
		exit 2
	fi
done

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
printf 'platform : %s\n' "$ANDROID_PLATFORM"
printf 'buildtools: %s\n' "$ANDROID_BUILD_TOOLS"
printf 'rustc    : %s\n' "$(rustc --version)"
printf 'javac    : %s\n' "$(javac -version 2>&1)"

mkdir -p "$ROOT/target"

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
python3 - "$WORK/QPeriaptAndroid.javap" "$ROOT/bindings/android/jni/qperiapt_jni.c" <<'PY'
import pathlib
import re
import sys

javap = pathlib.Path(sys.argv[1]).read_text()
csrc = pathlib.Path(sys.argv[2]).read_text()
expected = {
    "runtimeAbiVersionNative": "()I",
    "runtimeVersionNative": "()Ljava/lang/String;",
    "fixedSuiteIdNative": "()Ljava/lang/String;",
    "fixedSuiteIdLenNative": "()J",
    "statusNameNative": "(I)Ljava/lang/String;",
    "profileFromSignedPolicyNative": "([B[B[BI)B",
    "mlkem768KeypairNative": "([B[B[B)V",
    "mlkem768XWingKeypairNative": "([B[B[B)V",
    "x25519KeypairNative": "([B[B[B)V",
    "encapsulateNative": "(B[BI[B[B[B[B[B[B[B[B)V",
    "decapsulateNative": "(B[BI[B[B[B[B[B[B[B[B)V",
    "combineNative": "(B[B[B)V",
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
		cargo build -p q-periapt-ffi --release --locked --target "$triple"
	ffi_src="$ROOT/target/$triple/release/libq_periapt_ffi.so"
	test -f "$ffi_src" || {
		printf 'error: missing Rust Android cdylib: %s\n' "$ffi_src" >&2
		exit 1
	}
	abi_dir="$STAGE/jni/$abi"
	mkdir -p "$abi_dir"
	cp "$ffi_src" "$abi_dir/libq_periapt_ffi.so"
	"$clang" \
		-shared \
		-fPIC \
		-O2 \
		-std=c11 \
		-Wall \
		-Wextra \
		-Werror \
		-fvisibility=hidden \
		-I "$SYSROOT/usr/include" \
		-I "$ROOT/crates/q-periapt-ffi/include" \
		"$ROOT/bindings/android/jni/qperiapt_jni.c" \
		-L "$ROOT/target/$triple/release" \
		-lq_periapt_ffi \
		-Wl,--no-undefined \
		-Wl,--fatal-warnings \
		-Wl,-z,relro \
		-Wl,-z,now \
		-Wl,-soname,libqperiapt_jni.so \
		-o "$abi_dir/libqperiapt_jni.so"
	file "$abi_dir/libq_periapt_ffi.so" "$abi_dir/libqperiapt_jni.so"
	if ! "$LLVM_NM" -D --defined-only "$abi_dir/libq_periapt_ffi.so" 2>/dev/null | grep -F "q_periapt_abi_version" >/dev/null 2>&1; then
		printf 'error: missing q_periapt_abi_version export in %s\n' "$abi_dir/libq_periapt_ffi.so" >&2
		exit 1
	fi
	jni_exports=$("$LLVM_NM" -D --defined-only "$abi_dir/libqperiapt_jni.so" 2>/dev/null)
	if ! printf '%s\n' "$jni_exports" | grep -F "JNI_OnLoad" >/dev/null 2>&1; then
		printf 'error: missing JNI_OnLoad export in %s\n' "$abi_dir/libqperiapt_jni.so" >&2
		exit 1
	fi
	if printf '%s\n' "$jni_exports" | grep -F "Java_dev_qperiapt" >/dev/null 2>&1; then
		printf 'error: JNI shim for %s must use RegisterNatives and not export Java_* method symbols\n' "$abi" >&2
		exit 1
	fi
	if ! "$LLVM_READELF" -d "$abi_dir/libqperiapt_jni.so" 2>/dev/null | grep -F "Shared library: [libq_periapt_ffi.so]" >/dev/null 2>&1; then
		printf 'error: JNI shim for %s does not declare libq_periapt_ffi.so dependency\n' "$abi" >&2
		exit 1
	fi
done <<'EOF'
arm64-v8a|aarch64-linux-android|aarch64-linux-android23-clang|CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER|CC_aarch64_linux_android|AR_aarch64_linux_android
x86_64|x86_64-linux-android|x86_64-linux-android23-clang|CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER|CC_x86_64_linux_android|AR_x86_64_linux_android
armeabi-v7a|armv7-linux-androideabi|armv7a-linux-androideabi23-clang|CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER|CC_armv7_linux_androideabi|AR_armv7_linux_androideabi
x86|i686-linux-android|i686-linux-android23-clang|CARGO_TARGET_I686_LINUX_ANDROID_LINKER|CC_i686_linux_android|AR_i686_linux_android
EOF
printf 'PASS: Android ABI slices and JNI symbols\n'

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

python3 - "$AAR_PATH" <<'PY'
import pathlib
import stat
import sys
import zipfile

aar = pathlib.Path(sys.argv[1])
required = {
    "AndroidManifest.xml",
    "classes.jar",
    "R.txt",
    "proguard.txt",
    "jni/arm64-v8a/libq_periapt_ffi.so",
    "jni/arm64-v8a/libqperiapt_jni.so",
    "jni/x86_64/libq_periapt_ffi.so",
    "jni/x86_64/libqperiapt_jni.so",
    "jni/armeabi-v7a/libq_periapt_ffi.so",
    "jni/armeabi-v7a/libqperiapt_jni.so",
    "jni/x86/libq_periapt_ffi.so",
    "jni/x86/libqperiapt_jni.so",
}
allowed_toplevel = {"AndroidManifest.xml", "classes.jar", "R.txt", "proguard.txt", "jni", "META-INF"}
seen = set()
with zipfile.ZipFile(aar) as zf:
    names = set()
    for info in zf.infolist():
        name = info.filename
        if name in seen:
            raise SystemExit(f"error: duplicate AAR entry: {name}")
        seen.add(name)
        if name.startswith("/") or name.startswith("\\"):
            raise SystemExit(f"error: absolute AAR entry: {name}")
        parts = pathlib.PurePosixPath(name).parts
        if ".." in parts:
            raise SystemExit(f"error: parent traversal AAR entry: {name}")
        if parts[0] not in allowed_toplevel:
            raise SystemExit(f"error: unexpected AAR top-level entry: {name}")
        mode = (info.external_attr >> 16) & 0o777777
        if stat.S_ISLNK(mode) or stat.S_ISCHR(mode) or stat.S_ISBLK(mode) or stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode):
            raise SystemExit(f"error: unsafe AAR file type for {name}: {oct(mode)}")
        names.add(name)
    missing = sorted(required - names)
    if missing:
        raise SystemExit("error: AAR missing required entries: " + ", ".join(missing))
print("ANDROID_AAR_ZIP_AUDIT_PASS")
PY
printf 'PASS: deterministic AAR zip audit\n'

printf '\n=== Isolated Java consumer compile ===\n'
cat >"$CONSUMER/Consumer.java" <<'EOF'
import dev.qperiapt.android.QPeriaptAndroid;

final class Consumer {
    private Consumer() {
    }

    static int compileOnlyContract() {
        byte[] suite = QPeriaptAndroid.fixedSuiteId();
        QPeriaptAndroid.KeyPairResult keyPair = QPeriaptAndroid.mlkem768XWingKeypair(
                new byte[QPeriaptAndroid.MLKEM_XWING_SEED_LEN]
        );
        byte[] combined = QPeriaptAndroid.combine(QPeriaptAndroid.PROFILE_COMPAT_XWING, new byte[0]);
        Class<?> exceptionClass = QPeriaptAndroid.QPeriaptException.class;
        return suite.length + keyPair.publicKey().length + combined.length + exceptionClass.getName().length();
    }
}
EOF
javac --release 11 -Xlint:all -Werror -cp "$ANDROID_JAR:$CLASSES_JAR" -d "$CONSUMER/classes" "$CONSUMER/Consumer.java"
printf 'PASS: isolated Java consumer compile\n'

printf '\n=== Emit manifest and checksums ===\n'
python3 - "$ROOT" "$DIST" "$STAGE" "$AAR_PATH" "$CLASSES_JAR" "$MANIFEST" "$SHA256SUMS" "$ANDROID_SDK" "$ANDROID_NDK" "$ANDROID_PLATFORM" "$ANDROID_BUILD_TOOLS" <<'PY'
import datetime as dt
import hashlib
import json
import pathlib
import subprocess
import sys

root = pathlib.Path(sys.argv[1])
dist = pathlib.Path(sys.argv[2])
stage = pathlib.Path(sys.argv[3])
aar = pathlib.Path(sys.argv[4])
classes_jar = pathlib.Path(sys.argv[5])
manifest = pathlib.Path(sys.argv[6])
sha256sums = pathlib.Path(sys.argv[7])
android_sdk = pathlib.Path(sys.argv[8])
android_ndk = pathlib.Path(sys.argv[9])
android_platform = pathlib.Path(sys.argv[10])
android_build_tools = pathlib.Path(sys.argv[11])

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
        "ffi_so_sha256": sha256(stage / "jni" / abi / "libq_periapt_ffi.so"),
        "jni_so_sha256": sha256(stage / "jni" / abi / "libqperiapt_jni.so"),
    }

payload = {
    "schema": 1,
    "package": aar.name,
    "generated_at": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
    "git_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
    "package_only": True,
    "device_runtime_proof": False,
    "boundary": "AAR/JNI packaging proof only; Android emulator or physical-device instrumentation is required before claiming Android runtime readiness.",
    "android": {
        "sdk": "local-android-sdk",
        "ndk": android_ndk.name,
        "platform": android_platform.name,
        "build_tools": android_build_tools.name,
        "min_sdk": 23,
        "abis": abis,
    },
    "artifacts": {
        "aar_sha256": sha256(aar),
        "classes_jar_sha256": sha256(classes_jar),
        "java_facade_sha256": sha256(root / "bindings/android/src/main/java/dev/qperiapt/android/QPeriaptAndroid.java"),
        "jni_adapter_sha256": sha256(root / "bindings/android/jni/qperiapt_jni.c"),
        "script_sha256": sha256(root / "artifact/android-aar.sh"),
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
printf 'PASS: manifest and checksums\n'

printf '\nAAR      : %s\n' "$AAR_PATH"
printf 'Manifest : %s\n' "$MANIFEST"
printf 'SHA256   : %s\n' "$SHA256SUMS"
printf '\nANDROID_AAR_PACKAGE_PASS\n'
