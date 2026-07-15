#!/bin/sh
# Build, install, and run the Android AAR/JNI smoke on an adb device/emulator.
#
# This is a runtime proof gate, not a package-only gate. It installs a temporary
# debuggable APK that consumes the generated AAR, runs the Android Java facade on
# ART, and accepts only a run-bound PASS marker copied back from the app-private
# files directory.
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
need unzip

if [ "${QPERIAPT_ANDROID_DEVICE_SKIP_VERIFY:-0}" = "1" ]; then
	printf 'error: QPERIAPT_ANDROID_DEVICE_SKIP_VERIFY is not supported\n' >&2
	exit 2
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

ANDROID_PLATFORM=${QPERIAPT_ANDROID_PLATFORM:-$(choose_highest_child "$ANDROID_SDK/platforms" "Android platform")}
ANDROID_JAR="$ANDROID_PLATFORM/android.jar"
if [ ! -f "$ANDROID_JAR" ]; then
	printf 'error: Android platform is missing android.jar: %s\n' "$ANDROID_PLATFORM" >&2
	exit 2
fi

ANDROID_BUILD_TOOLS=${QPERIAPT_ANDROID_BUILD_TOOLS:-$(choose_highest_child "$ANDROID_SDK/build-tools" "Android build-tools")}
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

ADB=${QPERIAPT_ADB:-"$ANDROID_SDK/platform-tools/adb"}
EMULATOR=${QPERIAPT_EMULATOR:-"$ANDROID_SDK/emulator/emulator"}
if [ ! -x "$ADB" ]; then
	printf 'error: adb not found: %s\n' "$ADB" >&2
	exit 2
fi

OUT_ROOT=${QPERIAPT_ANDROID_DEVICE_OUT_DIR:-"$ROOT/target/qperiapt-android-device-smoke"}
require_under_target "$OUT_ROOT" "QPERIAPT_ANDROID_DEVICE_OUT_DIR"
WORK="$OUT_ROOT/work"
DIST="$OUT_ROOT/proof"
RUN_ID=$(python3 - <<'PY'
import secrets
print(secrets.token_hex(16))
PY
)
PACKAGE="dev.qperiapt.androidsmoke"
RESULT_TXT="$DIST/qperiapt-android-device-result.txt"
RESULT_JSON="$DIST/qperiapt-android-device-result.json"
PROOF_JSON="$DIST/qperiapt-android-device-proof.json"
SOURCE_TREE_SHA256=$(python3 - "$ROOT" <<'PY'
import pathlib
import sys

from artifact.claim_ledger import canonical_tree_digest, repository_paths

root = pathlib.Path(sys.argv[1]).resolve()
print(canonical_tree_digest(root, repository_paths(root)))
PY
)

if [ "${QPERIAPT_ALLOW_DIRTY_ANDROID_DEVICE:-0}" = "1" ]; then
	QPERIAPT_ALLOW_DIRTY_ANDROID_AAR=1 sh artifact/android-aar.sh
else
	sh artifact/android-aar.sh
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
if [ "$VERSION" != "0.1.0-alpha.2" ]; then
	printf 'error: Android ABI2 device-smoke version mismatch: got %s, expected 0.1.0-alpha.2\n' "$VERSION" >&2
	exit 1
fi
AAR_DIST="$ROOT/target/qperiapt-android-aar/q-periapt-android-$VERSION"
AAR_PATH="$AAR_DIST/q-periapt-android-$VERSION.aar"
test -f "$AAR_PATH" || {
	printf 'error: Android AAR was not built: %s\n' "$AAR_PATH" >&2
	exit 1
}

rm -rf "$OUT_ROOT"
mkdir -p "$WORK" "$DIST"

printf 'Q-Periapt Android device runtime smoke\n'
printf 'run-id   : %s\n' "$RUN_ID"
printf 'aar      : %s\n' "$AAR_PATH"
printf 'out      : %s\n' "$DIST"
printf 'platform : %s\n' "$ANDROID_PLATFORM"
printf 'buildtools: %s\n' "$ANDROID_BUILD_TOOLS"

safe_unzip_dir="$WORK/aar"
python3 - "$AAR_PATH" "$safe_unzip_dir" <<'PY'
import pathlib
import shutil
import stat
import sys
import zipfile

archive = pathlib.Path(sys.argv[1])
dest = pathlib.Path(sys.argv[2])
if dest.exists():
    shutil.rmtree(dest)
dest.mkdir(parents=True)
with zipfile.ZipFile(archive) as zf:
    seen = set()
    for info in zf.infolist():
        name = info.filename
        if name in seen:
            raise SystemExit(f"error: duplicate AAR entry: {name}")
        seen.add(name)
        parts = pathlib.PurePosixPath(name).parts
        if name.startswith("/") or name.startswith("\\") or ".." in parts:
            raise SystemExit(f"error: unsafe AAR entry: {name}")
        mode = (info.external_attr >> 16) & 0o777777
        if stat.S_ISLNK(mode) or stat.S_ISCHR(mode) or stat.S_ISBLK(mode) or stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode):
            raise SystemExit(f"error: unsafe AAR file type for {name}: {oct(mode)}")
        target = dest / pathlib.PurePosixPath(name)
        if name.endswith("/"):
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(zf.read(info))
PY
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
        expect("0.1.0-alpha.2".equals(QPeriaptAndroid.runtimeVersion()), "version mismatch");
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
"$ZIPALIGN" -f -p 4 "$UNSIGNED_APK" "$ALIGNED_APK"
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
"$APKSIGNER" verify --min-sdk-version 23 --print-certs "$SIGNED_APK" >"$DIST/apksigner-verify.txt"
printf 'PASS: temporary Android smoke APK built and signed\n'

adb_devices() {
	"$ADB" devices | awk '$2 == "device" { print $1 }'
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
	devices=$(adb_devices)
	count=$(printf '%s\n' "$devices" | sed '/^$/d' | wc -l | tr -d ' ')
	if [ "$count" = "1" ]; then
		printf '%s\n' "$devices" | sed '/^$/d'
		return
	fi
	if [ "$count" = "0" ]; then
		return 1
	fi
	printf 'error: multiple Android devices are attached; set QPERIAPT_ANDROID_SERIAL\n' >&2
	printf '%s\n' "$devices" | redact_serials >&2
	exit 2
}

printf '\n=== Select Android runtime device ===\n'
"$ADB" start-server >/dev/null
EMULATOR_STARTED=0
SERIAL=$(select_serial_or_empty)
if [ -z "$SERIAL" ] && [ "${QPERIAPT_ANDROID_BOOT_AVD:-0}" = "1" ]; then
	if [ -z "${QPERIAPT_ANDROID_AVD:-}" ]; then
		printf 'error: QPERIAPT_ANDROID_AVD is required when QPERIAPT_ANDROID_BOOT_AVD=1\n' >&2
		exit 2
	fi
	if [ ! -x "$EMULATOR" ]; then
		printf 'error: Android emulator not found: %s\n' "$EMULATOR" >&2
		exit 2
	fi
	printf 'boot-avd : %s\n' "$QPERIAPT_ANDROID_AVD"
	"$EMULATOR" \
		-avd "$QPERIAPT_ANDROID_AVD" \
		-no-window \
		-no-audio \
		-no-boot-anim \
		-gpu swiftshader_indirect \
		>"$DIST/emulator.log" 2>&1 &
	EMULATOR_PID=$!
	EMULATOR_STARTED=1
	i=0
	while [ "$i" -lt 90 ]; do
		SERIAL=$(select_serial_or_empty)
		if [ -n "$SERIAL" ]; then
			break
		fi
		sleep 1
		i=$((i + 1))
	done
	if [ -z "$SERIAL" ]; then
		"$EMULATOR" -accel-check >"$DIST/emulator-accel-check.log" 2>&1 || :
		kill "$EMULATOR_PID" >/dev/null 2>&1 || :
		printf 'error: emulator did not appear in adb devices within 90 seconds\n' >&2
		exit 1
	fi
fi
if [ -z "$SERIAL" ]; then
	printf 'error: no Android adb device available\n' >&2
	printf 'hint : attach a physical Android device and set QPERIAPT_ANDROID_SERIAL, or run with QPERIAPT_ANDROID_BOOT_AVD=1 QPERIAPT_ANDROID_AVD=<name>\n' >&2
	exit 2
fi
SERIAL_SHA256_PREFIX=$(python3 - "$SERIAL" <<'PY'
import hashlib
import sys

print(hashlib.sha256(sys.argv[1].encode("utf-8")).hexdigest()[:12])
PY
)

cleanup_emulator() {
	if [ "${EMULATOR_STARTED:-0}" = "1" ] && [ "${QPERIAPT_ANDROID_KEEP_EMULATOR:-0}" != "1" ]; then
		"$ADB" -s "$SERIAL" emu kill >/dev/null 2>&1 || :
		if [ -n "${EMULATOR_PID:-}" ]; then
			wait "$EMULATOR_PID" >/dev/null 2>&1 || :
		fi
	fi
}
trap cleanup_emulator EXIT INT TERM

"$ADB" -s "$SERIAL" wait-for-device
i=0
while [ "$i" -lt 120 ]; do
	booted=$("$ADB" -s "$SERIAL" shell getprop sys.boot_completed | tr -d '\r')
	if [ "$booted" = "1" ]; then
		break
	fi
	sleep 1
	i=$((i + 1))
done
if [ "$booted" != "1" ]; then
	printf 'error: Android device did not complete boot within 120 seconds: sha256:%s\n' "$SERIAL_SHA256_PREFIX" >&2
	exit 1
fi
qemu=$("$ADB" -s "$SERIAL" shell getprop ro.kernel.qemu | tr -d '\r')
if [ "$qemu" = "1" ]; then
	DEVICE_KIND=emulator
else
	DEVICE_KIND=physical
fi
case "${QPERIAPT_ANDROID_EXPECT_DEVICE_KIND:-any}" in
	any) ;;
	emulator | physical)
		if [ "${QPERIAPT_ANDROID_EXPECT_DEVICE_KIND}" != "$DEVICE_KIND" ]; then
			printf 'error: Android device kind mismatch: expected %s, got %s\n' "$QPERIAPT_ANDROID_EXPECT_DEVICE_KIND" "$DEVICE_KIND" >&2
			exit 1
		fi
		;;
	*)
		printf 'error: invalid QPERIAPT_ANDROID_EXPECT_DEVICE_KIND: %s\n' "$QPERIAPT_ANDROID_EXPECT_DEVICE_KIND" >&2
		exit 2
		;;
esac
printf 'serial   : sha256:%s\n' "$SERIAL_SHA256_PREFIX"
printf 'kind     : %s\n' "$DEVICE_KIND"
printf 'abi      : %s\n' "$("$ADB" -s "$SERIAL" shell getprop ro.product.cpu.abi | tr -d '\r')"
printf 'sdk      : %s\n' "$("$ADB" -s "$SERIAL" shell getprop ro.build.version.sdk | tr -d '\r')"

printf '\n=== Install and run Android runtime smoke ===\n'
"$ADB" -s "$SERIAL" install -r "$SIGNED_APK" >"$DIST/adb-install.log"
"$ADB" -s "$SERIAL" logcat -c
"$ADB" -s "$SERIAL" shell am force-stop "$PACKAGE" >"$DIST/adb-force-stop.log"
"$ADB" -s "$SERIAL" shell am start -W -n "$PACKAGE/.QPeriaptSmokeActivity" --es qperiapt_run_id "$RUN_ID" >"$DIST/adb-start.log"
i=0
while [ "$i" -lt 90 ]; do
	set +e
	"$ADB" -s "$SERIAL" exec-out run-as "$PACKAGE" cat "files/qperiapt-android-device-result.txt" >"$RESULT_TXT.tmp" 2>"$DIST/result-read.err"
	read_rc=$?
	set -e
	if [ "$read_rc" -eq 0 ]; then
		if grep -Fx "$EXPECTED_MARKER" "$RESULT_TXT.tmp" >/dev/null 2>&1; then
			mv "$RESULT_TXT.tmp" "$RESULT_TXT"
			break
		fi
		if grep -F "QPERIAPT_ANDROID_DEVICE_FAIL run-id=$RUN_ID" "$RESULT_TXT.tmp" >/dev/null 2>&1; then
			mv "$RESULT_TXT.tmp" "$RESULT_TXT"
			"$ADB" -s "$SERIAL" exec-out run-as "$PACKAGE" cat "files/qperiapt-android-device-result.json" >"$RESULT_JSON" 2>"$DIST/result-json-read.err"
			"$ADB" -s "$SERIAL" logcat -d >"$DIST/logcat.txt"
			printf 'error: Android runtime smoke reported failure; see %s and %s\n' "$RESULT_JSON" "$DIST/logcat.txt" >&2
			exit 1
		fi
	fi
	sleep 1
	i=$((i + 1))
done
rm -f "$RESULT_TXT.tmp"
test -f "$RESULT_TXT" || {
	"$ADB" -s "$SERIAL" logcat -d >"$DIST/logcat.txt"
	printf 'error: did not receive Android runtime PASS marker within 90 seconds; see %s\n' "$DIST/logcat.txt" >&2
	exit 1
}
"$ADB" -s "$SERIAL" exec-out run-as "$PACKAGE" cat "files/qperiapt-android-device-result.json" >"$RESULT_JSON"
"$ADB" -s "$SERIAL" logcat -d >"$DIST/logcat.txt"
if grep -E 'QPERIAPT_ANDROID_DEVICE_FAIL|FATAL EXCEPTION|JNI DETECTED ERROR|UnsatisfiedLinkError|NoSuchMethodError|NoClassDefFoundError|SIGSEGV|signal 11' "$DIST/logcat.txt" >/dev/null 2>&1; then
	printf 'error: Android logcat contains a runtime failure marker; see %s\n' "$DIST/logcat.txt" >&2
	exit 1
fi
"$ADB" -s "$SERIAL" uninstall "$PACKAGE" >"$DIST/adb-uninstall.log"

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

printf '\n=== Emit Android runtime proof ===\n'
python3 - "$ROOT" "$RUN_ID" "$SERIAL" "$DEVICE_KIND" "$AAR_PATH" "$AAR_DIST/MANIFEST.json" "$SIGNED_APK" "$RESULT_TXT" "$RESULT_JSON" "$DIST/logcat.txt" "$PROOF_JSON" "$ANDROID_PLATFORM" "$ANDROID_BUILD_TOOLS" "$safe_unzip_dir" "$ADB" "$SOURCE_TREE_SHA256" <<'PY'
import datetime as dt
import hashlib
import json
import pathlib
import re
import subprocess
import sys

from artifact.claim_ledger import canonical_tree_digest, repository_paths
from artifact.evidence_io import load_json_object_snapshot
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
android_platform = pathlib.Path(sys.argv[12])
android_build_tools = pathlib.Path(sys.argv[13])
aar_extract = pathlib.Path(sys.argv[14])
adb = pathlib.Path(sys.argv[15])
source_tree_sha256 = sys.argv[16]

def sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def adb_text(*args: str) -> str:
    return subprocess.check_output([str(adb), "-s", serial, *args], text=True).replace("\r", "").strip()

def getprop(name: str) -> str:
    return adb_text("shell", "getprop", name)

def sha_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()

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
    "android_device_smoke_script": root / "artifact/android-device-smoke.sh",
    "android_device_proof": root / "artifact/android_device_proof.py",
    "proof_to_byte": root / "artifact/proof-to-byte.sh",
    "android_aar_script": root / "artifact/android-aar.sh",
    "android_facade": root / "bindings/android/src/main/java/dev/qperiapt/android/QPeriaptAndroid.java",
    "android_jni_adapter": root / "bindings/android/jni/qperiapt_jni.c",
    "c_abi_contract": root / "crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json",
    "signed_policy_vectors": root / "bindings/signed-policy-vectors.json",
}

def rel(path: pathlib.Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()

payload = {
    "schema": 2,
    "generated_at": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
    "git_commit": git_commit(root),
    "source_tree_dirty": source_tree_dirty(root),
    "proof_source_tree_sha256": source_tree_sha256,
    "device_runtime_proof": True,
    "package_only": False,
    "run_id": run_id,
    "package": "dev.qperiapt.androidsmoke",
    "paths": {
        "aar": rel(aar),
        "aar_manifest": rel(aar_manifest),
        "smoke_apk": rel(apk),
        "apksigner_verify": rel(proof.parent / "apksigner-verify.txt"),
        "result_txt": rel(result_txt),
        "result_json": rel(result_json),
        "logcat": rel(logcat),
    },
    "device": {
        "kind": device_kind,
        "serial_sha256_prefix": sha_text(serial)[:12],
        "raw_serial_recorded": False,
        "manufacturer": getprop("ro.product.manufacturer"),
        "model": getprop("ro.product.model"),
        "abi": getprop("ro.product.cpu.abi"),
        "sdk": getprop("ro.build.version.sdk"),
        "release": getprop("ro.build.version.release"),
        "fingerprint_sha256_prefix": sha_text(getprop("ro.build.fingerprint"))[:12],
    },
    "android": {
        "platform": android_platform.name,
        "build_tools": android_build_tools.name,
        "min_sdk": 23,
        "target_sdk": int(target_sdk_match.group(1)),
        "adb_version": subprocess.check_output([str(adb), "version"], text=True).splitlines()[0],
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
        "apksigner_verify_sha256": sha256(proof.parent / "apksigner-verify.txt"),
        "logcat_sha256": sha256(logcat),
        "native": native,
    },
    "source_hashes": {name + "_sha256": sha256(path) for name, path in source_paths.items()},
}
proof.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
PY
python3 -m json.tool "$PROOF_JSON" >/dev/null
if [ "${QPERIAPT_ALLOW_DIRTY_ANDROID_DEVICE:-0}" = "1" ]; then
	set -- --allow-dirty-proof
else
	set --
fi
PYTHONPATH=artifact python3 artifact/android_device_proof.py verify \
	--root "$ROOT" \
	--proof "$PROOF_JSON" \
	--expected-device-kind "$DEVICE_KIND" \
	"$@"
printf 'Proof    : %s\n' "$PROOF_JSON"
printf '\nANDROID_DEVICE_RUNTIME_PASS proof=%s\n' "$PROOF_JSON"
