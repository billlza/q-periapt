"""Closed alpha/legacy admission tests; real JNI/ELF execution remains separate."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

import android_elf as android
import test_android_elf as fixtures


class AndroidSDKProfileTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.AndroidElfVerifierTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.profile = android.package_profile("sdk-020")

    def sdk_entries(self):
        entries = self.fixture.aar_entries()
        source = Path(__file__).resolve().parent.parent
        for name, relative in android.SDK_NOTICE_SOURCES.items():
            entries[name] = (source / relative).read_bytes()
        classes = dict(fixtures.CLASS_ENTRIES)
        classes["dev/qperiapt/android/QPeriaptSDK.class"] = fixtures.CLASS_BYTES
        for owner in ("Runtime", "Key", "PublicKey", "Ciphertext", "Secret", "DerivedKey", "Encapsulation",
                      "KeyPurpose", "PolicyStates", "PolicyUpdate", "Expert"):
            classes[f"dev/qperiapt/android/QPeriaptSDK${owner}.class"] = fixtures.CLASS_BYTES
        entries["classes.jar"] = fixtures.zip_bytes(classes)
        return entries, classes

    def test_profiles_preserve_legacy_and_reject_unknown(self):
        legacy = android.package_profile("legacy")
        self.assertEqual((legacy.version, legacy.schema, len(legacy.exports), len(legacy.jni_methods)), ("0.1.5", 4, 9, 9))
        self.assertEqual((self.profile.version, self.profile.schema, len(self.profile.exports), len(self.profile.jni_methods)),
                         ("0.2.0", 5, 43, 26))
        self.assertLess(legacy.exports, self.profile.exports)
        self.assertEqual({name: self.profile.jni_methods[name] for name in legacy.jni_methods}, legacy.jni_methods)
        for name in ("latest", "sdk", "0.2.0", ""):
            with self.assertRaisesRegex(android.AndroidVerificationError, "unsupported Android package profile"):
                android.package_profile(name)

    def test_alpha_and_legacy_archives_are_not_interchangeable(self):
        entries, _ = self.sdk_entries()
        android.audit_aar_bytes(fixtures.zip_bytes(entries), label="alpha fixture", profile="sdk-020")
        with self.assertRaisesRegex(android.AndroidVerificationError, "file set mismatch"):
            android.audit_aar_bytes(fixtures.zip_bytes(entries), label="alpha cannot be legacy")
        with self.assertRaisesRegex(android.AndroidVerificationError, "file set mismatch"):
            android.audit_aar_bytes(fixtures.zip_bytes(self.fixture.aar_entries()), label="legacy cannot be alpha", profile="sdk-020")

    def test_each_owner_class_and_java11_bytecode_are_required(self):
        entries, classes = self.sdk_entries()
        for name in tuple(classes):
            if "QPeriaptSDK" not in name:
                continue
            changed = dict(classes)
            del changed[name]
            entries["classes.jar"] = fixtures.zip_bytes(changed)
            with self.subTest(missing=name), self.assertRaisesRegex(android.AndroidVerificationError, "class is missing"):
                android.audit_aar_bytes(fixtures.zip_bytes(entries), label="missing owner", profile="sdk-020")
        changed = dict(classes)
        changed["dev/qperiapt/android/QPeriaptSDK.class"] = b"\xca\xfe\xba\xbe\x00\x00\x00\x3d"
        entries["classes.jar"] = fixtures.zip_bytes(changed)
        with self.assertRaisesRegex(android.AndroidVerificationError, "non-preview Java 11"):
            android.audit_aar_bytes(fixtures.zip_bytes(entries), label="wrong bytecode", profile="sdk-020")

    def test_alpha_still_requires_exact_callback_keep_rules_and_notices(self):
        entries, _ = self.sdk_entries()
        entries["proguard.txt"] += b"-dontwarn **\n"
        with self.assertRaisesRegex(android.AndroidVerificationError, "exact JNI"):
            android.audit_aar_bytes(fixtures.zip_bytes(entries), label="changed rules", profile="sdk-020")
        entries["proguard.txt"] = android.ANDROID_CONSUMER_RULES
        for name in android.SDK_NOTICE_SOURCES:
            changed = dict(entries)
            del changed[name]
            with self.subTest(missing=name), self.assertRaisesRegex(android.AndroidVerificationError, "file set mismatch"):
                android.audit_aar_bytes(fixtures.zip_bytes(changed), label="missing notice", profile="sdk-020")

    def test_producer_stages_only_the_selected_profiles_notices(self):
        source = Path(__file__).resolve().parent.parent
        script = (source / "artifact/android-aar.sh").read_text()
        start = script.index('mkdir -p "$STAGE/META-INF"')
        end = script.index("printf '\\n=== Build Android Rust FFI slices and JNI shim ===\\n'", start)
        staging = script[start:end]
        base = {"META-INF/" + name: name for name in ("LICENSE", "LICENSES/Apache-2.0.txt", "LICENSES/MIT.txt")}
        with tempfile.TemporaryDirectory(prefix="qperiapt-android-notices-") as directory:
            fixture = Path(directory)
            for name in set(base.values()) | set(android.SDK_NOTICE_SOURCES.values()):
                path = fixture / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((source / name).read_bytes())
            # A retired compiler notice and a later repository notice
            # must not expand either profile's closed Android payload.
            (fixture / "LICENSES/Rust-1.97.0-library.html").write_bytes(b"retired compiler notice\n")
            (fixture / "LICENSES/future-notice.txt").write_bytes(b"unrelated repository notice\n")
            for profile in ("legacy", "sdk-020"):
                with self.subTest(profile=profile):
                    stage = fixture / ("stage-" + profile)
                    environment = dict(os.environ, QPERIAPT_TEST_SOURCE=str(source),
                        QPERIAPT_TEST_FIXTURE=str(fixture), QPERIAPT_TEST_STAGE=str(stage),
                        QPERIAPT_TEST_PROFILE=profile)
                    prefix = ('set -eu\nROOT=$QPERIAPT_TEST_SOURCE\n. "$ROOT/artifact/python-env.sh"\n'
                              'ROOT=$QPERIAPT_TEST_FIXTURE\nSTAGE=$QPERIAPT_TEST_STAGE\n'
                              'PACKAGE_PROFILE=$QPERIAPT_TEST_PROFILE\ncd "$ROOT"\n')
                    result = subprocess.run(["sh", "-c", prefix + staging], env=environment,
                        capture_output=True, timeout=30, check=False)
                    self.assertEqual(result.returncode, 0, result.stderr.decode())
                    expected = dict(base)
                    if profile == "sdk-020":
                        expected.update(android.SDK_NOTICE_SOURCES)
                    actual = {path.relative_to(stage).as_posix(): path.read_bytes()
                              for path in stage.rglob("*") if path.is_file()}
                    self.assertEqual(set(actual), set(expected))
                    for name, relative in expected.items():
                        self.assertEqual(actual[name], (source / relative).read_bytes())

    def test_sdk_manifest_minimum_cannot_silently_differ(self):
        entries, _ = self.sdk_entries()
        entries["AndroidManifest.xml"] = entries["AndroidManifest.xml"].replace(b'minSdkVersion="23"', b'minSdkVersion="1"')
        with self.assertRaisesRegex(android.AndroidVerificationError, "exactly minSdkVersion=23"):
            android.audit_aar_bytes(fixtures.zip_bytes(entries), label="incorrect SDK floor", profile="sdk-020")

    def test_exact_native_export_table_required_for_the_selected_profile(self):
        library = self.fixture.write_library("arm64-v8a", android.FFI_LIBRARY)
        nm, readelf = self.fixture.fake_tools()
        with self.assertRaisesRegex(android.AndroidVerificationError, "exact allowlist"):
            android.verify_library(library, abi="arm64-v8a", library=android.FFI_LIBRARY,
                                   llvm_nm=nm, llvm_readelf=readelf, profile="sdk-020")
        nm = self.fixture.write_tool("sdk-nm", "\n".join(f"print({(name + ' T 100 8')!r})" for name in sorted(self.profile.exports)))
        android.verify_library(library, abi="arm64-v8a", library=android.FFI_LIBRARY,
                               llvm_nm=nm, llvm_readelf=readelf, profile="sdk-020")
        with self.assertRaisesRegex(android.AndroidVerificationError, "exact allowlist"):
            android.verify_library(library, abi="arm64-v8a", library=android.FFI_LIBRARY, llvm_nm=nm, llvm_readelf=readelf)
        with nm.open("a") as stream:
            stream.write("\nprint('debug_private_export T 100 8')\n")
        with self.assertRaisesRegex(android.AndroidVerificationError, "exact allowlist"):
            android.verify_library(library, abi="arm64-v8a", library=android.FFI_LIBRARY,
                                   llvm_nm=nm, llvm_readelf=readelf, profile="sdk-020")


if __name__ == "__main__":
    unittest.main()
