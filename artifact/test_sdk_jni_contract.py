"""Compile the actual Java facade and check its JNI descriptor contract."""

from __future__ import annotations

import os
import pathlib
import re
import subprocess
import tempfile
import unittest

import android_elf
from android_elf import JNI_NATIVE_METHOD_DESCRIPTORS
from sdk_abi2_spec import JNI_METHODS, PACKAGE_SEMVER
from test_android_minimal_consumer import CALLBACK, EXCEPTION, FACADE, NATIVE_METHODS, class_dump

ROOT = pathlib.Path(__file__).resolve().parent.parent


class SdkJniContractTests(unittest.TestCase):
    def test_versioned_dex_contracts_reject_cross_version_and_missing_extensions(self) -> None:
        owned = tuple((name, descriptor, "STATIC NATIVE") for name, descriptor in JNI_METHODS.items())
        callback = class_dump(1, EXCEPTION, CALLBACK)
        legacy = class_dump(0, FACADE, NATIVE_METHODS) + callback
        current = class_dump(0, FACADE, NATIVE_METHODS + owned) + callback
        android_elf.verify_minimal_consumer_dump(current, package_version=PACKAGE_SEMVER)
        android_elf.verify_minimal_consumer_dump(legacy)
        for output, version in ((current, "0.1.5"), (legacy, PACKAGE_SEMVER), (current, "0.2.0-unreviewed")):
            with self.subTest(version=version), self.assertRaises(android_elf.AndroidVerificationError):
                android_elf.verify_minimal_consumer_dump(output, package_version=version)
        for index in range(len(owned)):
            with self.subTest(missing=owned[index][0]), self.assertRaises(android_elf.AndroidVerificationError):
                android_elf.verify_minimal_consumer_dump(
                    class_dump(0, FACADE, NATIVE_METHODS + owned[:index] + owned[index + 1:]) + callback,
                    package_version=PACKAGE_SEMVER,
                )

    def test_compiled_descriptors_keep_legacy_methods_and_add_owned_surface(self) -> None:
        expected = {**JNI_NATIVE_METHOD_DESCRIPTORS, **JNI_METHODS}
        java_home = pathlib.Path(os.environ["JAVA_HOME"])
        source = ROOT / "bindings/android/src/main/java"
        with tempfile.TemporaryDirectory(prefix="qperiapt-sdk-jni-contract-") as directory:
            compiled = subprocess.run(
                [str(java_home / "bin/javac"), "--release", "11", "-Xlint:all", "-Werror", "-d", directory,
                 *[str(p) for p in sorted(source.rglob("*.java"))]],
                capture_output=True, text=True, timeout=60, check=False,
            )
            self.assertEqual((compiled.returncode, compiled.stdout, compiled.stderr), (0, "", ""))
            inspected = subprocess.run(
                [str(java_home / "bin/javap"), "-classpath", directory, "-s", "-p", "dev.qperiapt.android.QPeriaptAndroid"],
                capture_output=True, text=True, timeout=30, check=False,
            )
            self.assertEqual((inspected.returncode, inspected.stderr), (0, ""))
            methods = re.findall(
                r"native\s+[\w.$\[\]/]+[\s\[\]]+\b(\w+Native)\([^)]*\);\s+descriptor:\s+(\S+)",
                inspected.stdout,
            )
            self.assertEqual(len(methods), len(expected))
            self.assertEqual(dict(methods), expected)
        c_source = (ROOT / "bindings/android/jni/qperiapt_jni.c").read_text()
        registered = re.findall(r'\{"(\w+Native)",\s*"([^"]+)",\s*\(void \*\)', c_source)
        self.assertEqual(len(registered), len(expected))
        self.assertEqual(dict(registered), expected)


if __name__ == "__main__":
    unittest.main()
