"""Run the actual JNI input boundary with bounded public fixtures and no SDK."""

from __future__ import annotations

import os
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest

import c_abi_contract

ROOT = pathlib.Path(__file__).resolve().parent.parent


class AndroidJniInputShapeTests(unittest.TestCase):
    def test_native_preflight_preserves_errors_and_wipes_every_temporary(self) -> None:
        java_home = pathlib.Path(os.environ["JAVA_HOME"])
        self.assertIn(sys.platform, ("darwin", "linux"))
        jni_platform = {"darwin": "darwin", "linux": "linux"}[sys.platform]
        with tempfile.TemporaryDirectory(prefix="qperiapt-jni-shapes-") as directory:
            executable = pathlib.Path(directory) / "input-shapes"
            compiled = subprocess.run(
                [
                    "cc",
                    "-std=c11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-O0",
                    "-I",
                    str(java_home / "include"),
                    "-I",
                    str(java_home / "include" / jni_platform),
                    "-I",
                    str(ROOT / "crates/q-periapt-ffi/include"),
                    str(ROOT / "bindings/android/jni/input_shapes_test.c"),
                    "-o",
                    str(executable),
                ],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            self.assertEqual(
                (compiled.returncode, compiled.stdout, compiled.stderr), (0, "", "")
            )
            executed = subprocess.run(
                [str(executable)],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(
                (executed.returncode, executed.stdout, executed.stderr),
                (0, "JNI_INPUT_SHAPES_PASS cases=193\n", ""),
            )

    def test_binding_length_constants_match_the_existing_abi_contract(self) -> None:
        contract = c_abi_contract.load_contract(
            ROOT / "crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json"
        )
        names = {
            "MLKEM_PK_LEN": "Q_PERIAPT_MLKEM768_PK_LEN",
            "MLKEM_SK_LEN": "Q_PERIAPT_MLKEM768_SK_LEN",
            "MLKEM_CT_LEN": "Q_PERIAPT_MLKEM768_CT_LEN",
            "X25519_LEN": "Q_PERIAPT_X25519_LEN",
            "SECRET_LEN": "Q_PERIAPT_SECRET_LEN",
            "POLICY_DECISION_LEN": "Q_PERIAPT_POLICY_DECISION_LEN",
            "TRUSTED_POLICY_STATE_LEN": "Q_PERIAPT_TRUSTED_POLICY_STATE_LEN",
            "POLICY_SIGNATURE_LEN": "Q_PERIAPT_POLICY_SIGNATURE_LEN",
            "POLICY_VERIFICATION_KEY_LEN": "Q_PERIAPT_POLICY_VERIFICATION_KEY_LEN",
        }
        for relative in (
            "bindings/android/src/main/java/dev/qperiapt/android/QPeriaptAndroid.java",
            "bindings/kotlin/src/main/kotlin/dev/qperiapt/QPeriaptHybrid.kt",
        ):
            source = (ROOT / relative).read_text()
            for name, macro in names.items():
                with self.subTest(binding=relative, name=name):
                    matches = re.findall(
                        rf"(?:final int|const val) {name} = ([0-9]+);?", source
                    )
                    self.assertEqual(
                        matches, [str(contract.document["abi"]["macros"][macro])]
                    )


if __name__ == "__main__":
    unittest.main()
