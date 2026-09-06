"""Exact profile, R8 input, portable evidence, and result-transport regressions."""

from __future__ import annotations

import base64
import pathlib
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile

import android_agp_build as build
import android_agp_consumer as consumer
import android_agp_consumer_contract as contract
import android_bounded_command as bounded
import android_device_proof as runtime
import android_elf
from test_android_minimal_consumer import class_dump, complete_dump

ROOT = pathlib.Path(__file__).resolve().parent.parent
RUN_ID = "a" * 32


def projection(profile: str = "agp_full_release") -> dict[str, object]:
    value: dict[str, object] = {
        name: "b" * 64
        for name in contract.PROJECTION_FIELDS
        if name.endswith("_sha256")
    }
    value.update(
        profile=profile,
        run_id=RUN_ID,
        source_commit="c" * 40,
        passed_tests=list(contract.PROFILE_TESTS[profile]),
        agp_version="9.4.0",
        gradle_version="9.7.1",
    )
    return value


def validate(value: object, profile: str = "agp_full_release") -> dict[str, object]:
    return contract.validate_profile_projection(
        value,
        expected_profile=profile,
        expected_aar_sha256="b" * 64,
        expected_aar_manifest_sha256="b" * 64,
        expected_source_commit="c" * 40,
    )


def response(text: bytes = b"marker\n", data: bytes = b"{}\n") -> bytes:
    return (
        f"INSTRUMENTATION_RESULT: qperiapt_run_id={RUN_ID}\n"
        f"INSTRUMENTATION_RESULT: qperiapt_result_text_base64={base64.b64encode(text).decode()}\n"
        f"INSTRUMENTATION_RESULT: qperiapt_result_json_base64={base64.b64encode(data).decode()}\n"
        "INSTRUMENTATION_CODE: -1\n"
    ).encode()


def section(origin: str, body: str) -> str:
    return (
        f"# The proguard configuration file for the following section is {origin}\n"
        f"{body}\n# End of content from {origin}\n"
    )


DEFAULT = "-keepclasseswithmembernames,includedescriptorclasses class * {\n    native <methods>;\n}\n"
MANIFEST_RULES = (
    "-keep class dev.qperiapt.androidsmoke.QPeriaptSmokeActivity { <init>(); }\n"
    "-keep class dev.qperiapt.androidsmoke.QPeriaptResultInstrumentation { <init>(); }\n"
)


def configuration(aar: str) -> str:
    return (
        section(
            "Android Gradle plugin 9.4.0 (extracted file: ${WORK}/project/app/build/intermediates/default_proguard_files/global/proguard-android-optimize.txt-9.4.0)",
            DEFAULT,
        )
        + section(
            "${GRADLE_HOME}/caches/9.7.1/transforms/test/transformed/q-periapt-android-0.1.5/proguard.txt",
            aar,
        )
        + section("<unknown>", "")
    )


class AgpProjectionTests(unittest.TestCase):
    def test_profiles_have_exact_independent_workloads_and_legacy_stays_full(
        self,
    ) -> None:
        for profile in contract.PROFILES:
            self.assertEqual(
                validate(projection(profile), profile), projection(profile)
            )
        self.assertEqual(
            runtime.EXPECTED_TESTS, list(contract.PROFILE_TESTS["agp_full_release"])
        )
        self.assertEqual(
            runtime.expected_marker(RUN_ID),
            f"QPERIAPT_ANDROID_DEVICE_PASS run-id={RUN_ID} tests=3",
        )
        self.assertEqual(
            runtime.expected_marker(
                RUN_ID, runtime.RuntimeResultProfile.AGP_MINIMAL_RELEASE
            ),
            f"QPERIAPT_ANDROID_DEVICE_PASS run-id={RUN_ID} tests=1",
        )
        with self.assertRaises(contract.AndroidAgpConsumerError):
            validate(projection("agp_minimal_release"))

    def test_fields_types_hashes_toolchain_and_expected_bindings_are_strict(
        self,
    ) -> None:
        mutations = {
            "run_id": [True, "A" * 32],
            "source_commit": ["d" * 40, True],
            "aar_sha256": ["e" * 64, "bad"],
            "aar_manifest_sha256": ["e" * 64],
            "passed_tests": [
                [],
                ["runtimeVersionOnly"],
                tuple(contract.PROFILE_TESTS["agp_full_release"]),
            ],
            "agp_version": ["9.3.0"],
            "gradle_version": ["9.7"],
            "proof_sha256": [False, "z" * 64],
        }
        for key, values in mutations.items():
            for replacement in values:
                with self.subTest(key=key, replacement=replacement):
                    value = projection()
                    value[key] = replacement
                    with self.assertRaises(contract.AndroidAgpConsumerError):
                        validate(value)
        for value in (
            None,
            [],
            {**projection(), "extra": True},
            {
                key: value
                for key, value in projection().items()
                if key != "proof_sha256"
            },
        ):
            with self.assertRaises(contract.AndroidAgpConsumerError):
                validate(value)

    def test_minimal_result_schema_and_count_are_exact_integers(self) -> None:
        import json

        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            paths = {
                name: directory / name
                for name in ("result_txt", "result_json", "logcat")
            }
            marker = runtime.expected_marker(
                RUN_ID, runtime.RuntimeResultProfile.AGP_MINIMAL_RELEASE
            )
            paths["result_txt"].write_text(marker + "\n")
            paths["logcat"].write_text("I/QPeriaptSmoke: " + marker + "\n")
            for field in ("schema", "test_count"):
                for replacement in (True, 1.0):
                    result = {
                        "schema": 1,
                        "status": "pass",
                        "run_id": RUN_ID,
                        "test_count": 1,
                        "passed_tests": ["runtimeVersionOnly"],
                    }
                    result[field] = replacement
                    paths["result_json"].write_text(json.dumps(result))
                    with self.assertRaises(SystemExit):
                        runtime.verify_result_files(
                            paths,
                            RUN_ID,
                            runtime.RuntimeResultProfile.AGP_MINIMAL_RELEASE,
                        )

    def test_pure_contract_import_does_not_load_io_or_publication_modules(self) -> None:
        code = (
            "import sys; sys.path.insert(0,sys.argv[1]); import android_agp_consumer_contract; "
            "assert not any(n in sys.modules for n in ('android_device_proof','android_agp_consumer','proof_manifest','release_publication_contract'))"
        )
        result = subprocess.run(
            [sys.executable, "-B", "-c", code, str(ROOT / "artifact")],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, "", ""))


class AgpTransportTests(unittest.TestCase):
    def test_one_successful_nonce_bound_bundle_decodes_exact_bytes(self) -> None:
        self.assertEqual(
            consumer.decode_instrumentation_output(response(), RUN_ID),
            (b"marker\n", b"{}\n"),
        )

    def test_failure_ambiguity_missing_fields_and_unexpected_diagnostics_are_rejected(
        self,
    ) -> None:
        raw = response()
        variants = [
            raw.replace(b"CODE: -1", b"CODE: 0"),
            raw + b"INSTRUMENTATION_CODE: -1\n",
            raw + b"INSTRUMENTATION_RESULT: qperiapt_run_id=" + RUN_ID.encode() + b"\n",
            raw.replace(RUN_ID.encode(), b"f" * 32),
            raw.replace(b"bWFya2VyCg==", b"!!"),
            raw.replace(
                b"INSTRUMENTATION_RESULT: qperiapt_run_id=",
                b"INSTRUMENTATION_RESULT: wrong=",
            ),
            raw + b"WARNING: runtime failure\n",
            raw + b"INSTRUMENTATION_FAILED: crashed\n",
            b"\xff",
        ]
        for data in variants:
            with self.subTest(data=data):
                with self.assertRaises(contract.AndroidAgpConsumerError):
                    consumer.decode_instrumentation_output(data, RUN_ID)

    def test_bounded_operation_uses_fixed_component_nonce_and_deadline(self) -> None:
        spec = bounded.OPERATION_SPECS[bounded.AndroidOperation.RUN_INSTRUMENTATION]
        self.assertEqual(
            (spec.mode, spec.timeout_seconds, spec.timeout_maximum), ("write", 110, 110)
        )
        self.assertEqual(spec.output.leaf, "adb-instrumentation.txt")
        self.assertLessEqual(spec.output.maximum_bytes, 16 * 1024 * 1024)
        self.assertTrue(spec.stderr_to_stdout)

    def test_reader_has_no_q_reference_and_no_completed_json_retry(self) -> None:
        source = (ROOT / consumer.INSTRUMENTATION_SOURCE).read_text()
        self.assertNotIn("dev.qperiapt.android.", source)
        self.assertNotIn("QPeriaptAndroid", source)
        self.assertNotIn("catch (JSONException", source)
        self.assertIn('json.getString("run_id")', source)
        self.assertIn("finish(Activity.RESULT_CANCELED, result)", source)


class AgpR8AndInputTests(unittest.TestCase):
    def test_r8_sources_are_exact_and_app_keep_or_unknown_directive_is_rejected(
        self,
    ) -> None:
        aar = android_elf.ANDROID_CONSUMER_RULES.decode()
        valid = configuration(aar)
        consumer.verify_r8_configuration(
            valid, default=DEFAULT, manifest=MANIFEST_RULES, aar_rules=aar
        )
        invalid = [
            valid + "-keep class dev.qperiapt.android.** { *; }\n",
            valid + section("app/proguard-rules.pro", aar),
            valid.replace(aar.strip(), aar.strip() + "\n-keep class ** { *; }"),
            valid.replace(
                section("<unknown>", ""), section("<unknown>", "-dontshrink")
            ),
            valid.replace("q-periapt-android-0.1.5", "another-library"),
            valid.replace("${GRADLE_HOME}", "/Users/private/.gradle"),
        ]
        for text in invalid:
            with self.subTest(text=text):
                with self.assertRaises(contract.AndroidAgpConsumerError):
                    consumer.verify_r8_configuration(
                        text, default=DEFAULT, manifest=MANIFEST_RULES, aar_rules=aar
                    )
        with self.assertRaises(contract.AndroidAgpConsumerError):
            consumer.verify_r8_configuration(
                valid,
                default=DEFAULT,
                manifest=MANIFEST_RULES + "-keep class ** { *; }\n",
                aar_rules=aar,
            )

    def test_profile_input_sets_are_closed_and_minimal_calls_only_runtime_version(
        self,
    ) -> None:
        full = consumer.compiled_sources("agp_full_release")
        minimal = consumer.compiled_sources("agp_minimal_release")
        self.assertEqual((len(full), len(minimal)), (4, 3))
        self.assertFalse(any("/full/" in name for name in minimal))
        self.assertTrue(all((ROOT / name).is_file() for name in full + minimal))
        entry = (
            ROOT
            / next(
                name for name in minimal if name.endswith("QPeriaptSmokeActivity.java")
            )
        ).read_text()
        import re

        self.assertEqual(
            re.findall(r"QPeriaptAndroid\.(\w+)\(", entry), ["runtimeVersion"]
        )
        template = (ROOT / consumer.TEMPLATE_ROOT / "app/build.gradle.kts").read_text()
        self.assertIn("source.files.map", template)
        self.assertIn("isMinifyEnabled = true", template)
        self.assertIn("isDebuggable = false", template)
        self.assertNotIn("proguard-rules.pro", template)
        self.assertNotIn("testImplementation", template)

    def test_multidex_definitions_are_parsed_and_instrumentation_strings_do_not_count(
        self,
    ) -> None:
        raw = complete_dump() + class_dump(0, consumer.INSTRUMENTATION_DESCRIPTOR, ())
        android_elf.verify_minimal_consumer_dump(raw)
        self.assertIn(
            consumer.INSTRUMENTATION_DESCRIPTOR,
            android_elf.parse_consumer_dex_classes(raw),
        )
        self.assertNotIn(
            consumer.INSTRUMENTATION_DESCRIPTOR,
            android_elf.parse_consumer_dex_classes(
                complete_dump() + consumer.INSTRUMENTATION_DESCRIPTOR
            ),
        )
        with self.assertRaises(android_elf.AndroidVerificationError):
            android_elf.parse_consumer_dex_classes(
                raw + class_dump(1, consumer.INSTRUMENTATION_DESCRIPTOR, ())
            )
        for name in ("classes.dex", "classes2.dex", "classes10.dex", "classes101.dex"):
            self.assertIsNotNone(consumer.DEX_NAME.fullmatch(name))
        for name in ("classes1.dex", "classes01.dex", "folder/classes.dex"):
            self.assertIsNone(consumer.DEX_NAME.fullmatch(name))

    def test_instrumentation_requires_real_concrete_methods(self) -> None:
        methods = (
            ("<init>", "()V", "PUBLIC CONSTRUCTOR"),
            ("onCreate", "(Landroid/os/Bundle;)V", "PUBLIC"),
            ("onStart", "()V", "PUBLIC"),
        )
        consumer.verify_agp_dex_dump(
            complete_dump()
            + class_dump(0, consumer.INSTRUMENTATION_DESCRIPTOR, methods)
        )
        for index in range(len(methods)):
            with self.assertRaises(contract.AndroidAgpConsumerError):
                consumer.verify_agp_dex_dump(
                    complete_dump()
                    + class_dump(
                        0,
                        consumer.INSTRUMENTATION_DESCRIPTOR,
                        methods[:index] + methods[index + 1 :],
                    )
                )

    def test_actual_release_manifest_shape_rejects_debuggable_and_wrong_instrumentation(
        self,
    ) -> None:
        valid = (
            "E: manifest (line=1)\n"
            "  E: application (line=2)\n    A: android:debuggable(0x0101000f)=(type 0x12)0x0\n"
            "  E: instrumentation (line=4)\n"
            '    A: android:name(0x01010003)="dev.qperiapt.androidsmoke.QPeriaptResultInstrumentation" (Raw: "instrumentation")\n'
            '    A: android:targetPackage(0x01010021)="dev.qperiapt.androidsmoke" (Raw: "package")\n'
        )
        consumer.verify_release_manifest_dump(valid)
        for changed in (
            valid.replace("(type 0x12)0x0", "(type 0x12)0xffffffff"),
            valid.replace("QPeriaptResultInstrumentation", "AnotherInstrumentation"),
            valid.replace(
                'targetPackage(0x01010021)="dev.qperiapt.androidsmoke"',
                'targetPackage(0x01010021)="another.package"',
            ),
            valid + "  E: instrumentation (line=9)\n",
        ):
            with self.assertRaises(contract.AndroidAgpConsumerError):
                consumer.verify_release_manifest_dump(changed)

    def test_incomplete_local_and_exported_proofs_never_return_success(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            proof = directory / "proof.json"
            proof.write_text('{"device":{"kind":"emulator"}}')
            constraints = dict(
                expected_profile="agp_minimal_release",
                expected_aar_sha256="b" * 64,
                expected_aar_manifest_sha256="b" * 64,
                expected_source_commit="c" * 40,
            )
            with self.assertRaises(contract.AndroidAgpConsumerError):
                consumer.validate_completed_profile(ROOT, proof, **constraints)
            with self.assertRaises(contract.AndroidAgpConsumerError):
                consumer.verify_exported_profile(ROOT, directory, **constraints)
            with self.assertRaises(contract.AndroidAgpConsumerError):
                consumer.profile_evidence_files(ROOT, proof)
            linked = directory / "linked"
            linked.symlink_to(directory, target_is_directory=True)
            with self.assertRaises(contract.AndroidAgpConsumerError):
                consumer.verify_exported_profile(ROOT, linked, **constraints)

    def test_normalization_is_explicit_path_replacement_and_keeps_warning_lines(
        self,
    ) -> None:
        original = b"WARNING: issue /Users/example/project/a.java\n-keep class Example { *; }\n"
        result = build.normalized(
            original, {"SOURCE": pathlib.Path("/Users/example/project")}
        )
        self.assertEqual(
            result, b"WARNING: issue ${SOURCE}/a.java\n-keep class Example { *; }\n"
        )
        with self.assertRaises(contract.AndroidAgpConsumerError):
            build.normalized(original, {})

    def test_special_apk_entries_and_noncanonical_paths_are_rejected(self) -> None:
        for path in ("../a", "/a", "a/../b", "a//b", "a\\b"):
            with self.assertRaises(contract.AndroidAgpConsumerError):
                consumer._relative(path, "fixture")
        with tempfile.TemporaryDirectory() as temp:
            apk = pathlib.Path(temp) / "consumer.apk"
            for mode in (stat.S_IFLNK, stat.S_IFIFO, stat.S_IFSOCK):
                with zipfile.ZipFile(apk, "w") as archive:
                    entry = zipfile.ZipInfo("classes.dex")
                    entry.external_attr = (mode | 0o600) << 16
                    archive.writestr(entry, b"payload")
                with self.assertRaises(contract.AndroidAgpConsumerError):
                    consumer._apk_entries(apk)


if __name__ == "__main__":
    unittest.main()
