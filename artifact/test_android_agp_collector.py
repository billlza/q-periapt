"""Formal collector source/configuration authority and actual build JVM regressions."""

from __future__ import annotations

import os
import json
import pathlib
import subprocess
import tempfile
import unittest
from unittest import mock

import android_agp_build as build
import android_agp_consumer as consumer
import android_agp_test_fixture as fixture
import android_maintenance_bundle as bundle
import android_runtime_state as state


ROOT = pathlib.Path(__file__).resolve().parent.parent
PROFILE = "agp_full_release"


def build_arguments(root: pathlib.Path, output_root: pathlib.Path) -> list[str]:
    result = ["--root", str(root), "--profile", PROFILE]
    for option in ("work", "output", "raw-output", "aar", "aar-manifest"):
        result.extend(["--" + option, str(output_root / option)])
    result.extend(
        ["--sdk", str(state.ADB_PROFILE_PATHS["macos-account"].parent.parent)]
    )
    for option, value in (
        ("expected-source-commit", "a" * 40),
        ("expected-aar-sha256", "b" * 64),
        ("expected-aar-manifest-sha256", "c" * 64),
    ):
        result.extend(["--" + option, value])
    return result


class CollectorCliTests(unittest.TestCase):
    def invoke(self, module: str, arguments: list[str], *, environment=None):
        return subprocess.run(
            [
                "/bin/sh",
                str(ROOT / "artifact/python-run.sh"),
                str(ROOT / "artifact" / module),
                *arguments,
            ],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )

    def test_real_cli_rejects_a_script_with_b_source_before_any_b_side_effect(self):
        with tempfile.TemporaryDirectory() as temporary:
            other = pathlib.Path(temporary).resolve()
            initialized = subprocess.run(
                [
                    "/usr/bin/git",
                    "init",
                    "--quiet",
                    "--initial-branch=main",
                    str(other),
                ],
                capture_output=True,
                check=False,
            )
            self.assertEqual(
                (initialized.returncode, initialized.stdout, initialized.stderr),
                (0, b"", b""),
            )
            before = {
                path.relative_to(other): path.read_bytes()
                for path in other.rglob("*")
                if path.is_file()
            }
            verify = [
                "verify",
                "--root",
                str(other),
                "--proof",
                str(other / "missing-proof"),
                "--sdk",
                str(other / "unregistered-sdk"),
                "--profile",
                PROFILE,
                "--expected-source-commit",
                "a" * 40,
                "--expected-aar-sha256",
                "b" * 64,
                "--expected-aar-manifest-sha256",
                "c" * 64,
            ]
            maintenance = ["--root", str(other)]
            for option in (
                "runtime-bundle",
                "full-proof",
                "minimal-proof",
                "output",
                "llvm-nm",
                "llvm-readelf",
                "apksigner",
                "zipalign",
            ):
                maintenance.extend(["--" + option, str(other / option)])
            for module, arguments in (
                ("android_agp_build.py", build_arguments(other, other)),
                ("android_agp_consumer.py", verify),
                ("android_maintenance_bundle.py", maintenance),
            ):
                with self.subTest(module=module):
                    result = self.invoke(module, arguments)
                    self.assertEqual((result.returncode, result.stdout), (1, ""))
                    self.assertIn(
                        "requires the executing repository root", result.stderr
                    )
                    self.assertNotIn("Traceback", result.stderr)
                    self.assertEqual(
                        before,
                        {
                            path.relative_to(other): path.read_bytes()
                            for path in other.rglob("*")
                            if path.is_file()
                        },
                    )

    def test_source_selector_returns_module_authority_and_rejects_alias(self):
        self.assertIs(state.collector_repository_root(ROOT), state.REPOSITORY_ROOT)
        with tempfile.TemporaryDirectory() as temporary:
            alias = pathlib.Path(temporary) / "source-alias"
            alias.symlink_to(ROOT, target_is_directory=True)
            with self.assertRaises(state.AndroidRuntimeStateError):
                state.collector_repository_root(alias)

    def test_real_verify_cli_rejects_external_traversal_and_wrong_leaf_before_reading(
        self,
    ):
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary).resolve()
            external = directory / "malformed.json"
            external.write_bytes(b"this must not be parsed as JSON\n")
            run = state.AndroidRunLayout.from_run_id("a" * 32)
            for proof in (
                external,
                run.proof / ".." / "proof" / consumer.runtime.ANDROID_PROOF_LEAF,
                run.proof / "wrong-leaf.json",
            ):
                arguments = [
                    "verify",
                    "--root",
                    str(ROOT),
                    "--proof",
                    str(proof),
                    "--sdk",
                    str(directory / "must-not-be-inspected"),
                    "--profile",
                    PROFILE,
                    "--expected-source-commit",
                    "a" * 40,
                    "--expected-aar-sha256",
                    "b" * 64,
                    "--expected-aar-manifest-sha256",
                    "c" * 64,
                ]
                result = self.invoke("android_agp_consumer.py", arguments)
                self.assertEqual((result.returncode, result.stdout), (1, ""))
                self.assertIn("AGP collector proof must use", result.stderr)
                self.assertNotIn("Traceback", result.stderr)
            maintenance = [
                "--root",
                str(ROOT),
                "--full-proof",
                str(external),
                "--minimal-proof",
                str(external),
            ]
            for option in (
                "runtime-bundle",
                "output",
                "llvm-nm",
                "llvm-readelf",
                "apksigner",
                "zipalign",
            ):
                maintenance.extend(["--" + option, str(directory / option)])
            result = self.invoke("android_maintenance_bundle.py", maintenance)
            self.assertEqual((result.returncode, result.stdout), (1, ""))
            self.assertIn("AGP collector proof must use", result.stderr)
            self.assertEqual(list(directory.iterdir()), [external])
            self.assertEqual(
                external.read_bytes(), b"this must not be parsed as JSON\n"
            )

    def test_valid_proof_selector_rebuilds_the_existing_run_layout_without_io(self):
        selected = (
            state.AndroidRunLayout.from_run_id("a" * 32).proof
            / consumer.runtime.ANDROID_PROOF_LEAF
        )
        with mock.patch.object(
            pathlib.Path,
            "resolve",
            side_effect=AssertionError("proof was resolved before admission"),
        ):
            self.assertEqual(consumer.collector_proof_path(selected), selected)
            wrong = (
                state.RUNS_ROOT
                / ("A" * 32)
                / "proof"
                / consumer.runtime.ANDROID_PROOF_LEAF
            )
            with self.assertRaises(consumer.AndroidAgpConsumerError):
                consumer.collector_proof_path(wrong)

    def test_real_cli_rejects_cache_override_before_git_or_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            output_root = pathlib.Path(temporary).resolve()
            environment = dict(os.environ, GRADLE_USER_HOME=str(output_root / "cache"))
            result = self.invoke(
                "android_agp_build.py",
                build_arguments(ROOT, output_root),
                environment=environment,
            )
            self.assertEqual((result.returncode, result.stdout), (1, ""))
            self.assertIn("requires the account .gradle cache", result.stderr)
            self.assertEqual(list(output_root.iterdir()), [])

    def test_cache_uses_passwd_account_home_and_never_inspects_override(self):
        selected = state.ACCOUNT_HOME / ".gradle"
        with mock.patch.dict(os.environ, {"HOME": "/unrelated/home"}, clear=True):
            self.assertEqual(build.collector_gradle_home(), selected)
        with mock.patch.dict(
            os.environ, {"GRADLE_USER_HOME": str(selected)}, clear=True
        ):
            self.assertEqual(build.collector_gradle_home(), selected)
        with (
            mock.patch.dict(
                os.environ, {"GRADLE_USER_HOME": "/unregistered/cache"}, clear=True
            ),
            mock.patch.object(
                pathlib.Path,
                "resolve",
                side_effect=AssertionError("untrusted cache was resolved"),
            ),
            mock.patch.object(
                pathlib.Path,
                "exists",
                side_effect=AssertionError("untrusted cache was inspected"),
            ),
        ):
            with self.assertRaises(consumer.AndroidAgpConsumerError):
                build.collector_gradle_home()


class RegisteredSdkTests(unittest.TestCase):
    def test_all_registered_profiles_select_paths_without_adb_or_filesystem_probes(
        self,
    ):
        with (
            mock.patch.object(
                state,
                "canonical_adb_profile",
                side_effect=AssertionError("adb was probed"),
            ),
            mock.patch.object(
                pathlib.Path,
                "resolve",
                side_effect=AssertionError("caller SDK was resolved"),
            ),
        ):
            for adb in state.ADB_PROFILE_PATHS.values():
                sdk = adb.parent.parent
                self.assertEqual(state.registered_sdk_root(sdk), sdk)
                self.assertEqual(state.registered_sdk_root(str(sdk)), sdk)
            for value in (
                "auto",
                "/unregistered/sdk",
                str(state.ACCOUNT_HOME / "Library/Android/sdk/../sdk"),
            ):
                with self.assertRaises(state.AndroidRuntimeStateError):
                    state.registered_sdk_root(value)

    def test_bundle_uses_registered_ndk_tools_without_adb_and_rejects_mixed_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary).resolve()
            profiles = {
                name: directory / name / "platform-tools/adb"
                for name in state.ADB_PROFILE_PATHS
            }
            with mock.patch.object(state, "ADB_PROFILE_PATHS", profiles):
                for name, adb in profiles.items():
                    with self.subTest(profile=name):
                        sdk = adb.parent.parent
                        ndk = sdk / "ndk/29.0.14206865"
                        toolchain = ndk / "toolchains/llvm/prebuilt/darwin-x86_64"
                        bin_root = toolchain / "bin"
                        nm = bin_root / "llvm-nm"
                        readelf = bin_root / "llvm-readelf"
                        signer = sdk / "build-tools/36.0.0/apksigner"
                        alignment = signer.with_name("zipalign")
                        for path in (nm, bin_root / "llvm-readobj", signer, alignment):
                            fixture.write(path, b"fixture executable identity\n")
                            path.chmod(0o700)
                        readelf.symlink_to("llvm-readobj")
                        fixture.write(
                            ndk / "source.properties", b"Pkg.Revision = 29.0.14206865\n"
                        )
                        fixture.write(
                            toolchain / "sysroot/usr/include/jni.h",
                            b"fixture JNI header\n",
                        )
                        self.assertFalse(adb.exists())
                        self.assertEqual(
                            bundle.registered_bundle_tools(
                                nm, readelf, signer, alignment
                            ),
                            (nm, readelf, signer, alignment),
                        )
                        with self.assertRaises(bundle.AndroidMaintenanceBundleError):
                            bundle.registered_bundle_tools(
                                nm, directory / "llvm-readelf", signer, alignment
                            )
                        with self.assertRaises(bundle.AndroidMaintenanceBundleError):
                            bundle.registered_bundle_tools(
                                nm, readelf, signer, directory / "zipalign"
                            )


class BuildJvmTests(unittest.TestCase):
    def test_collector_rejects_jdk_alias_before_it_can_select_another_build_jvm(self):
        output = fixture.gradle_version("/installed/canonical-jdk")
        self.assertEqual(
            build.selected_gradle_jvm(
                output, pathlib.Path("/installed/canonical-jdk")
            ).java_home,
            "/installed/canonical-jdk",
        )
        with self.assertRaisesRegex(consumer.AndroidAgpConsumerError, "canonical JVM"):
            build.selected_gradle_jvm(output, pathlib.Path("/selected/jdk-alias"))

    def test_actual_task_jvm_matches_gradle_vm_fields_and_keeps_runtime_vendor_distinct(
        self,
    ):
        selected = consumer.parse_gradle_jvm(
            fixture.gradle_version().decode(), normalized=True
        )
        for profile in ("agp_full_release", "agp_minimal_release"):
            value = fixture.build_jvm(profile)
            value["java_vendor"] = "A distinct runtime distributor"
            consumer.verify_build_jvm(value, selected, profile=profile)
        raw = consumer.parse_gradle_jvm(
            fixture.gradle_version("/installed/jdk").decode(), normalized=False
        )
        consumer.verify_build_jvm(
            fixture.build_jvm(PROFILE, "/installed/jdk"), raw, profile=PROFILE
        )

    def test_missing_duplicate_or_rerouted_gradle_jvm_identity_is_rejected(self):
        original = fixture.gradle_version().decode()
        lines = original.splitlines(keepends=True)
        invalid = [
            original.replace("Gradle 9.7.1", "Gradle 9.7.2"),
            original.replace("Launcher JVM:", "Another JVM:"),
            original.replace("Daemon JVM:", "Another JVM:"),
            original.replace("${JAVA_HOME}", "/private/host/jdk"),
            original.replace(
                "no Daemon JVM specified, using current Java home",
                "from org.gradle.java.home",
            ),
            original.replace("21.0.11 (Homebrew 21.0.11)", "unknown"),
            *(original + line for line in lines),
        ]
        for text in invalid:
            with self.subTest(text=text):
                with self.assertRaises(consumer.AndroidAgpConsumerError):
                    consumer.parse_gradle_jvm(text, normalized=True)

    def test_actual_build_task_schema_home_compiler_and_vm_mismatches_fail(self):
        selected = consumer.parse_gradle_jvm(
            fixture.gradle_version().decode(), normalized=True
        )
        for field, replacement in (
            ("schema", True),
            ("task", ":app:compileMinimalReleaseJavaWithJavac"),
            ("java_home", "${ANOTHER_JDK}"),
            ("compiler_java_home", "${ANOTHER_JDK}"),
            ("compiler_fork", True),
            ("compiler_fork", 0),
            ("java_version", "21.0.12"),
            ("java_vm_vendor", "Different VM vendor"),
            ("java_vm_version", "21.0.11+other"),
            ("java_runtime_version", ""),
            ("java_vendor", "vendor\nwith a control character"),
        ):
            with self.subTest(field=field, replacement=replacement):
                value = fixture.build_jvm(PROFILE)
                value[field] = replacement
                with self.assertRaises(consumer.AndroidAgpConsumerError):
                    consumer.verify_build_jvm(value, selected, profile=PROFILE)
        for field in consumer.BUILD_JVM_FIELDS:
            value = fixture.build_jvm(PROFILE)
            del value[field]
            with self.assertRaises(consumer.AndroidAgpConsumerError):
                consumer.verify_build_jvm(value, selected, profile=PROFILE)

    def test_capture_replaces_unpublished_probe_without_legacy_or_blank_fields(self):
        self.assertNotIn("java_version", consumer.BUILD_FILE_NAMES)
        self.assertNotIn("java-version.txt", consumer.NORMALIZED_FILES)
        self.assertEqual(consumer.BUILD_FILE_NAMES["build_jvm"], "build-jvm.json")
        source = (
            ROOT / "artifact/android-agp-consumer/app/build.gradle.kts"
        ).read_text()
        self.assertIn("StandardOpenOption.CREATE_NEW", source)
        self.assertIn("check(!options.isFork)", source)
        for key in (
            "java.home",
            "java.version",
            "java.runtime.version",
            "java.vendor",
            "java.vm.vendor",
            "java.vm.version",
        ):
            self.assertIn(f'System.getProperty("{key}")', source)
        self.assertIn("javaCompiler.get().metadata.installationPath", source)

    def test_complete_profile_rejects_rehashed_jvm_or_unexecuted_compile_before_sdk(
        self,
    ):
        with tempfile.TemporaryDirectory() as temporary:
            pair = fixture.create_agp_fixture_pair(pathlib.Path(temporary))
            item = pair.profiles[PROFILE]
            receipt_path = item.proof.parent / "agp-build/receipt.json"
            receipt_data = receipt_path.read_bytes()
            proof_data = item.proof.read_bytes()
            paths = {
                key: receipt_path.parent / name
                for key, name in consumer.BUILD_FILE_NAMES.items()
            }
            original = {
                key: paths[key].read_bytes() for key in ("build_jvm", "gradle_log")
            }
            self.assertFalse((pair.sdk / "platform-tools/adb").exists())
            with mock.patch.object(
                consumer, "run_sdk_tool", side_effect=fixture.sdk_runner
            ):
                consumer.validate_completed_profile(
                    item.root, item.proof, sdk=item.sdk, **item.expected
                )
            wrong_jvm = json.loads(original["build_jvm"])
            wrong_jvm["java_home"] = "${DIFFERENT_JDK}"
            for key, replacement, error in (
                (
                    "build_jvm",
                    fixture.json_bytes(wrong_jvm),
                    "actual AGP build JVM differs",
                ),
                (
                    "gradle_log",
                    original["gradle_log"].replace(
                        b"JavaWithJavac\n", b"JavaWithJavac UP-TO-DATE\n"
                    ),
                    "actual JavaCompile/R8 execution",
                ),
            ):
                with self.subTest(key=key):
                    for name, data in original.items():
                        fixture.write(paths[name], data)
                    fixture.write(paths[key], replacement)
                    receipt = json.loads(receipt_data)
                    receipt["files"][key] = fixture.record(paths[key])
                    fixture.write(receipt_path, fixture.json_bytes(receipt))
                    proof = json.loads(proof_data)
                    proof["consumer"]["build_receipt"] = fixture.record(
                        receipt_path, str(receipt_path.relative_to(pair.root))
                    )
                    fixture.write(item.proof, fixture.json_bytes(proof))
                    with mock.patch.object(
                        consumer,
                        "run_sdk_tool",
                        side_effect=AssertionError(
                            "invalid build JVM reached SDK replay"
                        ),
                    ):
                        with self.assertRaisesRegex(
                            consumer.AndroidAgpConsumerError, error
                        ):
                            consumer.validate_completed_profile(
                                item.root, item.proof, sdk=item.sdk, **item.expected
                            )


if __name__ == "__main__":
    unittest.main()
