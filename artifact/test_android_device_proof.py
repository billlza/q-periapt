#!/usr/bin/env python3

from __future__ import annotations

import argparse
import copy
import datetime as dt
import pathlib
import re
import stat
import subprocess
import tempfile
import unittest

import android_device_proof


def complete_proof_shape() -> dict[str, object]:
    native = {
        abi: {
            "ffi_so_sha256": "1" * 64,
            "jni_so_sha256": "2" * 64,
        }
        for abi in android_device_proof.REQUIRED_NATIVE_ABIS
    }
    return {
        "schema": android_device_proof.PROOF_SCHEMA_VERSION,
        "generated_at": "2026-07-15T00:00:00Z",
        "git_commit": "a" * 40,
        "source_tree_dirty": False,
        "proof_source_tree_sha256": "b" * 64,
        "device_runtime_proof": True,
        "package_only": False,
        "release_candidate_mode": False,
        "run_id": "c" * 32,
        "package": "dev.qperiapt.androidsmoke",
        "paths": {
            key: f"target/android/{key}"
            for key in android_device_proof.PROOF_PATH_KEYS
        },
        "device": {
            "kind": "emulator",
            "serial_sha256_prefix": "3" * 12,
            "raw_serial_recorded": False,
            "manufacturer": "Google",
            "model": "Android SDK built for arm64",
            "abi": "arm64-v8a",
            "page_size": 16384,
            "sdk": 35,
            "release": "15",
            "fingerprint_sha256_prefix": "4" * 12,
        },
        "android": {
            "platform": "android-35",
            "build_tools": "36.0.0",
            "ndk": "29.0.14206865",
            "native_page_alignment": 16384,
            "min_sdk": 23,
            "target_sdk": 35,
            "adb_version": "Android Debug Bridge version 1.0.41",
            "apksigner_sha256": "5" * 64,
            "zipalign_sha256": "6" * 64,
        },
        "abi": {
            "major": 2,
            "contract_path": "crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json",
            "contract_sha256": "7" * 64,
            "runtime_library": "libq_periapt_ffi_abi2.so",
            "jni_library": "libqperiapt_jni_abi2.so",
            "legacy_library_names_present": False,
        },
        "result": {
            "marker_sha256": "8" * 64,
            "json_sha256": "9" * 64,
            "status": "pass",
            "test_count": len(android_device_proof.EXPECTED_TESTS),
            "passed_tests": list(android_device_proof.EXPECTED_TESTS),
        },
        "artifacts": {
            "aar_sha256": "a" * 64,
            "aar_manifest_sha256": "b" * 64,
            "smoke_apk_sha256": "c" * 64,
            "apksigner_verify_sha256": "d" * 64,
            "zipalign_verify_sha256": "e" * 64,
            "logcat_sha256": "f" * 64,
            "native": native,
        },
        "source_hashes": {
            name + "_sha256": "0" * 64
            for name in android_device_proof.SOURCE_INPUTS
        },
    }


class AndroidDeviceProofProvenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp_dir.name)
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(["git", "-C", str(self.root), "config", "user.name", "QPeriapt Test"], check=True)
        subprocess.run(["git", "-C", str(self.root), "config", "user.email", "test@invalid.local"], check=True)
        (self.root / ".gitignore").write_text("target/\n", encoding="utf-8")
        (self.root / "tracked.txt").write_text("clean\n", encoding="utf-8")
        self.core_source = self.root / "crates" / "q-periapt-core" / "src" / "lib.rs"
        self.core_source.parent.mkdir(parents=True)
        self.core_source.write_text("pub const PROOF_INPUT: &str = \"original\";\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.root), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.root), "commit", "-qm", "fixture"], check=True)
        self.commit = android_device_proof.git_commit(self.root)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_matching_clean_provenance_passes(self) -> None:
        android_device_proof.verify_git_provenance(
            self.root,
            {"git_commit": self.commit, "source_tree_dirty": False},
            allow_dirty_proof=False,
        )

    def test_allow_dirty_never_bypasses_commit_binding(self) -> None:
        with self.assertRaisesRegex(SystemExit, "commit provenance failed"):
            android_device_proof.verify_git_provenance(
                self.root,
                {"git_commit": "0" * 40, "source_tree_dirty": True},
                allow_dirty_proof=True,
            )

    def test_evidence_only_successor_commit_can_bind_release_proof(self) -> None:
        proof_commit = self.commit
        proof_digest = android_device_proof.current_source_tree_digest(self.root)
        results = self.root / "artifact" / "results.json"
        results.parent.mkdir()
        results.write_text('{"proof":"bound"}\n', encoding="utf-8")
        subprocess.run(["git", "-C", str(self.root), "add", "artifact/results.json"], check=True)
        subprocess.run(["git", "-C", str(self.root), "commit", "-qm", "bind evidence"], check=True)

        android_device_proof.verify_git_provenance(
            self.root,
            {"git_commit": proof_commit, "source_tree_dirty": False},
            allow_dirty_proof=False,
        )
        android_device_proof.verify_source_tree_digest(
            self.root,
            {"proof_source_tree_sha256": proof_digest},
        )

    def test_source_changing_successor_commit_is_rejected(self) -> None:
        proof_commit = self.commit
        (self.root / "tracked.txt").write_text("changed\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.root), "add", "tracked.txt"], check=True)
        subprocess.run(["git", "-C", str(self.root), "commit", "-qm", "change source"], check=True)

        with self.assertRaisesRegex(SystemExit, "commit provenance failed"):
            android_device_proof.verify_git_provenance(
                self.root,
                {"git_commit": proof_commit, "source_tree_dirty": False},
                allow_dirty_proof=False,
            )

    def test_strict_verification_rejects_current_dirty_tree(self) -> None:
        (self.root / "untracked.txt").write_text("dirty\n", encoding="utf-8")
        with self.assertRaisesRegex(SystemExit, "current source tree is dirty"):
            android_device_proof.verify_git_provenance(
                self.root,
                {"git_commit": self.commit, "source_tree_dirty": False},
                allow_dirty_proof=False,
            )

    def test_diagnostic_verification_allows_dirty_tree_but_keeps_commit_binding(self) -> None:
        (self.root / "untracked.txt").write_text("dirty\n", encoding="utf-8")
        android_device_proof.verify_git_provenance(
            self.root,
            {"git_commit": self.commit, "source_tree_dirty": True},
            allow_dirty_proof=True,
        )

    def test_proof_schema_v3_is_required(self) -> None:
        proof = complete_proof_shape()
        wrong_schema = copy.deepcopy(proof)
        wrong_schema["schema"] = 2
        with self.assertRaisesRegex(SystemExit, "Android proof schema must be 3"):
            android_device_proof.verify_proof_schema(wrong_schema)
        android_device_proof.verify_proof_schema(proof)

        extra_top_level = copy.deepcopy(proof)
        extra_top_level["raw_serial"] = "emulator-5554"
        with self.assertRaisesRegex(SystemExit, "Android proof fields differ"):
            android_device_proof.verify_proof_schema(extra_top_level)

        extra_device_field = copy.deepcopy(proof)
        extra_device_field["device"]["serial"] = "emulator-5554"
        with self.assertRaisesRegex(SystemExit, "Android proof device fields differ"):
            android_device_proof.verify_proof_schema(extra_device_field)

        extra_result_field = copy.deepcopy(proof)
        extra_result_field["result"]["raw_serial"] = "emulator-5554"
        with self.assertRaisesRegex(SystemExit, "Android proof result fields differ"):
            android_device_proof.verify_proof_schema(extra_result_field)

    def test_freshness_gate_is_separate_from_timeless_schema_validation(self) -> None:
        proof = complete_proof_shape()
        android_device_proof.verify_proof_schema(proof)
        generated_at = dt.datetime(2026, 7, 15, tzinfo=dt.timezone.utc)
        proof["generated_at"] = generated_at.isoformat().replace("+00:00", "Z")
        android_device_proof.verify_proof_freshness(
            proof,
            86400,
            reference_time=generated_at + dt.timedelta(hours=23),
        )
        with self.assertRaisesRegex(SystemExit, "Android proof is stale"):
            android_device_proof.verify_proof_freshness(
                proof,
                86400,
                reference_time=generated_at + dt.timedelta(days=8),
            )

    def test_verify_bundle_cli_is_timeless_but_bundle_creation_has_freshness_gate(self) -> None:
        parser = android_device_proof.build_parser()
        bundle_args = parser.parse_args(
            [
                "verify-bundle",
                "--root",
                ".",
                "--bundle",
                "bundle.zip",
                "--llvm-nm",
                "llvm-nm",
                "--llvm-readelf",
                "llvm-readelf",
                "--apksigner",
                "apksigner",
                "--zipalign",
                "zipalign",
            ]
        )
        self.assertFalse(hasattr(bundle_args, "max_age_seconds"))
        create_args = parser.parse_args(
            [
                "create-bundle",
                "--root",
                ".",
                "--proof",
                "proof.json",
                "--output",
                "bundle.zip",
                "--llvm-nm",
                "llvm-nm",
                "--llvm-readelf",
                "llvm-readelf",
                "--apksigner",
                "apksigner",
                "--zipalign",
                "zipalign",
            ]
        )
        self.assertEqual(create_args.max_age_seconds, 86400)

    def test_release_device_metadata_requires_exact_16k_abi_bound_proof(self) -> None:
        proof = {
            "release_candidate_mode": True,
            "device": {
                "kind": "emulator",
                "serial_sha256_prefix": "3" * 12,
                "raw_serial_recorded": False,
                "manufacturer": "Google",
                "model": "Android SDK built for arm64",
                "abi": "arm64-v8a",
                "page_size": 16384,
                "sdk": 35,
                "release": "15",
                "fingerprint_sha256_prefix": "4" * 12,
            },
            "android": {
                "platform": "android-35",
                "min_sdk": 23,
                "target_sdk": 35,
                "ndk": "29.0.14206865",
                "native_page_alignment": 16384,
                "build_tools": "36.0.0",
                "adb_version": "Android Debug Bridge version 1.0.41",
                "apksigner_sha256": "0" * 64,
                "zipalign_sha256": "1" * 64,
            },
        }
        android_device_proof.verify_device_metadata(
            proof,
            expected_device_kind="emulator",
            expected_device_abi="arm64-v8a",
            expected_page_size=16384,
            expected_device_sdk=35,
            require_release_mode=True,
        )

    def test_device_kind_matches_explicit_expectation(self) -> None:
        proof = complete_proof_shape()
        proof["release_candidate_mode"] = True
        for actual_kind, other_kind in (
            ("emulator", "physical"),
            ("physical", "emulator"),
        ):
            with self.subTest(actual_kind=actual_kind):
                proof["device"]["kind"] = actual_kind
                android_device_proof.verify_device_metadata(
                    proof,
                    expected_device_kind=actual_kind,
                    expected_device_abi="arm64-v8a",
                    expected_page_size=16384,
                    expected_device_sdk=35,
                    require_release_mode=True,
                )
                with self.assertRaisesRegex(
                    SystemExit,
                    re.escape(
                        f"expected Android device kind {other_kind}, got {actual_kind}"
                    ),
                ):
                    android_device_proof.verify_device_metadata(
                        proof,
                        expected_device_kind=other_kind,
                        expected_device_abi="arm64-v8a",
                        expected_page_size=16384,
                        expected_device_sdk=35,
                        require_release_mode=True,
                    )

    def test_release_device_metadata_rejects_4k_device(self) -> None:
        proof = {
            "release_candidate_mode": True,
            "device": {
                "kind": "emulator",
                "serial_sha256_prefix": "3" * 12,
                "raw_serial_recorded": False,
                "manufacturer": "Google",
                "model": "Android SDK built for arm64",
                "abi": "arm64-v8a",
                "page_size": 4096,
                "sdk": 35,
                "release": "15",
                "fingerprint_sha256_prefix": "4" * 12,
            },
            "android": {
                "platform": "android-35",
                "min_sdk": 23,
                "target_sdk": 35,
                "ndk": "29.0.14206865",
                "native_page_alignment": 16384,
                "build_tools": "36.0.0",
                "adb_version": "Android Debug Bridge version 1.0.41",
                "apksigner_sha256": "0" * 64,
                "zipalign_sha256": "1" * 64,
            },
        }
        with self.assertRaisesRegex(SystemExit, "expected Android page size 16384"):
            android_device_proof.verify_device_metadata(
                proof,
                expected_device_abi="arm64-v8a",
                expected_page_size=16384,
                expected_device_sdk=35,
                require_release_mode=True,
            )

    def test_device_sdk_is_an_exact_integer_and_matches_expectation(self) -> None:
        proof = {
            "release_candidate_mode": False,
            "device": {
                "kind": "emulator",
                "serial_sha256_prefix": "3" * 12,
                "raw_serial_recorded": False,
                "manufacturer": "Google",
                "model": "Android SDK built for arm64",
                "abi": "arm64-v8a",
                "page_size": 16384,
                "sdk": 35,
                "release": "15",
                "fingerprint_sha256_prefix": "4" * 12,
            },
            "android": {
                "platform": "android-35",
                "min_sdk": 23,
                "target_sdk": 35,
                "ndk": "29.0.14206865",
                "native_page_alignment": 16384,
                "build_tools": "36.0.0",
                "adb_version": "Android Debug Bridge version 1.0.41",
                "apksigner_sha256": "0" * 64,
                "zipalign_sha256": "1" * 64,
            },
        }
        android_device_proof.verify_device_metadata(
            proof, expected_device_sdk=35
        )
        for invalid in (None, True, "35", 35.0):
            with self.subTest(invalid=invalid):
                proof["device"]["sdk"] = invalid
                with self.assertRaisesRegex(SystemExit, "invalid Android device SDK"):
                    android_device_proof.verify_device_metadata(
                        proof, expected_device_sdk=35
                    )
        proof["device"]["sdk"] = 34
        with self.assertRaisesRegex(SystemExit, "expected Android device SDK 35"):
            android_device_proof.verify_device_metadata(
                proof, expected_device_sdk=35
            )

    def test_release_requires_expected_device_and_target_sdk_35(self) -> None:
        proof = {
            "release_candidate_mode": True,
            "device": {
                "kind": "emulator",
                "serial_sha256_prefix": "3" * 12,
                "raw_serial_recorded": False,
                "manufacturer": "Google",
                "model": "Android SDK built for arm64",
                "abi": "arm64-v8a",
                "page_size": 16384,
                "sdk": 35,
                "release": "15",
                "fingerprint_sha256_prefix": "4" * 12,
            },
            "android": {
                "platform": "android-35",
                "min_sdk": 23,
                "target_sdk": 35,
                "ndk": "29.0.14206865",
                "native_page_alignment": 16384,
                "build_tools": "36.0.0",
                "adb_version": "Android Debug Bridge version 1.0.41",
                "apksigner_sha256": "0" * 64,
                "zipalign_sha256": "1" * 64,
            },
        }
        for expected_sdk in (None, 34):
            with self.subTest(expected_sdk=expected_sdk):
                with self.assertRaisesRegex(
                    SystemExit, "release verification requires expected Android device SDK 35"
                ):
                    android_device_proof.verify_device_metadata(
                        proof,
                        expected_device_abi="arm64-v8a",
                        expected_page_size=16384,
                        expected_device_sdk=expected_sdk,
                        require_release_mode=True,
                    )
        proof["android"]["platform"] = "android-34"
        proof["android"]["target_sdk"] = 34
        with self.assertRaisesRegex(SystemExit, "not built against SDK 35"):
            android_device_proof.verify_device_metadata(
                proof,
                expected_device_abi="arm64-v8a",
                expected_page_size=16384,
                expected_device_sdk=35,
                require_release_mode=True,
            )

    def test_release_toolchain_metadata_is_exact_and_bound_to_ndk_tools(self) -> None:
        proof = complete_proof_shape()
        proof["release_candidate_mode"] = True
        android_device_proof.verify_device_metadata(
            proof,
            expected_device_abi="arm64-v8a",
            expected_page_size=16384,
            expected_device_sdk=35,
            require_release_mode=True,
        )
        proof["android"]["ndk"] = "29.1.0"
        with self.assertRaisesRegex(SystemExit, "must use NDK 29.0.14206865"):
            android_device_proof.verify_device_metadata(
                proof,
                expected_device_abi="arm64-v8a",
                expected_page_size=16384,
                expected_device_sdk=35,
                require_release_mode=True,
            )
        proof["android"]["ndk"] = "29.0.14206865"
        proof["android"]["build_tools"] = "not-a-version"
        with self.assertRaisesRegex(SystemExit, "invalid build-tools metadata"):
            android_device_proof.verify_device_metadata(proof)
        proof["android"]["build_tools"] = "36.0.0"
        proof["android"]["adb_version"] = "adb 1.0.41\nsecret"
        with self.assertRaisesRegex(SystemExit, "invalid adb version metadata"):
            android_device_proof.verify_device_metadata(proof)

        ndk = self.root / "ndk" / "29.0.14206865"
        bin_directory = (
            ndk / "toolchains" / "llvm" / "prebuilt" / "darwin-aarch64" / "bin"
        )
        bin_directory.mkdir(parents=True)
        (ndk / "source.properties").write_text(
            "Pkg.Revision = 29.0.14206865\n", encoding="utf-8"
        )
        llvm_nm = bin_directory / "llvm-nm"
        llvm_readelf = bin_directory / "llvm-readelf"
        for tool in (llvm_nm, llvm_readelf):
            tool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            tool.chmod(0o700)
        resolved_nm, resolved_readelf, revision = (
            android_device_proof.verified_ndk_tools(llvm_nm, llvm_readelf)
        )
        self.assertEqual(resolved_nm, llvm_nm.resolve(strict=True))
        self.assertEqual(resolved_readelf, llvm_readelf.resolve(strict=True))
        self.assertEqual(revision, "29.0.14206865")

    def test_device_sdk_cli_type_is_canonical_and_bounded(self) -> None:
        self.assertEqual(android_device_proof.validate_device_sdk("35"), 35)
        for invalid in ("0", "+35", "035", "35.0", "1000"):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(
                    argparse.ArgumentTypeError, "canonical integer between 1 and 999"
                ):
                    android_device_proof.validate_device_sdk(invalid)

    def test_matching_canonical_source_tree_digest_passes(self) -> None:
        digest = android_device_proof.current_source_tree_digest(self.root)
        android_device_proof.verify_source_tree_digest(
            self.root,
            {"proof_source_tree_sha256": digest},
        )

    def test_missing_source_tree_digest_fails_closed(self) -> None:
        with self.assertRaisesRegex(SystemExit, "lacks a valid proof_source_tree_sha256"):
            android_device_proof.verify_source_tree_digest(self.root, {})

    def test_tampered_source_tree_digest_fails_closed(self) -> None:
        with self.assertRaisesRegex(SystemExit, "canonical source-input tree changed"):
            android_device_proof.verify_source_tree_digest(
                self.root,
                {"proof_source_tree_sha256": "0" * 64},
            )

    def test_core_change_invalidates_dirty_diagnostic_proof(self) -> None:
        digest = android_device_proof.current_source_tree_digest(self.root)
        self.core_source.write_text("pub const PROOF_INPUT: &str = \"changed\";\n", encoding="utf-8")
        with self.assertRaisesRegex(SystemExit, "canonical source-input tree changed"):
            android_device_proof.verify_source_tree_digest(
                self.root,
                {"proof_source_tree_sha256": digest},
            )

    def test_ignored_target_proof_does_not_create_a_self_hash_loop(self) -> None:
        digest = android_device_proof.current_source_tree_digest(self.root)
        proof_output = self.root / "target" / "android" / "proof.json"
        proof_output.parent.mkdir(parents=True)
        proof_output.write_text('{"proof_source_tree_sha256":"placeholder"}\n', encoding="utf-8")
        self.assertEqual(digest, android_device_proof.current_source_tree_digest(self.root))

    def test_expected_runtime_inventory_uses_atomic_policy_decision(self) -> None:
        self.assertIn(
            "signedPolicyDecisionIsExactAndFailClosed",
            android_device_proof.EXPECTED_TESTS,
        )
        self.assertNotIn(
            "combineReferenceVectors",
            android_device_proof.EXPECTED_TESTS,
        )
        self.assertEqual(len(android_device_proof.EXPECTED_TESTS), 3)

    def test_producer_and_verifier_source_input_inventories_match(self) -> None:
        producer = (pathlib.Path(__file__).resolve().parent / "android-device-smoke.sh").read_text(
            encoding="utf-8"
        )
        match = re.search(r"source_paths = \{\n(?P<body>.*?)\n\}", producer, re.DOTALL)
        self.assertIsNotNone(match)
        entries = dict(
            re.findall(r'^    "([^"]+)": root / "([^"]+)",$', match.group("body"), re.MULTILINE)
        )
        self.assertEqual(entries, android_device_proof.SOURCE_INPUTS)

    def test_producer_runs_independent_verifier_before_pass_marker(self) -> None:
        producer = (pathlib.Path(__file__).resolve().parent / "android-device-smoke.sh").read_text(
            encoding="utf-8"
        )
        verify = producer.index("artifact/android_device_proof.py verify")
        bundle = producer.index("artifact/android_device_proof.py create-bundle")
        pass_marker = producer.index("ANDROID_DEVICE_RUNTIME_PASS")
        self.assertLess(verify, pass_marker)
        self.assertLess(verify, bundle)
        self.assertLess(bundle, pass_marker)
        self.assertIn('QPERIAPT_ANDROID_EXPECT_SDK=35', producer)
        self.assertIn('"sdk": device_sdk', producer)
        self.assertIn('--expected-device-sdk "$DEVICE_SDK"', producer)

    def test_temporary_keystore_is_private_and_cleaned_on_every_exit(self) -> None:
        producer = (
            pathlib.Path(__file__).resolve().parent / "android-device-smoke.sh"
        ).read_text(encoding="utf-8")
        self.assertIn("umask 077", producer)
        self.assertIn('chmod 700 "$WORK" "$DIST"', producer)
        keystore_assignment = producer.index(
            'KEYSTORE="$WORK/qperiapt-android-smoke.p12"'
        )
        exit_trap = producer.index("trap cleanup_exit EXIT")
        keytool = producer.index("keytool -genkeypair")
        signer = producer.index('"$APKSIGNER" sign')
        eager_removal = producer.index('rm -f -- "$KEYSTORE"', signer)
        self.assertLess(keystore_assignment, exit_trap)
        self.assertLess(exit_trap, keytool)
        self.assertLess(keytool, eager_removal)
        self.assertIn('rm -f -- "$KEYSTORE"', producer[keystore_assignment:keytool])
        self.assertIn("stop_emulator_process()", producer)
        self.assertIn('"$cleanup_wait_count" -lt 15', producer)
        self.assertIn('"$cleanup_wait_count" -lt 5', producer)
        self.assertNotIn("|| :", producer)
        self.assertNotIn("|| true", producer)
        self.assertNotIn("qperiapt-android-smoke.p12", "\n".join(android_device_proof.BUNDLE_FILE_PATHS.values()))

    def test_producer_captures_only_the_smoke_log_tag(self) -> None:
        producer = (
            pathlib.Path(__file__).resolve().parent / "android-device-smoke.sh"
        ).read_text(encoding="utf-8")
        self.assertIn("capture_app_logcat()", producer)
        self.assertIn("logcat -d -v tag -s 'QPeriaptSmoke:*' '*:S'", producer)
        self.assertNotIn('"$ADB" -s "$SERIAL" logcat -d >', producer)

    def test_result_verifier_rejects_unrelated_logcat_data(self) -> None:
        run_id = "a" * 32
        result_txt = self.root / "result.txt"
        result_json = self.root / "result.json"
        logcat = self.root / "logcat.txt"
        result_txt.write_text(
            android_device_proof.expected_marker(run_id) + "\n", encoding="utf-8"
        )
        result_json.write_text(
            '{"schema":1,"status":"pass","run_id":"'
            + run_id
            + '","test_count":3,"passed_tests":['
            '"runtimeMetadataMatches",'
            '"signedPolicyDecisionIsExactAndFailClosed",'
            '"osRandomPolicyRoundtripAndWipes"]}\n',
            encoding="utf-8",
        )
        paths = {
            "result_txt": result_txt,
            "result_json": result_json,
            "logcat": logcat,
        }
        logcat.write_text("I/QPeriaptSmoke: verified\n", encoding="utf-8")
        android_device_proof.verify_result_files(paths, run_id)
        logcat.write_text(
            "--------- beginning of main\nI/QPeriaptSmoke( 123): verified\n",
            encoding="utf-8",
        )
        android_device_proof.verify_result_files(paths, run_id)
        logcat.write_text(
            "I/QPeriaptSmoke: verified\nI/OtherApplication: private data\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(SystemExit, "outside the QPeriaptSmoke tag"):
            android_device_proof.verify_result_files(paths, run_id)
        logcat.write_text(
            "I/OtherApplication: mentions QPeriaptSmoke but is unrelated\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(SystemExit, "outside the QPeriaptSmoke tag"):
            android_device_proof.verify_result_files(paths, run_id)

    def test_private_directory_canonicalization_accepts_only_aliases_above_leaf(self) -> None:
        physical_parent = self.root / "physical-parent"
        private_directory = physical_parent / "private"
        private_directory.mkdir(parents=True, mode=0o700)
        private_directory.chmod(0o700)
        alias_parent = self.root / "alias-parent"
        try:
            alias_parent.symlink_to(physical_parent, target_is_directory=True)
        except OSError as exc:
            self.skipTest(f"platform cannot create a directory symlink: {exc}")

        resolved = android_device_proof.canonical_private_directory(
            alias_parent / "private", "test private directory"
        )
        self.assertEqual(resolved, private_directory.resolve(strict=True))
        self.assertTrue(stat.S_ISDIR(resolved.lstat().st_mode))

        leaf_alias = self.root / "private-leaf-alias"
        leaf_alias.symlink_to(private_directory, target_is_directory=True)
        with self.assertRaisesRegex(SystemExit, "must be a non-symlink directory"):
            android_device_proof.canonical_private_directory(
                leaf_alias, "test private directory"
            )

    def test_bundle_manifest_binds_exact_fixed_file_set(self) -> None:
        bundle_root = self.root / "bundle"
        proof = complete_proof_shape()
        payloads = {
            key: (
                android_device_proof.canonical_json(proof)
                if key == "proof"
                else f"evidence-{key}\n".encode("utf-8")
            )
            for key in android_device_proof.BUNDLE_FILE_PATHS
        }
        records = {}
        for key, relative in android_device_proof.BUNDLE_FILE_PATHS.items():
            path = bundle_root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payloads[key])
            records[key] = {
                "bytes": len(payloads[key]),
                "path": relative,
                "sha256": android_device_proof.sha256_bytes(payloads[key]),
            }
        manifest = {
            "schema_version": android_device_proof.BUNDLE_SCHEMA_VERSION,
            "kind": android_device_proof.BUNDLE_KIND,
            "source_date_epoch": 1_700_000_000,
            "git_commit": proof["git_commit"],
            "run_id": proof["run_id"],
            "release_candidate_mode": False,
            "device": {
                key: proof["device"][key]
                for key in ("kind", "abi", "page_size", "sdk")
            },
            "raw_serial_recorded": False,
            "files": records,
        }
        selected, parsed_proof = android_device_proof.verify_bundle_manifest(
            bundle_root,
            manifest,
            archive_mtime=1_700_000_000,
        )
        self.assertEqual(set(android_device_proof.BUNDLE_FILE_PATHS), set(selected))
        self.assertEqual(proof, parsed_proof)
        self.assertNotIn("keystore", "\n".join(android_device_proof.BUNDLE_FILE_PATHS.values()))

        missing_sdk = copy.deepcopy(manifest)
        del missing_sdk["device"]["sdk"]
        with self.assertRaisesRegex(SystemExit, "bundle device fields differ"):
            android_device_proof.verify_bundle_manifest(
                bundle_root,
                missing_sdk,
                archive_mtime=1_700_000_000,
            )

        wrong_sdk = copy.deepcopy(manifest)
        wrong_sdk["device"]["sdk"] = 34
        with self.assertRaisesRegex(SystemExit, "device metadata differs from proof"):
            android_device_proof.verify_bundle_manifest(
                bundle_root,
                wrong_sdk,
                archive_mtime=1_700_000_000,
            )

        extra_device_field = copy.deepcopy(manifest)
        extra_device_field["device"]["model"] = "unbound"
        with self.assertRaisesRegex(SystemExit, "bundle device fields differ"):
            android_device_proof.verify_bundle_manifest(
                bundle_root,
                extra_device_field,
                archive_mtime=1_700_000_000,
            )

        tampered_proof = copy.deepcopy(proof)
        tampered_proof["device"]["sdk"] = 34
        proof_path = selected["proof"]
        proof_path.write_bytes(android_device_proof.canonical_json(tampered_proof))
        cross_tamper = copy.deepcopy(manifest)
        cross_tamper["files"]["proof"] = android_device_proof.bundle_file_record(
            proof_path,
            android_device_proof.BUNDLE_FILE_PATHS["proof"],
        )
        with self.assertRaisesRegex(SystemExit, "device metadata differs from proof"):
            android_device_proof.verify_bundle_manifest(
                bundle_root,
                cross_tamper,
                archive_mtime=1_700_000_000,
            )
        proof_path.write_bytes(android_device_proof.canonical_json(proof))

        selected["logcat"].write_text("tampered\n", encoding="utf-8")
        with self.assertRaisesRegex(SystemExit, "bundled evidence bytes differ"):
            android_device_proof.verify_bundle_manifest(
                bundle_root,
                manifest,
                archive_mtime=1_700_000_000,
            )

    def test_proof_path_inventory_rejects_extra_dependencies(self) -> None:
        paths = {key: f"target/{key}" for key in android_device_proof.PROOF_PATH_KEYS}
        android_device_proof.proof_path_fields({"paths": paths})
        paths["keystore"] = "target/debug.keystore"
        with self.assertRaisesRegex(SystemExit, "path fields differ"):
            android_device_proof.proof_path_fields({"paths": paths})


if __name__ == "__main__":
    unittest.main()
