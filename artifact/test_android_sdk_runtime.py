"""SDK ART evidence contract regressions; synthetic fixtures are not runtime evidence.

Only SDK tool execution is simulated. Source provenance, containers, manifests,
workload selection, exported closure, and all rejection paths use real validators.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import unittest
from unittest import mock
import zipfile

import android_agp_consumer as consumer
import android_agp_consumer_contract as contract
import android_agp_test_fixture as fixture
import android_device_proof as runtime
from test_android_elf import zip_bytes
from test_android_agp_consumer import projection


class SDKProjectionTests(unittest.TestCase):
    def test_scope_requires_a_caller_selected_architecture_and_exact_types(self):
        for profile in contract.SDK_PROFILES:
            for abi in ("arm64-v8a", "x86_64"):
                value = projection(profile)
                value["runtime_target"] = contract.runtime_target(profile, abi)
                expected = dict(expected_profile=profile, expected_aar_sha256="b" * 64,
                    expected_aar_manifest_sha256="b" * 64, expected_source_commit="c" * 40,
                    expected_device_abi=abi)
                self.assertEqual(contract.validate_profile_projection(value, **expected), value)
                for field, other in (("kind", "physical"), ("abi", "x86_64" if abi == "arm64-v8a" else "arm64-v8a"),
                                     ("sdk", 35.0), ("sdk", True), ("sdk", 36),
                                     ("page_size", 4096), ("page_size", 16384.0)):
                    changed = copy.deepcopy(value)
                    changed["runtime_target"][field] = other
                    with self.subTest(profile=profile, abi=abi, field=field, other=other), self.assertRaises(contract.AndroidAgpConsumerError):
                        contract.validate_profile_projection(changed, **expected)
                for absent in (None, "", "armeabi-v7a"):
                    with self.assertRaisesRegex(contract.AndroidAgpConsumerError, "explicit"):
                        contract.validate_profile_projection(value, **{**expected, "expected_device_abi": absent})
        with self.assertRaisesRegex(contract.AndroidAgpConsumerError, "legacy AGP target"):
            contract.runtime_target("agp_full_release", "x86_64")

    def test_workloads_sources_and_abi_contracts_remain_separate(self):
        legacy = runtime.source_inputs()
        self.assertEqual(legacy, runtime.SOURCE_INPUTS)
        for profile in contract.SDK_PROFILES:
            spec = contract.profile_spec(profile)
            sources = consumer.compiled_sources(profile)
            self.assertFalse(any("/smoke/full/" in path or "/smoke/minimal/" in path for path in sources))
            self.assertEqual(any(path.endswith("QPeriaptSDKWorkload.java") for path in sources), spec.flavor == "Full")
            result_profile = runtime.RuntimeResultProfile(profile)
            self.assertEqual(runtime.result_tests(result_profile), list(contract.PROFILE_TESTS[profile]))
            self.assertIn("android_sdk", runtime.source_inputs(result_profile))
            self.assertNotEqual(runtime.source_inputs(result_profile)["c_abi_contract"], legacy["c_abi_contract"])
            self.assertNotEqual(spec.proof_kind, contract.PROOF_KIND)
            self.assertNotEqual(spec.build_kind, contract.BUILD_KIND)
        self.assertEqual(contract.PROFILES, {"agp_full_release", "agp_minimal_release"})


class SDKRuntimeExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        cls.pairs, cls.exports, cls.projections, cls.receipt_identity = {}, {}, {}, {}
        with mock.patch.object(consumer, "run_sdk_tool", side_effect=fixture.sdk_runner):
            for abi in ("arm64-v8a", "x86_64"):
                pair = fixture.create_agp_fixture_pair(cls.directory / abi, sdk_profile=True, device_abi=abi)
                cls.pairs[abi] = pair
                for name, profile in pair.profiles.items():
                    destination = cls.directory / (abi + "-" + name)
                    source = profile.root / json.loads(profile.proof.read_bytes())["paths"]["adb_isolation_emulator_pre_exec"]
                    before = (stat.S_IMODE(source.stat().st_mode), fixture.digest(source))
                    previous_umask = os.umask(0o077) # The real collector's private creation policy.
                    try:
                        cls.projections[abi, name] = consumer.export_completed_profile(
                            profile.root, profile.proof, destination, sdk=profile.sdk, **profile.expected)
                    finally:
                        os.umask(previous_umask)
                    cls.receipt_identity[abi, name] = (before, (stat.S_IMODE(source.stat().st_mode), fixture.digest(source)))
                    cls.exports[abi, name] = destination
                # Replaying the portable closure cannot fall back to original run or AAR paths.
                (pair.root / "target" / runtime.ANDROID_RUNS_ROOT_LEAF).rename(pair.root / "target/retired-runs")
                pair.aar.parent.rename(pair.root / "target/retired-aar")

    def verify(self, abi, name, directory, **overrides):
        profile = self.pairs[abi].profiles[name]
        with mock.patch.object(consumer, "run_sdk_tool", side_effect=fixture.sdk_runner):
            return consumer.verify_exported_profile(profile.root, directory, sdk=profile.sdk,
                                                     **{**profile.expected, **overrides})

    def test_both_profiles_and_architectures_replay_without_original_runs(self):
        for (abi, name), directory in self.exports.items():
            value = self.verify(abi, name, directory)
            self.assertEqual(value, self.projections[abi, name])
            self.assertEqual(value["runtime_target"], {"kind": "emulator", "abi": abi, "sdk": 35, "page_size": 16384})
            with self.assertRaisesRegex(contract.AndroidAgpConsumerError, "device ABI"):
                self.verify(abi, name, directory, expected_device_abi="x86_64" if abi == "arm64-v8a" else "arm64-v8a")
            with self.assertRaisesRegex(contract.AndroidAgpConsumerError, "explicit"):
                self.verify(abi, name, directory, expected_device_abi=None)

    def test_export_uses_portable_copy_modes_without_changing_private_receipts(self):
        for key, directory in self.exports.items():
            with self.subTest(profile=key):
                before, after = self.receipt_identity[key]
                self.assertEqual(before, after)
                self.assertEqual(after[0], 0o600)
                self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
                for path in directory.rglob("*"):
                    expected = 0o700 if path.is_dir() else 0o644
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), expected, str(path))

    def test_mutated_sdk_evidence_cannot_masquerade_as_old_or_current_evidence(self):
        name, abi = "agp_sdk_full_release", "x86_64"
        cases = {
            "old_proof_kind": "schema", "old_build_kind": "schema",
            "old_contract": "contract path", "abi3": "ABI major",
            "library_rename": "runtime library", "missing_sdk_source": "source hash",
            "old_workload": "passed_tests", "old_jni_dump": "registration contract",
            "compressed_native": "uncompressed", "old_manifest": "schema",
        }
        for mutation, message in cases.items():
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary) / "evidence"
                shutil.copytree(self.exports[abi, name], directory)
                proof_path = directory / "proof.json"
                receipt_path = directory / "build/receipt.json"
                proof, receipt = json.loads(proof_path.read_bytes()), json.loads(receipt_path.read_bytes())
                paths = {key: directory / "runtime" / value for key, value in consumer.profile_bundle_paths(proof, name).items()}
                expected = {}
                if mutation == "old_proof_kind":
                    proof["kind"] = contract.PROOF_KIND
                elif mutation == "old_build_kind":
                    receipt["kind"] = contract.BUILD_KIND
                elif mutation == "old_contract":
                    proof["abi"]["contract_path"] = runtime.SOURCE_INPUTS["c_abi_contract"]
                elif mutation == "abi3":
                    proof["abi"]["major"] = 3
                elif mutation == "library_rename":
                    proof["abi"]["runtime_library"] = "libq_periapt_ffi_abi3.so"
                elif mutation == "missing_sdk_source":
                    del proof["source_hashes"]["android_sdk_sha256"]
                elif mutation == "old_workload":
                    proof["result"]["passed_tests"] = list(contract.PROFILE_TESTS["agp_full_release"])
                elif mutation == "old_jni_dump":
                    dump = directory / "build/dexdump.txt"
                    fixture.write(dump, fixture.DEX_DUMP.encode())
                    receipt["files"]["dexdump"] = fixture.record(dump)
                elif mutation == "compressed_native":
                    apk = paths["smoke_apk"]
                    fixture.write(apk, zip_bytes(consumer._apk_entries(apk), compression=zipfile.ZIP_DEFLATED))
                    proof["artifacts"]["smoke_apk_sha256"] = fixture.digest(apk)
                elif mutation == "old_manifest":
                    manifest = paths["aar_manifest"]
                    value = json.loads(manifest.read_bytes())
                    value["schema_version"] = 4
                    fixture.write(manifest, fixture.json_bytes(value))
                    receipt["aar_manifest_sha256"] = proof["artifacts"]["aar_manifest_sha256"] = fixture.digest(manifest)
                    expected["expected_aar_manifest_sha256"] = fixture.digest(manifest)
                fixture.write(receipt_path, fixture.json_bytes(receipt))
                proof["consumer"]["build_receipt"].update(sha256=fixture.digest(receipt_path), bytes=receipt_path.stat().st_size)
                fixture.write(proof_path, fixture.json_bytes(proof))
                with self.assertRaisesRegex(contract.AndroidAgpConsumerError, message):
                    self.verify(abi, name, directory, **expected)


if __name__ == "__main__":
    unittest.main()
