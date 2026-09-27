from __future__ import annotations

import copy
import os
import pathlib
import subprocess
import tempfile
import unittest
from unittest import mock

import apple_device_proof as proof
import apple_sdk_device_contract as contract
import apple_toolchain
import test_apple_device_proof as legacy_tests
from bounded_process import BoundedResult
from test_apple_toolchain import AppleToolchainFixture


class AppleSDKDeviceIdentityTests(unittest.TestCase):
    def test_marker_cli_requires_explicit_sdk_selection(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            marker = pathlib.Path(temporary) / "marker.txt"
            marker.write_text(contract.sdk_marker("c" * 32) + "\n")
            command = ["sh", "artifact/python-run.sh", "artifact/apple_device_proof.py",
                       "verify-marker", "--path", str(marker), "--run-id", "c" * 32]
            for flags, status in (([], 1), (["--capture-profile", "sdk-alpha1"], 0),
                                  (["--capture-profile", "abi3"], 2)):
                result = subprocess.run(command + flags, cwd=root, capture_output=True,
                                        text=True, timeout=20, check=False)
                with self.subTest(flags=flags):
                    self.assertEqual(result.returncode, status, result.stderr)
                    if status == 0:
                        self.assertEqual(result.stdout, "APPLE_DEVICE_MARKER_PASS profile=sdk-alpha1\n")
                    else:
                        self.assertNotIn("MARKER_PASS", result.stdout)

    def test_profiles_cannot_admit_each_others_markers(self):
        run_id = "a" * 32
        for profile in contract.CAPTURE_PROFILES:
            marker = proof.expected_marker(run_id, profile)
            other = proof.expected_marker(run_id, "legacy" if profile == "sdk-alpha1" else "sdk-alpha1")
            proof.require_marker_text(marker + "\n", pathlib.Path("marker"), "test", run_id, profile)
            for text in (other, marker + "\n" + other, marker + "\n" + marker,
                         marker + "\nQPERIAPT_DEVICE_FAIL failure",
                         marker + "\n" + proof.expected_marker("b" * 32, profile)):
                with self.subTest(profile=profile, text=text), self.assertRaises(SystemExit):
                    proof.require_marker_text(text, pathlib.Path("marker"), "test", run_id, profile)

    def test_sdk_marker_binds_version_abi_extension_and_all_workloads(self):
        run_id = "1" * 32
        marker = contract.sdk_marker(run_id)
        for old, new in ((contract.SDK_VERSION, "0.1.5"), ("abi=2", "abi=3"),
                         ("extension=1", "extension=0"),
                         ("," + contract.SDK_TESTS[-1], ""), (run_id, "2" * 32)):
            with self.subTest(old=old), self.assertRaises(SystemExit):
                proof.require_marker_text(marker.replace(old, new), pathlib.Path("marker"),
                                          "test", run_id, contract.SDK_PROFILE)

    def test_root_identity_is_closed_and_never_selected_by_the_proof(self):
        for matrix in (False, True):
            fields = proof.MATRIX_PROOF_FIELDS if matrix else proof.APPLE_PROOF_FIELDS
            sdk = {key: None for key in fields} | proof.capture_identity("sdk-alpha1", matrix=matrix)
            legacy = {key: None for key in fields} | proof.capture_identity("legacy", matrix=matrix)
            proof.verify_capture_identity(sdk, "sdk-alpha1", matrix=matrix)
            proof.verify_capture_identity(legacy, "legacy", matrix=matrix)
            for value, selected in ((sdk, "legacy"), (legacy, "sdk-alpha1")):
                with self.subTest(matrix=matrix, selected=selected), self.assertRaises(SystemExit):
                    proof.verify_capture_identity(value, selected, matrix=matrix)
            for key, value in (("abi_major", 3), ("extension_revision", True),
                               ("tests", list(contract.SDK_TESTS[:-1])),
                               ("policy_update_storage", "durable"), ("extra", 1)):
                changed = copy.deepcopy(sdk)
                changed["sdk"][key] = value
                with self.subTest(key=key, matrix=matrix), self.assertRaises(SystemExit):
                    proof.verify_capture_identity(changed, "sdk-alpha1", matrix=matrix)
            for schema in (True, 1.0, 4, 5):
                changed = copy.deepcopy(sdk)
                changed["schema_version"] = schema
                with self.subTest(schema=schema), self.assertRaises(SystemExit):
                    proof.verify_capture_identity(changed, "sdk-alpha1", matrix=matrix)

    def test_sdk_hashes_require_and_bind_the_workload_wrapper_and_vectors(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            for relative in proof.source_inputs("sdk-alpha1").values():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(relative + "\n")
            sdk = {"source_inputs_sha256": proof.source_hashes(root, "sdk-alpha1")}
            proof.verify_source_hashes(root, sdk, "sdk-alpha1")
            legacy = {"source_inputs_sha256": proof.source_hashes(root)}
            with self.assertRaisesRegex(SystemExit, "missing fields"):
                proof.verify_source_hashes(root, legacy, "sdk-alpha1")
            for key in ("apple_sdk_device_workload", "swift_sdk_binding", "sdk_revocation_vector"):
                path = root / contract.SDK_SOURCE_INPUTS[key]
                original = path.read_bytes()
                path.write_bytes(original + b"changed\n")
                with self.subTest(key=key), self.assertRaisesRegex(SystemExit, key):
                    proof.verify_source_hashes(root, sdk, "sdk-alpha1")
                path.write_bytes(original)

    def test_sdk_device_query_ignores_ambient_tool_selection(self):
        with (mock.patch.dict(os.environ, {"DEVELOPER_DIR": "/tmp/other", "PATH": "/tmp/other"}),
              mock.patch.object(proof, "capture_stdout", return_value=BoundedResult(0, b"{}")) as call):
            proof.run_devicectl_json(["list", "devices"], "fixture", "sdk-alpha1")
        self.assertEqual(call.call_args.args[0][:2], ["/usr/bin/xcrun", "devicectl"])
        self.assertEqual(call.call_args.kwargs["environment"], {
            "DEVELOPER_DIR": str(apple_toolchain.SDK_DEVELOPER_DIR),
            "PATH": apple_toolchain.COMMAND_ENVIRONMENT_PATH, "LC_ALL": "C", "LANG": "C",
        })

    def test_toolchain_mismatch_is_rejected_before_receipt_or_device_io(self):
        with mock.patch.object(apple_toolchain, "verify_sdk_receipt") as verify:
            for selected in (str(apple_toolchain.FIXED_DEVELOPER_DIR), "/tmp/Xcode.app/Contents/Developer"):
                with self.subTest(selected=selected), self.assertRaises(SystemExit):
                    proof._verify_fixed_apple_toolchain_receipt(
                        {}, selected, selection_label="test", capture_profile="sdk-alpha1")
            verify.assert_not_called()
        for selected in ("sdk", "abi3", "", None):
            with self.subTest(selected=selected), self.assertRaises(ValueError):
                proof.capture_identity(selected)

    def test_matrix_profiles_keep_distinct_transport_contracts(self):
        self.assertEqual(proof.matrix_transports("legacy"), {"ipad": "wired", "iphone": "localNetwork"})
        fixture = legacy_tests.AppleReleaseMatrixPolicyTests()
        fixture.setUp()
        self.addCleanup(fixture.tearDown)
        matrix, child_snapshots, children = fixture.matrix_snapshot()
        matrix.value.update(proof.capture_identity("sdk-alpha1", matrix=True))
        for label, child in children.items():
            child["device"]["transport"] = "wired"
            value = {key: None for key in proof.APPLE_PROOF_FIELDS} | child
            value.update(proof.capture_identity("sdk-alpha1"))
            child_snapshots[label].value.update(value)
        for entry in matrix.value["devices"]:
            entry["transport"] = "wired"

        def verify_child(_root, snapshot, *_args, **kwargs):
            self.assertEqual(kwargs["capture_profile"], "sdk-alpha1")
            self.assertEqual(kwargs["expected_transport"], "wired")
            proof.verify_capture_identity(snapshot.value, kwargs["capture_profile"])
            return snapshot.value

        with (mock.patch.object(proof, "verify_git_provenance"),
              mock.patch.object(proof, "verify_source_tree_digest"),
              mock.patch.object(proof, "verify_source_hashes"),
              mock.patch.object(proof, "_require_no_extended_acl"),
              mock.patch.object(proof, "load_apple_json_snapshot",
                                side_effect=lambda path, _label: child_snapshots[path.parent.name]),
              mock.patch.object(proof, "verify_proof_snapshot", side_effect=verify_child)):
            proof.verify_matrix_snapshot(fixture.root, matrix, fixture.matrix_root, 86400, True, "sdk-alpha1")
            matrix.value["devices"][1]["transport"] = "localNetwork"
            with self.assertRaisesRegex(SystemExit, "requires wired transport"):
                proof.verify_matrix_snapshot(fixture.root, matrix, fixture.matrix_root, 86400, True, "sdk-alpha1")
            matrix.value["devices"][1]["transport"] = "wired"
            child_snapshots["iphone"].value["schema_version"] = proof.SCHEMA_VERSION
            with self.assertRaisesRegex(SystemExit, "schema must be 1"):
                proof.verify_matrix_snapshot(fixture.root, matrix, fixture.matrix_root, 86400, True, "sdk-alpha1")


class AppleSDKToolchainReceiptTests(AppleToolchainFixture):
    def setUp(self):
        super().setUp()
        sdk_app = self.applications / "Xcode.app"
        self.app.rename(sdk_app)
        self.app = sdk_app
        self.developer_dir = self.app / "Contents/Developer"
        patch = mock.patch.object(apple_toolchain, "SDK_DEVELOPER_DIR", self.developer_dir)
        patch.start()
        self.addCleanup(patch.stop)

    def _command_result(self, argv, **kwargs):
        result = super()._command_result(argv, **kwargs)
        result = result.replace("Authority=Software Signing", "Authority=Apple Mac OS Application Signing")
        result = result.replace("Authority=Apple Code Signing Certification Authority",
                                "Authority=Apple Worldwide Developer Relations Certification Authority")
        return result.replace("source=Apple System", "source=Mac App Store")

    def test_sdk_receipt_roundtrip_and_cross_profile_refusal(self):
        with mock.patch.object(apple_toolchain, "_run_command", side_effect=self._command_result):
            receipt = apple_toolchain.capture_sdk_receipt()
            self.assertEqual(apple_toolchain.verify_sdk_receipt(receipt), receipt)
            with self.assertRaisesRegex(apple_toolchain.AppleToolchainError, "fixed Apple"):
                apple_toolchain.verify_receipt(receipt)
            output = self.root / "private" / "receipt.json"
            output.parent.mkdir(mode=0o700)
            apple_toolchain._write_new_private_json(output, receipt, capture_profile="sdk-alpha1")
            self.assertEqual(apple_toolchain._load_private_receipt(output, capture_profile="sdk-alpha1"), receipt)
            with self.assertRaises(apple_toolchain.AppleToolchainError):
                apple_toolchain._load_private_receipt(output)
            native = self.app / apple_toolchain.ARTIFACT_PATHS["xcodebuild"]
            native.write_bytes(b"changed native tool\n")
            with self.assertRaisesRegex(apple_toolchain.AppleToolchainError, "changed"):
                apple_toolchain.verify_sdk_receipt(receipt)

    def test_sdk_capture_keeps_apple_signature_and_directory_checks(self):
        def wrong_signer(argv, **kwargs):
            return self._command_result(argv, **kwargs).replace("59GAB85EFG", "WRONGTEAM1")
        with (mock.patch.object(apple_toolchain, "_run_command", side_effect=wrong_signer),
              self.assertRaises(apple_toolchain.AppleToolchainError)):
            apple_toolchain.capture_sdk_receipt()
        self.app.chmod(0o777)
        with (mock.patch.object(apple_toolchain, "_run_command") as run,
              self.assertRaises(apple_toolchain.AppleToolchainError)):
            apple_toolchain.capture_sdk_receipt()
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
