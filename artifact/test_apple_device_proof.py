#!/usr/bin/env python3

from __future__ import annotations

import datetime as dt
import hashlib
import os
import pathlib
import subprocess
import tempfile
import unittest
from unittest import mock

import apple_device_proof
import apple_proof_contract
import proof_manifest
from bounded_process import BoundedResult
from evidence_io import FileSnapshot, JsonObjectSnapshot


class AppleDeviceProofSourceBindingTests(unittest.TestCase):
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
        self.core_source.write_text('pub const PROOF_INPUT: &str = "original";\n', encoding="utf-8")
        subprocess.run(["git", "-C", str(self.root), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.root), "commit", "-qm", "fixture"], check=True)
        self.commit = apple_device_proof.git_commit(self.root)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_schema_v4_is_required(self) -> None:
        self.assertEqual(
            apple_device_proof.SCHEMA_VERSION,
            apple_proof_contract.APPLE_DEVICE_PROOF_SCHEMA_VERSION,
        )
        self.assertEqual(
            apple_device_proof.MATRIX_SCHEMA_VERSION,
            apple_proof_contract.APPLE_MATRIX_PROOF_SCHEMA_VERSION,
        )
        self.assertEqual(
            proof_manifest.APPLE_DEVICE_PROOF_SCHEMA_VERSION,
            apple_proof_contract.APPLE_DEVICE_PROOF_SCHEMA_VERSION,
        )
        self.assertEqual(
            proof_manifest.APPLE_MATRIX_PROOF_SCHEMA_VERSION,
            apple_proof_contract.APPLE_MATRIX_PROOF_SCHEMA_VERSION,
        )
        with self.assertRaisesRegex(SystemExit, "Apple device proof schema must be 4"):
            apple_device_proof.verify_proof_schema({"schema_version": 3}, "Apple device proof")
        apple_device_proof.verify_proof_schema({"schema_version": 4}, "Apple device proof")

    def test_matching_canonical_source_tree_digest_passes(self) -> None:
        digest = apple_device_proof.current_source_tree_digest(self.root)
        apple_device_proof.verify_source_tree_digest(
            self.root,
            {"proof_source_tree_sha256": digest},
            "Apple device proof",
        )

    def test_missing_source_tree_digest_fails_closed(self) -> None:
        with self.assertRaisesRegex(SystemExit, "lacks a valid proof_source_tree_sha256"):
            apple_device_proof.verify_source_tree_digest(self.root, {}, "Apple device proof")

    def test_tampered_source_tree_digest_fails_closed(self) -> None:
        with self.assertRaisesRegex(SystemExit, "canonical source-input tree changed since Apple device proof"):
            apple_device_proof.verify_source_tree_digest(
                self.root,
                {"proof_source_tree_sha256": "0" * 64},
                "Apple device proof",
            )

    def test_core_change_invalidates_proof(self) -> None:
        digest = apple_device_proof.current_source_tree_digest(self.root)
        self.core_source.write_text('pub const PROOF_INPUT: &str = "changed";\n', encoding="utf-8")
        with self.assertRaisesRegex(SystemExit, "canonical source-input tree changed since Apple device proof"):
            apple_device_proof.verify_source_tree_digest(
                self.root,
                {"proof_source_tree_sha256": digest},
                "Apple device proof",
            )

    def test_ignored_target_output_does_not_create_self_hash_loop(self) -> None:
        digest = apple_device_proof.current_source_tree_digest(self.root)
        proof_output = self.root / "target" / "apple-device" / "proof.json"
        proof_output.parent.mkdir(parents=True)
        proof_output.write_text('{"proof_source_tree_sha256":"placeholder"}\n', encoding="utf-8")
        self.assertEqual(digest, apple_device_proof.current_source_tree_digest(self.root))

    def test_pre_emit_recheck_rejects_source_change_after_freeze(self) -> None:
        commit, digest = apple_device_proof.freeze_source_snapshot(self.root)
        (self.root / "tracked.txt").write_text("changed during device run\n", encoding="utf-8")
        with self.assertRaisesRegex(SystemExit, "canonical source-input tree changed while Apple device proof was running"):
            apple_device_proof.require_source_snapshot_unchanged(
                self.root,
                commit,
                digest,
                "Apple device proof was running",
            )

    def test_pre_emit_recheck_rejects_commit_change_after_freeze(self) -> None:
        commit, digest = apple_device_proof.freeze_source_snapshot(self.root)
        subprocess.run(["git", "-C", str(self.root), "commit", "--allow-empty", "-qm", "advance"], check=True)
        with self.assertRaisesRegex(SystemExit, "git commit changed while Apple device proof was running"):
            apple_device_proof.require_source_snapshot_unchanged(
                self.root,
                commit,
                digest,
                "Apple device proof was running",
            )

    def test_allow_dirty_never_bypasses_commit_binding(self) -> None:
        (self.root / "untracked.txt").write_text("diagnostic\n", encoding="utf-8")
        with self.assertRaisesRegex(SystemExit, "commit provenance failed"):
            apple_device_proof.verify_git_provenance(
                self.root,
                {"git_commit": "0" * 40, "source_tree_dirty": True},
                allow_dirty_proof=True,
                label="Apple device proof",
            )

    def test_evidence_only_successor_commit_can_bind_release_manifest(self) -> None:
        proof_commit = self.commit
        results = self.root / "artifact" / "results.json"
        results.parent.mkdir()
        results.write_text('{"selected":"proof"}\n', encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(self.root), "add", "artifact/results.json"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(self.root), "commit", "-qm", "bind evidence"],
            check=True,
        )
        apple_device_proof.verify_git_provenance(
            self.root,
            {"git_commit": proof_commit, "source_tree_dirty": False},
            allow_dirty_proof=False,
            label="Apple device proof",
        )

    def test_strict_verification_rejects_current_dirty_tree(self) -> None:
        (self.root / "untracked.txt").write_text("diagnostic\n", encoding="utf-8")
        with self.assertRaisesRegex(SystemExit, "current source tree is dirty"):
            apple_device_proof.verify_git_provenance(
                self.root,
                {"git_commit": self.commit, "source_tree_dirty": False},
                allow_dirty_proof=False,
                label="Apple device proof",
            )

    def test_diagnostic_verification_accepts_current_bound_dirty_tree(self) -> None:
        (self.root / "untracked.txt").write_text("diagnostic\n", encoding="utf-8")
        digest = apple_device_proof.current_source_tree_digest(self.root)
        proof = {
            "git_commit": self.commit,
            "source_tree_dirty": True,
            "proof_source_tree_sha256": digest,
        }
        apple_device_proof.verify_git_provenance(
            self.root,
            proof,
            allow_dirty_proof=True,
            label="Apple device proof",
        )
        apple_device_proof.verify_source_tree_digest(self.root, proof, "Apple device proof")

    def test_allow_dirty_never_bypasses_source_digest_binding(self) -> None:
        digest = apple_device_proof.current_source_tree_digest(self.root)
        (self.root / "untracked.txt").write_text("diagnostic\n", encoding="utf-8")
        apple_device_proof.verify_git_provenance(
            self.root,
            {"git_commit": self.commit, "source_tree_dirty": True},
            allow_dirty_proof=True,
            label="Apple device proof",
        )
        with self.assertRaisesRegex(SystemExit, "canonical source-input tree changed since Apple device proof"):
            apple_device_proof.verify_source_tree_digest(
                self.root,
                {"proof_source_tree_sha256": digest},
                "Apple device proof",
            )

    def test_device_id_digest_is_recomputed(self) -> None:
        device_id = "00000000-0000000000000000"
        apple_device_proof.verify_device_id_digest(
            {
                "device_id": device_id,
                "device_id_sha256": hashlib.sha256(device_id.encode()).hexdigest(),
            },
            "Apple device proof",
        )
        with self.assertRaisesRegex(SystemExit, "does not bind device_id"):
            apple_device_proof.verify_device_id_digest(
                {"device_id": device_id, "device_id_sha256": "0" * 64},
                "Apple device proof",
            )

    def test_devicectl_app_listing_is_exact_and_fail_closed(self) -> None:
        bundle_id = "dev.qperiapt.DeviceRunner.run" + "a" * 32
        absent = {
            "result": {
                "matchingBundleIdentifier": bundle_id,
                "apps": [],
            }
        }
        self.assertEqual(
            apple_device_proof.parse_installed_app_state(absent, bundle_id),
            "absent",
        )
        present = {
            "result": {
                "matchingBundleIdentifier": bundle_id,
                "apps": [{"bundleIdentifier": bundle_id}],
            }
        }
        self.assertEqual(
            apple_device_proof.parse_installed_app_state(present, bundle_id),
            "present",
        )
        malformed_documents = (
            {},
            {"result": []},
            {"result": {"matchingBundleIdentifier": bundle_id}},
            {
                "result": {
                    "matchingBundleIdentifier": "dev.qperiapt.Other",
                    "apps": [],
                }
            },
            {
                "result": {
                    "matchingBundleIdentifier": bundle_id,
                    "apps": [{"bundleIdentifier": "dev.qperiapt.Other"}],
                }
            },
            {
                "result": {
                    "matchingBundleIdentifier": bundle_id,
                    "apps": [
                        {"bundleIdentifier": bundle_id},
                        {"bundleIdentifier": bundle_id},
                    ],
                }
            },
        )
        for document in malformed_documents:
            with self.subTest(document=document):
                with self.assertRaises(SystemExit):
                    apple_device_proof.parse_installed_app_state(document, bundle_id)

    def test_release_freshness_and_profile_policy_are_fixed(self) -> None:
        apple_device_proof.require_release_policy(
            86400, False, min_profile_valid_days=30
        )
        with self.assertRaisesRegex(SystemExit, "freshness to 86400"):
            apple_device_proof.require_release_policy(
                604800, False, min_profile_valid_days=30
            )
        with self.assertRaisesRegex(SystemExit, "30-day profile-validity"):
            apple_device_proof.require_release_policy(
                86400, False, min_profile_valid_days=0
            )
        apple_device_proof.require_release_policy(
            604800, True, min_profile_valid_days=0
        )

    def test_selected_evidence_tree_requires_owner_only_modes_and_regular_files(self) -> None:
        evidence = self.root / "private-evidence"
        evidence.mkdir(mode=0o700)
        child = evidence / "child"
        child.mkdir(mode=0o700)
        proof = child / "proof.json"
        proof.write_text("{}\n", encoding="utf-8")
        proof.chmod(0o600)
        with mock.patch.object(apple_device_proof, "_require_no_extended_acl"):
            apple_device_proof.inspect_private_evidence_tree(evidence, "test evidence")

            proof.chmod(0o640)
            with self.assertRaisesRegex(SystemExit, "file mode must be 0600"):
                apple_device_proof.inspect_private_evidence_tree(evidence, "test evidence")
            proof.chmod(0o600)

            child.chmod(0o750)
            with self.assertRaisesRegex(SystemExit, "directory mode must be 0700"):
                apple_device_proof.inspect_private_evidence_tree(evidence, "test evidence")
            child.chmod(0o700)

            linked = child / "linked.json"
            linked.hardlink_to(proof)
            with self.assertRaisesRegex(SystemExit, "must not be hard-linked"):
                apple_device_proof.inspect_private_evidence_tree(evidence, "test evidence")
            linked.unlink()

            symlink = child / "proof-link.json"
            symlink.symlink_to(proof.name)
            with self.assertRaisesRegex(SystemExit, "must not contain symlinks"):
                apple_device_proof.inspect_private_evidence_tree(evidence, "test evidence")

    def test_acl_inspection_rejects_non_macos_hosts(self) -> None:
        with (
            mock.patch.object(apple_device_proof.sys, "platform", "linux"),
            mock.patch.object(apple_device_proof, "capture_stdout") as capture,
            self.assertRaisesRegex(SystemExit, "ACL inspection requires macOS"),
        ):
            apple_device_proof._require_no_extended_acl(self.root, "test evidence")
        capture.assert_not_called()

    def test_acl_inspection_accepts_plain_mode_and_rejects_acl_marker(self) -> None:
        for mode, accepted in (
            (b"drwx------ 2 owner group 64 Aug 13 00:00 path\n", True),
            (b"drwx------+ 2 owner group 64 Aug 13 00:00 path\n", False),
        ):
            with (
                self.subTest(mode=mode),
                mock.patch.object(apple_device_proof.sys, "platform", "darwin"),
                mock.patch.object(
                    apple_device_proof,
                    "capture_stdout",
                    return_value=BoundedResult(returncode=0, stdout=mode),
                ),
            ):
                if accepted:
                    apple_device_proof._require_no_extended_acl(
                        self.root, "test evidence"
                    )
                else:
                    with self.assertRaisesRegex(SystemExit, "extended ACL"):
                        apple_device_proof._require_no_extended_acl(
                            self.root, "test evidence"
                        )

    def test_selected_evidence_tree_rejects_extended_acl(self) -> None:
        evidence = self.root / "private-evidence"
        evidence.mkdir(mode=0o700)
        with (
            mock.patch.object(
                apple_device_proof,
                "_require_no_extended_acl",
                side_effect=SystemExit("error: test evidence must not carry an extended ACL"),
            ),
            self.assertRaisesRegex(SystemExit, "must not carry an extended ACL"),
        ):
            apple_device_proof.inspect_private_evidence_tree(evidence, "test evidence")

    def test_private_proof_writer_is_atomic_private_and_replaces_only_safe_output(self) -> None:
        evidence = self.root / "private-evidence"
        evidence.mkdir(mode=0o700)
        output = evidence / "proof.json"
        apple_device_proof.write_private_json_atomic(
            output,
            {"schema_version": 4, "status": "pass"},
            "test proof",
        )
        self.assertEqual(output.stat().st_nlink, 1)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        self.assertEqual(
            output.read_text(encoding="utf-8"),
            '{\n  "schema_version": 4,\n  "status": "pass"\n}\n',
        )
        apple_device_proof.write_private_json_atomic(
            output,
            {"schema_version": 4, "status": "updated"},
            "test proof",
        )
        self.assertIn('"status": "updated"', output.read_text(encoding="utf-8"))

        output.chmod(0o644)
        with self.assertRaisesRegex(SystemExit, "existing test proof"):
            apple_device_proof.write_private_json_atomic(
                output,
                {"schema_version": 4, "status": "forged"},
                "test proof",
            )

    def test_private_proof_writer_reports_cleanup_failure(self) -> None:
        evidence = self.root / "private-evidence"
        evidence.mkdir(mode=0o700)
        output = evidence / "proof.json"
        real_open = apple_device_proof.os.open
        real_close = apple_device_proof.os.close
        directory_fd: list[int] = []

        def recording_open(*args: object, **kwargs: object) -> int:
            descriptor = real_open(*args, **kwargs)
            if not directory_fd:
                directory_fd.append(descriptor)
            return descriptor

        def failing_directory_close(descriptor: int) -> None:
            if directory_fd and descriptor == directory_fd[0]:
                directory_fd.clear()
                real_close(descriptor)
                raise OSError("injected directory close failure")
            real_close(descriptor)

        with (
            mock.patch.object(apple_device_proof.os, "open", side_effect=recording_open),
            mock.patch.object(apple_device_proof.os, "close", side_effect=failing_directory_close),
            self.assertRaisesRegex(SystemExit, "closing test proof directory failed"),
        ):
            apple_device_proof.write_private_json_atomic(
                output,
                {"schema_version": 4, "status": "pass"},
                "test proof",
            )

    def test_private_proof_writer_preserves_old_output_on_write_failure(self) -> None:
        evidence = self.root / "private-evidence"
        evidence.mkdir(mode=0o700)
        output = evidence / "proof.json"
        output.write_text("old\n", encoding="utf-8")
        output.chmod(0o600)
        with (
            mock.patch.object(
                apple_device_proof.os,
                "write",
                side_effect=OSError("injected write failure"),
            ),
            self.assertRaisesRegex(SystemExit, "cannot publish test proof atomically"),
        ):
            apple_device_proof.write_private_json_atomic(
                output,
                {"schema_version": 4, "status": "pass"},
                "test proof",
            )
        self.assertEqual(output.read_text(encoding="utf-8"), "old\n")
        self.assertEqual(
            [path.name for path in evidence.iterdir()],
            ["proof.json"],
        )

    def test_private_proof_writer_rejects_unverifiable_payload_size(self) -> None:
        evidence = self.root / "private-evidence"
        evidence.mkdir(mode=0o700)
        output = evidence / "proof.json"
        with self.assertRaisesRegex(SystemExit, "test proof exceeds"):
            apple_device_proof.write_private_json_atomic(
                output,
                {"payload": "x" * apple_device_proof.MAX_APPLE_PROOF_BYTES},
                "test proof",
            )
        self.assertFalse(output.exists())

    def test_private_apple_identifiers_are_not_echoed_in_validation_errors(self) -> None:
        device_id = "00008132-0006452C1138801C"
        expected_team = "YKUPL7Z869"
        profile_team = "ABCDE12345"
        profile = {
            "Name": "test profile",
            "TeamIdentifier": [profile_team],
            "Entitlements": {"application-identifier": f"{profile_team}.*"},
            "ProvisionedDevices": [device_id],
            "ExpirationDate": dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=60),
        }
        entitlements = {
            "com.apple.developer.team-identifier": profile_team,
            "application-identifier": f"{profile_team}.dev.qperiapt.test",
        }
        with self.assertRaises(SystemExit) as caught:
            apple_device_proof.validate_profile(
                profile,
                entitlements,
                "dev.qperiapt.test",
                device_id,
                expected_team,
                30,
            )
        message = str(caught.exception)
        self.assertNotIn(device_id, message)
        self.assertNotIn(expected_team, message)
        self.assertNotIn(profile_team, message)

        private_bundle = "dev.qperiapt.DeviceRunner.run0123456789abcdef"
        duplicate_apps = {
            "result": {
                "matchingBundleIdentifier": private_bundle,
                "apps": [
                    {"bundleIdentifier": private_bundle},
                    {"bundleIdentifier": private_bundle},
                ],
            }
        }
        with self.assertRaises(SystemExit) as duplicate_failure:
            apple_device_proof.parse_installed_app_state(
                duplicate_apps,
                private_bundle,
            )
        self.assertNotIn(private_bundle, str(duplicate_failure.exception))

        private_diagnostic = (
            f"error: profile={device_id} team={expected_team} application-id="
            f"{profile_team}.dev.qperiapt.test"
        )
        private_log_path = self.root / "private-build.log"
        with self.assertRaises(SystemExit) as log_failure:
            apple_device_proof.require_clean_build_log_text(
                private_diagnostic,
                private_log_path,
            )
        log_message = str(log_failure.exception)
        self.assertIn(str(private_log_path), log_message)
        self.assertNotIn(device_id, log_message)
        self.assertNotIn(expected_team, log_message)
        self.assertNotIn(profile_team, log_message)

    def test_smoke_script_freezes_before_build_and_passes_snapshot_to_emit(self) -> None:
        script = (pathlib.Path(__file__).parent / "apple-device-smoke.sh").read_text(encoding="utf-8")
        freeze_position = script.index("freeze-source --root")
        first_build_position = script.index("cargo build -p q-periapt-ffi")
        self.assertLess(freeze_position, first_build_position)
        self.assertIn('--expected-git-commit "$SOURCE_GIT_COMMIT"', script)
        self.assertIn('--expected-source-tree-sha256 "$SOURCE_TREE_SHA256"', script)
        toolchain_capture = script.index("apple_toolchain.py capture")
        emit = script.index("apple_device_proof.py emit")
        self.assertLess(toolchain_capture, first_build_position)
        self.assertLess(first_build_position, emit)
        self.assertIn('--xcode-toolchain-receipt "$XCODE_TOOLCHAIN_RECEIPT"', script)

    def test_smoke_script_owns_only_a_run_unique_device_app(self) -> None:
        artifact = pathlib.Path(__file__).parent
        script = (artifact / "apple-device-smoke.sh").read_text(encoding="utf-8")
        trap_position = script.index("trap cleanup_exit EXIT")
        preflight_position = script.index(
            "inspect_device_app --expect absent", trap_position
        )
        armed_position = script.index(
            "APPLE_APP_CLEANUP_ARMED=1", preflight_position
        )
        install_position = script.index("device install app")
        normal_cleanup_position = script.index(
            "if ! cleanup_device_app; then", install_position
        )
        emit_position = script.index("apple_device_proof.py emit")
        self.assertIn(
            'BUNDLE_ID="dev.qperiapt.DeviceRunner.run$RUN_ID"', script
        )
        self.assertNotIn(
            "QPERIAPT_IOS_BUNDLE_ID:-dev.qperiapt.DeviceRunner", script
        )
        self.assertIn("QPERIAPT_IOS_BUNDLE_ID is not supported", script)
        verifier = (artifact / "apple_device_proof.py").read_text(encoding="utf-8")
        self.assertIn('"--include-all-apps"', verifier)
        self.assertIn("DEVICECTL_COMMAND_TIMEOUT_SECONDS", verifier)
        self.assertLess(trap_position, preflight_position)
        self.assertLess(preflight_position, armed_position)
        self.assertLess(armed_position, install_position)
        self.assertLess(install_position, normal_cleanup_position)
        self.assertLess(normal_cleanup_position, emit_position)
        self.assertEqual(script.count("device uninstall app"), 1)
        self.assertIn("required_absent_observations=8", script)
        self.assertIn("APPLE_APP_INSTALL_CONFIRMED=1", script)
        self.assertIn("Apple app cleanup outcome is unresolved", script)
        self.assertIn("xcodebuild -checkFirstLaunchStatus", script)
        self.assertIn('--timeout "$DEVICECTL_TIMEOUT_SECONDS"', script)
        self.assertNotIn("--terminate-existing", script)
        self.assertNotIn("pick_device()", script)
        self.assertNotIn("${1:-}", script)
        self.assertIn("QPERIAPT_IOS_DEVICE_ID is required", script)
        self.assertIn("QPERIAPT_DEVICE_RESULT_DIR must be an absolute path", script)

        matrix = (artifact / "apple-device-matrix.sh").read_text(encoding="utf-8")
        self.assertIn("QPERIAPT_IOS_DEVICE_MATRIX is required", matrix)
        self.assertNotIn("devicectl list devices", matrix)

        xcode27 = (artifact / "apple-device-xcode27-gate.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "QPERIAPT_IOS_DEVICE_MATRIX is required for the Xcode 27 matrix gate",
            xcode27,
        )

    def test_smoke_script_freezes_and_rechecks_installed_binary_inputs(self) -> None:
        script = (pathlib.Path(__file__).parent / "apple-device-smoke.sh").read_text(encoding="utf-8")
        freeze = script.index("FROZEN_BINARY_HASHES=$(binary_hashes)")
        install = script.index("device install app")
        result = script.index("QPERIAPT_DEVICE_RESULT_VERIFIED")
        recheck = script.index("FINAL_BINARY_HASHES=$(binary_hashes)")
        emit = script.index("apple_device_proof.py emit")
        self.assertLess(freeze, install)
        self.assertLess(install, result)
        self.assertLess(result, recheck)
        self.assertLess(recheck, emit)
        self.assertGreaterEqual(script.count("codesign --verify --deep --strict"), 2)
        self.assertIn(
            '--expected-app-executable-sha256 "$FROZEN_APP_EXECUTABLE_SHA256"',
            script,
        )
        self.assertIn(
            '--expected-staticlib-sha256 "$FROZEN_STATICLIB_SHA256"',
            script,
        )
        copy = script.index("device copy from")
        private_copy = script.index('chmod 600 "$DEVICE_RESULT_COPY"')
        consume_copy = script.index('cp "$DEVICE_RESULT_COPY" "$DEVICE_RESULT"')
        self.assertLess(copy, private_copy)
        self.assertLess(private_copy, consume_copy)
        self.assertNotIn('cat "$BUILD_LOG"', script)
        self.assertNotIn('cat "$LOG"', script)

    def test_smoke_script_rechecks_device_route_around_runtime_actions(self) -> None:
        script = (pathlib.Path(__file__).parent / "apple-device-smoke.sh").read_text(
            encoding="utf-8"
        )
        install = script.index("device install app")
        launch = script.index("device process launch")
        copy = script.index("device copy from")
        emit = script.index("apple_device_proof.py emit")
        self.assertGreater(script.rfind("assert_device_route", 0, install), 0)
        self.assertGreater(script.rfind("assert_device_route", install, launch), install)
        self.assertGreater(script.rfind("assert_device_route", launch, copy), launch)
        self.assertGreater(script.rfind("assert_device_route", copy, emit), copy)
        self.assertGreaterEqual(script.count("assert_device_route"), 7)
        self.assertGreaterEqual(
            script.count('--expected-device-type "$EXPECTED_DEVICE_TYPE"'), 4
        )
        self.assertGreaterEqual(
            script.count('--expected-transport "$EXPECTED_DEVICE_TRANSPORT"'), 4
        )

    def test_emit_rejects_binary_replacements_after_install_freeze(self) -> None:
        executable = self.root / "target" / "app" / "QPeriaptDeviceRunner"
        staticlib = self.root / "target" / "libq_periapt_ffi_abi2.a"
        executable.parent.mkdir(parents=True)
        executable.write_bytes(b"installed executable")
        staticlib.write_bytes(b"installed staticlib")
        executable_sha256 = hashlib.sha256(executable.read_bytes()).hexdigest()
        staticlib_sha256 = hashlib.sha256(staticlib.read_bytes()).hexdigest()
        self.assertEqual(
            apple_device_proof.verify_expected_binary_hashes(
                executable,
                staticlib,
                executable_sha256,
                staticlib_sha256,
            ),
            (executable_sha256, staticlib_sha256),
        )
        executable.write_bytes(b"replacement executable")
        with self.assertRaisesRegex(
            SystemExit,
            "app executable changed after device-install freeze",
        ):
            apple_device_proof.verify_expected_binary_hashes(
                executable,
                staticlib,
                executable_sha256,
                staticlib_sha256,
            )
        executable.write_bytes(b"installed executable")
        staticlib.write_bytes(b"replacement staticlib")
        with self.assertRaisesRegex(
            SystemExit,
            "static Rust FFI library changed after device-install freeze",
        ):
            apple_device_proof.verify_expected_binary_hashes(
                executable,
                staticlib,
                executable_sha256,
                staticlib_sha256,
            )

    def test_apple_capture_entrypoints_use_private_umask(self) -> None:
        artifact = pathlib.Path(__file__).parent
        for name in (
            "apple-device-smoke.sh",
            "apple-device-matrix.sh",
            "apple-device-xcode27-gate.sh",
        ):
            with self.subTest(entrypoint=name):
                source = (artifact / name).read_text(encoding="utf-8")
                self.assertLess(
                    source.index("umask 077"),
                    source.index('. "$ROOT/artifact/python-env.sh"'),
                )


class AppleReleaseMatrixPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp_dir.name).resolve()
        self.matrix_root = self.root / "artifact" / "device-runs" / "matrix"
        self.matrix_root.mkdir(parents=True)
        self.matrix_root.chmod(0o700)
        self.matrix_path = self.matrix_root / "apple-device-matrix-proof.json"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def child(self, label: str) -> dict[str, object]:
        device_type = apple_device_proof.REQUIRED_MATRIX_LABEL_TO_TYPE[label]
        transport = apple_device_proof.REQUIRED_MATRIX_LABEL_TO_TRANSPORT[label]
        return {
            "git_commit": "a" * 40,
            "proof_source_tree_sha256": "b" * 64,
            "source_tree_dirty": True,
            "device_id_sha256": hashlib.sha256(label.encode()).hexdigest(),
            "run_id": ("1" if label == "ipad" else "2") * 32,
            "xcode_toolchain": {"schema_version": 1, "selected": "same"},
            "device": {
                "label": label,
                "type": device_type,
                "product_type": f"product-{label}",
                "marketing_name": f"device-{label}",
                "os_version": "27.0",
                "os_build": f"build-{label}",
                "transport": transport,
            },
        }

    def entry(self, label: str, child: dict[str, object], digest: str) -> dict[str, object]:
        device = child["device"]
        assert isinstance(device, dict)
        return {
            "label": label,
            "prefix": label,
            "device_type": device["type"],
            "product_type": device["product_type"],
            "marketing_name": device["marketing_name"],
            "os_version": device["os_version"],
            "os_build": device["os_build"],
            "transport": device["transport"],
            "device_id_sha256": child["device_id_sha256"],
            "run_id": child["run_id"],
            "proof": f"{label}/{label}-device-proof.json",
            "build_log": f"{label}/{label}-build.log",
            "launch_log": f"{label}/{label}-device-launch.log",
            "device_result": f"{label}/{label}-device-result.txt",
            "proof_sha256": digest,
        }

    def matrix_snapshot(
        self,
        *,
        required_types: list[str] | None = None,
        duplicate_device: bool = False,
    ) -> tuple[JsonObjectSnapshot, dict[str, JsonObjectSnapshot], dict[str, dict[str, object]]]:
        children = {label: self.child(label) for label in ("ipad", "iphone")}
        if duplicate_device:
            children["iphone"]["device_id_sha256"] = children["ipad"]["device_id_sha256"]
        snapshots: dict[str, JsonObjectSnapshot] = {}
        entries = []
        for label, child in children.items():
            path = self.matrix_root / label / f"{label}-device-proof.json"
            data = f"child-{label}".encode()
            file_snapshot = FileSnapshot(
                path=path,
                data=data,
                size=len(data),
                sha256=hashlib.sha256(data).hexdigest(),
            )
            snapshots[label] = JsonObjectSnapshot(file=file_snapshot, value={})
            entries.append(self.entry(label, child, file_snapshot.sha256))
        proof = {
            "schema_version": apple_device_proof.MATRIX_SCHEMA_VERSION,
            "status": "pass",
            "git_commit": "a" * 40,
            "source_tree_dirty": True,
            "proof_source_tree_sha256": "b" * 64,
            "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "required_device_types": required_types
            if required_types is not None
            else list(apple_device_proof.REQUIRED_MATRIX_TYPES),
            "source_inputs_sha256": {},
            "devices": entries,
        }
        data = b"matrix"
        return (
            JsonObjectSnapshot(
                file=FileSnapshot(
                    path=self.matrix_path,
                    data=data,
                    size=len(data),
                    sha256=hashlib.sha256(data).hexdigest(),
                ),
                value=proof,
            ),
            snapshots,
            children,
        )

    def verify_fixture(
        self,
        snapshot: JsonObjectSnapshot,
        child_snapshots: dict[str, JsonObjectSnapshot],
        children: dict[str, dict[str, object]],
    ) -> None:
        def load_child(path: pathlib.Path, _label: str) -> JsonObjectSnapshot:
            return child_snapshots[path.parent.name]

        def verify_child(
            _root: pathlib.Path,
            child_snapshot: JsonObjectSnapshot,
            *_args: object,
            **_kwargs: object,
        ) -> dict[str, object]:
            return children[child_snapshot.file.path.parent.name]

        with (
            mock.patch.object(apple_device_proof, "verify_git_provenance"),
            mock.patch.object(apple_device_proof, "verify_source_tree_digest"),
            mock.patch.object(apple_device_proof, "verify_source_hashes"),
            mock.patch.object(
                apple_device_proof,
                "load_apple_json_snapshot",
                side_effect=load_child,
            ),
            mock.patch.object(
                apple_device_proof,
                "verify_proof_snapshot",
                side_effect=verify_child,
            ),
            mock.patch.object(apple_device_proof, "_require_no_extended_acl"),
        ):
            apple_device_proof.verify_matrix_snapshot(
                self.root,
                snapshot,
                self.matrix_root,
                86400,
                True,
            )

    def test_matrix_requires_exactly_ipad_and_iphone(self) -> None:
        snapshot, child_snapshots, children = self.matrix_snapshot()
        self.verify_fixture(snapshot, child_snapshots, children)

        for weakened in ([], ["iPad"], ["iPhone"]):
            with self.subTest(weakened=weakened):
                snapshot, child_snapshots, children = self.matrix_snapshot(
                    required_types=weakened
                )
                with self.assertRaisesRegex(SystemExit, "exactly iPad and iPhone"):
                    self.verify_fixture(snapshot, child_snapshots, children)

    def test_matrix_rejects_old_schema_and_duplicate_physical_device(self) -> None:
        snapshot, child_snapshots, children = self.matrix_snapshot()
        snapshot.value["schema_version"] = 4
        with self.assertRaisesRegex(SystemExit, "schema must be 5"):
            self.verify_fixture(snapshot, child_snapshots, children)

        snapshot, child_snapshots, children = self.matrix_snapshot(
            duplicate_device=True
        )
        with self.assertRaisesRegex(SystemExit, "distinct physical devices"):
            self.verify_fixture(snapshot, child_snapshots, children)

    def test_matrix_rejects_wrong_transport_for_label(self) -> None:
        snapshot, child_snapshots, children = self.matrix_snapshot()
        snapshot.value["devices"][0]["transport"] = "localNetwork"
        with self.assertRaisesRegex(SystemExit, "requires wired transport"):
            self.verify_fixture(snapshot, child_snapshots, children)

    def test_matrix_rejects_different_xcode_toolchains(self) -> None:
        snapshot, child_snapshots, children = self.matrix_snapshot()
        children["iphone"]["xcode_toolchain"] = {
            "schema_version": 1,
            "selected": "different",
        }
        with self.assertRaisesRegex(SystemExit, "different Xcode toolchains"):
            self.verify_fixture(snapshot, child_snapshots, children)


if __name__ == "__main__":
    unittest.main()
