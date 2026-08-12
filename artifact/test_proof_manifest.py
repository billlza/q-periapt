from __future__ import annotations

import hashlib
import json
import pathlib
import tempfile
import unittest

import proof_manifest
from proof_manifest import (
    ProofManifestError,
    load_results_manifest_snapshot,
    select_bound_json_snapshot,
)


class ProofManifestTests(unittest.TestCase):
    def performance_manifest(
        self,
        relative: str,
        digest: str,
    ) -> dict[str, object]:
        source_digest = "a" * 64
        return {
            "proof_source_tree_sha256": source_digest,
            "performance": {
                "current_source_status": "current_controlled_pass",
                "proof_schema": 4,
                "proof_source_tree_sha256": source_digest,
                "proof_path": relative,
                "proof_sha256": digest,
                "proof_generated_at": "2026-08-12T00:00:00Z",
                "status": "pass",
            },
        }

    def current_android_manifest(
        self,
        *,
        device_kind: str = "emulator",
    ) -> dict[str, object]:
        digest = "a" * 64
        commit = "c" * 40
        run_id = "d" * 32
        status = f"current_clean_tree_{device_kind}_pass"
        runtime = {
            "android_sdk": 35 if device_kind == "emulator" else 36,
            "build_tools": "36.0.0",
            "covered_tests": list(proof_manifest.ANDROID_EXPECTED_TESTS),
            "current_source_status": status,
            "device_abi": "arm64-v8a",
            "device_kind": device_kind,
            "page_size": 16_384 if device_kind == "emulator" else 4_096,
            "proof_generated_at": "2026-08-12T00:00:00Z",
            "proof_path": (
                f"target/qperiapt-android-device-smoke-runs/{run_id}/proof/"
                "qperiapt-android-device-proof.json"
            ),
            "proof_schema": proof_manifest.ANDROID_DEVICE_PROOF_SCHEMA_VERSION,
            "proof_sha256": "b" * 64,
            "proof_source_tree_sha256": digest,
            "release_candidate_mode": device_kind == "emulator",
            "run_id": run_id,
            "source_commit": commit,
            "source_tree_dirty": False,
            "status": "pass",
        }
        runtime_section = (
            "android_device_runtime"
            if device_kind == "emulator"
            else "android_physical_runtime"
        )
        return {
            "android_aar": {
                "aar_path": proof_manifest.ANDROID_AAR_PATH,
                "aar_sha256": "e" * 64,
                "current_source_status": "current_clean_tree_package_pass",
                "manifest_generated_at": "2026-08-12T00:00:00Z",
                "manifest_path": proof_manifest.ANDROID_AAR_MANIFEST_PATH,
                "manifest_schema": 4,
                "manifest_sha256": "f" * 64,
                "proof_source_tree_sha256": digest,
                "source_commit": commit,
                "source_tree_dirty": False,
                "status": "pass",
                "targets": list(proof_manifest.ANDROID_ABIS),
            },
            runtime_section: runtime,
            "proof_source_tree_sha256": digest,
            "provenance": {"snapshot_commit": commit},
        }

    def test_declared_current_performance_rejects_stale_schema_or_source(self) -> None:
        digest = "a" * 64
        current = {
            "proof_source_tree_sha256": digest,
            "performance": {
                "current_source_status": "current_controlled_pass",
                "proof_schema": 4,
                "proof_source_tree_sha256": digest,
                "proof_path": "target/performance/proof.json",
                "proof_sha256": "b" * 64,
                "proof_generated_at": "2026-07-11T00:00:00Z",
                "status": "pass",
            },
        }
        proof_manifest.validate_declared_currentness(current)
        current["performance"]["proof_schema"] = 3
        with self.assertRaisesRegex(
            proof_manifest.ProofManifestError, "requires proof schema 4"
        ):
            proof_manifest.validate_declared_currentness(current)
        current["performance"]["proof_schema"] = 4
        current["performance"]["proof_source_tree_sha256"] = "b" * 64
        with self.assertRaisesRegex(
            proof_manifest.ProofManifestError, "does not match"
        ):
            proof_manifest.validate_declared_currentness(current)

    def test_declared_current_performance_requires_bound_path_hash_and_pass(self) -> None:
        digest = "a" * 64
        section = {
            "current_source_status": "current_controlled_pass",
            "proof_schema": 4,
            "proof_source_tree_sha256": digest,
            "proof_path": "target/performance/proof.json",
            "proof_sha256": "b" * 64,
            "proof_generated_at": "2026-07-11T00:00:00Z",
            "status": "pass",
        }
        manifest = {"proof_source_tree_sha256": digest, "performance": section}
        proof_manifest.validate_declared_currentness(manifest)
        for field, bad_value, message in (
            ("proof_path", "../proof.json", "selected-proof path"),
            ("proof_sha256", "bad", "selected-proof SHA-256"),
            ("status", "fail", "passing proof"),
            ("proof_generated_at", None, "generation time"),
        ):
            with self.subTest(field=field):
                original = section[field]
                section[field] = bad_value
                with self.assertRaisesRegex(proof_manifest.ProofManifestError, message):
                    proof_manifest.validate_declared_currentness(manifest)
                section[field] = original

    def test_declared_current_apple_requires_bound_passing_schema3_attempt(self) -> None:
        digest = "a" * 64
        section = {
            "current_source_status": "current_clean_tree_physical_pass",
            "current_proof_schema": 3,
            "proof_source_tree_sha256": digest,
            "current_proof_path": "artifact/device-runs/ipad/proof.json",
            "current_proof_sha256": "b" * 64,
            "current_proof_generated_at": "2026-07-11T00:00:00Z",
            "current_proof_source_tree_dirty": False,
            "current_attempt": {"status": "pass", "proof_emitted": True},
        }
        manifest = {"proof_source_tree_sha256": digest, "apple_device": section}
        proof_manifest.validate_declared_currentness(manifest)
        section["current_attempt"] = {"status": "fail", "proof_emitted": False}
        with self.assertRaisesRegex(
            proof_manifest.ProofManifestError, "passing emitted-proof attempt"
        ):
            proof_manifest.validate_declared_currentness(manifest)

    def test_current_apple_status_rejects_mismatched_cleanliness(self) -> None:
        digest = "a" * 64
        section = {
            "current_source_status": "current_dirty_diagnostic_pass",
            "current_proof_schema": 3,
            "proof_source_tree_sha256": digest,
            "current_proof_path": "artifact/device-runs/ipad/proof.json",
            "current_proof_sha256": "b" * 64,
            "current_proof_generated_at": "2026-07-11T00:00:00Z",
            "current_proof_source_tree_dirty": False,
            "current_attempt": {"status": "pass", "proof_emitted": True},
        }
        with self.assertRaisesRegex(
            proof_manifest.ProofManifestError, "inconsistent source-tree cleanliness"
        ):
            proof_manifest.validate_declared_currentness(
                {"proof_source_tree_sha256": digest, "apple_device": section}
            )

    def test_declared_current_apple_matrix_requires_bound_passing_schema3_proof(self) -> None:
        digest = "a" * 64
        section = {
            "matrix_source_status": "current_clean_tree_physical_pass",
            "matrix_proof_schema": 4,
            "proof_source_tree_sha256": digest,
            "matrix_proof_path": "artifact/device-runs/matrix/apple-device-matrix-proof.json",
            "matrix_proof_sha256": "b" * 64,
            "matrix_generated_at": "2026-07-11T00:00:00Z",
            "matrix_status": "pass",
            "matrix_source_tree_dirty": False,
        }
        manifest = {"proof_source_tree_sha256": digest, "apple_device": section}
        proof_manifest.validate_declared_currentness(manifest)

        for field, bad_value, message in (
            ("matrix_proof_path", "../proof.json", "selected-proof path"),
            ("matrix_proof_sha256", "bad", "selected-proof SHA-256"),
            ("matrix_proof_schema", 3, "requires proof schema 4"),
            ("proof_source_tree_sha256", "c" * 64, "does not match"),
            ("matrix_status", "fail", "passing proof"),
            ("matrix_generated_at", None, "generation time"),
        ):
            with self.subTest(field=field):
                original = section[field]
                section[field] = bad_value
                with self.assertRaisesRegex(proof_manifest.ProofManifestError, message):
                    proof_manifest.validate_declared_currentness(manifest)
                section[field] = original

        manifest.pop("proof_source_tree_sha256")
        with self.assertRaisesRegex(
            proof_manifest.ProofManifestError, "does not match"
        ):
            proof_manifest.validate_declared_currentness(manifest)

    def test_noncurrent_apple_matrix_does_not_require_current_proof_fields(self) -> None:
        proof_manifest.validate_declared_currentness(
            {
                "proof_source_tree_sha256": "a" * 64,
                "apple_device": {"matrix_source_status": "stale_requires_rerun"},
            }
        )

    def test_declared_current_android_requires_bound_passing_current_schema_proof(self) -> None:
        manifest = self.current_android_manifest()
        section = manifest["android_device_runtime"]
        proof_manifest.validate_declared_currentness(manifest)

        for field, bad_value, message in (
            ("proof_path", "../proof.json", "selected-proof path"),
            ("proof_sha256", "bad", "selected-proof SHA-256"),
            (
                "proof_schema",
                proof_manifest.ANDROID_DEVICE_PROOF_SCHEMA_VERSION - 1,
                (
                    "requires proof schema "
                    f"{proof_manifest.ANDROID_DEVICE_PROOF_SCHEMA_VERSION}"
                ),
            ),
            ("proof_source_tree_sha256", "c" * 64, "does not match"),
            ("status", "fail", "passing proof"),
            ("proof_generated_at", None, "generation time"),
            ("source_tree_dirty", True, "clean source provenance"),
            ("android_sdk", "35", "SDK is invalid"),
            ("page_size", True, "page size is invalid"),
            ("covered_tests", [], "exact runtime test set"),
        ):
            with self.subTest(field=field):
                original = section[field]
                section[field] = bad_value
                with self.assertRaisesRegex(proof_manifest.ProofManifestError, message):
                    proof_manifest.validate_declared_currentness(manifest)
                section[field] = original

    def test_current_android_status_is_bound_to_the_declared_device_kind(self) -> None:
        for declared_kind, status_kind in (
            ("physical", "emulator"),
            ("emulator", "physical"),
        ):
            with self.subTest(declared_kind=declared_kind, status_kind=status_kind):
                manifest = self.current_android_manifest(device_kind=declared_kind)
                runtime_section = (
                    "android_device_runtime"
                    if declared_kind == "emulator"
                    else "android_physical_runtime"
                )
                runtime = manifest[runtime_section]
                runtime["current_source_status"] = (
                    f"current_clean_tree_{status_kind}_pass"
                )
                with self.assertRaisesRegex(
                    proof_manifest.ProofManifestError,
                    "unknown status",
                ):
                    proof_manifest.validate_declared_currentness(manifest)

    def test_canonical_and_physical_android_runtime_can_be_current_together(
        self,
    ) -> None:
        manifest = self.current_android_manifest()
        physical = self.current_android_manifest(device_kind="physical")
        manifest["android_physical_runtime"] = physical["android_physical_runtime"]
        proof_manifest.validate_declared_currentness(manifest)

        self.assertEqual(
            proof_manifest.expected_android_runtime_device_kind(manifest),
            "emulator",
        )
        self.assertEqual(
            proof_manifest.expected_android_runtime_device_kind(
                manifest,
                binding="android_physical_runtime",
            ),
            "physical",
        )
        self.assertIs(
            proof_manifest.current_android_runtime_section(manifest),
            manifest["android_device_runtime"],
        )
        self.assertIs(
            proof_manifest.current_android_runtime_section(
                manifest,
                binding="android_physical_runtime",
            ),
            manifest["android_physical_runtime"],
        )

    def test_current_physical_runtime_allows_real_device_characteristics(self) -> None:
        manifest = self.current_android_manifest(device_kind="physical")
        section = manifest["android_physical_runtime"]
        section.update(
            {
                "device_abi": "armeabi-v7a",
                "page_size": 4_096,
                "android_sdk": 37,
                "release_candidate_mode": False,
                "build_tools": "37.0.0-rc1",
            }
        )
        proof_manifest.validate_declared_currentness(manifest)

        for field, bad_value, message in (
            ("device_abi", "mips", "ABI is invalid"),
            ("page_size", 8_192, "page size is invalid"),
            ("android_sdk", 0, "SDK is invalid"),
            ("release_candidate_mode", 1, "release mode is invalid"),
            ("proof_schema", 4, "proof schema 5"),
            ("status", "fail", "passing proof"),
            ("source_tree_dirty", True, "clean source provenance"),
        ):
            with self.subTest(field=field):
                original = section[field]
                section[field] = bad_value
                with self.assertRaisesRegex(
                    proof_manifest.ProofManifestError,
                    message,
                ):
                    proof_manifest.validate_declared_currentness(manifest)
                section[field] = original

    def test_runtime_binding_selection_never_falls_back_between_sections(self) -> None:
        canonical = self.current_android_manifest()
        canonical["android_device_runtime"]["current_source_status"] = (
            "stale_requires_rerun"
        )
        physical = self.current_android_manifest(device_kind="physical")
        canonical["android_physical_runtime"] = physical["android_physical_runtime"]

        with self.assertRaisesRegex(
            proof_manifest.ProofManifestError,
            "current emulator runtime status",
        ):
            proof_manifest.current_android_runtime_section(canonical)
        self.assertEqual(
            proof_manifest.expected_android_runtime_device_kind(
                canonical,
                binding="android_physical_runtime",
            ),
            "physical",
        )
        with self.assertRaisesRegex(
            proof_manifest.ProofManifestError,
            "unknown Android runtime results binding",
        ):
            proof_manifest.select_android_runtime_results_binding("physical")

    def test_current_android_emulator_requires_the_canonical_release_runtime(self) -> None:
        for field, bad_value in (
            ("device_abi", "x86_64"),
            ("page_size", 4_096),
            ("android_sdk", 36),
            ("release_candidate_mode", False),
            ("build_tools", "35.0.0"),
        ):
            with self.subTest(field=field):
                manifest = self.current_android_manifest()
                manifest["android_device_runtime"][field] = bad_value
                with self.assertRaisesRegex(
                    proof_manifest.ProofManifestError,
                    "canonical release runtime",
                ):
                    proof_manifest.validate_declared_currentness(manifest)

    def test_current_android_aar_requires_exact_source_paths_and_targets(self) -> None:
        manifest = self.current_android_manifest()
        manifest["android_device_runtime"]["current_source_status"] = (
            "stale_requires_rerun"
        )
        section = manifest["android_aar"]
        proof_manifest.validate_declared_currentness(manifest)
        for field, bad_value, message in (
            ("aar_path", "target/other.aar", "path is not canonical"),
            ("manifest_sha256", "bad", "selected-proof SHA-256"),
            ("manifest_schema", 3, "manifest schema 4"),
            ("targets", list(reversed(proof_manifest.ANDROID_ABIS)), "four ABI"),
            ("source_commit", "0" * 40, "source commit"),
            ("source_tree_dirty", True, "clean source provenance"),
        ):
            with self.subTest(field=field):
                original = section[field]
                section[field] = bad_value
                with self.assertRaisesRegex(
                    proof_manifest.ProofManifestError,
                    message,
                ):
                    proof_manifest.validate_declared_currentness(manifest)
                section[field] = original

    def test_current_local_index_requires_exact_runtime_and_consumer_receipt(self) -> None:
        manifest = self.current_android_manifest()
        commit = manifest["provenance"]["snapshot_commit"]
        runtime = manifest["android_device_runtime"]
        receipt_run_id = "9" * 32
        section = {
            "android_runtime_proof_sha256": runtime["proof_sha256"],
            "android_runtime_run_id": runtime["run_id"],
            "channel": "release",
            "consumer_receipt_generated_at": "2026-08-12T00:05:00Z",
            "consumer_receipt_path": (
                "target/qperiapt-release-consumer-smoke/receipts/"
                f"{receipt_run_id}/qperiapt-release-consumer-receipt.json"
            ),
            "consumer_receipt_run_id": receipt_run_id,
            "consumer_receipt_schema": 1,
            "consumer_receipt_sha256": "8" * 64,
            "consumer_status": "pass",
            "current_source_status": (
                "current_clean_tree_local_index_consumer_pass"
            ),
            "generated_at": "2026-08-12T00:04:00Z",
            "index_path": (
                "target/qperiapt-local-release/release/0.1.0-alpha.2/"
                f"{commit}/index.json"
            ),
            "index_schema": 5,
            "index_sha256": "7" * 64,
            "proof_source_tree_sha256": manifest["proof_source_tree_sha256"],
            "source_commit": commit,
            "source_tree_dirty": False,
            "status": "pass",
        }
        manifest["local_release_index"] = section
        proof_manifest.validate_declared_currentness(manifest)
        for field, bad_value, message in (
            ("channel", "diagnostic", "release channel"),
            ("index_schema", 4, "index schema 5"),
            ("consumer_receipt_schema", True, "receipt schema 1"),
            ("android_runtime_run_id", "1" * 32, "selection differs"),
            ("consumer_receipt_path", "target/receipt.json", "not canonical"),
        ):
            with self.subTest(field=field):
                original = section[field]
                section[field] = bad_value
                with self.assertRaisesRegex(
                    proof_manifest.ProofManifestError,
                    message,
                ):
                    proof_manifest.validate_declared_currentness(manifest)
                section[field] = original

    def test_stale_android_runtime_cannot_be_selected(self) -> None:
        manifest = self.current_android_manifest()
        manifest["android_device_runtime"]["current_source_status"] = (
            "stale_requires_rerun"
        )
        with self.assertRaisesRegex(
            proof_manifest.ProofManifestError,
            "requires a current emulator runtime status",
        ):
            proof_manifest.expected_android_runtime_device_kind(manifest)

    def test_noncurrent_android_does_not_require_current_proof_fields(self) -> None:
        proof_manifest.validate_declared_currentness(
            {
                "proof_source_tree_sha256": "a" * 64,
                "android_device_runtime": {"current_source_status": "stale_requires_rerun"},
            }
        )

    def test_unknown_currentness_statuses_fail_closed(self) -> None:
        for section, key in (
            ("performance", "current_source_status"),
            ("apple_device", "current_source_status"),
            ("apple_device", "matrix_source_status"),
            ("android_device_runtime", "current_source_status"),
            ("android_physical_runtime", "current_source_status"),
            ("android_aar", "current_source_status"),
            ("local_release_index", "current_source_status"),
        ):
            with self.subTest(section=section, key=key), self.assertRaisesRegex(
                proof_manifest.ProofManifestError,
                "unknown status",
            ):
                proof_manifest.validate_declared_currentness(
                    {section: {key: "current_pass_typo"}}
                )

    def test_every_manifest_bound_file_rejects_a_stale_status(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            artifact = root / "artifact"
            artifact.mkdir()
            digest = "b" * 64
            stale = "stale_requires_rerun"
            manifest_value = {
                "apple_device": {
                    "current_source_status": stale,
                    "current_proof_path": "artifact/device/proof.json",
                    "current_proof_sha256": digest,
                    "matrix_source_status": stale,
                    "matrix_proof_path": "artifact/device/matrix.json",
                    "matrix_proof_sha256": digest,
                },
                "android_aar": {
                    "current_source_status": stale,
                    "aar_path": proof_manifest.ANDROID_AAR_PATH,
                    "aar_sha256": digest,
                    "manifest_path": proof_manifest.ANDROID_AAR_MANIFEST_PATH,
                    "manifest_sha256": digest,
                },
                "android_device_runtime": {
                    "current_source_status": stale,
                    "proof_path": "target/android/canonical.json",
                    "proof_sha256": digest,
                },
                "android_physical_runtime": {
                    "current_source_status": stale,
                    "proof_path": "target/android/physical.json",
                    "proof_sha256": digest,
                },
                "local_release_index": {
                    "current_source_status": stale,
                    "index_path": "target/release/index.json",
                    "index_sha256": digest,
                    "consumer_receipt_path": "target/release/receipt.json",
                    "consumer_receipt_sha256": digest,
                },
                "performance": {
                    "current_source_status": stale,
                    "proof_path": "target/performance/proof.json",
                    "proof_sha256": digest,
                },
            }
            manifest_path = artifact / "results.json"
            manifest_path.write_text(
                json.dumps(manifest_value, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            manifest = load_results_manifest_snapshot(manifest_path)
            for binding in proof_manifest.BINDINGS:
                with self.subTest(binding=binding), self.assertRaisesRegex(
                    ProofManifestError,
                    rf"manifest-bound {binding} selection requires current status",
                ):
                    proof_manifest.resolve_bound_file_declaration(
                        root,
                        manifest,
                        binding=binding,
                    )

    def make_fixture(self, root: pathlib.Path) -> pathlib.Path:
        proof = root / "proofs" / "selected.json"
        proof.parent.mkdir()
        proof.write_bytes(b'{"status":"pass"}\n')
        digest = hashlib.sha256(proof.read_bytes()).hexdigest()
        artifact = root / "artifact"
        artifact.mkdir()
        (artifact / "results.json").write_text(
            json.dumps(
                self.performance_manifest("proofs/selected.json", digest),
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        return proof

    def test_bound_snapshot_uses_manifest_path_hash_and_same_proof_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            proof = self.make_fixture(root)
            manifest = load_results_manifest_snapshot(root / "artifact" / "results.json")
            snapshot = select_bound_json_snapshot(
                root,
                manifest,
                binding="performance",
                selected_path=proof,
                label="performance proof",
            )
            proof.write_text('{"status":"replaced"}\n', encoding="utf-8")
            self.assertEqual(snapshot.value, {"status": "pass"})
            self.assertEqual(
                snapshot.file.sha256,
                manifest.value["performance"]["proof_sha256"],
            )

    def test_startup_manifest_digest_is_pinned(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            self.make_fixture(root)
            manifest_path = root / "artifact" / "results.json"
            snapshot = load_results_manifest_snapshot(manifest_path)
            load_results_manifest_snapshot(
                manifest_path, expected_sha256=snapshot.file.sha256
            )
            with self.assertRaisesRegex(ProofManifestError, "manifest changed"):
                load_results_manifest_snapshot(
                    manifest_path, expected_sha256="0" * 64
                )

    def test_different_selected_path_fails_even_with_identical_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            proof = self.make_fixture(root)
            other = proof.with_name("other.json")
            other.write_bytes(proof.read_bytes())
            manifest = load_results_manifest_snapshot(root / "artifact" / "results.json")
            with self.assertRaisesRegex(ProofManifestError, "differs from results manifest"):
                select_bound_json_snapshot(
                    root,
                    manifest,
                    binding="performance",
                    selected_path=other,
                    label="performance proof",
                )

    def test_selected_path_rejects_a_noncanonical_alias(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            proof = self.make_fixture(root)
            manifest = load_results_manifest_snapshot(root / "artifact" / "results.json")
            alias = proof.parent / "nonexistent" / ".." / proof.name
            with self.assertRaisesRegex(ProofManifestError, "canonically spelled"):
                select_bound_json_snapshot(
                    root,
                    manifest,
                    binding="performance",
                    selected_path=alias,
                    label="performance proof",
                )

    def test_hash_mismatch_and_duplicate_manifest_keys_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            proof = self.make_fixture(root)
            manifest_path = root / "artifact" / "results.json"
            manifest_path.write_text(
                json.dumps(
                    self.performance_manifest(
                        "proofs/selected.json",
                        "0" * 64,
                    ),
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            manifest = load_results_manifest_snapshot(manifest_path)
            with self.assertRaisesRegex(ProofManifestError, "hash differs"):
                select_bound_json_snapshot(
                    root,
                    manifest,
                    binding="performance",
                    selected_path=proof,
                    label="performance proof",
                )

            manifest_path.write_text(
                '{"performance":{},"performance":{}}', encoding="utf-8"
            )
            with self.assertRaisesRegex(ProofManifestError, "duplicate JSON key"):
                load_results_manifest_snapshot(manifest_path)
            manifest_path.write_text('{"ignored":NaN}', encoding="utf-8")
            with self.assertRaisesRegex(ProofManifestError, "non-finite JSON number"):
                load_results_manifest_snapshot(manifest_path)

    def test_noncanonical_manifest_paths_and_proof_symlinks_fail(self) -> None:
        for relative in (
            "/absolute/proof.json",
            "../proof.json",
            "proofs//selected.json",
            "proofs\\selected.json",
        ):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary)
                proof = self.make_fixture(root)
                digest = hashlib.sha256(proof.read_bytes()).hexdigest()
                (root / "artifact" / "results.json").write_text(
                    json.dumps(
                        self.performance_manifest(relative, digest),
                        sort_keys=True,
                    )
                    + "\n",
                    encoding="utf-8",
                )
                with self.assertRaises(ProofManifestError):
                    manifest = load_results_manifest_snapshot(
                        root / "artifact" / "results.json"
                    )
                    select_bound_json_snapshot(
                        root,
                        manifest,
                        binding="performance",
                        selected_path=proof,
                        label="performance proof",
                    )

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            proof = self.make_fixture(root)
            target = proof.with_name("target.json")
            proof.rename(target)
            proof.symlink_to(target)
            manifest = load_results_manifest_snapshot(root / "artifact" / "results.json")
            with self.assertRaises(ProofManifestError):
                select_bound_json_snapshot(
                    root,
                    manifest,
                    binding="performance",
                    selected_path=proof,
                    label="performance proof",
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            outside = root / "outside"
            outside.mkdir()
            external_proof = outside / "selected.json"
            external_proof.write_bytes(b'{"status":"pass"}\n')
            proofs = root / "proofs"
            proofs.mkdir()
            (proofs / "external").symlink_to(outside, target_is_directory=True)
            artifact = root / "artifact"
            artifact.mkdir()
            digest = hashlib.sha256(external_proof.read_bytes()).hexdigest()
            manifest_path = artifact / "results.json"
            manifest_path.write_text(
                json.dumps(
                    self.performance_manifest(
                        "proofs/external/selected.json",
                        digest,
                    ),
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            manifest = load_results_manifest_snapshot(manifest_path)
            with self.assertRaisesRegex(ProofManifestError, "cannot safely open"):
                select_bound_json_snapshot(
                    root,
                    manifest,
                    binding="performance",
                    selected_path=proofs / "external" / "selected.json",
                    label="performance proof",
                )


if __name__ == "__main__":
    unittest.main()
