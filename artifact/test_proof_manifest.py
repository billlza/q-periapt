from __future__ import annotations

import hashlib
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

    def test_declared_current_apple_requires_bound_passing_schema2_attempt(self) -> None:
        digest = "a" * 64
        section = {
            "current_source_status": "current_dirty_diagnostic_pass",
            "current_dirty_proof_schema": 2,
            "proof_source_tree_sha256": digest,
            "current_dirty_proof_path": "artifact/device-runs/ipad/proof.json",
            "current_dirty_proof_sha256": "b" * 64,
            "current_dirty_proof_generated_at": "2026-07-11T00:00:00Z",
            "current_attempt": {"status": "pass", "proof_emitted": True},
        }
        manifest = {"proof_source_tree_sha256": digest, "apple_device": section}
        proof_manifest.validate_declared_currentness(manifest)
        section["current_attempt"] = {"status": "fail", "proof_emitted": False}
        with self.assertRaisesRegex(
            proof_manifest.ProofManifestError, "passing emitted-proof attempt"
        ):
            proof_manifest.validate_declared_currentness(manifest)

    def test_declared_current_apple_matrix_requires_bound_passing_schema3_proof(self) -> None:
        digest = "a" * 64
        section = {
            "matrix_source_status": "current_dirty_diagnostic_pass",
            "matrix_proof_schema": 3,
            "proof_source_tree_sha256": digest,
            "matrix_proof_path": "artifact/device-runs/matrix/apple-device-matrix-proof.json",
            "matrix_proof_sha256": "b" * 64,
            "matrix_generated_at": "2026-07-11T00:00:00Z",
            "matrix_status": "pass",
        }
        manifest = {"proof_source_tree_sha256": digest, "apple_device": section}
        proof_manifest.validate_declared_currentness(manifest)

        for field, bad_value, message in (
            ("matrix_proof_path", "../proof.json", "selected-proof path"),
            ("matrix_proof_sha256", "bad", "selected-proof SHA-256"),
            ("matrix_proof_schema", 2, "requires proof schema 3"),
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

    def test_declared_current_android_requires_bound_passing_schema2_proof(self) -> None:
        digest = "a" * 64
        section = {
            "current_source_status": "current_clean_tree_emulator_pass",
            "proof_schema": 2,
            "proof_source_tree_sha256": digest,
            "proof_path": "target/android/proof.json",
            "proof_sha256": "b" * 64,
            "proof_generated_at": "2026-07-13T00:00:00Z",
            "status": "pass",
        }
        manifest = {"proof_source_tree_sha256": digest, "android_device_runtime": section}
        proof_manifest.validate_declared_currentness(manifest)

        for field, bad_value, message in (
            ("proof_path", "../proof.json", "selected-proof path"),
            ("proof_sha256", "bad", "selected-proof SHA-256"),
            ("proof_schema", 1, "requires proof schema 2"),
            ("proof_source_tree_sha256", "c" * 64, "does not match"),
            ("status", "fail", "passing proof"),
            ("proof_generated_at", None, "generation time"),
        ):
            with self.subTest(field=field):
                original = section[field]
                section[field] = bad_value
                with self.assertRaisesRegex(proof_manifest.ProofManifestError, message):
                    proof_manifest.validate_declared_currentness(manifest)
                section[field] = original

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
        ):
            with self.subTest(section=section, key=key), self.assertRaisesRegex(
                proof_manifest.ProofManifestError,
                "unknown status",
            ):
                proof_manifest.validate_declared_currentness(
                    {section: {key: "current_pass_typo"}}
                )

    def make_fixture(self, root: pathlib.Path) -> pathlib.Path:
        proof = root / "proofs" / "selected.json"
        proof.parent.mkdir()
        proof.write_bytes(b'{"status":"pass"}\n')
        digest = hashlib.sha256(proof.read_bytes()).hexdigest()
        artifact = root / "artifact"
        artifact.mkdir()
        (artifact / "results.json").write_text(
            "{\n"
            '  "performance": {\n'
            '    "proof_path": "proofs/selected.json",\n'
            f'    "proof_sha256": "{digest}"\n'
            "  }\n"
            "}\n",
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

    def test_hash_mismatch_and_duplicate_manifest_keys_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            proof = self.make_fixture(root)
            manifest_path = root / "artifact" / "results.json"
            manifest_path.write_text(
                '{"performance":{"proof_path":"proofs/selected.json",'
                '"proof_sha256":"' + "0" * 64 + '"}}',
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
                    '{"performance":{"proof_path":"'
                    + relative.replace("\\", "\\\\")
                    + '","proof_sha256":"'
                    + digest
                    + '"}}',
                    encoding="utf-8",
                )
                manifest = load_results_manifest_snapshot(
                    root / "artifact" / "results.json"
                )
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
                '{"performance":{"proof_path":"proofs/external/selected.json",'
                f'"proof_sha256":"{digest}"' + "}}",
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
