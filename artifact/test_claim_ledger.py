import json
import pathlib
import subprocess
import tempfile
import unittest
from unittest import mock

import claim_ledger
from claim_ledger import (
    LedgerError,
    canonical_tree_digest,
    repository_paths,
    validate_ledger,
    verify,
)
from evidence_io import load_json_object_snapshot


REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parents[1]


class ClaimLedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        (self.root / "evidence.txt").write_text("proof", encoding="utf-8")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def ledger(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "claims": [
                {
                    "id": "C-1",
                    "title": "claim",
                    "status": "implementation_tested",
                    "boundary": "test boundary",
                    "evidence": {"tests": ["evidence.txt"]},
                }
            ],
        }

    def test_valid_ledger_and_tree_digest_are_deterministic(self) -> None:
        validate_ledger(self.root, self.ledger())
        first = canonical_tree_digest(self.root, ["evidence.txt"])
        second = canonical_tree_digest(self.root, ["evidence.txt", "evidence.txt"])
        self.assertEqual(first, second)
        (self.root / "evidence.txt").write_text("changed", encoding="utf-8")
        self.assertNotEqual(first, canonical_tree_digest(self.root, ["evidence.txt"]))

    def test_duplicate_claim_and_path_traversal_fail_closed(self) -> None:
        ledger = self.ledger()
        ledger["claims"] = [ledger["claims"][0], ledger["claims"][0]]
        with self.assertRaises(LedgerError):
            validate_ledger(self.root, ledger)

    def test_generated_manifest_and_camera_transcript_do_not_self_hash(self) -> None:
        (self.root / "artifact").mkdir()
        (self.root / "paper").mkdir()
        manifest = self.root / "artifact" / "results.json"
        transcript = self.root / "paper" / "camera-ready-results.txt"
        manifest.write_text("first manifest", encoding="utf-8")
        transcript.write_text("first transcript", encoding="utf-8")
        paths = ["evidence.txt", "artifact/results.json", "paper/camera-ready-results.txt"]
        before = canonical_tree_digest(self.root, paths)
        manifest.write_text("second manifest", encoding="utf-8")
        transcript.write_text("second transcript", encoding="utf-8")
        self.assertEqual(before, canonical_tree_digest(self.root, paths))
        ledger = self.ledger()
        ledger["claims"][0]["evidence"] = {"tests": ["../escape"]}
        with self.assertRaises(LedgerError):
            validate_ledger(self.root, ledger)

    def test_non_pending_claim_requires_concrete_evidence(self) -> None:
        ledger = self.ledger()
        ledger["claims"][0]["evidence"] = {"tests": []}
        with self.assertRaises(LedgerError):
            validate_ledger(self.root, ledger)

    def make_verify_fixture(self) -> tuple[pathlib.Path, pathlib.Path]:
        artifact = self.root / "artifact"
        artifact.mkdir(exist_ok=True)
        ledger_path = artifact / "claim-ledger.json"
        manifest_path = artifact / "results.json"
        ledger_path.write_text(
            json.dumps(self.ledger(), sort_keys=True) + "\n", encoding="utf-8"
        )
        subprocess.run(["git", "init", "-q"], cwd=self.root, check=True)
        actual = canonical_tree_digest(self.root, repository_paths(self.root))
        manifest_path.write_text(
            json.dumps({"proof_source_tree_sha256": actual}) + "\n",
            encoding="utf-8",
        )
        return ledger_path, manifest_path

    def test_verify_rejects_duplicate_keys_in_ledger_and_manifest(self) -> None:
        ledger_path, manifest_path = self.make_verify_fixture()
        ledger_path.write_text(
            '{"schema_version":1,"schema_version":1,"claims":[]}',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(LedgerError, "duplicate JSON key"):
            verify(self.root, ledger_path, manifest_path)

        ledger_path.write_text(
            json.dumps(self.ledger(), sort_keys=True), encoding="utf-8"
        )
        manifest_path.write_text(
            '{"proof_source_tree_sha256":"'
            + "0" * 64
            + '","proof_source_tree_sha256":"'
            + "0" * 64
            + '"}',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(LedgerError, "duplicate JSON key"):
            verify(self.root, ledger_path, manifest_path)

    def test_validated_ledger_bytes_are_pinned_into_tree_digest(self) -> None:
        ledger_path, manifest_path = self.make_verify_fixture()
        original = ledger_path.read_bytes()
        paths = repository_paths(self.root)
        expected = canonical_tree_digest(
            self.root,
            paths,
            pinned_files={"artifact/claim-ledger.json": original},
        )
        manifest_path.write_text(
            json.dumps({"proof_source_tree_sha256": expected}) + "\n",
            encoding="utf-8",
        )
        real_loader = load_json_object_snapshot

        def load_then_replace(path: pathlib.Path, *, maximum: int, label: str):
            snapshot = real_loader(path, maximum=maximum, label=label)
            if label == "claim ledger":
                ledger_path.write_text(
                    json.dumps({"schema_version": 1, "claims": []}) + "\n",
                    encoding="utf-8",
                )
            return snapshot

        with mock.patch.object(
            claim_ledger,
            "load_json_object_snapshot",
            side_effect=load_then_replace,
        ):
            self.assertEqual(expected, verify(self.root, ledger_path, manifest_path))

    def test_repository_migration_claims_are_evidence_bound_and_scoped(self) -> None:
        ledger_path = REPOSITORY_ROOT / "artifact" / "claim-ledger.json"
        ledger = load_json_object_snapshot(
            ledger_path,
            maximum=claim_ledger.MAX_CLAIM_LEDGER_BYTES,
            label="repository claim ledger",
        ).value
        validate_ledger(REPOSITORY_ROOT, ledger)
        claims = {claim["id"]: claim for claim in ledger["claims"]}
        expected = {
            "MIG-BIND-K-STATE-V2": "formal/easycrypt/MigrationBindingV2.ec",
            "MIG-ROLLBACK-V2": "formal/tamarin/migration_v2_no_witness.spthy",
            "MIG-AGREE-V2": "formal/tamarin/migration_v2_agreement.spthy",
            "MIG-FLOOR-V2": "formal/tamarin/migration_v2_negative_controls.spthy",
        }
        for claim_id, formal_path in expected.items():
            with self.subTest(claim_id=claim_id):
                claim = claims[claim_id]
                self.assertEqual(claim["status"], "machine_checked")
                self.assertIn(formal_path, claim["evidence"]["formal"])
                self.assertIn("not", claim["boundary"].lower())
                self.assertTrue(
                    "refinement" in claim["boundary"].lower()
                    or "correspondence" in claim["boundary"].lower()
                )

        migration_claim = claims["MIG-BIND-K-STATE-V2"]
        migration_boundary = migration_claim["boundary"].lower()
        for required_boundary in (
            "one abstract h_sha3",
            "four-field current staterevisionv1 recheck",
            "h_accept or h_context",
            "add h_state",
            "post-digest-only",
            "not finished forgery",
            "not independently derive k_abi2",
            "formal-to-rust",
        ):
            with self.subTest(required_boundary=required_boundary):
                self.assertIn(required_boundary, migration_boundary)

        migration_source = (
            REPOSITORY_ROOT / "formal" / "easycrypt" / "MigrationBindingV2.ec"
        ).read_text(encoding="utf-8")
        for required_formal in (
            "op H_sha3 : bytes -> bytes.",
            "type state_revision = {",
            "type accepted_session_key = {",
            "lemma mig_bind_k_state_bad_event_decomposition",
            "lemma mig_bind_k_revision_bad_event_decomposition",
            "lemma honest_role_kem_direction_nonvacuous",
            "lemma stale_current_recheck_both_roles_negative_control",
            "lemma peer_finished_both_roles_negative_control",
            "lemma omitted_state_end_to_end_negative_control",
            "lemma omitted_post_ciphertext_negative_control",
            "lemma omitted_finished_role_negative_control",
            "lemma omitted_accept_finished_negative_control",
        ):
            with self.subTest(required_formal=required_formal):
                self.assertIn(required_formal, migration_source)
        self.assertNotIn(
            "op migration_accepted : migration_execution -> bool.",
            migration_source,
        )

    def test_prepublication_security_claim_does_not_invent_live_tag_facts(self) -> None:
        ledger = load_json_object_snapshot(
            REPOSITORY_ROOT / "artifact" / "claim-ledger.json",
            maximum=claim_ledger.MAX_CLAIM_LEDGER_BYTES,
            label="repository claim ledger",
        ).value
        claims = {claim["id"]: claim for claim in ledger["claims"]}
        security = claims["SOURCE-SECURITY-CODE-SCANNING-ADJUDICATION"]
        boundary = security["boundary"]
        self.assertIn("eventual exact-R receipt", boundary)
        self.assertIn("actual result count", boundary)
        self.assertIn("zero unadjudicated findings", boundary)
        self.assertNotIn("At the tagged commit", boundary)
        self.assertNotIn("199 results", boundary)

        android = claims["ANDROID-RUNTIME-DIAGNOSTIC-CURRENTNESS"]["boundary"]
        self.assertIn("not a prerequisite for stable package publication", android)
        self.assertIn("production aggregate stays pending", android)


if __name__ == "__main__":
    unittest.main()
