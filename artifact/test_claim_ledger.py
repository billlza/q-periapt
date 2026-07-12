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


if __name__ == "__main__":
    unittest.main()
