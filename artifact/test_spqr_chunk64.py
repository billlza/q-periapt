"""Negative controls for a modified reference workspace and its source receipts."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from artifact import spqr_chunk64 as variant
from artifact import spqr_reference as ref


class Chunk64Tests(unittest.TestCase):
    def test_dependency_change_cannot_hide_behind_path_override(self):
        baseline = (variant.DRIVER/"Cargo.lock").read_bytes()
        source_line = (f'source = "git+https://github.com/signalapp/SparsePostQuantumRatchet?rev={ref.REVISION}#{ref.REVISION}"\n').encode()
        self.assertEqual(baseline.count(source_line), 1)
        correct = baseline.replace(source_line, b"")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root/"upstream").mkdir()
            (root/"driver").mkdir()
            original = b"upstream lock identity control\n"
            (root/"upstream/Cargo.lock").write_bytes(original)
            with patch.object(ref, "UPSTREAM_LOCK", hashlib.sha256(original).hexdigest()):
                for lock in (correct, baseline, correct.replace(b'version = "1.5.1"', b'version = "1.5.2"'),
                             correct.replace(b'name = "hkdf"', b'name = "unapproved-kdf"')):
                    (root/"driver/Cargo.lock").write_bytes(lock)
                    if lock == correct:
                        variant.check_dependencies(root)
                    else:
                        with self.assertRaises(ref.ReferenceError): variant.check_dependencies(root)
                (root/"driver/Cargo.lock").write_bytes(correct)
                (root/"upstream/Cargo.lock").write_bytes(original+b"changed")
                with self.assertRaises(ref.ReferenceError): variant.check_dependencies(root)

    def test_inventory_detects_added_changed_and_removed_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root/"source.rs").write_bytes(b"original source")
            initial = variant.inventory(root)
            (root/"source.rs").write_bytes(b"different source")
            self.assertNotEqual(variant.inventory(root), initial)
            (root/"source.rs").write_bytes(b"original source")
            (root/"extra.rs").write_bytes(b"unrecorded source")
            self.assertNotEqual(variant.inventory(root), initial)
            (root/"source.rs").unlink()
            self.assertNotEqual(variant.inventory(root), initial)

    def test_preparation_cannot_claim_unmodified_conformance_or_inherited_proof(self):
        receipt = {"schema":1,"profile":variant.PROFILE,"identity":{},"files":{},
                   "component_conformance_claim":False,"inherited_formal_proof_claim":False}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            for field, value in (("schema",True),("profile","public_api_v1"),
                                 ("component_conformance_claim",True),("inherited_formal_proof_claim",True),
                                 ("unrecorded_field",True)):
                modified = copy.deepcopy(receipt)
                modified[field] = value
                (root/"preparation.json").write_text(json.dumps(modified))
                with self.subTest(field=field), self.assertRaises(ref.ReferenceError):
                    variant.verify_preparation(root)


if __name__ == "__main__":
    unittest.main(warnings="error")
