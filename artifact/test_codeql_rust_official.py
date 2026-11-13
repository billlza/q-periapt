"""Reject query-pack mutation while admitting the full official-plan contract."""
from __future__ import annotations

from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import codeql_rust_official as official


@unittest.skipUnless(os.name == "posix" and hasattr(os, "geteuid"), "pack metadata checks require POSIX")
class OfficialPackTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.pack = self.root / "pack"
        self.pack.mkdir()
        self.evidence = self.root / "evidence"
        self.evidence.mkdir()
        self.manifest = self.root / "queries.json"
        names = json.loads(official.QUERY_MANIFEST.read_text())["queries"]
        self.queries = {}
        self.compiled = {}
        for name in names:
            data = ("// " + name + "\n").encode()
            self.write(name, data)
            self.queries[name] = hashlib.sha256(data).hexdigest()
            compiled = ("compiled " + name).encode()
            self.write(str(Path(name).with_suffix(".qlx")), compiled)
            self.compiled[name] = hashlib.sha256(compiled).hexdigest()
        self.dependency = ".codeql/libraries/codeql/rust-all/model.yml"
        self.write(self.dependency, b"fixed model\n")
        self.value = {"codeql_version": "2.27.4", "query_pack": "0.1.46", "queries": self.queries}
        self.manifest.write_text(json.dumps(self.value))
        self.identity = official.expected_identity()
        files = self.inventory()
        self.identity.update(
            query_manifest_sha256=hashlib.sha256(self.manifest.read_bytes()).hexdigest(),
            query_source_sha256=self.queries["queries/summary/SummaryStats.ql"],
            compiled_inventory_sha256=official.canonical_sha(self.compiled),
            pack_inventory_sha256=official.canonical_sha(files), pack_file_count=len(files),
            pack_total_bytes=sum(item["bytes"] for item in files.values()))
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch.object(official, "QUERY_MANIFEST", self.manifest))
        stack.enter_context(patch.object(official, "expected_identity", return_value=self.identity))

    def write(self, name, data):
        path = self.pack / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(0o600)

    def inventory(self):
        return {path.relative_to(self.pack).as_posix(): {
            "bytes": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "mode": path.stat().st_mode & 0o777}
            for path in self.pack.rglob("*") if path.is_file()}

    def test_admission_preserves_every_pack_byte_and_records_the_identity(self):
        before = self.inventory()
        self.assertEqual(official.admit(self.pack, self.evidence), self.identity)
        self.assertEqual(self.inventory(), before)
        self.assertEqual(json.loads((self.evidence / "SUMMARY_PLAN.json").read_text()), self.identity)

    def test_full_summary_plan_and_dependency_replacements_are_rejected(self):
        for name in ("queries/summary/SummaryStats.qlx", self.dependency):
            with self.subTest(name=name):
                path = self.pack / name
                original = path.read_bytes()
                path.write_bytes(b"x" * len(original))
                with self.assertRaisesRegex(ValueError, "pack inventory differs"):
                    official.validate(self.pack)
                path.write_bytes(original)

    def test_extra_model_or_missing_full_summary_is_rejected(self):
        extra = self.pack / "unadmitted.model.yml"
        extra.write_text("new source/sink model")
        with self.assertRaisesRegex(ValueError, "pack inventory differs"):
            official.validate(self.pack)
        extra.unlink()
        (self.pack / "queries/summary/SummaryStats.qlx").unlink()
        with self.assertRaisesRegex(ValueError, "pack inventory differs"):
            official.validate(self.pack)

    def test_changed_query_manifest_cannot_reuse_pack_admission(self):
        self.manifest.write_text(json.dumps({**self.value, "query_pack": "0.1.44"}))
        with self.assertRaisesRegex(ValueError, "root query manifest differs"):
            official.validate(self.pack)

    def test_full_summary_is_required_even_with_rebound_manifest_digest(self):
        self.value["queries"] = {name: digest for name, digest in self.queries.items()
                                 if name != "queries/summary/SummaryStats.ql"}
        self.manifest.write_text(json.dumps(self.value))
        self.identity["query_manifest_sha256"] = hashlib.sha256(self.manifest.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError, "full query census differs"):
            official.validate(self.pack)

    def test_group_writable_pack_member_is_rejected(self):
        (self.pack / self.dependency).chmod(0o660)
        with self.assertRaisesRegex(ValueError, "writable mode differs"):
            official.validate(self.pack)

    def test_linked_pack_member_is_rejected(self):
        os.link(self.pack / self.dependency, self.root / "linked-model")
        with self.assertRaisesRegex(ValueError, "ownership or links differ"):
            official.validate(self.pack)

    def test_symlink_pack_directory_is_rejected(self):
        (self.pack / "foreign").symlink_to(self.root / "evidence", target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "directory is nonregular"):
            official.validate(self.pack)


if __name__ == "__main__":
    unittest.main()
