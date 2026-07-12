from __future__ import annotations

import ast
import hashlib
import os
import pathlib
import tempfile
import unittest

from evidence_io import (
    EvidenceIOError,
    load_json_object_snapshot,
    parse_strict_json_bytes,
    read_regular_snapshot,
)


class EvidenceIOTests(unittest.TestCase):
    def test_snapshot_hash_and_parse_use_the_same_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "proof.json"
            data = b'{"status":"pass","nested":{"value":1}}\n'
            path.write_bytes(data)
            snapshot = load_json_object_snapshot(
                path, maximum=1024, label="test proof"
            )
            self.assertEqual(snapshot.file.data, data)
            self.assertEqual(snapshot.file.sha256, hashlib.sha256(data).hexdigest())
            self.assertEqual(snapshot.value["nested"], {"value": 1})

            path.write_bytes(b'{"status":"replaced"}\n')
            self.assertEqual(snapshot.value["status"], "pass")
            self.assertEqual(snapshot.file.sha256, hashlib.sha256(data).hexdigest())

    def test_duplicate_keys_are_rejected_at_every_depth(self) -> None:
        for payload in (
            b'{"status":"fail","status":"pass"}',
            b'{"outer":{"gate":false,"gate":true}}',
        ):
            with self.subTest(payload=payload):
                with self.assertRaisesRegex(EvidenceIOError, "duplicate JSON key"):
                    parse_strict_json_bytes(payload, label="duplicate test")

    def test_nonfinite_constants_are_rejected(self) -> None:
        for constant in (b"NaN", b"Infinity", b"-Infinity"):
            with self.subTest(constant=constant):
                with self.assertRaisesRegex(EvidenceIOError, "non-finite JSON number"):
                    parse_strict_json_bytes(
                        b'{"value":' + constant + b"}", label="constant test"
                    )

    def test_finite_syntax_that_overflows_binary64_is_rejected(self) -> None:
        for number in (b"1e999", b"-1e999", b"1.7976931348623159e308"):
            with self.subTest(number=number):
                with self.assertRaisesRegex(EvidenceIOError, "non-finite JSON number"):
                    parse_strict_json_bytes(
                        b'{"value":' + number + b"}", label="overflow test"
                    )

        parsed = parse_strict_json_bytes(
            b'{"value":1.7976931348623157e308}', label="finite test"
        )
        self.assertEqual(parsed["value"], 1.7976931348623157e308)

    def test_oversized_integer_failure_is_wrapped(self) -> None:
        with self.assertRaisesRegex(EvidenceIOError, "strict UTF-8 JSON"):
            parse_strict_json_bytes(
                b'{"value":' + b"9" * 5000 + b"}", label="large integer test"
            )

    def test_invalid_utf8_and_non_object_roots_are_rejected(self) -> None:
        with self.assertRaisesRegex(EvidenceIOError, "strict UTF-8 JSON"):
            parse_strict_json_bytes(b'{"value":"\xff"}', label="UTF-8 test")
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "array.json"
            path.write_text("[]", encoding="utf-8")
            with self.assertRaisesRegex(EvidenceIOError, "root must be a JSON object"):
                load_json_object_snapshot(path, maximum=1024, label="object test")

    def test_symlink_fifo_and_oversize_files_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            target = root / "target.json"
            target.write_text("{}", encoding="utf-8")
            symlink = root / "link.json"
            symlink.symlink_to(target)
            with self.assertRaises(EvidenceIOError):
                read_regular_snapshot(symlink, maximum=1024, label="symlink")

            fifo = root / "proof.fifo"
            os.mkfifo(fifo)
            with self.assertRaisesRegex(EvidenceIOError, "not a regular file"):
                read_regular_snapshot(fifo, maximum=1024, label="FIFO")

            oversize = root / "large.json"
            oversize.write_bytes(b"x" * 17)
            with self.assertRaisesRegex(EvidenceIOError, "exceeds 16 bytes"):
                read_regular_snapshot(oversize, maximum=16, label="large proof")

    def test_ancestor_directory_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            outside = root / "outside"
            outside.mkdir()
            (outside / "proof.json").write_text("{}", encoding="utf-8")
            linked = root / "linked"
            linked.symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(EvidenceIOError, "cannot safely open"):
                read_regular_snapshot(
                    linked / "proof.json", maximum=1024, label="ancestor symlink"
                )

    def test_parent_traversal_is_rejected_before_open(self) -> None:
        with self.assertRaisesRegex(EvidenceIOError, "must not contain '..'"):
            read_regular_snapshot(
                pathlib.Path("artifact") / ".." / "artifact" / "results.json",
                maximum=1024 * 1024,
                label="traversal",
            )

    def test_production_artifact_modules_do_not_bypass_strict_json(self) -> None:
        artifact = pathlib.Path(__file__).resolve().parent
        violations = []
        for path in sorted(artifact.glob("*.py")):
            if path.name.startswith("test_") or path.name == "evidence_io.py":
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                    continue
                if (
                    isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "json"
                    and node.func.attr in {"load", "loads"}
                ):
                    violations.append(f"{path.name}:{node.lineno}:json.{node.func.attr}")
        self.assertEqual(violations, [])


if __name__ == "__main__":
    unittest.main()
