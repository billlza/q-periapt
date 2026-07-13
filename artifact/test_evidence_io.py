from __future__ import annotations

import ast
import hashlib
import os
import pathlib
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

import evidence_io
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

    def test_binary_snapshot_preserves_every_byte(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "proof.bin"
            data = b"first\r\nsecond\x1a\x00last\r\n"
            path.write_bytes(data)
            snapshot = read_regular_snapshot(
                path, maximum=len(data), label="binary proof"
            )
            self.assertEqual(snapshot.data, data)
            self.assertEqual(snapshot.size, len(data))
            self.assertEqual(snapshot.sha256, hashlib.sha256(data).hexdigest())

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

    def test_symlink_directory_fifo_and_oversize_files_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            target = root / "target.json"
            target.write_text("{}", encoding="utf-8")
            symlink = root / "link.json"
            symlink.symlink_to(target)
            with self.assertRaisesRegex(EvidenceIOError, "reparse|safely open"):
                read_regular_snapshot(symlink, maximum=1024, label="symlink")

            directory = root / "directory"
            directory.mkdir()
            with self.assertRaises(EvidenceIOError):
                read_regular_snapshot(directory, maximum=1024, label="directory")

            if os.name == "posix":
                fifo = root / "proof.fifo"
                os.mkfifo(fifo)
                with self.assertRaisesRegex(EvidenceIOError, "not a regular file"):
                    read_regular_snapshot(fifo, maximum=1024, label="FIFO")
            else:
                self.assertEqual(os.name, "nt")
                self.assertFalse(hasattr(os, "mkfifo"))

            oversize = root / "large.json"
            oversize.write_bytes(b"x" * 17)
            with self.assertRaisesRegex(EvidenceIOError, "exceeds 16 bytes"):
                read_regular_snapshot(oversize, maximum=16, label="large proof")
            moved_oversize = root / "moved-large.json"
            oversize.rename(moved_oversize)
            moved_oversize.rename(oversize)

    def test_ancestor_directory_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            outside = root / "outside"
            outside.mkdir()
            (outside / "proof.json").write_text("{}", encoding="utf-8")
            linked = root / "linked"
            linked.symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(EvidenceIOError, "reparse|cannot safely open"):
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

    def test_descriptor_metadata_change_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "proof.bin"
            path.write_bytes(b"stable bytes")
            with mock.patch.object(
                evidence_io,
                "_descriptor_identity",
                side_effect=[("before",), ("after",)],
            ):
                with self.assertRaisesRegex(EvidenceIOError, "changed while it was read"):
                    read_regular_snapshot(
                        path, maximum=1024, label="mutating proof"
                    )

    def test_windows_ambiguous_path_forms_fail_closed(self) -> None:
        if os.name != "nt":
            self.assertEqual(os.name, "posix")
            return

        cases = (
            pathlib.Path(r"\\server\share\proof.json"),
            pathlib.Path(r"\\?\C:\proof.json"),
            pathlib.Path(r"\\.\C:\proof.json"),
            pathlib.Path(r"\??\C:\proof.json"),
            pathlib.Path(r"C:relative\proof.json"),
            pathlib.Path(r"\root-relative\proof.json"),
            pathlib.Path("proof.json:stream"),
            pathlib.Path("NUL.txt"),
            pathlib.Path("CONIN$.txt"),
            pathlib.Path("CONOUT$.txt"),
            pathlib.Path("trailing-dot."),
            pathlib.Path("trailing-space "),
            pathlib.Path("wildcard*.json"),
            pathlib.Path("surrogate-\ud800.json"),
        )
        for path in cases:
            with self.subTest(path=path), self.assertRaises(EvidenceIOError):
                read_regular_snapshot(path, maximum=1024, label="unsafe path")

    def test_windows_junction_ancestor_is_rejected(self) -> None:
        if os.name != "nt":
            self.assertEqual(os.name, "posix")
            return

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            outside = root / "outside"
            outside.mkdir()
            proof = outside / "proof.json"
            proof.write_text("{}", encoding="utf-8")
            junction = root / "junction"
            subprocess.run(
                [
                    "cmd.exe",
                    "/d",
                    "/c",
                    "mklink",
                    "/J",
                    os.fspath(junction),
                    os.fspath(outside),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            attributes = junction.lstat().st_file_attributes
            self.assertTrue(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)
            with self.assertRaisesRegex(EvidenceIOError, "reparse|safely open"):
                read_regular_snapshot(
                    junction / proof.name,
                    maximum=1024,
                    label="junction proof",
                )
            junction.rmdir()
            self.assertTrue(outside.is_dir())
            self.assertEqual(proof.read_text(encoding="utf-8"), "{}")

    def test_windows_subst_root_is_rejected(self) -> None:
        if os.name != "nt":
            self.assertEqual(os.name, "posix")
            return

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            (root / "proof.bin").write_bytes(b"stable")
            drive = next(
                (
                    f"{letter}:"
                    for letter in reversed("DEFGHIJKLMNOPQRSTUVWXYZ")
                    if not pathlib.Path(f"{letter}:\\").exists()
                ),
                None,
            )
            if drive is None:
                self.fail("no unused drive letter is available for SUBST")
            subprocess.run(
                ["subst.exe", drive, os.fspath(root)],
                check=True,
                capture_output=True,
                text=True,
            )
            try:
                with self.assertRaisesRegex(EvidenceIOError, "volume root|fixed local drive"):
                    read_regular_snapshot(
                        pathlib.Path(f"{drive}\\proof.bin"),
                        maximum=1024,
                        label="SUBST proof",
                    )
            finally:
                subprocess.run(
                    ["subst.exe", drive, "/D"],
                    check=True,
                    capture_output=True,
                    text=True,
                )

    def test_windows_open_handles_block_replacement_until_snapshot_finishes(self) -> None:
        if os.name != "nt":
            self.assertEqual(os.name, "posix")
            return

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary) / "owned"
            root.mkdir()
            path = root / "proof.bin"
            path.write_bytes(b"stable")
            moved_root = root.with_name("moved-owned")
            attempted: list[bool] = []
            real_open_relative = evidence_io._windows_open_relative

            def open_relative(parent, component, **kwargs):
                if component == path.name:
                    with self.assertRaises(OSError):
                        root.rename(moved_root)
                    attempted.append(True)
                return real_open_relative(parent, component, **kwargs)

            with mock.patch.object(
                evidence_io,
                "_windows_open_relative",
                side_effect=open_relative,
            ):
                snapshot = read_regular_snapshot(
                    path, maximum=1024, label="replacement proof"
                )
            self.assertEqual(snapshot.data, b"stable")
            self.assertEqual(attempted, [True])
            root.rename(moved_root)
            moved_root.rename(root)

    def test_windows_final_handle_blocks_writes_and_rename_during_read(self) -> None:
        if os.name != "nt":
            self.assertEqual(os.name, "posix")
            return

        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "proof.bin"
            path.write_bytes(b"stable")
            replacement = path.with_name("replacement.bin")
            real_read = evidence_io.os.read
            attempted: list[bool] = []

            def read_with_replacement_check(descriptor: int, size: int) -> bytes:
                if not attempted:
                    with self.assertRaises(OSError):
                        path.rename(replacement)
                    with self.assertRaises(OSError):
                        path.write_bytes(b"changed")
                    attempted.append(True)
                return real_read(descriptor, size)

            with mock.patch.object(
                evidence_io.os,
                "read",
                side_effect=read_with_replacement_check,
            ):
                snapshot = read_regular_snapshot(
                    path, maximum=1024, label="locked proof"
                )
            self.assertEqual(snapshot.data, b"stable")
            self.assertEqual(attempted, [True])
            path.rename(replacement)
            replacement.rename(path)

    def test_windows_existing_writer_is_rejected(self) -> None:
        if os.name != "nt":
            self.assertEqual(os.name, "posix")
            return

        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "proof.bin"
            path.write_bytes(b"stable")
            with path.open("r+b"):
                with self.assertRaisesRegex(EvidenceIOError, "cannot safely open"):
                    read_regular_snapshot(
                        path,
                        maximum=1024,
                        label="writer-locked proof",
                    )
            self.assertEqual(
                read_regular_snapshot(path, maximum=1024, label="released proof").data,
                b"stable",
            )

    def test_windows_read_failure_releases_every_handle(self) -> None:
        if os.name != "nt":
            self.assertEqual(os.name, "posix")
            return

        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "proof.bin"
            path.write_bytes(b"stable")
            moved = path.with_name("moved.bin")
            with mock.patch.object(
                evidence_io.os,
                "read",
                side_effect=OSError("synthetic read failure"),
            ):
                with self.assertRaisesRegex(EvidenceIOError, "synthetic read failure"):
                    read_regular_snapshot(
                        path,
                        maximum=1024,
                        label="read-failure proof",
                    )
            path.rename(moved)
            moved.rename(path)

    def test_windows_conversion_failure_releases_every_handle(self) -> None:
        if os.name != "nt":
            self.assertEqual(os.name, "posix")
            return

        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "proof.bin"
            path.write_bytes(b"stable")
            moved = path.with_name("moved.bin")
            with mock.patch.object(
                evidence_io.msvcrt,
                "open_osfhandle",
                side_effect=OSError("synthetic conversion failure"),
            ):
                with self.assertRaisesRegex(
                    EvidenceIOError, "synthetic conversion failure"
                ):
                    read_regular_snapshot(
                        path, maximum=1024, label="conversion proof"
                    )
            path.rename(moved)
            moved.rename(path)

    def test_windows_binary_mode_failure_releases_transferred_handle(self) -> None:
        if os.name != "nt":
            self.assertEqual(os.name, "posix")
            return

        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "proof.bin"
            path.write_bytes(b"stable")
            moved = path.with_name("moved.bin")
            with mock.patch.object(
                evidence_io.msvcrt,
                "setmode",
                side_effect=OSError("synthetic binary-mode failure"),
            ):
                with self.assertRaisesRegex(
                    EvidenceIOError, "synthetic binary-mode failure"
                ):
                    read_regular_snapshot(
                        path,
                        maximum=1024,
                        label="binary-mode proof",
                    )
            path.rename(moved)
            moved.rename(path)

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
