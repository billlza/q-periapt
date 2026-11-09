"""Input-identity and path controls for the independent public-trace audit."""
from contextlib import redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location(
    "matched_trace_audit", Path(__file__).resolve().with_name("audit_matched_traces.py"))
if spec is None or spec.loader is None:
    raise ImportError("independent trace audit module is unavailable")
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class AuditInputBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="qperiapt-audit-input-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_regular_file_bytes_and_digest_agree(self):
        path = self.root / "record.json"
        data = '{"label":"来源"}\n'.encode("utf-8")
        path.write_bytes(data)
        self.assertEqual(audit.read_bytes(path), data)
        self.assertEqual(audit.read(path), {"label": "来源"})
        self.assertEqual(audit.digest(path), hashlib.sha256(data).hexdigest())

    def test_nonregular_inputs_are_rejected(self):
        real = self.root / "real.json"
        real.write_bytes(b"{}\n")
        link = self.root / "link.json"
        link.symlink_to(real)
        paths = [self.root, self.root / "missing", link]
        if hasattr(os, "mkfifo"):
            pipe = self.root / "fifo"
            os.mkfifo(pipe)
            paths.append(pipe)
        for path in paths:
            with self.subTest(path=path.name), self.assertRaisesRegex(ValueError, "nonregular"):
                audit.read_bytes(path)

    def test_manifest_rejects_noncanonical_and_cross_platform_escapes(self):
        for value in ("", ".", "..", "../outside", "/outside", "a/../outside",
                      "a/./b", "a//b", "a/", "C:/outside", "C:outside",
                      "a\\b", "\\\\server\\share", None, 17):
            with self.subTest(value=value), self.assertRaises(ValueError):
                audit.manifest_path(self.root, value)

    def test_manifest_rejects_leaf_and_directory_symlinks(self):
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "record.json").write_bytes(b"{}\n")
        evidence = self.root / "evidence"
        evidence.mkdir()
        (evidence / "leaf.json").symlink_to(outside / "record.json")
        (evidence / "directory").symlink_to(outside, target_is_directory=True)
        for value in ("leaf.json", "directory/record.json"):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "symlink"):
                audit.manifest_path(evidence, value)
        (evidence / "inside").mkdir()
        (evidence / "inside/record.json").write_bytes(b"{}\n")
        self.assertEqual(audit.manifest_path(evidence, "inside/record.json"),
                         evidence / "inside/record.json")

    def test_replacement_between_stat_and_open_is_rejected(self):
        victim = self.root / "victim.json"
        replacement = self.root / "replacement.json"
        victim.write_bytes(b"one")
        replacement.write_bytes(b"two")
        original_open = Path.open

        def replace_then_open(path, *args, **kwargs):
            if path == victim:
                replacement.replace(victim)
            return original_open(path, *args, **kwargs)

        with mock.patch.object(Path, "open", replace_then_open):
            with self.assertRaisesRegex(ValueError, "replaced before reading"):
                audit.read_bytes(victim)

    def test_change_during_descriptor_read_is_rejected(self):
        path = self.root / "changing.json"
        path.write_bytes(b"{}\n")
        original_open = Path.open

        class ChangingReader:
            def __init__(self, source):
                self.source = source

            def __enter__(self):
                return self

            def __exit__(self, *args):
                self.source.close()

            def fileno(self):
                return self.source.fileno()

            def read(self):
                data = self.source.read()
                with original_open(path, "ab") as changed:
                    changed.write(b" ")
                return data

        def changing_open(selected, *args, **kwargs):
            source = original_open(selected, *args, **kwargs)
            return ChangingReader(source) if selected == path else source

        with mock.patch.object(Path, "open", changing_open):
            with self.assertRaisesRegex(ValueError, "changed while reading"):
                audit.read_bytes(path)

    def test_compact_digest_binds_parsed_bytes_after_a_later_path_change(self):
        evidence = self.root / "evidence"
        evidence.mkdir()
        data = b"abc"
        files = []
        for index in range(126):
            name = f"object-{index}.bin"
            (evidence / name).write_bytes(data)
            files.append({"path": name, "bytes": len(data),
                          "sha256": hashlib.sha256(data).hexdigest()})
        (evidence / "manifest.json").write_text(json.dumps({"status": "complete", "files": files}))
        expected = {(p, s): {"profile": p, "scenario": s, "value": "original"}
                    for p in audit.PROFILES for s in audit.SCENARIOS}
        compact = self.root / "compact.json"
        compact_bytes = json.dumps(list(expected.values())).encode("utf-8")
        compact.write_bytes(compact_bytes)
        output = self.root / "audit.json"
        changed = False

        def native(path, profile, scenario):
            nonlocal changed
            if not changed:
                compact.write_bytes(b"[]\n")
                changed = True
            return expected[profile, scenario], {"profile": profile, "scenario": scenario}

        def reference(directory, profile, scenario):
            return expected[profile, scenario]

        # Only trace recounting is replaced: this control exercises the real
        # manifest admission, compact parsing and final report construction.
        with mock.patch.object(sys, "argv", ["audit", str(evidence), str(compact), str(output)]), \
             mock.patch.object(audit, "native", native), \
             mock.patch.object(audit, "reference", reference), redirect_stdout(io.StringIO()):
            audit.main()
        report = json.loads(output.read_text())
        self.assertEqual(report["compact_results_sha256"], hashlib.sha256(compact_bytes).hexdigest())
        self.assertNotEqual(report["compact_results_sha256"], hashlib.sha256(compact.read_bytes()).hexdigest())
        self.assertEqual(report["compact_rows_equal"], 49)


if __name__ == "__main__":
    unittest.main()
