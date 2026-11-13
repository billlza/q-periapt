from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import zipfile

import ci_protoc as bootstrap


class ProtocBootstrapTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.environment = self.root / "environment"
        self.search_path = self.root / "path"
        self.environment.write_text("EXISTING=kept\n")
        self.search_path.write_text("/existing/bin\n")
        self.installations = self.root / "installations"
        self.installations.mkdir()
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("bin/protoc", b"controlled executable fixture")
            archive.writestr("include/google/protobuf/timestamp.proto", b"schema fixture")
        self.archive = stream.getvalue()
        for patch in (
            mock.patch.object(bootstrap.platform, "system", return_value="Linux"),
            mock.patch.object(bootstrap.platform, "machine", return_value="x86_64"),
            mock.patch.object(bootstrap, "SIZE", len(self.archive)),
            mock.patch.object(bootstrap, "SHA256", hashlib.sha256(self.archive).hexdigest()),
            mock.patch.dict(os.environ, {"RUNNER_TEMP": str(self.installations),
                                        "GITHUB_ENV": str(self.environment),
                                        "GITHUB_PATH": str(self.search_path)}),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def compiler(self, argv, **options):
        if argv[0] == "/usr/bin/curl":
            return self.archive
        if argv[-1] == "--version":
            return bootstrap.VERSION
        descriptor = next(value.split("=", 1)[1] for value in argv
                          if value.startswith("--descriptor_set_out="))
        Path(descriptor).write_bytes(b"compiled descriptor fixture")
        return b""

    def assert_unpublished(self):
        self.assertEqual(list(self.installations.iterdir()), [])
        self.assertEqual(self.environment.read_text(), "EXISTING=kept\n")
        self.assertEqual(self.search_path.read_text(), "/existing/bin\n")

    def test_wrong_size_or_digest_never_extracts_or_publishes(self):
        for data in (self.archive[:-1], self.archive + b"x", b"x" * len(self.archive)):
            with self.subTest(size=len(data)), mock.patch.object(
                    bootstrap, "command", return_value=data) as command:
                with self.assertRaisesRegex(RuntimeError, "size or SHA-256"):
                    bootstrap.main()
                command.assert_called_once()
                self.assert_unpublished()

    def test_download_failure_is_not_replaced_with_a_system_compiler(self):
        with mock.patch.object(bootstrap, "command", side_effect=RuntimeError("download failed")):
            with self.assertRaisesRegex(RuntimeError, "download failed"):
                bootstrap.main()
        self.assert_unpublished()

    def test_wrong_version_cleans_installation_before_publication(self):
        with mock.patch.object(bootstrap, "command", side_effect=[self.archive, b"libprotoc 99.0\n"]):
            with self.assertRaisesRegex(RuntimeError, "did not report"):
                bootstrap.main()
        self.assert_unpublished()

    def test_failed_schema_compile_cleans_installation_before_publication(self):
        with mock.patch.object(bootstrap, "command", side_effect=[
                self.archive, bootstrap.VERSION, RuntimeError("schema failed")]):
            with self.assertRaisesRegex(RuntimeError, "schema failed"):
                bootstrap.main()
        self.assert_unpublished()

    def test_schema_success_without_a_descriptor_is_rejected(self):
        with mock.patch.object(bootstrap, "command", side_effect=[self.archive, bootstrap.VERSION, b""]):
            with self.assertRaises(FileNotFoundError):
                bootstrap.main()
        self.assert_unpublished()

    def test_validated_tool_reaches_both_cargo_and_result_recorders(self):
        with mock.patch.object(bootstrap, "command", side_effect=self.compiler), \
                mock.patch("sys.stdout", new_callable=io.StringIO) as output:
            bootstrap.main()
        receipt = json.loads(output.getvalue())
        protoc = Path(receipt["protoc"])
        self.assertEqual(protoc.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.environment.read_text(),
                         f"EXISTING=kept\nPROTOC={protoc}\nPROTOC_INCLUDE={receipt['include']}\n")
        self.assertEqual(self.search_path.read_text(), f"/existing/bin\n{protoc.parent}\n")
        self.assertEqual(receipt["descriptor_sha256"],
                         hashlib.sha256(b"compiled descriptor fixture").hexdigest())


if __name__ == "__main__":
    unittest.main()
