from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from codeql_cargo_metadata import rewrite_metadata


class CargoMetadataTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.host = "x86_64-unknown-linux-gnu"
        self.arguments = ["metadata", "--filter-platform", "wasm32-unknown-unknown",
                          "--manifest-path", str(self.root / "Cargo.toml"), "--locked", "--offline"]

    def rewrite(self, arguments):
        return rewrite_metadata(arguments, self.host, [self.root], self.root)

    def test_only_cross_metadata_receives_the_host_filter(self) -> None:
        self.assertEqual(self.rewrite(self.arguments), [*self.arguments, "--filter-platform", self.host])
        for args in (["check", "--target", "wasm32-unknown-unknown"], ["metadata", "--all-features"],
                     ["metadata", "--filter-platform", self.host], ["--version"]):
            with self.subTest(args=args):
                self.assertEqual(self.rewrite(args), args)

    def test_rewrite_is_idempotent_and_accepts_equals_form(self) -> None:
        first = self.rewrite(self.arguments)
        self.assertEqual(self.rewrite(first), first)
        args = ["metadata", "--filter-platform=wasm32-unknown-unknown", "--manifest-path=Cargo.toml"]
        self.assertEqual(self.rewrite(args), [*args, "--filter-platform", self.host])

    def test_missing_manifest_preserves_cargo_failure_boundary(self) -> None:
        self.assertFalse((self.root / "Cargo.toml").exists())
        self.assertEqual(self.rewrite(self.arguments)[-2:], ["--filter-platform", self.host])

    def test_escape_and_conflicting_targets_are_rejected(self) -> None:
        for args in ([*self.arguments, "--filter-platform", "x86_64-pc-windows-msvc"],
                     [*self.arguments, "--manifest-path", str(self.root / "second.toml")],
                     [*self.arguments[:4], str(self.root.parent / "outside.toml")],
                     ["metadata", "--filter-platform"]):
            with self.subTest(args=args), self.assertRaises(ValueError):
                self.rewrite(args)

    def test_manifest_symlink_cannot_escape_the_source_boundary(self) -> None:
        (self.root / "outside").symlink_to(self.root.parent, target_is_directory=True)
        args = ["metadata", "--filter-platform", "wasm32-unknown-unknown", "--manifest-path", "outside/Cargo.toml"]
        with self.assertRaisesRegex(ValueError, "outside"):
            self.rewrite(args)

    def test_real_child_stdout_stderr_and_exit_status_are_unmodified(self) -> None:
        artifact = Path(__file__).resolve().parent
        settings = self.root / "settings.json"
        settings.write_text(json.dumps({"cargo": sys.executable, "host": self.host,
                                       "roots": [str(self.root)], "audit": str(self.root / "audit.jsonl")}))
        code = "import sys;print('exact stdout');print('exact stderr',file=sys.stderr);sys.exit(17)"
        direct = subprocess.run([sys.executable, "-c", code], capture_output=True, check=False)
        wrapped = subprocess.run([sys.executable, "-I", "-S", "-B", str(artifact / "python_bootstrap.py"),
                                  str(artifact / "codeql_cargo_metadata.py"), str(settings), "-c", code],
                                 capture_output=True, check=False)
        self.assertEqual((wrapped.returncode, wrapped.stdout, wrapped.stderr),
                         (direct.returncode, direct.stdout, direct.stderr))
        record = json.loads((self.root / "audit.jsonl").read_text())
        self.assertFalse(record["host_filter_added"])
        self.assertEqual(record["original_argv_sha256"], record["executed_argv_sha256"])


if __name__ == "__main__":
    unittest.main()
