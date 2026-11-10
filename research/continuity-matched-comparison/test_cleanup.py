"""Output ownership controls; native/reference execution is tested separately."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import run as matched


class CleanupOwnershipTests(unittest.TestCase):
    def test_failed_source_check_preserves_existing_files(self):
        for mode in ("prepare", "run"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                output = root / "preexisting"
                output.mkdir()
                private = output / ".private-unrelated.keys"
                private.write_bytes(b"preexisting unrelated data")
                argv = ["run.py", mode, "--repository", str(root), "--output", str(output)]
                with patch.object(sys, "argv", argv), self.assertRaises(subprocess.CalledProcessError):
                    matched.main()  # Real git rejects the temporary non-repository.
                self.assertTrue(private.exists(), "failed preflight removed a preexisting file")
                self.assertEqual(private.read_bytes(), b"preexisting unrelated data")
                self.assertFalse((output / "source").exists())

    def test_existing_output_rejection_preserves_files(self):
        for mode in ("prepare", "run"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                output = root / "preexisting"
                output.mkdir()
                private = output / ".private-unrelated.keys"
                private.write_bytes(b"preexisting unrelated data")
                argv = ["run.py", mode, "--repository", str(root), "--output", str(output)]
                with patch.object(sys, "argv", argv), \
                        patch.object(matched, "git", return_value=matched.BASE.encode()), \
                        self.assertRaises(FileExistsError):
                    matched.main()
                self.assertEqual(private.read_bytes(), b"preexisting unrelated data")

    def _owned_execution(self, fail):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "owned"
            outside = root / ".private-outside.keys"
            outside.write_bytes(b"outside this run")

            def prepare(repository, destination):
                destination.mkdir()

            def execute(destination):
                evidence = destination / "evidence"
                evidence.mkdir()
                (destination / ".private-first.keys").write_bytes(b"owned observation")
                (evidence / ".private-second.keys").write_bytes(b"owned observation")
                (evidence / "public.json").write_bytes(b"public evidence")
                if fail:
                    raise RuntimeError("execution failed after creating feeds")

            with patch.object(matched, "prepare", prepare), \
                    patch.object(matched, "_execute_prepared", execute):
                if fail:
                    with self.assertRaisesRegex(RuntimeError, "execution failed"):
                        matched.run(root, output)
                else:
                    matched.run(root, output)
            self.assertEqual(list(output.rglob(".private-*.keys")), [])
            self.assertEqual((output / "evidence/public.json").read_bytes(), b"public evidence")
            self.assertEqual(outside.read_bytes(), b"outside this run")

    def test_owned_success_cleans_private_feeds(self):
        self._owned_execution(fail=False)

    def test_owned_failure_cleans_private_feeds(self):
        self._owned_execution(fail=True)

    def test_owned_cleanup_rejects_a_symlink_feed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "owned"
            outside = root / "outside.keys"
            outside.write_bytes(b"outside this run")

            def prepare(repository, destination):
                destination.mkdir()

            def execute(destination):
                (destination / ".private-link.keys").symlink_to(outside)

            with patch.object(matched, "prepare", prepare), \
                    patch.object(matched, "_execute_prepared", execute), \
                    self.assertRaisesRegex(ValueError, "private feed type"):
                matched.run(root, output)
            self.assertTrue((output / ".private-link.keys").is_symlink())
            self.assertEqual(outside.read_bytes(), b"outside this run")


if __name__ == "__main__":
    unittest.main()
