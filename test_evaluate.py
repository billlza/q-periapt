from pathlib import Path
import os
import stat
import sys
import tempfile
import unittest
import zipfile

import evaluate


class AdmissionTests(unittest.TestCase):
    def test_refuses_archive_escape_and_links(self):
        for name in ("/outside", "../outside", "a/../../outside", "a\\outside", "a//b"):
            with self.subTest(name=name), self.assertRaises(evaluate.ControlError):
                evaluate.safe_name(zipfile.ZipInfo(name))
        link = zipfile.ZipInfo("link")
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        with self.assertRaises(evaluate.ControlError):
            evaluate.safe_name(link)

    def test_refuses_wrong_database_before_extraction(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "different.zip"
            path.write_bytes(b"not the selected database")
            with self.assertRaises(evaluate.ControlError):
                evaluate.inspect_database(path)

    def test_deadline_is_failure_and_reaps_owned_process(self):
        with tempfile.TemporaryDirectory() as folder:
            result = evaluate.run_command(
                [sys.executable, "-c", "import time; time.sleep(60)"],
                Path(folder) / "deadline", dict(os.environ), 0.05)
            self.assertEqual(result["stopped"], "deadline")
            self.assertNotEqual(result["returncode"], 0)

    def test_failed_command_is_not_success(self):
        with tempfile.TemporaryDirectory() as folder:
            result = evaluate.run_command(
                [sys.executable, "-c", "raise SystemExit(7)"],
                Path(folder) / "failure", dict(os.environ), 15)
            self.assertEqual(result["returncode"], 7)
            self.assertIsNone(result["stopped"])


if __name__ == "__main__":
    unittest.main()
