"""Exercise actual command capture and rejection of a successful truncated pipe."""
from pathlib import Path
import hashlib
import os
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import android_runtime_control as control


class CaptureTest(unittest.TestCase):
    def test_successful_short_read_cannot_be_a_complete_transfer(self):
        with tempfile.TemporaryDirectory() as directory:
            obj = control.Control.__new__(control.Control)
            obj.output = Path(directory)
            obj.environment = dict(os.environ)
            obj.deadline = time.monotonic() + 15
            obj.events = []
            obj.result = {"commands": obj.events}
            whole = b"expected complete read-only file"
            record = obj.command("partial", [sys.executable, "-I", "-c",
                                 "import sys; sys.stdout.buffer.write(b'expected')"])
            self.assertEqual(record["returncode"], 0)
            self.assertFalse(control.transfer_matches(record, len(whole), hashlib.sha256(whole).hexdigest()))
            self.assertFalse(control.transfer_matches(record, 8, hashlib.sha256(b"modified").hexdigest()))
            self.assertTrue(control.transfer_matches(record, 8, hashlib.sha256(b"expected").hexdigest()))
            self.assertEqual((obj.output / "partial.stdout").read_bytes(), b"expected")
            self.assertEqual(len(obj.events), 1)
            self.assertTrue((obj.output / "RESULT.json").is_file())

    def test_timeout_preserves_partial_evidence_and_never_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            obj = control.Control.__new__(control.Control)
            obj.output = Path(directory)
            obj.environment = dict(os.environ)
            obj.deadline = time.monotonic() + 15
            obj.events = []
            obj.result = {"commands": obj.events}
            record = obj.command("timeout", [sys.executable, "-I", "-c",
                                 "import sys,time; print('partial',flush=True); time.sleep(30)"], 1)
            self.assertTrue(record["timed_out"])
            self.assertEqual((obj.output / "timeout.stdout").read_bytes(), b"partial\n")
            self.assertFalse(control.transfer_matches(record, 8, hashlib.sha256(b"partial\n").hexdigest()))

    def test_desktop_cannot_start_runtime(self):
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "false"}), patch.object(control, "Control") as constructor:
            with self.assertRaisesRegex(RuntimeError, "disposable GitHub-hosted"):
                control.main()
            constructor.assert_not_called()

    def test_only_spawned_child_is_stopped(self):
        with tempfile.TemporaryDirectory() as directory:
            obj = control.Control.__new__(control.Control)
            obj.output = Path(directory)
            obj.result = {}
            owned = subprocess.Popen([sys.executable, "-I", "-c", "import time; time.sleep(30)"])
            unrelated = subprocess.Popen([sys.executable, "-I", "-c", "import time; time.sleep(30)"])
            try:
                obj.children = [("owned", owned)]
                obj.stop()
                self.assertIsNotNone(owned.poll())
                self.assertIsNone(unrelated.poll())
                self.assertEqual(len(obj.result["owned_child_exits"]), 1)
            finally:
                if owned.poll() is None:
                    owned.kill()
                owned.wait()
                unrelated.terminate()
                unrelated.wait(timeout=10)


if __name__ == "__main__":
    unittest.main()
