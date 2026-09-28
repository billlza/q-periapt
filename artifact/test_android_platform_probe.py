"""Real ownership checks for the isolated hosted platform diagnostic."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from bounded_process import capture_stdout

ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "research/android-platform-probe"


class PlatformProbeTests(unittest.TestCase):
    def test_local_invocation_refuses_before_creating_state(self):
        spec = importlib.util.spec_from_file_location("android_platform_probe", PROBE / "run.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "not-created"
            with mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "false"}), mock.patch.object(module, "OUTPUT", destination):
                with self.assertRaisesRegex(RuntimeError, "hosted Linux workflow"):
                    module.main()
            self.assertFalse(destination.exists())

    def test_actual_cleanup_reaps_children_and_preserves_driver_failure(self):
        script = (PROBE / "run.sh").read_text()
        start = script.index("cleanup() {")
        end = script.index("trap cleanup EXIT", start) + len("trap cleanup EXIT")
        cleanup = script[start:end]
        with tempfile.TemporaryDirectory() as directory:
            driver = Path(directory) / "driver.sh"
            driver.write_text("set -euo pipefail\nadb_pid=\nemulator_pid=\n" + cleanup + "\n"
                              "/bin/sleep 30 &\nadb_pid=$!\n"
                              "/bin/sleep 30 &\nemulator_pid=$!\n"
                              "printf '%s %s\\n' \"$adb_pid\" \"$emulator_pid\"\nexit 17\n")
            result = capture_stdout(["/bin/bash", str(driver)], timeout_seconds=5, maximum_bytes=4096)
            self.assertEqual(result.returncode, 17, result.stdout)
            pids = [int(value) for value in result.stdout.splitlines()[0].split()]
            self.assertEqual(len(pids), 2)
            for pid in pids:
                with self.assertRaises(ProcessLookupError):
                    os.kill(pid, 0)


if __name__ == "__main__":
    unittest.main()
