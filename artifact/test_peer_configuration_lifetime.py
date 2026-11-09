"""Optimized C controls for caller ownership in the qualification client."""

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent


@unittest.skipIf(sys.platform == "win32", "Unix guarded-client control; Windows uses installed SDK qualification")
class PeerConfigurationLifetimeTests(unittest.TestCase):
    def test_owned_inputs_survive_and_each_borrowed_input_is_detected(self):
        with tempfile.TemporaryDirectory(prefix="qperiapt-peer-lifetime-") as temporary:
            for optimization in ("-O0", "-O3"):
                executable = Path(temporary) / ("lifetime" + optimization)
                compiled = subprocess.run([
                    "cc", "-std=c11", "-Wall", "-Wextra", "-Werror", optimization,
                    "-I", str(ROOT / "bindings/c/ContinuityPackageConsumer"),
                    str(ROOT / "artifact/testdata/peer_configuration_lifetime.c"),
                    "-o", str(executable)], capture_output=True, text=True, timeout=60, check=False)
                self.assertEqual((compiled.returncode, compiled.stdout, compiled.stderr), (0, "", ""))
                for reopen in (0, 1):
                    for borrowed in range(7 + reopen):
                        with self.subTest(optimization=optimization, reopen=reopen, borrowed=borrowed):
                            run = subprocess.run([str(executable), str(borrowed), str(reopen)],
                                                 capture_output=True, text=True, timeout=10, check=False)
                            expected = (1, "QPC_PEER_CONFIGURATION_HEADER_GUARD_PASS\n",
                                        "lifetime control: borrowed caller input rejected\n") if borrowed else (
                                        0, "QPC_PEER_CONFIGURATION_HEADER_GUARD_PASS\nPEER_CONFIGURATION_LIFETIME_PASS\n", "")
                            self.assertEqual((run.returncode, run.stdout, run.stderr), expected)


if __name__ == "__main__":
    unittest.main()
