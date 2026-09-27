"""The local TLS diagnostic rejects blocking or oversized executable inputs."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from evidence_io import EvidenceIOError
import standard_tls_interop as interop


class PeerSnapshotTests(unittest.TestCase):
    def test_identity_and_sealed_copy_bind_the_bytes_and_preserve_prior_attempts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "peer"
            source.write_bytes(b"original executable bytes")
            output = root / "attempt"
            output.mkdir()
            sealed = interop.seal_peer(source, output)
            expected = hashlib.sha256(source.read_bytes()).hexdigest()
            self.assertEqual(interop.identity(sealed), {"path": str(sealed.resolve()), "sha256": expected})
            source.write_bytes(b"replacement")
            self.assertEqual(interop.identity(sealed)["sha256"], expected)
            with self.assertRaises(FileExistsError):
                interop.seal_peer(source, output)
            self.assertEqual(sealed.read_bytes(), b"original executable bytes")
            if os.name == "posix":
                self.assertEqual(sealed.stat().st_mode & 0o777, 0o500)

    def test_size_bound_is_enforced_before_creating_a_sealed_copy(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(interop, "MAX_IDENTITY_BYTES", 16):
            root = Path(temporary)
            source = root / "peer"
            source.write_bytes(b"x" * 16)
            self.assertEqual(interop.identity(source)["sha256"], hashlib.sha256(b"x" * 16).hexdigest())
            source.write_bytes(b"x" * 17)
            with self.assertRaises(EvidenceIOError):
                interop.identity(source)
            with self.assertRaises(EvidenceIOError):
                interop.seal_peer(source, root)
            self.assertFalse((root / "bin").exists())

    @unittest.skipUnless(os.name == "posix", "FIFO input is specific to the Unix diagnostic")
    def test_fifo_is_rejected_without_waiting_for_a_writer(self):
        # A subprocess deadline makes a regression fail instead of hanging the
        # test runner. Both public helper paths inspect a real FIFO, no mocks.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fifo = root / "peer.fifo"
            os.mkfifo(fifo, 0o600)
            for expression in ("interop.identity(source)", "interop.seal_peer(source, output)"):
                code = ("from pathlib import Path; import sys; import standard_tls_interop as interop; "
                        "source=Path(sys.argv[1]); output=Path(sys.argv[2]); " + expression)
                completed = subprocess.run(
                    ["sh", str(interop.ROOT / "artifact/python-run.sh"), "-c", code, str(fifo), str(root)],
                    cwd=interop.ROOT, stdin=subprocess.DEVNULL, capture_output=True, timeout=5, check=False)
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(b"not a regular file", completed.stderr)
                self.assertFalse((root / "bin").exists())


if __name__ == "__main__":
    unittest.main()
