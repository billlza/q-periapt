"""The local TLS diagnostic rejects blocking or oversized executable inputs."""
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from bounded_process import capture_output
from evidence_io import EvidenceIOError
import sdk_connection_interop as connection
import standard_tls_interop as interop
from sdk_connection_interop import run_controlled_client


class ControlObservationTests(unittest.TestCase):
    def command(self, code):
        return [sys.executable, "-I", "-S", "-c", code]

    def test_two_exact_observations_authorize_two_pipe_signals(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            records = []
            server = interop.Peer(self.command(
                "import time; print('ACCEPTED 1',flush=True); time.sleep(.05); "
                "print('ACCEPTED 2',flush=True); time.sleep(5)"), output, "server", records)
            try:
                client = self.command("import os; "
                    "first=os.read(0,1); second=os.read(0,1); "
                    "raise SystemExit(0 if first==second==b'\\n' else 1)")
                self.assertEqual(run_controlled_client(client, output, "client", records, server,
                    (b"ACCEPTED 1", b"ACCEPTED 2"), dict(os.environ)), 0)
                self.assertEqual(records[-1]["control_observations"], ["ACCEPTED 1", "ACCEPTED 2"])
                self.assertEqual(records[-1]["returncode"], 0)
            finally:
                server.close()

    def test_similar_marker_never_grants_control_and_children_are_reaped(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            records = []
            server = interop.Peer(self.command(
                "import time; print('ACCEPTED 10',flush=True); time.sleep(5)"),
                output, "server", records)
            try:
                client = self.command("import os; os.read(0,1); print('WRONGLY_GRANTED',flush=True)")
                with self.assertRaises(TimeoutError):
                    run_controlled_client(client, output, "client", records, server,
                                          (b"ACCEPTED 1",), dict(os.environ))
                self.assertEqual(records[-1]["control_observations"], [])
                self.assertIsNotNone(records[-1]["returncode"])
                self.assertNotIn(b"WRONGLY_GRANTED", (output / "client.stdout").read_bytes())
            finally:
                server.close()


class PeerSnapshotTests(unittest.TestCase):
    def test_connection_copy_retains_exact_bytes_and_refuses_existing_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, destination = root / "input", root / "frozen"
            data = b"selected connection executable or library"
            source.write_bytes(data)
            self.assertEqual(connection.freeze(source, destination), destination)
            source.write_bytes(b"rebuilt source")
            self.assertEqual(destination.read_bytes(), data)
            with self.assertRaises(FileExistsError):
                connection.freeze(source, destination)
            self.assertEqual(destination.read_bytes(), data)
            if os.name == "posix":
                self.assertEqual(destination.stat().st_mode & 0o777, 0o500)

    def test_connection_input_limit_is_enforced_before_copy_creation(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(connection, "MAX_IDENTITY_BYTES", 16):
            root = Path(temporary)
            source = root / "input"
            source.write_bytes(b"x" * 16)
            connection.freeze(source, root / "accepted")
            self.assertEqual((root / "accepted").read_bytes(), b"x" * 16)
            source.write_bytes(b"x" * 17)
            with self.assertRaises(EvidenceIOError):
                connection.freeze(source, root / "rejected")
            self.assertFalse((root / "rejected").exists())

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
        # test runner. All helper paths inspect a real FIFO, no mocks; the
        # bounded parent also reaps the launcher and its child on regression.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fifo = root / "peer.fifo"
            os.mkfifo(fifo, 0o600)
            for expression in ("interop.identity(source)", "interop.seal_peer(source, output)",
                               "connection.freeze(source, output / 'frozen')"):
                code = ("from pathlib import Path; import sys; import standard_tls_interop as interop; "
                        "import sdk_connection_interop as connection; "
                        "source=Path(sys.argv[1]); output=Path(sys.argv[2]); " + expression)
                completed = capture_output(
                    ["sh", str(interop.ROOT / "artifact/python-run.sh"), "-c", code, str(fifo), str(root)],
                    timeout_seconds=5, maximum_stdout_bytes=65536, maximum_stderr_bytes=65536)
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(b"not a regular file", completed.stderr)
                self.assertFalse((root / "bin").exists())
                self.assertFalse((root / "frozen").exists())


if __name__ == "__main__":
    unittest.main()
