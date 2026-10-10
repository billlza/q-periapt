"""Exercise actual command capture and rejection of a successful truncated pipe."""
from pathlib import Path
import hashlib
import os
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

import android_runtime_control as control


class CaptureTest(unittest.TestCase):
    def make_control(self, directory):
        obj = control.Control.__new__(control.Control)
        obj.output = Path(directory)
        obj.environment = dict(os.environ)
        obj.deadline = time.monotonic() + 15
        obj.events = []
        obj.result = {"commands": obj.events}
        return obj

    def test_production_writer_and_direct_file_capture_the_same_actual_stream(self):
        with tempfile.TemporaryDirectory() as directory:
            obj = self.make_control(directory)
            payload = b"abcd" * 65537
            argv = [sys.executable, "-I", "-c",
                    "import sys; sys.stdout.buffer.write(b'abcd' * 65537)"]
            direct = obj.command("direct", argv)
            with patch.object(control.bounded_process, "write_stdout_at",
                              wraps=control.bounded_process.write_stdout_at) as writer:
                bounded = obj.bounded_command("bounded", argv, len(payload))
            self.assertEqual(writer.call_args.kwargs["maximum_bytes"], len(payload))
            self.assertFalse(writer.call_args.kwargs["retain_nonzero"])
            for record in [direct, bounded]:
                self.assertTrue(control.transfer_matches(record, len(payload), hashlib.sha256(payload).hexdigest()))
                self.assertEqual((obj.output / (record["label"] + ".stdout")).read_bytes(), payload)
            self.assertEqual([r["capture_method"] for r in obj.events], ["direct-file", "bounded-writer"])

    def test_successful_truncation_fails_both_copy_methods(self):
        with tempfile.TemporaryDirectory() as directory:
            obj = self.make_control(directory)
            argv = [sys.executable, "-I", "-c", "import sys; sys.stdout.buffer.write(b'partial')"]
            expected = b"partial stream must not be called complete"
            records = [obj.command("direct-short", argv), obj.bounded_command("bounded-short", argv, len(expected))]
            for record in records:
                self.assertEqual(record["returncode"], 0)
                self.assertEqual(record["stdout_bytes"], 7)
                self.assertFalse(control.transfer_matches(record, len(expected), hashlib.sha256(expected).hexdigest()))
            self.assertTrue(records[1]["stdout_published"])

    def test_bounded_timeout_retains_failure_without_publishing_a_false_empty_output(self):
        with tempfile.TemporaryDirectory() as directory:
            obj = self.make_control(directory)
            with self.assertRaises(control.bounded_process.BoundedProcessError):
                obj.bounded_command("bounded-timeout", [sys.executable, "-I", "-c",
                    "import sys,time; print('partial',flush=True); time.sleep(30)"], 1024, 1)
            record = obj.events[-1]
            self.assertTrue(record["timed_out"])
            self.assertEqual(record["bounded_failure"]["kind"], "timeout")
            self.assertFalse(record["stdout_published"])
            self.assertIsNone(record["stdout_bytes"])
            self.assertIsNone(record["stdout_sha256"])
            self.assertFalse(control.transfer_matches(record, 0, hashlib.sha256(b"").hexdigest()))

    def test_bounded_nonzero_never_publishes_or_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            obj = self.make_control(directory)
            record = obj.bounded_command("bounded-failed", [sys.executable, "-I", "-c",
                "import sys; print('partial',flush=True); sys.exit(7)"], 1024)
            self.assertEqual(record["returncode"], 7)
            self.assertFalse(record["stdout_published"])
            self.assertFalse(control.transfer_matches(record, 0, hashlib.sha256(b"").hexdigest()))

    def test_bounded_device_copy_requires_its_original_owned_children(self):
        with tempfile.TemporaryDirectory() as directory:
            obj = self.make_control(directory)
            child = Mock()
            child.poll.return_value = 7
            obj.children = [("original-adb", child)]
            with patch.object(obj, "bounded_command") as command:
                with self.assertRaisesRegex(RuntimeError, "owned process exited: original-adb"):
                    obj.adb_bounded_command("copy", ["exec-out", "cat", control.GUEST_FILE], 1024)
                command.assert_not_called()

    def test_observation_keeps_twelve_copies_per_method_and_alternates_the_first_method(self):
        with tempfile.TemporaryDirectory() as directory:
            obj = self.make_control(directory)
            obj.samples = []
            copied = []
            size, digest = 1048576, "a" * 64
            def observe(label, args, timeout=15):
                if label.endswith("-transfer"):
                    copied.append("direct-file")
                return {"label": label, "returncode": 0, "timed_out": False,
                        "stdout_bytes": size, "stdout_sha256": digest,
                        "text": str(size) if label == "file-size" else "123"}
            def bounded(label, args, maximum):
                self.assertEqual(maximum, size)
                copied.append("bounded-writer")
                return {"label": label, "returncode": 0, "timed_out": False,
                        "stdout_bytes": size, "stdout_sha256": digest}
            with patch.object(obj, "adb_command", side_effect=observe), \
                 patch.object(obj, "adb_bounded_command", side_effect=bounded), \
                 patch.object(obj, "text", side_effect=lambda r: r["text"]), \
                 patch.object(obj, "guest_hash", return_value=digest), \
                 patch.object(obj, "snapshot"), patch.object(control.time, "sleep"):
                obj.observe()
            self.assertEqual(len(obj.samples), 24)
            self.assertEqual(copied.count("direct-file"), 12)
            self.assertEqual(copied.count("bounded-writer"), 12)
            self.assertEqual(copied[:4], ["direct-file", "bounded-writer", "bounded-writer", "direct-file"])
            self.assertTrue(obj.result["completed"])
            self.assertTrue(obj.result["observations_clean"])

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

    def test_final_console_retains_a_crash_absent_from_the_later_adb_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            obj = self.make_control(directory)
            obj.result.update(system_crash_observed=False, observations_clean=True)
            (obj.output / "guest-logcat.log").write_text(
                "10-10 11:54:38.961   549   563 F libc : Fatal signal 11 (SIGSEGV), "
                "code 1 (SEGV_MAPERR) in tid 563 (HeapTaskDaemon), pid 549 (system_server)\n"
                "normal output after a restarted system_server\n")
            emulator = Mock()
            emulator.poll.return_value = 0
            emulator.returncode = 0
            emulator.pid = 123
            obj.children = [("emulator", emulator)]
            obj.stop()
            self.assertTrue(obj.result["system_crash_observed"])
            self.assertFalse(obj.result["observations_clean"])
            console = obj.result["guest_console_observation"]
            self.assertEqual(console["system_crash_lines"], [1])
            self.assertTrue(console["complete"])
            self.assertEqual(console["sha256"], control.file_hash(obj.output / "guest-logcat.log"))

    def test_missing_console_after_emulator_start_is_a_diagnostic_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            obj = self.make_control(directory)
            obj.result["observations_clean"] = True
            emulator = Mock()
            emulator.poll.return_value = 0
            emulator.returncode = 0
            emulator.pid = 123
            obj.children = [("emulator", emulator)]
            obj.stop()
            self.assertFalse(obj.result["observations_clean"])
            self.assertIn("guest-logcat-console", obj.result["diagnostic_failures"])
            self.assertFalse(obj.result["guest_console_observation"]["complete"])
            self.assertNotIn("system_crash_observed", obj.result)

    def test_console_without_crash_does_not_erase_an_earlier_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            obj = self.make_control(directory)
            obj.result.update(system_crash_observed=True, observations_clean=False)
            (obj.output / "guest-logcat.log").write_text("normal system_server observation\n")
            emulator = Mock()
            emulator.poll.return_value = 0
            emulator.returncode = 0
            emulator.pid = 123
            obj.children = [("emulator", emulator)]
            obj.stop()
            self.assertTrue(obj.result["system_crash_observed"])
            self.assertFalse(obj.result["observations_clean"])

    def test_console_scan_has_a_line_size_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            obj = self.make_control(directory)
            (obj.output / "guest-logcat.log").write_bytes(b"x" * 65537)
            emulator = Mock()
            emulator.poll.return_value = 0
            emulator.returncode = 0
            emulator.pid = 123
            obj.children = [("emulator", emulator)]
            obj.stop()
            self.assertIn("guest-logcat-console", obj.result["diagnostic_failures"])
            self.assertFalse(obj.result["guest_console_observation"]["complete"])

    def test_live_console_cannot_be_reported_as_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            obj = self.make_control(directory)
            (obj.output / "guest-logcat.log").write_text("normal output so far\n")
            emulator = Mock()
            emulator.poll.return_value = None
            obj.children = [("emulator", emulator)]
            obj.retain_console_observation()
            self.assertFalse(obj.result["guest_console_observation"]["complete"])
            self.assertFalse(obj.result["observations_clean"])
            self.assertIn("guest-logcat-console", obj.result["diagnostic_failures"])


if __name__ == "__main__":
    unittest.main()
