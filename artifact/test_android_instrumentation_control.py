"""Reject misleading instrumentation/packaging evidence in the independent control."""
from pathlib import Path
import os
import tempfile
import unittest
import zipfile
from unittest.mock import patch

import android_instrumentation_control as control

TOKEN = "a" * 32
GOOD = (f"INSTRUMENTATION_RESULT: qperiapt_control_token={TOKEN}\n"
        "INSTRUMENTATION_RESULT: qperiapt_control_version=1\n"
        "INSTRUMENTATION_CODE: -1\n")


class EvidenceTest(unittest.TestCase):
    def test_success_requires_complete_exact_invocation_result(self):
        record = {"returncode": 0, "timed_out": False}
        self.assertTrue(control.invocation_passed(record, GOOD, TOKEN))
        self.assertTrue(control.invocation_passed(record, GOOD.replace("\n", "\r\n"), TOKEN))
        for raw in ("", GOOD.replace(TOKEN, "b" * 32), GOOD.replace("CODE: -1", "CODE: 0"),
                    GOOD.replace("version=1", "version=2"),
                    GOOD + "INSTRUMENTATION_CODE: -1\n", GOOD.splitlines()[0] + "\n",
                    GOOD + "INSTRUMENTATION_FAILED: system died\n"):
            self.assertFalse(control.invocation_passed(record, raw, TOKEN))
        for bad in ({"returncode": 1, "timed_out": False}, {"returncode": 0, "timed_out": True}):
            self.assertFalse(control.invocation_passed(bad, GOOD, TOKEN))
        with self.assertRaises(ValueError):
            control.invocation_passed(record, GOOD, TOKEN + ";")

    def test_system_failure_is_observable_even_if_instrumentation_reported_success(self):
        for log in (
            "F libc : Fatal signal 11 (SIGSEGV), pid 563 (system_server)",
            "F DEBUG : >>> system_server <<<",
            "E AndroidRuntime: *** FATAL EXCEPTION IN SYSTEM PROCESS: binder:563_C",
        ):
            self.assertTrue(control.system_crash_observed(log))
        self.assertFalse(control.system_crash_observed("normal system_server observation"))

    def test_packaging_refuses_native_code_or_substituted_dex(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dex = root / "classes.dex"
            dex.write_bytes(b"test compiler output")
            for label, additional, actual in (
                ("native", {"lib/x86_64/foreign.so": b"ELF"}, dex.read_bytes()),
                ("sdk", {"classes2.dex": b"foreign"}, dex.read_bytes()),
                ("dex", {}, b"changed compiler output"),
            ):
                apk = root / (label + ".apk")
                with zipfile.ZipFile(apk, "w") as z:
                    z.writestr("resources.arsc", b"table")
                    z.writestr("AndroidManifest.xml", b"manifest")
                    z.writestr("classes.dex", actual)
                    for name, body in additional.items():
                        z.writestr(name, body)
                with self.assertRaises(RuntimeError):
                    control.check_apk(apk, dex)

    def test_resource_table_requires_uncompressed_aligned_storage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dex = root / "classes.dex"
            dex.write_bytes(b"test compiler output")
            for label, compression, aligned in (
                ("compressed", zipfile.ZIP_DEFLATED, True),
                ("unaligned", zipfile.ZIP_STORED, False),
                ("valid", zipfile.ZIP_STORED, True),
            ):
                apk = root / (label + ".apk")
                resource = zipfile.ZipInfo("resources.arsc")
                resource.compress_type = compression
                # 30-byte header + 14-byte filename are aligned; a valid five-
                # byte extra field moves the resource data off that boundary.
                if not aligned:
                    resource.extra = b"\xff\xff\x01\x00\x00"
                with zipfile.ZipFile(apk, "w") as archive:
                    archive.writestr(resource, b"table")
                    archive.writestr("AndroidManifest.xml", b"manifest")
                    archive.writestr("classes.dex", dex.read_bytes())
                if label == "valid":
                    info = control.check_apk(apk, dex)
                    self.assertEqual(info["resources_compression"], "stored")
                    self.assertEqual(info["resources_data_offset"], 44)
                else:
                    with self.assertRaisesRegex(RuntimeError, "resource table"):
                        control.check_apk(apk, dex)

    def test_instrumentation_cannot_run_on_desktop(self):
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "false"}), \
             patch.object(control, "InstrumentationControl") as constructor:
            with self.assertRaisesRegex(RuntimeError, "disposable GitHub-hosted"):
                control.main()
            constructor.assert_not_called()

    def test_one_failed_invocation_cannot_be_hidden_by_later_success(self):
        # Execute the real orchestration with a bounded fake transport: this is a
        # controller regression, not device evidence or a substitute for the CI run.
        with tempfile.TemporaryDirectory() as directory:
            obj = control.InstrumentationControl.__new__(control.InstrumentationControl)
            obj.output = Path(directory)
            obj.apk = obj.output / "test.apk"
            obj.result = {"boot_observed_monotonic": 0}
            obj.samples = []
            obj.events = []
            obj.children = []
            obj.saved = []

            def command(label, argv, timeout=15):
                code, raw = 0, "563\n"
                if label == "install-control":
                    raw = "Success\n"
                elif label.startswith("invocation-") and not label.endswith("-pid"):
                    token = argv[-2]
                    raw = GOOD.replace(TOKEN, token)
                    if label == "invocation-00":
                        code, raw = 1, "INSTRUMENTATION_FAILED: system died\n"
                (obj.output / (label + ".stdout")).write_text(raw)
                return {"label": label, "returncode": code, "timed_out": False}

            obj.adb_command = command
            obj.text = lambda record: (obj.output / (record["label"] + ".stdout")).read_text().strip()
            def snapshot(label):
                obj.saved.append(label)
                (obj.output / (label + "-logcat.stdout")).write_text("")
            obj.snapshot = snapshot
            obj.save = lambda: None
            with patch.object(control.time, "sleep"):
                obj.observe()
            self.assertTrue(obj.result["completed"])
            self.assertFalse(obj.result["observations_clean"])
            self.assertEqual([s["framework_invocation_passed"] for s in obj.samples], [False, True, True])
            self.assertEqual(len({s["token"] for s in obj.samples}), 3)
            self.assertIn("invocation-00-after", obj.saved)


if __name__ == "__main__":
    unittest.main()
