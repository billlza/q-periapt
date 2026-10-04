"""Local process/parser controls, not Android execution or root-cause evidence."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

import android_apk_transport_probe as probe
from bounded_process import BoundedProcessError, BoundedResult


class ApkTransportProbeTests(unittest.TestCase):
    def experiment(self, directory, mode):
        work = Path(directory) / "work";work.mkdir(mode=0o700)
        return probe.Experiment(mode, work, "localfilesystem:" + str(work / "adb.sock"), "emulator-5584")

    def test_only_canonical_single_package_path_is_accepted(self):
        value = b"package:/data/app/~~abc==/dev.qperiapt.androidsmoke-xyz==/base.apk\n"
        self.assertEqual(probe.remote_path(value), value[8:-1].decode())
        for data in (b"", b"error: offline\n", value + value, value.replace(b"abc", b".."),
                     value.replace(b"/base", b"//base"), value.replace(b"base.apk", b"split.apk")):
            with self.subTest(data=data), self.assertRaises(ValueError): probe.remote_path(data)

    def test_archive_pin_is_checked_before_creating_any_apk(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary);source = root / "source";source.mkdir();archive=source / "one.zip"
            with zipfile.ZipFile(archive, "w") as output: output.writestr(probe.APK_MEMBER, b"untrusted")
            with self.assertRaisesRegex(ValueError, "artifact bytes"):
                probe.prepare_archive(source, root / "probe.apk")
            self.assertFalse((root / "probe.apk").exists())

    def test_short_zero_exit_copy_is_measured_before_after_query_and_fails(self):
        for mode in ("apk-pipe-copy", "apk-file-copy"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                experiment = self.experiment(temporary, mode)
                experiment.adb = [sys.executable, "-I", "-S", "-c", "import sys; sys.stdout.buffer.write(b'xxx')"]
                def path(label):
                    if label.endswith("-after"):
                        event = experiment.events[-1]
                        self.assertEqual(event["label"], "sample-01-copy")
                        self.assertEqual(event["returncode"], 0)
                        self.assertEqual(event["bytes"], 3)
                        self.assertFalse(event["exact"])
                    return "/data/app/approved/base.apk"
                with mock.patch.object(probe, "APK_BYTES", 64), \
                     mock.patch.object(probe, "APK_SHA256", hashlib.sha256(b"x" * 64).hexdigest()), \
                     mock.patch.object(experiment, "path", side_effect=path), contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaisesRegex(RuntimeError, "copy or package identity"):
                        experiment.sample(1)
                self.assertEqual(experiment.events[-1]["label"], "sample-01-result")

    def test_both_copy_arms_read_full_output_and_path_only_claims_no_copy(self):
        for mode in probe.MODES:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                experiment = self.experiment(temporary, mode)
                experiment.adb = [sys.executable, "-I", "-S", "-c", "import sys; sys.stdout.buffer.write(b'x'*64)"]
                with mock.patch.object(probe, "APK_BYTES", 64), \
                     mock.patch.object(probe, "APK_SHA256", hashlib.sha256(b"x" * 64).hexdigest()), \
                     mock.patch.object(experiment, "path", return_value="/data/app/approved/base.apk"), \
                     mock.patch.object(experiment, "identity"), contextlib.redirect_stdout(io.StringIO()):
                    experiment.sample(1)
                event = experiment.events[-1]
                self.assertEqual(event["copy_exact"], None if mode == "apk-path-only" else True)
                self.assertFalse((experiment.work / "sample-01.apk").exists())

    def test_direct_comparison_enforces_size_and_timeout(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            with mock.patch.object(probe, "APK_BYTES", 64):
                result=probe.direct_copy([sys.executable,"-I","-S","-c","import os; os.write(1,b'x'*128)"],
                    root/"oversize",root/"oversize.err",2,dict(os.environ))
                # A short OS write is also possible, but no oversized file can
                # pass the common exact hash readback.
                self.assertLessEqual((root/"oversize").stat().st_size,64)
                self.assertIn("client_pid",result)
                with self.assertRaises(subprocess.TimeoutExpired):
                    probe.direct_copy([sys.executable,"-I","-S","-c","import time;time.sleep(30)"],
                        root/"timeout",root/"timeout.err",1,dict(os.environ))

    def test_diagnostic_failure_does_not_report_success_or_hide_primary(self):
        with tempfile.TemporaryDirectory() as temporary:
            experiment=self.experiment(temporary,"apk-path-only")
            with mock.patch.object(experiment,"identity"), mock.patch.object(experiment,"sample"), \
                 mock.patch.object(experiment,"query",return_value=BoundedResult(1,b"offline")), \
                 contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(RuntimeError,"final diagnostics"):
                    experiment.run()
            report=json.loads((Path(temporary)/"samples.json").read_text())
            self.assertEqual(report["status"],"observation_failed")
            self.assertFalse(report["release_claim_eligible"])
        with tempfile.TemporaryDirectory() as temporary:
            experiment=self.experiment(temporary,"apk-path-only")
            with mock.patch.object(experiment,"identity"), \
                 mock.patch.object(experiment,"sample",side_effect=RuntimeError("primary sample failed")), \
                 mock.patch.object(experiment,"query",side_effect=RuntimeError("diagnostic offline")), \
                 contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(RuntimeError,"primary sample failed"):
                    experiment.run()
            report=json.loads((Path(temporary)/"samples.json").read_text())
            self.assertEqual(report["completed_samples"],0)
            self.assertEqual(report["status"],"observation_failed")

    def test_identity_change_and_failed_empty_query_are_not_absence(self):
        with tempfile.TemporaryDirectory() as temporary:
            experiment=self.experiment(temporary,"apk-path-only")
            with mock.patch.object(experiment,"query",return_value=BoundedResult(1,b"")):
                with self.assertRaisesRegex(RuntimeError,"package-path command failed"):
                    experiment.path("failed")
            first=b"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\n442\n880\n3.00 0.00\n"
            with mock.patch.object(experiment,"query",return_value=BoundedResult(0,first)):
                experiment.identity("before")
            with mock.patch.object(experiment,"query",return_value=BoundedResult(0,first.replace(b"442",b"443"))):
                with self.assertRaisesRegex(RuntimeError,"identity changed"):
                    experiment.identity("after")


if __name__ == "__main__": unittest.main()
