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


def process_stat(pid, name, *, parent=1, started=20, state="S"):
    return (f"{pid} ({name}) {state} {parent} " + "0 "*17 + str(started) + " 0"*30 + "\n").encode()


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
        for mode in ("apk-pipe-copy", "apk-file-copy", *probe.PROTOCOL_MODES):
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

    def test_full_copy_with_nonzero_exit_still_fails_in_both_protocol_arms(self):
        for mode in probe.PROTOCOL_MODES:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                experiment = self.experiment(temporary, mode)
                experiment.adb = [sys.executable, "-I", "-S", "-c", "import sys;sys.stdout.buffer.write(b'x'*64);sys.exit(7)"]
                with mock.patch.object(probe, "APK_BYTES", 64), \
                     mock.patch.object(probe, "APK_SHA256", hashlib.sha256(b"x"*64).hexdigest()), \
                     mock.patch.object(experiment, "path", return_value=probe.BLOB_PATH), \
                     mock.patch.object(experiment, "identity") as identity, contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaisesRegex(RuntimeError, "copy or package identity"):
                        experiment.sample(1)
                self.assertTrue(experiment.events[-2]["exact"])
                self.assertEqual(experiment.events[-2]["returncode"], 7)
                suffix = ["shell", "-T", "-n", "cat", probe.BLOB_PATH] if mode == "uninstalled-shell-copy" else ["exec-out", "cat", probe.BLOB_PATH]
                self.assertEqual(experiment.events[-2]["command"][-len(suffix):], suffix)
                identity.assert_not_called()

    def test_protocol_controls_require_actual_separate_streams_and_remote_status(self):
        for payload, code, valid in (("import sys;print('QP_OUT');print('QP_ERR',file=sys.stderr)",7,True),
                                    ("print('QP_OUT');print('QP_ERR')",7,False),
                                    ("import sys;print('QP_OUT');print('QP_ERR',file=sys.stderr)",0,False)):
            with tempfile.TemporaryDirectory() as temporary:
                experiment = self.experiment(temporary, "uninstalled-shell-copy")
                experiment.adb = [sys.executable,"-I","-S","-c",payload+f";raise SystemExit({code})"]
                routes = [BoundedResult(0,b"shell_v2\nabb_exec\n"),
                          BoundedResult(0,b"_adb_connect: shell,v2,raw:true\nuse_shell_protocol=true shell_type_arg=raw\n"),
                          BoundedResult(0,b"_adb_connect: exec:true\n")]
                with mock.patch.object(experiment,"query",side_effect=routes) as query, contextlib.redirect_stdout(io.StringIO()):
                    if valid: experiment.protocol_controls()
                    else:
                        with self.assertRaisesRegex(RuntimeError,"stdout/stderr/exit"): experiment.protocol_controls()
                self.assertEqual(query.call_args_list[1].kwargs["environment"]["ADB_TRACE"],"adb")

    def test_missing_feature_or_wrong_service_route_never_falls_back(self):
        good = [BoundedResult(0,b"shell_v2\n"),
                BoundedResult(0,b"shell,v2,raw:true\nuse_shell_protocol=true shell_type_arg=raw\n"),
                BoundedResult(0,b"exec:true\n")]
        for index, bad in ((0,BoundedResult(0,b"abb_exec\n")),(0,BoundedResult(1,b"shell_v2\n")),
                           (0,BoundedResult(0,b"error shell_v2\n")),(1,BoundedResult(0,b"shell,pty:true\n")),
                           (1,BoundedResult(1,good[1].stdout)),(2,BoundedResult(0,b"shell,v2,raw:true\n"))):
            with tempfile.TemporaryDirectory() as temporary:
                experiment=self.experiment(temporary,"uninstalled-shell-copy")
                replies=good[:index]+[bad]
                with mock.patch.object(experiment,"query",side_effect=replies) as query, \
                     mock.patch.object(probe,"capture_stdout") as capture, self.assertRaises(RuntimeError):
                    experiment.protocol_controls()
                self.assertEqual(query.call_count,index+1)
                capture.assert_not_called()

    def test_independent_log_requires_a_logcat_record_not_a_command_echo(self):
        marker=probe.LOG_MARKER.encode()
        for data in (b"10-04 21:33:00.000 12 13 I QPeriaptProbe: "+marker+b"\n",
                     b"I/QPeriaptProbe( 12): "+marker+b"\n"):
            self.assertTrue(probe.independent_marker(data))
        for data in (marker,b"_adb_connect: shell,v2,raw:log -p i -t QPeriaptProbe "+marker+b"\n",
                     b"I OtherTag: "+marker+b"\n",b"I QPeriaptProbe: "+marker+b"_wrong\n"):
            self.assertFalse(probe.independent_marker(data))
        for payload, valid in ((b"I QPeriaptProbe: "+marker+b"\n",True),(b"command "+marker+b"\n",False)):
            with tempfile.TemporaryDirectory() as temporary:
                experiment=self.experiment(temporary,"uninstalled-shell-copy");experiment.deadline=100
                (Path(temporary)/"commands.log").write_bytes(payload)
                with mock.patch.object(experiment,"query",return_value=BoundedResult(0,b"")), \
                     mock.patch.object(probe.time,"monotonic",side_effect=[0,0,4]), contextlib.redirect_stdout(io.StringIO()):
                    if valid:experiment.confirm_independent_log()
                    else:
                        with self.assertRaisesRegex(RuntimeError,"marker not observed"):experiment.confirm_independent_log()

    def test_failed_protocol_preflight_prevents_every_copy(self):
        for mode in probe.PROTOCOL_MODES:
            with tempfile.TemporaryDirectory() as temporary:
                experiment=self.experiment(temporary,mode)
                with mock.patch.object(experiment,"query",return_value=BoundedResult(0,b"")), \
                     mock.patch.object(experiment,"confirm_independent_log"), \
                     mock.patch.object(experiment,"protocol_controls",side_effect=RuntimeError("protocol not established")), \
                     mock.patch.object(experiment,"sample") as sample, contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaisesRegex(RuntimeError,"protocol not established"):experiment.run()
                sample.assert_not_called()
                result=json.loads((Path(temporary)/"samples.json").read_text())
                self.assertEqual(result["completed_samples"],0)
                self.assertEqual(result["status"],"observation_failed")

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
            def observed(label, args):
                if label.endswith("-adbd-stat"): return BoundedResult(0,process_stat(442,"adbd"))
                if label.endswith("-system_server-stat"): return BoundedResult(0,process_stat(880,"system_server",parent=99))
                return BoundedResult(0,first)
            with mock.patch.object(experiment,"query",side_effect=observed):
                experiment.identity("before")
            with mock.patch.object(experiment,"query",return_value=BoundedResult(0,first.replace(b"442",b"443"))):
                with self.assertRaisesRegex(RuntimeError,"identity changed"):
                    experiment.identity("after")

    def test_same_name_child_does_not_replace_original_process_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            experiment=self.experiment(temporary,"apk-path-only")
            observed_pids=b"880";started=20;parent=99
            def observed(label,args):
                if label.endswith("-adbd-stat"): return BoundedResult(0,process_stat(442,"adbd"))
                if label.endswith("-system_server-stat"):
                    self.assertEqual(args[-1],"/proc/880/stat")
                    return BoundedResult(0,process_stat(880,"system_server",parent=parent,started=started))
                return BoundedResult(0,b"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\n442\n"+observed_pids+b"\n3.00 0.00\n")
            with mock.patch.object(experiment,"query",side_effect=observed):
                experiment.identity("before")
                observed_pids=b"880 990"
                experiment.identity("additional-name-match")
                started=21
                with self.assertRaisesRegex(RuntimeError,"start time changed"):
                    experiment.identity("reused-pid")
                started=20;parent=1
                with self.assertRaisesRegex(RuntimeError,"parent or start time"):
                    experiment.identity("changed-parent")
                parent=99;observed_pids=b"990"
                with self.assertRaisesRegex(RuntimeError,"identity changed"):
                    experiment.identity("original-gone")
                experiment.guest_identity=None;observed_pids=b"880 990"
                with self.assertRaisesRegex(RuntimeError,"baseline guest service identity is ambiguous"):
                    experiment.identity("ambiguous-baseline")

    def test_process_stat_rejects_replacement_dead_and_malformed_records(self):
        valid=process_stat(880,"system_server",parent=99,started=20)
        self.assertEqual(probe.process_identity(valid,b"880",b"system_server"),(b"880",b"system_server",99,20))
        for value in (valid.replace(b"880",b"881"), valid.replace(b"system_server",b"other"),
                      process_stat(880,"system_server",state="Z"),process_stat(880,"system_server",state="?"),
                      process_stat(880,"system_server",started=0), b"880 (system_server) S\n",
                      valid[:-1],valid + valid,valid + b"880 (system_server) Z 99\n",
                      valid.replace(b" 0 ",b" garbage ",1),valid.replace(b" 0 ",b" \t0 ",1),
                      b"880 (system_server) S 99 " + b"0 "*17 + b"20\n",
                      valid[:-3] + b"\n",valid[:-1] + b" 0\n"):
            with self.subTest(value=value),self.assertRaises(ValueError):
                probe.process_identity(value,b"880",b"system_server")
        signed=valid.replace(b" 0 ",b" -1 ",1)
        self.assertEqual(probe.process_identity(signed,b"880",b"system_server"),(b"880",b"system_server",99,20))

    def test_failed_or_empty_stat_does_not_establish_identity(self):
        census=b"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\n442\n880\n3.00 0.00\n"
        for result in (BoundedResult(1,b""),BoundedResult(0,b"")):
            with tempfile.TemporaryDirectory() as temporary:
                experiment=self.experiment(temporary,"apk-path-only")
                with mock.patch.object(experiment,"query",side_effect=[BoundedResult(0,census),result]):
                    with self.assertRaises((ValueError,RuntimeError)):
                        experiment.identity("bad-stat")
                self.assertIsNone(experiment.guest_identity)

    def test_uninstalled_blob_path_requires_exact_successful_size(self):
        for mode in probe.UNINSTALLED_MODES:
            with tempfile.TemporaryDirectory() as temporary:
                experiment=self.experiment(temporary,mode)
                valid=str(probe.APK_BYTES).encode()+b"\n"
                with mock.patch.object(experiment,"query",return_value=BoundedResult(0,valid)) as query:
                    self.assertEqual(experiment.path("before"),probe.BLOB_PATH)
                    self.assertNotIn("pm",query.call_args.args[1])
                    self.assertIn(probe.BLOB_PATH,query.call_args.args[1][-1])
                for result in (BoundedResult(1,valid),BoundedResult(0,b""),BoundedResult(0,b"1\n"),
                               BoundedResult(0,valid+valid),BoundedResult(0,valid[:-1])):
                    with mock.patch.object(experiment,"query",return_value=result),self.assertRaises(RuntimeError):
                        experiment.path("invalid")

    def test_uninstalled_run_refuses_unknown_or_present_packages_before_and_after(self):
        for before in (True,False):
            for result in (BoundedResult(1,b""),BoundedResult(0,b"package:dev.qperiapt.androidsmoke\n")):
                with tempfile.TemporaryDirectory() as temporary:
                    experiment=self.experiment(temporary,"uninstalled-file-copy")
                    def query(label,args,**options):
                        return result if label==("package-absence-before" if before else "package-absence-after") else BoundedResult(0,b"")
                    with mock.patch.object(experiment,"query",side_effect=query), \
                         mock.patch.object(experiment,"sample") as sample, mock.patch.object(experiment,"identity"), \
                         contextlib.redirect_stdout(io.StringIO()),self.assertRaises(RuntimeError):
                        experiment.run()
                    self.assertEqual(sample.call_count,0 if before else 24)
                    report=json.loads((Path(temporary)/"samples.json").read_text())
                    self.assertEqual(report["status"],"observation_failed")
                    self.assertEqual(report["source_kind"],"uninstalled_same_bytes")


if __name__ == "__main__": unittest.main()
