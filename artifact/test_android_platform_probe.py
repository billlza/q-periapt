"""Real ownership checks for the isolated hosted platform diagnostic."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import tempfile
import time
import unittest
from unittest import mock

from bounded_process import BoundedProcessError, BoundedResult, capture_stdout

ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "research/android-platform-probe"


class PlatformProbeTests(unittest.TestCase):
    def test_failure_capture_retains_delayed_backtrace_and_original_status(self):
        script = (PROBE / "run.sh").read_text()
        start = script.index("capture_failure() {")
        end = script.index("\n}\n", start) + 3
        capture = script[start:end]
        with tempfile.TemporaryDirectory() as directory:
            driver = Path(directory) / "capture.sh"
            driver.write_text(
                "set -euo pipefail\nserial=emulator-5584\nreads=0\ngraced=0\n"
                "statuses=(\"$1\" \"$2\" \"$3\" \"$4\")\ngrace_status=$5\n"
                "adb_call() {\n"
                "  status=${statuses[$reads]}\n"
                "  reads=$((reads + 1))\n"
                "  case \" $* \" in\n"
                "    *' -b main '*|*' -b system '*) printf 'ActivityManager context\\n' ;;\n"
                "    *' -b crash '*)\n"
                "      if [ \"$graced\" -eq 0 ]; then\n"
                "        printf 'Fatal signal 11 (system_server)\\n'\n"
                "      else\n"
                "        printf 'backtrace: frame_00 retained after grace\\n'\n"
                "      fi ;;\n"
                "    *) return 99 ;;\n"
                "  esac\n"
                "  return \"$status\"\n"
                "}\n"
                "sleep() { test \"$1\" = 10; graced=1; printf 'GRACE_WINDOW\\n'; "
                "return \"$grace_status\"; }\n"
                + capture + "\ncapture_failure\nexit 23\n")
            # Fail each read independently and all reads together. A failed
            # crash read must still allow context and the deferred retry.
            for statuses in ((0, 0, 0, 0), (7, 0, 0, 0), (0, 9, 0, 0),
                             (0, 0, 11, 0), (0, 0, 0, 13), (7, 9, 11, 13)):
                with self.subTest(statuses=statuses):
                    result = capture_stdout(
                        ["/bin/bash", str(driver), *(str(value) for value in statuses), "0"],
                        timeout_seconds=5, maximum_bytes=4096)
                    self.assertEqual(result.returncode, 23, result.stdout)
                    self.assertEqual(result.stdout.count(b"GRACE_WINDOW\n"), 1)
                    self.assertIn(b"Fatal signal 11 (system_server)\n", result.stdout)
                    self.assertEqual(result.stdout.count(b"ActivityManager context\n"), 2)
                    self.assertIn(b"PLATFORM_FAILURE_CAPTURE phase=deferred\n", result.stdout)
                    self.assertLess(result.stdout.index(b"GRACE_WINDOW\n"),
                                    result.stdout.index(b"backtrace: frame_00"))
                    for status, (kind, phase) in zip(statuses, (
                            (b"CRASH", b"immediate"), (b"LOG", b"immediate"),
                            (b"CRASH", b"deferred"), (b"LOG", b"deferred"))):
                        marker = b"UNAVAILABLE" if status else b"CAPTURED"
                        self.assertIn(b"PLATFORM_FAILURE_" + kind + b"_" + marker +
                                      b" phase=" + phase + b"\n", result.stdout)
            interrupted = capture_stdout(
                ["/bin/bash", str(driver), "0", "0", "0", "0", "1"],
                timeout_seconds=5, maximum_bytes=4096)
            self.assertEqual(interrupted.returncode, 23, interrupted.stdout)
            self.assertIn(b"PLATFORM_FAILURE_GRACE_INTERRUPTED\n", interrupted.stdout)
            self.assertNotIn(b"phase=deferred", interrupted.stdout)

    def test_failure_capture_preserves_crash_before_context_exhausts_output(self):
        script = (PROBE / "run.sh").read_text()
        start = script.index("capture_failure() {")
        end = script.index("\n}\n", start) + 3
        capture = script[start:end]
        with tempfile.TemporaryDirectory() as directory:
            acknowledged = Path(directory) / "crash-retained"
            driver = Path(directory) / "noisy-context.sh"
            driver.write_text(
                "set -euo pipefail\nserial=emulator-5584\nacknowledged=$1\n"
                "adb_call() {\n"
                "  case \" $* \" in\n"
                # A combined tail can contain only recent context, even when
                # an older fatal signal is still in the separate crash buffer.
                "    *' -b main '*|*' -b system '*)\n"
                "      for line in {1..1000}; do\n"
                "        printf 'ActivityManager: noisy context occupies the log tail\\n'\n"
                "      done ;;\n"
                "    *' -b crash '*)\n"
                "      printf 'Fatal signal 11 (system_server) [crash buffer]\\n'\n"
                # Synchronize with the bounded reader, without depending on
                # pipe chunk sizes or scheduler timing before context floods.
                "      for attempt in {1..100}; do\n"
                "        if [ -f \"$acknowledged\" ]; then return 0; fi\n"
                "        /bin/sleep 0.01\n"
                "      done\n"
                "      return 99 ;;\n"
                "    *) return 99 ;;\n"
                "  esac\n"
                "}\n"
                "sleep() { :; }\n" + capture + "\ncapture_failure\nexit 23\n")
            retained = bytearray()
            def retain(chunk):
                retained.extend(chunk)
                if b"Fatal signal 11 (system_server) [crash buffer]\n" in retained:
                    acknowledged.touch()
            with self.assertRaises(BoundedProcessError) as failure:
                capture_stdout(["/bin/bash", str(driver), str(acknowledged)],
                               timeout_seconds=5, maximum_bytes=4096, output_sink=retain)
            self.assertEqual(failure.exception.kind, "output_limit")
            self.assertIn(b"Fatal signal 11 (system_server) [crash buffer]\n", retained)

    def test_fresh_checkout_records_a_failed_driver_without_a_target_directory(self):
        spec = importlib.util.spec_from_file_location("android_platform_probe_fresh", PROBE / "run.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "target" / "android-platform-probe"
            def command(argv, **options):
                if argv[-1] == "HEAD" and "rev-parse" in argv:
                    return BoundedResult(0, b"a" * 40 + b"\n")
                if "diff" in argv:
                    return BoundedResult(0)
                self.assertEqual(argv[0], "/bin/bash")
                options["output_sink"](b"controlled driver failure\n")
                return BoundedResult(7)
            old_umask = os.umask(0o077)
            try:
                with mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "true", "RUNNER_OS": "Linux",
                                                   "GITHUB_SHA": "a" * 40, "JAVA_HOME": directory}), \
                     mock.patch.object(module.sys, "platform", "linux"), \
                     mock.patch.object(module, "OUTPUT", destination), \
                     mock.patch.object(module, "capture_stdout", side_effect=command):
                    self.assertEqual(module.main(), 1)
            finally:
                os.umask(old_umask)
            observation = json.loads((destination / "observation.json").read_text())
            self.assertEqual(observation["status"], "observation_failed")
            self.assertEqual(observation["driver_exit_status"], 7)
            self.assertFalse(observation["sdk_installation_attempted"])
            self.assertEqual((destination / "commands.log").read_bytes(), b"controlled driver failure\n")

    def test_absence_requires_a_completed_empty_package_query(self):
        script = (PROBE / "run.sh").read_text()
        start = script.index("confirm_no_sdk_package() {")
        end = script.index("\n}\n", start) + 3
        guard = script[start:end]
        with tempfile.TemporaryDirectory() as directory:
            driver = Path(directory) / "guard.sh"
            reply = Path(directory) / "reply"
            driver.write_text("set -euo pipefail\nfixture=$1\nquery_status=$2\n"
                              "guest() { /bin/cat \"$fixture\"; return \"$query_status\"; }\n"
                              "capture_failure() { :; }\n"
                              + guard + "\nconfirm_no_sdk_package\n")
            for payload, query_status, expected in ((b"", 0, 0), (b"", 17, 1),
                                                    (b"package:dev.qperiapt.androidsmoke\n", 0, 1),
                                                    (b"service unavailable\n", 1, 1)):
                reply.write_bytes(payload)
                with self.subTest(payload=payload, query_status=query_status):
                    result = capture_stdout(["/bin/bash", str(driver), str(reply), str(query_status)],
                                            timeout_seconds=5, maximum_bytes=4096)
                    self.assertEqual(result.returncode, expected, result.stdout)

    def test_absence_failures_capture_diagnostics_at_both_call_sites(self):
        script = (PROBE / "run.sh").read_text()
        # Keep the production definitions and both invocations in their actual
        # order, including the guard before the first platform sample.
        pieces = []
        for name in ("capture_failure", "confirm_no_sdk_package"):
            start = script.index(name + "() {")
            end = script.index("\n}\n", start) + 3
            pieces.append((start, script[start:end]))
        calls = list(re.finditer(r"(?m)^confirm_no_sdk_package$", script))
        self.assertEqual(len(calls), 2)
        pieces.extend((match.start(), match.group() + "\n") for match in calls)
        body = "\n".join(value for _, value in sorted(pieces))
        with tempfile.TemporaryDirectory() as directory:
            counter = Path(directory) / "queries"
            driver = Path(directory) / "absence-boundaries.sh"
            driver.write_text(
                "set -euo pipefail\nserial=emulator-5584\n"
                "counter=$1\nfailed_query=$2\ndiagnostic_status=$3\n"
                "guest() {\n"
                "  test \"$*\" = 'pm list packages dev.qperiapt'\n"
                "  count=$(( $(/bin/cat \"$counter\") + 1 ))\n"
                "  printf '%s\\n' \"$count\" > \"$counter\"\n"
                "  if [ \"$count\" -eq \"$failed_query\" ]; then return 17; fi\n"
                "}\n"
                "adb_call() { printf 'DIAGNOSTIC_READ\\n'; return \"$diagnostic_status\"; }\n"
                "sleep() { test \"$1\" = 10; printf 'GRACE_WINDOW\\n'; }\n"
                + body)
            for failed_query in (0, 1, 2):
                for diagnostic_status in (0, 9):
                    with self.subTest(failed_query=failed_query, diagnostic_status=diagnostic_status):
                        counter.write_text("0\n")
                        result = capture_stdout(
                            ["/bin/bash", str(driver), str(counter), str(failed_query),
                             str(diagnostic_status)], timeout_seconds=5, maximum_bytes=8192)
                        self.assertEqual(result.returncode, 1 if failed_query else 0, result.stdout)
                        self.assertEqual(counter.read_text(), "1\n" if failed_query == 1 else "2\n")
                        self.assertEqual(result.stdout.count(b"DIAGNOSTIC_READ\n"),
                                         4 if failed_query else 0, result.stdout)
                        if failed_query:
                            self.assertIn(b"PLATFORM_PACKAGE_ABSENCE_UNCONFIRMED\n", result.stdout)
                            self.assertEqual(result.stdout.count(b"GRACE_WINDOW\n"), 1)
                            marker = b"UNAVAILABLE" if diagnostic_status else b"CAPTURED"
                            for phase in (b"immediate", b"deferred"):
                                for kind in (b"CRASH", b"LOG"):
                                    self.assertIn(b"PLATFORM_FAILURE_" + kind + b"_" + marker +
                                                  b" phase=" + phase + b"\n", result.stdout)

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
            diagnostic = {"parent_signal_mask": sorted(int(value) for value in
                          signal.pthread_sigmask(signal.SIG_BLOCK, set()))}
            captured = bytearray()
            def observe_children(chunk):
                captured.extend(chunk)
                if "children" in diagnostic or b"\n" not in captured:
                    return
                diagnostic["children"] = []
                if not Path("/proc").is_dir():
                    return
                pids = [int(value) for value in bytes(captured).splitlines()[0].split()]
                for delay in (0, 0.05, 0.2):
                    time.sleep(delay)
                    sample = {}
                    for pid in pids:
                        status_path = Path(f"/proc/{pid}/status")
                        try:
                            with status_path.open() as stream:
                                status = stream.read(8192)
                        except OSError as error:
                            sample[pid] = type(error).__name__
                        else:
                            sample[pid] = [line for line in status.splitlines()
                                if line.startswith(("Name:", "State:", "PPid:", "NSpgid:",
                                                    "SigPnd:", "ShdPnd:", "SigBlk:", "SigIgn:", "SigCgt:"))]
                    diagnostic["children"].append(sample)
            try:
                result = capture_stdout(["/bin/bash", str(driver)], timeout_seconds=5,
                                        maximum_bytes=4096, output_sink=observe_children)
            except BoundedProcessError as error:
                diagnostic["driver_output"] = bytes(captured).decode("utf-8", errors="replace")
                error.add_note("cleanup control context: " + json.dumps(diagnostic, sort_keys=True))
                raise
            self.assertEqual(result.returncode, 17, result.stdout)
            guarded_children = result.stdout.count(b"PLATFORM_CLEANUP_NONOWNER ")
            if guarded_children:
                print(f"cleanup ownership control: guarded_children={guarded_children}", flush=True)
            pids = [int(value) for value in result.stdout.splitlines()[0].split()]
            self.assertEqual(len(pids), 2)
            for pid in pids:
                with self.assertRaises(ProcessLookupError):
                    os.kill(pid, 0)

    def test_subshell_exit_does_not_run_the_parent_cleanup(self):
        script = (PROBE / "run.sh").read_text()
        start = script.index("cleanup() {")
        end = script.index("trap cleanup EXIT", start) + len("trap cleanup EXIT")
        cleanup = script[start:end]
        with tempfile.TemporaryDirectory() as directory:
            driver = Path(directory) / "subshell.sh"
            driver.write_text("set -euo pipefail\nadb_pid=\nemulator_pid=\n" + cleanup + "\n"
                              "/bin/sleep 30 &\nadb_pid=$!\n"
                              "( trap cleanup EXIT; exit 19 ) &\nhelper_pid=$!\n"
                              "if wait \"$helper_pid\"; then child_status=0; else child_status=$?; fi\n"
                              "test \"$child_status\" -eq 19\n"
                              "kill -0 \"$adb_pid\"\n"
                              "printf 'SUBSHELL_EXIT_ISOLATED\\n'\nexit 17\n")
            result = capture_stdout(["/bin/bash", str(driver)], timeout_seconds=5,
                                    maximum_bytes=4096)
            self.assertEqual(result.returncode, 17, result.stdout)
            self.assertIn(b"SUBSHELL_EXIT_ISOLATED\n", result.stdout)

    def test_uncooperative_child_escalates_without_reporting_driver_success(self):
        script = (PROBE / "run.sh").read_text()
        start = script.index("cleanup() {")
        end = script.index("trap cleanup EXIT", start) + len("trap cleanup EXIT")
        cleanup = script[start:end]
        with tempfile.TemporaryDirectory() as directory:
            driver = Path(directory) / "uncooperative.sh"
            driver.write_text("set -euo pipefail\nadb_pid=\nemulator_pid=\n"
                              "ready=$1\nselected_status=$2\n"
                              + cleanup + "\n"
                              "( trap - EXIT; trap '' TERM; printf ready > \"$ready\"; "
                              "exec /bin/sleep 30 ) &\nadb_pid=$!\n"
                              "for attempt in {1..100}; do\n"
                              "  if [ -f \"$ready\" ]; then break; fi\n"
                              "  /bin/sleep 0.01\ndone\ntest -f \"$ready\"\n"
                              "exit \"$selected_status\"\n")
            for primary in (0, 17):
                with self.subTest(primary=primary):
                    ready = Path(directory) / f"ready-{primary}"
                    result = capture_stdout(["/bin/bash", str(driver), str(ready), str(primary)],
                                            timeout_seconds=30, maximum_bytes=4096)
                    self.assertEqual(result.returncode, -signal.SIGKILL, result.stdout)
                    self.assertIn(f"PLATFORM_CLEANUP_ESCALATED primary={primary}\n".encode(),
                                  result.stdout)


if __name__ == "__main__":
    unittest.main()
