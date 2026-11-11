"""Resource diagnostics with real allocating descendants and failure controls."""

from __future__ import annotations

from contextlib import nullcontext
import io
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import codeql_process_resources as resources
import codeql_summary_control as control
from bounded_process import BoundedProcessError


def process(pid: int, ppid: int, start: int, *, rss: int = 4096) -> dict:
    return {"pid": pid, "ppid": ppid, "start_ticks": start, "rss_bytes": rss,
            "pgrp": pid, "session": pid, "user_ticks": 11, "system_ticks": 3,
            "comm": "fixture", "state": "S"}


def stat_bytes(pid: int, ppid: int, start: int, *, comm: bytes = b"python") -> bytes:
    fields = [b"S"] + [b"0"] * 21
    for index, number in {1: ppid, 2: pid, 3: pid, 11: 13, 12: 7, 19: start, 20: 12345, 21: 23}.items():
        fields[index] = str(number).encode()
    return str(pid).encode() + b" (" + comm + b") " + b" ".join(fields) + b"\n"


def fast_sampler(evidence: Path, **kwargs) -> resources.ProcessResourceSampler:
    return resources.ProcessResourceSampler(evidence, interval_seconds=0.02, **kwargs)


class StatAndMembershipTests(unittest.TestCase):
    def test_comm_with_parentheses_spaces_and_newline(self):
        row = resources.parse_stat(stat_bytes(91, 3, 700, comm=b"a ) b (\nc"), 91, 4096)
        self.assertEqual((row["pid"], row["ppid"], row["start_ticks"]), (91, 3, 700))
        self.assertEqual(row["comm"], "a ) b (\nc")
        self.assertEqual((row["rss_bytes"], row["user_ticks"], row["system_ticks"]), (23 * 4096, 13, 7))

    def test_stat_identity_and_short_records_rejected(self):
        for body in [stat_bytes(92, 3, 700), b"91 (java) S 1", b"91 java S 1"]:
            with self.subTest(body=body), self.assertRaises((ValueError, resources.SamplingError)):
                resources.parse_stat(body, 91, 4096)

    def test_tree_roots_and_preexisting_subtree_exclusion(self):
        census = {1: process(1, 0, 10), 2: process(2, 1, 20), 3: process(3, 2, 30),
                  4: process(4, 1, 40), 5: process(5, 4, 50), 6: process(6, 0, 60)}
        selected = resources.select_processes(census, (1, 10), {(4, 40)}, {})
        self.assertEqual(selected, {2: (2, 20), 3: (2, 20)})

    def test_reparented_observed_process_retains_original_root(self):
        census = {1: process(1, 0, 10), 3: process(3, 99, 30), 7: process(7, 3, 70)}
        self.assertEqual(resources.select_processes(census, (1, 10), set(), {(3, 30): (2, 20)}),
                         {3: (2, 20), 7: (2, 20)})

    def test_reused_pid_does_not_inherit_membership(self):
        census = {1: process(1, 0, 10), 3: process(3, 99, 31), 7: process(7, 3, 70)}
        self.assertEqual(resources.select_processes(census, (1, 10), set(), {(3, 30): (2, 20)}), {})
        with self.assertRaisesRegex(resources.SamplingError, "controller_identity"):
            resources.select_processes(census, (1, 9), set(), {})

    def test_nonatomic_census_does_not_attach_old_child_to_reused_parent(self):
        census = {1: process(1, 0, 10), 2: process(2, 1, 80), 3: process(3, 2, 30)}
        self.assertEqual(resources.select_processes(census, (1, 10), set(), {}), {2: (2, 80)})
        # A separately observed identity retains its original tree after a
        # reparenting event; the new parent's identity does not rewrite it.
        self.assertEqual(resources.select_processes(census, (1, 10), set(), {(3, 30): (2, 20)}),
                         {2: (2, 80), 3: (2, 20)})

    def test_per_process_io_counter_admission(self):
        valid = b"read_bytes: 42\nwrite_bytes: 84\ncancelled_write_bytes: 4\nrchar: 999\n"
        self.assertEqual(resources.parse_io(valid), {"read_bytes": 42, "write_bytes": 84,
                                                   "cancelled_write_bytes": 4})
        for body in [b"read_bytes: 42\n", valid + b"read_bytes: 2\n", valid.replace(b"42", b"-1")]:
            with self.subTest(body=body), self.assertRaises(resources.SamplingError):
                resources.parse_io(body)

    def test_proc_input_rejects_symlink_and_oversize(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "data").write_bytes(b"x" * (resources.MAX_PROC_BYTES + 1))
            (root / "link").symlink_to(root / "data")
            with self.assertRaises(OSError):
                resources.read_small(root / "link")
            with self.assertRaisesRegex(resources.SamplingError, "proc_file_limit"):
                resources.read_small(root / "data")


class SamplingShutdownTests(unittest.TestCase):
    def worker(self, census, *, stop: bool = False, error: Exception | None = None):
        sampler = resources.ProcessResourceSampler(Path("."))
        sampler.state["status"] = "sampling"
        sampler.controller = (1, 10)
        sampler.excluded_roots = set()
        sampler.stream = io.BytesIO()

        def sample_census():
            if stop:
                sampler.stop_event.set()
            if error is not None:
                raise error
            return census

        with patch.object(sampler, "_census", side_effect=sample_census):
            sampler._worker()
        self.assertTrue(sampler.stream.closed)
        self.assertEqual((sampler.state["samples"], sampler.state["output_bytes"]), (0, 0))
        return sampler.state

    def test_stop_during_census_discards_unfinished_sample(self):
        state = self.worker(({}, {"read_errors": 0, "complete": False,
                                  "limit": "stopping", "processes_seen": 0}), stop=True)
        self.assertEqual(state["status"], "stopped")
        self.assertNotIn("failure", state)

    def test_missing_controller_remains_a_failure_during_stop(self):
        for limit in (None, "census_work_limit"):
            for stop in (False, True):
                with self.subTest(limit=limit, stop=stop):
                    state = self.worker(({}, {"read_errors": 1, "complete": limit is None,
                                              "limit": limit, "processes_seen": 1}), stop=stop)
                    self.assertEqual(state["status"], "partial")
                    self.assertEqual(state["failure"], "controller_not_in_census")

    def test_stopping_census_requires_an_actual_stop_request(self):
        state = self.worker(({}, {"read_errors": 0, "complete": False,
                                  "limit": "stopping", "processes_seen": 0}))
        self.assertEqual((state["status"], state["failure"]), ("partial", "controller_not_in_census"))

    def test_read_errors_are_preserved_when_stop_is_requested(self):
        for error in (PermissionError("proc access denied"),
                      resources.SamplingError("malformed_stat_identity")):
            with self.subTest(error=type(error).__name__):
                state = self.worker(None, stop=True, error=error)
                self.assertEqual(state["status"], "partial")
                self.assertEqual(state["failure_type"], type(error).__name__)


class CensusShutdownTests(unittest.TestCase):
    def worker(self, stat_operation, *, entries: tuple[int, ...] = (1, 2)):
        sampler = resources.ProcessResourceSampler(Path("."))
        sampler.state["status"] = "sampling"
        sampler.controller = (1, 10)
        sampler.excluded_roots = set()
        sampler.stream = io.BytesIO()
        directory = nullcontext(iter(SimpleNamespace(name=str(pid)) for pid in entries))
        with patch.object(resources.os, "scandir", return_value=directory), \
                patch.object(sampler, "_stat", side_effect=lambda pid: stat_operation(sampler, pid)):
            sampler._worker()
        self.assertTrue(sampler.stream.closed)
        self.assertEqual((sampler.state["samples"], sampler.state["output_bytes"]), (0, 0))
        self.assertEqual(sampler.state["partial_censuses"], 1)
        return sampler.state

    def test_clean_census_interrupted_before_controller_stops_normally(self):
        def stat_operation(sampler, pid):
            sampler.stop_event.set()
            return process(pid, 99, 20)

        state = self.worker(stat_operation, entries=(2, 1))
        self.assertEqual((state["status"], state["proc_read_errors"]), ("stopped", 0))
        self.assertNotIn("failure", state)

    def test_census_read_error_is_preserved_with_simultaneous_stop(self):
        for error in (PermissionError("controller read denied"),
                      resources.SamplingError("malformed_stat_identity")):
            def stat_operation(sampler, _pid):
                sampler.stop_event.set()
                raise error

            with self.subTest(error=type(error).__name__):
                state = self.worker(stat_operation)
                self.assertEqual((state["status"], state["proc_read_errors"]), ("partial", 1))
                self.assertEqual(state["failure"], "interrupted_census_read_errors")

    def test_observed_controller_identity_change_is_preserved_during_stop(self):
        def stat_operation(sampler, pid):
            sampler.stop_event.set()
            return process(pid, 0, 11)

        state = self.worker(stat_operation)
        self.assertEqual((state["status"], state["proc_read_errors"]), ("partial", 0))
        self.assertEqual(state["failure"], "controller_identity_changed")


@unittest.skipUnless(platform.system() == "Linux", "real procfs sampling requires Linux")
class LiveResourceTests(unittest.TestCase):
    def samples(self, root: Path) -> list[dict]:
        return [json.loads(line) for line in (root / "PROCESS_RESOURCES.jsonl").read_text().splitlines()]

    def test_real_allocating_root_and_child_are_observed(self):
        child = "import os,time; data=bytearray(b'x')*(32*1024**2); print(os.getpid(),flush=True); time.sleep(0.8)"
        program = ("import os,subprocess,sys,time; data=bytearray(b'y')*(24*1024**2); "
                   f"p=subprocess.Popen([sys.executable,'-c',{child!r}],stdout=subprocess.PIPE,text=True); "
                   "print(str(os.getpid())+' '+p.stdout.readline().strip(),flush=True); p.wait()")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(control, "ProcessResourceSampler", side_effect=fast_sampler):
                result = control.run_queries([sys.executable, "-c", program], root, dict(os.environ), seconds=5)
            root_pid, child_pid = map(int, (root / "query.stdout").read_text().split())
            report = result["resource_observation"]
            self.assertEqual(result["returncode"], 0)
            self.assertEqual((report["status"], report["shutdown_complete"]), ("stopped", True))
            self.assertEqual((report["observed_root_identities"], report["observed_process_identities"]), (1, 2))
            joint = [sample for sample in self.samples(root)
                     if {row["pid"] for row in sample["processes"]} == {root_pid, child_pid}]
            self.assertTrue(joint)
            self.assertTrue(all(row["root_pid"] == root_pid for row in joint[-1]["processes"]))
            self.assertGreater(report["peak_sampled_roots_rss_bytes"], 20 * 1024**2)
            self.assertGreater(report["peak_sampled_tree_rss_bytes"], 50 * 1024**2)
            self.assertGreaterEqual(report["peak_sampled_tree_rss_bytes"], report["peak_sampled_roots_rss_bytes"])
            self.assertNotIn(os.getpid(), {row["pid"] for sample in self.samples(root) for row in sample["processes"]})
            self.assertEqual(report, json.loads((root / "PROCESS_RESOURCES.json").read_text()))

    def test_real_preexisting_background_child_is_excluded(self):
        background = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(20)"])
        try:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                with patch.object(control, "ProcessResourceSampler", side_effect=fast_sampler):
                    result = control.run_queries([sys.executable, "-c", "import time; time.sleep(0.2)"],
                                                 root, dict(os.environ), seconds=5)
                self.assertEqual(result["returncode"], 0)
                self.assertGreaterEqual(result["resource_observation"]["excluded_preexisting_roots"], 1)
                self.assertNotIn(background.pid, {row["pid"] for sample in self.samples(root) for row in sample["processes"]})
        finally:
            background.terminate()
            background.wait(timeout=5)

    def test_real_timeout_keeps_primary_error_and_resource_samples(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(control, "ProcessResourceSampler", side_effect=fast_sampler), \
                    self.assertRaises(BoundedProcessError) as stopped:
                control.run_queries([sys.executable, "-c", "import time; data=bytearray(b'x')*(8*1024**2); time.sleep(20)"],
                                    root, dict(os.environ), seconds=1)
            self.assertEqual(stopped.exception.kind, "timeout")
            receipt = json.loads((root / "query.json").read_text())
            self.assertEqual(receipt["stopped"], "timeout")
            self.assertFalse(receipt["cleanup_ambiguous"])
            self.assertTrue(receipt["resource_observation"]["shutdown_complete"])
            self.assertGreater(receipt["resource_observation"]["samples_with_processes"], 0)

    def test_count_and_output_limits_stop_only_the_sampler(self):
        for kwargs, reason in [({"max_samples": 1}, "sample_count_limit"),
                               ({"max_output_bytes": 1}, "sample_output_limit")]:
            with self.subTest(kwargs=kwargs), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                sampler = fast_sampler(root, **kwargs)
                with patch.object(control, "ProcessResourceSampler", return_value=sampler):
                    result = control.run_queries([sys.executable, "-c", "import time; time.sleep(0.2)"],
                                                 root, dict(os.environ), seconds=5)
                self.assertEqual(result["returncode"], 0)
                self.assertEqual(result["resource_observation"]["failure"], reason)
                self.assertTrue(result["resource_observation"]["shutdown_complete"])
                self.assertLessEqual(result["resource_observation"]["samples"], kwargs.get("max_samples", resources.MAX_SAMPLES))
                self.assertLessEqual(result["resource_observation"]["output_bytes"], kwargs.get("max_output_bytes", resources.MAX_OUTPUT_BYTES))

    def test_missing_procfs_reports_unavailable_and_preserves_exit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sampler = fast_sampler(root, proc_root=root / "missing-proc")
            with patch.object(control, "ProcessResourceSampler", return_value=sampler):
                result = control.run_queries([sys.executable, "-c", "raise SystemExit(17)"], root, dict(os.environ), seconds=5)
            self.assertEqual(result["returncode"], 17)
            self.assertEqual(result["resource_observation"]["status"], "unavailable")
            self.assertIsNone(result["resource_observation"]["peak_sampled_tree_rss_bytes"])

    def test_secondary_start_and_stop_failures_preserve_exit(self):
        for method in ("start", "stop"):
            with self.subTest(method=method), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                sampler = fast_sampler(root)
                try:
                    with patch.object(control, "ProcessResourceSampler", return_value=sampler), \
                            patch.object(sampler, method, side_effect=OSError("diagnostic failure")):
                        result = control.run_queries([sys.executable, "-c", "raise SystemExit(19)"],
                                                     root, dict(os.environ), seconds=5)
                    self.assertEqual(result["returncode"], 19)
                    receipt = json.loads((root / "query.json").read_text())
                    self.assertEqual(receipt["returncode"], 19)
                finally:
                    sampler.stop()

    def test_sampler_stream_is_exclusive(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "PROCESS_RESOURCES.jsonl"
            path.write_bytes(b"existing\n")
            sampler = fast_sampler(root)
            sampler.start()
            self.assertEqual(sampler.stop()["status"], "unavailable")
            self.assertEqual(path.read_bytes(), b"existing\n")

    def test_unsupported_platform_is_explicit_and_keeps_exit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(resources.platform, "system", return_value="Darwin"), \
                    patch.object(control, "ProcessResourceSampler", side_effect=fast_sampler):
                result = control.run_queries([sys.executable, "-c", "raise SystemExit(23)"],
                                             root, dict(os.environ), seconds=5)
            self.assertEqual(result["returncode"], 23)
            self.assertEqual(result["resource_observation"]["status"], "unsupported")


if __name__ == "__main__":
    unittest.main()
