"""Bounded, read-only Linux resource samples for the retained CodeQL control.

RSS is the kernel's approximate per-process counter.  A tree sum can count
shared pages more than once; neither a sample nor its maximum is a physical
memory high-water mark.  Sampling never changes evaluator admission or exit.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import stat
import threading
import time


INTERVAL_SECONDS = 2.0
SCAN_SECONDS = 0.75
STOP_SECONDS = 2.0
MAX_CENSUS_PROCESSES = 8192
MAX_SELECTED_PROCESSES = 512
MAX_OBSERVED_IDENTITIES = 4096
MAX_SAMPLES = 10000
MAX_OUTPUT_BYTES = 32 * 1024**2
MAX_PROC_BYTES = 16 * 1024


class SamplingError(ValueError):
    """The diagnostic reached an explicit resource or format boundary."""


def read_small(path: Path) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise SamplingError("nonregular_proc_file")
        value = os.read(descriptor, MAX_PROC_BYTES + 1)
        if len(value) > MAX_PROC_BYTES:
            raise SamplingError("proc_file_limit")
        return value
    finally:
        os.close(descriptor)


def parse_stat(raw: bytes, expected_pid: int, page_bytes: int) -> dict:
    # The comm field can contain spaces, parentheses, and newlines.  Numeric
    # fields follow its final closing parenthesis; splitlines() is unsuitable.
    opening, closing = raw.find(b" ("), raw.rfind(b")")
    if opening < 1 or closing <= opening or int(raw[:opening]) != expected_pid:
        raise SamplingError("malformed_stat_identity")
    fields = raw[closing + 1:].split()
    if len(fields) < 22 or len(fields[0]) != 1:
        raise SamplingError("short_stat")
    indexes = {"ppid": 1, "pgrp": 2, "session": 3, "user_ticks": 11,
               "system_ticks": 12, "start_ticks": 19, "rss_pages": 21}
    result = {name: int(fields[index]) for name, index in indexes.items()}
    if any(number < 0 for number in result.values()):
        raise SamplingError("negative_stat_counter")
    result.update(pid=expected_pid, comm=raw[opening + 2:closing].decode("utf-8", "replace"),
                  state=fields[0].decode("ascii"), rss_bytes=result.pop("rss_pages") * page_bytes)
    return result


def identity(record: dict) -> tuple[int, int]:
    return record["pid"], record["start_ticks"]


def parse_io(raw: bytes) -> dict:
    result = {}
    wanted = {"read_bytes", "write_bytes", "cancelled_write_bytes"}
    for line in raw.splitlines():
        key, separator, value = line.partition(b":")
        name = key.decode("ascii")
        if separator and name in wanted:
            if name in result:
                raise SamplingError("duplicate_io_counter")
            result[name] = int(value)
    if set(result) != wanted or any(value < 0 for value in result.values()):
        raise SamplingError("malformed_io_counters")
    return result


def select_processes(census: dict[int, dict], controller: tuple[int, int],
                     excluded_roots: set[tuple[int, int]],
                     observed: dict[tuple[int, int], tuple[int, int]]) -> dict[int, tuple[int, int]]:
    """Follow current ancestry plus previously observed identities after reparenting.

    The controller is excluded.  A pre-existing direct child's complete subtree
    is excluded.  PID reuse alone never inherits membership in a query tree.
    """
    if controller[0] not in census:
        raise SamplingError("controller_not_in_census")
    if identity(census[controller[0]]) != controller:
        raise SamplingError("controller_identity_changed")
    selected = {pid: observed[identity(record)] for pid, record in census.items()
                if identity(record) in observed}
    for pid, record in census.items():
        key = identity(record)
        if record["ppid"] == controller[0] and key not in excluded_roots:
            selected[pid] = key
    children: dict[int, list[int]] = {}
    for pid, record in census.items():
        children.setdefault(record["ppid"], []).append(pid)
    pending = list(selected)
    while pending:
        parent = pending.pop()
        for child in children.get(parent, []):
            # The census is not atomic.  A reused parent PID must not adopt an
            # older child that was read before the old parent disappeared.
            if (child not in selected and child != controller[0]
                    and census[child]["start_ticks"] >= census[parent]["start_ticks"]):
                selected[child] = selected[parent]
                pending.append(child)
    if len(selected) > MAX_SELECTED_PROCESSES:
        raise SamplingError("selected_process_limit")
    return selected


class ProcessResourceSampler:
    """An optional diagnostic; start/stop report errors without raising them.

    Procfs reads and each census have byte/count/work-time bounds.  The worker
    checks its stop event between operations; stop waits at most STOP_SECONDS.
    An incomplete shutdown is reported explicitly, not treated as a complete
    measurement.  The worker is a daemon so it cannot hold up controller exit.
    """

    def __init__(self, evidence: Path, *, interval_seconds: float = INTERVAL_SECONDS,
                 proc_root: Path = Path("/proc"), max_samples: int = MAX_SAMPLES,
                 max_output_bytes: int = MAX_OUTPUT_BYTES):
        self.evidence = evidence
        self.proc_root = proc_root
        self.interval = interval_seconds
        self.max_samples = max_samples
        self.max_output = max_output_bytes
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None
        self.stream = None
        self.started = time.monotonic()
        self.observed: dict[tuple[int, int], tuple[int, int]] = {}
        self.cpu_ticks: dict[tuple[int, int], int] = {}
        self.state = {"schema": 1, "kind": "qperiapt.codeql_process_resources",
                      "platform": platform.system(), "status": "not_started",
                      "scope": "new controller descendants observed during query evaluation",
                      "samples_file": "PROCESS_RESOURCES.jsonl", "samples": 0,
                      "samples_with_processes": 0, "output_bytes": 0,
                      "observed_process_identities": 0, "observed_root_identities": 0,
                      "peak_sampled_tree_rss_bytes": None, "peak_sampled_roots_rss_bytes": None,
                      "observed_process_cpu_seconds": 0.0, "sampler_cpu_seconds": 0.0,
                      "sampling_wall_seconds": 0.0, "max_sample_span_seconds": 0.0,
                      "proc_read_errors": 0, "io_unavailable": 0, "partial_censuses": 0,
                      "shutdown_complete": False,
                      "interval_seconds": interval_seconds,
                      "limits": {"census_processes": MAX_CENSUS_PROCESSES,
                                 "selected_processes": MAX_SELECTED_PROCESSES,
                                 "observed_identities": MAX_OBSERVED_IDENTITIES,
                                 "proc_file_bytes": MAX_PROC_BYTES, "samples": max_samples,
                                 "output_bytes": max_output_bytes, "scan_work_seconds": SCAN_SECONDS,
                                 "shutdown_wait_seconds": STOP_SECONDS},
                      "interpretation": {
                          "rss": "approximate proc stat RSS; tree sums may double-count shared pages",
                          "peak": "maximum recorded non-atomic sample, not actual job peak or PSS",
                          "cpu": "sum of maximum observed own-process user/system ticks per identity",
                          "io": "per-process raw counters only; may include waited-for children",
                          "omissions": "short-lived or already-reparented unseen descendants and between-sample peaks may be missed",
                          "exit": "evaluator exit, deadline, query coverage and result admission are independent"}}

    def _stat(self, pid: int) -> dict:
        return parse_stat(read_small(self.proc_root / str(pid) / "stat"), pid, self.page_bytes)

    def _census(self) -> tuple[dict[int, dict], dict]:
        deadline = time.monotonic() + SCAN_SECONDS
        census = {}
        notes = {"read_errors": 0, "complete": True, "limit": None}
        seen = 0
        with os.scandir(self.proc_root) as entries:
            for entry in entries:
                if self.stop_event.is_set():
                    notes.update(complete=False, limit="stopping")
                    break
                if not entry.name.isascii() or not entry.name.isdecimal():
                    continue
                seen += 1
                if seen > MAX_CENSUS_PROCESSES or time.monotonic() >= deadline:
                    notes.update(complete=False, limit="census_work_limit")
                    break
                pid = int(entry.name)
                try:
                    census[pid] = self._stat(pid)
                except (OSError, ValueError):
                    notes["read_errors"] += 1
        notes["processes_seen"] = seen
        return census, notes

    def start(self) -> None:
        try:
            if self.state["platform"] != "Linux":
                self.state.update(status="unsupported", reason="Linux procfs is required")
                return
            if not 0.01 <= self.interval <= INTERVAL_SECONDS or not 1 <= self.max_samples <= MAX_SAMPLES \
                    or not 1 <= self.max_output <= MAX_OUTPUT_BYTES:
                raise SamplingError("invalid_sampling_limits")
            self.page_bytes = os.sysconf("SC_PAGE_SIZE")
            self.clock_ticks = os.sysconf("SC_CLK_TCK")
            self.controller = identity(self._stat(os.getpid()))
            census, notes = self._census()
            if not notes["complete"] or notes["read_errors"]:
                raise SamplingError("incomplete_initial_census")
            self.excluded_roots = {identity(record) for record in census.values()
                                   if record["ppid"] == self.controller[0]}
            descriptor = os.open(self.evidence / "PROCESS_RESOURCES.jsonl",
                                 os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
            self.stream = os.fdopen(descriptor, "wb", buffering=0)
            self.state.update(status="sampling", controller_pid=self.controller[0],
                              controller_start_ticks=self.controller[1], page_bytes=self.page_bytes,
                              clock_ticks_per_second=self.clock_ticks,
                              excluded_preexisting_roots=len(self.excluded_roots))
            self.thread = threading.Thread(target=self._worker, name="codeql-resource-sampler", daemon=True)
            self.thread.start()
        except Exception as error:
            self.state.update(status="unavailable", failure_type=type(error).__name__,
                              failure=str(error) if isinstance(error, SamplingError) else "sampler start failed")
            if self.stream is not None and (self.thread is None or not self.thread.is_alive()):
                self.stream.close()

    def _sample(self) -> dict | None:
        started = time.monotonic()
        census, notes = self._census()
        if notes["limit"] == "stopping" and self.stop_event.is_set():
            # stop() may interrupt the census before it reaches the controller.
            # Retain errors and any identity contradiction already observed;
            # only an otherwise clean interrupted census can be discarded.
            self.state["proc_read_errors"] += notes["read_errors"]
            self.state["partial_censuses"] += 1
            if self.controller[0] in census and identity(census[self.controller[0]]) != self.controller:
                raise SamplingError("controller_identity_changed")
            if notes["read_errors"]:
                raise SamplingError("interrupted_census_read_errors")
            return None
        selected = select_processes(census, self.controller, self.excluded_roots, self.observed)
        processes = []
        for pid in sorted(selected):
            if self.stop_event.is_set() or time.monotonic() - started >= SCAN_SECONDS:
                notes.update(complete=False, limit="sample_work_limit")
                break
            record = dict(census[pid])
            key, root = identity(record), selected[pid]
            record["root_pid"], record["root_start_ticks"] = root
            try:
                record["io"] = parse_io(read_small(self.proc_root / str(pid) / "io"))
                if identity(self._stat(pid)) != key:
                    notes["read_errors"] += 1
                    continue
            except (OSError, ValueError):
                record["io"] = None
            if key not in self.observed and len(self.observed) >= MAX_OBSERVED_IDENTITIES:
                raise SamplingError("observed_identity_limit")
            self.observed[key] = root
            self.cpu_ticks[key] = max(self.cpu_ticks.get(key, 0), record["user_ticks"] + record["system_ticks"])
            processes.append(record)
        return {"sequence": self.state["samples"], "elapsed_seconds": started - self.started,
                "span_seconds": time.monotonic() - started, "census": notes,
                "processes": processes, "tree_rss_bytes": sum(row["rss_bytes"] for row in processes),
                "roots_rss_bytes": sum(row["rss_bytes"] for row in processes
                                       if identity(row) == (row["root_pid"], row["root_start_ticks"]))}

    def _worker(self) -> None:
        cpu_start, wall_start = time.thread_time(), time.monotonic()
        try:
            while not self.stop_event.is_set():
                if self.state["samples"] >= self.max_samples:
                    raise SamplingError("sample_count_limit")
                sample = self._sample()
                if sample is None:
                    break
                encoded = (json.dumps(sample, sort_keys=True, separators=(",", ":")) + "\n").encode()
                if self.state["output_bytes"] + len(encoded) > self.max_output:
                    raise SamplingError("sample_output_limit")
                if self.stop_event.is_set():
                    break
                self.stream.write(encoded)
                self.state["samples"] += 1
                self.state["output_bytes"] += len(encoded)
                self.state["proc_read_errors"] += sample["census"]["read_errors"]
                self.state["partial_censuses"] += not sample["census"]["complete"]
                self.state["io_unavailable"] += sum(row["io"] is None for row in sample["processes"])
                self.state["max_sample_span_seconds"] = max(self.state["max_sample_span_seconds"], sample["span_seconds"])
                if sample["processes"]:
                    self.state["samples_with_processes"] += 1
                    for field in ("tree", "roots"):
                        name = "peak_sampled_" + field + "_rss_bytes"
                        self.state[name] = max(self.state[name] or 0, sample[field + "_rss_bytes"])
                self.state["observed_process_identities"] = len(self.observed)
                self.state["observed_root_identities"] = len(set(self.observed.values()))
                self.state["observed_process_cpu_seconds"] = sum(self.cpu_ticks.values()) / self.clock_ticks
                if self.stop_event.wait(self.interval):
                    break
            if self.state["status"] == "sampling":
                self.state["status"] = "stopped"
        except BaseException as error:
            self.state.update(status="partial", failure_type=type(error).__name__,
                              failure=str(error) if isinstance(error, SamplingError) else "sampler read or write failed")
        finally:
            self.state["sampler_cpu_seconds"] = time.thread_time() - cpu_start
            self.state["sampling_wall_seconds"] = time.monotonic() - wall_start
            try:
                self.stream.close()
            except BaseException:
                self.state.update(status="partial", failure="sample_stream_close_failed")

    def stop(self) -> dict:
        self.stop_event.set()
        try:
            if self.thread is not None:
                self.thread.join(STOP_SECONDS)
            complete = self.thread is None or not self.thread.is_alive()
            self.state["shutdown_complete"] = complete
            if not complete:
                self.state["status"] = "shutdown_incomplete"
            return dict(self.state)
        except Exception as error:
            return dict(self.state, status="shutdown_incomplete", failure_type=type(error).__name__)
