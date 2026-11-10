"""Bounded, read-only diagnostics for failed installed-consumer child processes."""
from collections import Counter
import os
from pathlib import Path
import re
import sys
import time

from continuity_process_crash import CrashFormatError, MAX_CRASH_BYTES, match_report
from evidence_io import EvidenceIOError, read_regular_snapshot
import rust_sdk_profile as sdk

MARKER = b"QPC_CHILD_FAILURE_V1 "
MAX_EVENTS = 32
MAX_DIRECTORY_ENTRIES = 2048
MAX_RECENT_FILES = 16
CONTRACT_TESTS = frozenset({
    "normal_output_keeps_streams_and_has_no_failure_event",
    "nonzero_exit_retains_status_identity_and_stream_sizes",
    "abort_remains_signal_with_empty_stderr_and_no_exit_code",
    "invalid_label_is_rejected_before_process_spawn",
})
EVENT = re.compile(
    rb"QPC_CHILD_FAILURE_V1 parent_pid=(\d{1,10}) pid=(\d{1,10}) "
    rb"start_ms=(\d{1,18}|unavailable) end_ms=(\d{1,18}|unavailable) "
    rb"signal=(\d{1,3}|none) exit=(\d{1,3}|none) program_hex=([0-9a-f]{2,510}) "
    rb"label=([A-Za-z0-9._-]{1,128}) stdout_bytes=(\d{1,20}) stderr_bytes=(\d{1,20})"
)


def verify_contract(stdout):
    text = stdout.decode()
    names = re.findall(r"^test ([a-z_]+) \.\.\. ok$", text, re.MULTILINE)
    sdk.require(len(names) == len(CONTRACT_TESTS) and set(names) == CONTRACT_TESTS
                and re.search(r"^test result: ok\. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;",
                              text, re.MULTILINE), "child-process diagnostic contract did not execute completely")


def events(data):
    if len(data) > 16 * 1024 * 1024:
        raise ValueError("failure_stream_bound")
    result, seen = [], set()
    for line in data.splitlines():
        if not line.startswith(MARKER):
            continue
        match = EVENT.fullmatch(line)
        if match is None or len(result) >= MAX_EVENTS or line in seen:
            raise ValueError("invalid_or_excessive_failure_events")
        seen.add(line)
        parent, pid, started, ended, sig, exit_code, program, label, stdout, stderr = match.groups()
        try:
            name = bytes.fromhex(program.decode()).decode("utf-8")
        except (UnicodeError, ValueError) as error:
            raise ValueError("invalid_program_name") from error
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,255}", name) or name in (".", ".."):
            raise ValueError("invalid_program_name")
        optional = lambda v, absent: None if v == absent else int(v)
        row = dict(parent_pid=int(parent), pid=int(pid), start_ms=optional(started, b"unavailable"),
                   end_ms=optional(ended, b"unavailable"), signal=optional(sig, b"none"),
                   exit_code=optional(exit_code, b"none"), program=name, label=label.decode(),
                   stdout_bytes=int(stdout), stderr_bytes=int(stderr))
        if (not 0 < row["pid"] < 2**31 or not 0 < row["parent_pid"] < 2**31
                or (row["signal"] is None) == (row["exit_code"] is None)
                or (row["signal"] is not None and not 0 < row["signal"] < 128)
                or (row["exit_code"] is not None and not 0 <= row["exit_code"] <= 255)
                or (row["exit_code"] == 0 and row["stderr_bytes"] == 0)
                or max(row["stdout_bytes"], row["stderr_bytes"]) >= 2**64):
            raise ValueError("inconsistent_failure_event")
        result.append(row)
    return result


def scan(directory, selected):
    matches = [[] for _ in selected]
    errors = Counter()
    eligible = [e for e in selected if e["signal"] is not None
                and e["start_ms"] is not None and e["end_ms"] is not None
                and e["start_ms"] <= e["end_ms"]]
    if not eligible:
        return matches, {"status": "no_attributable_signal_event"}
    names = {e["program"] for e in eligible}
    earliest = min(e["start_ms"] for e in eligible) / 1000 - 2
    recent = 0
    try:
        with os.scandir(directory) as entries:
            for ordinal, entry in enumerate(entries):
                if ordinal >= MAX_DIRECTORY_ENTRIES:
                    return matches, {"status": "directory_bound", "errors": dict(errors)}
                if not entry.name.endswith(".ips") or not any(
                        entry.name.startswith(n + "-") or entry.name.startswith(n + "_") for n in names):
                    continue
                try:
                    metadata = entry.stat(follow_symlinks=False)
                    if metadata.st_mtime < earliest:
                        continue
                    if recent >= MAX_RECENT_FILES:
                        return matches, {"status": "report_count_bound", "errors": dict(errors)}
                    recent += 1
                    raw = read_regular_snapshot(Path(entry.path), maximum=MAX_CRASH_BYTES,
                                                label="owned child crash report").data
                except (OSError, EvidenceIOError) as error:
                    errors["report_read_" + type(error).__name__] += 1
                    continue
                for index, event in enumerate(selected):
                    if event not in eligible:
                        continue
                    try:
                        found = match_report(raw, event)
                    except CrashFormatError as error:
                        errors[str(error)] += 1
                        continue
                    if found is not None:
                        matches[index].append(found)
    except OSError as error:
        return matches, {"status": "directory_unavailable", "errno": error.errno}
    return matches, {"status": "scanned", "recent_files_read": recent, "errors": dict(errors)}


def collect(prefix, *, directory=None, platform=None, attempts=3, pause=time.sleep):
    """Never retry the SDK command. Three report observations at most, two seconds apart in total."""
    if type(attempts) is not int or not 1 <= attempts <= 3:
        raise ValueError("diagnostic_attempt_bound")
    result = {"schema_version": 1, "kind": "qperiapt.child_process_failure",
              "primary_command_failed": True, "raw_reports_exported": False,
              "registers_and_application_messages_exported": False, "root_cause_confirmed": False}
    try:
        raw = read_regular_snapshot(prefix.with_suffix(".stderr"), maximum=16 * 1024 * 1024,
                                    label="failed command stderr").data
        selected = events(raw)
    except (OSError, ValueError) as error:
        return dict(result, collection_status="failure_events_unavailable", error_type=type(error).__name__)
    result["events"] = selected
    if not selected:
        return dict(result, collection_status="no_child_failure_event")
    if (sys.platform if platform is None else platform) != "darwin":
        return dict(result, collection_status="platform_crash_reader_unavailable")
    directory = Path.home() / "Library/Logs/DiagnosticReports" if directory is None else directory
    observations = []
    accumulated = [{} for _ in selected]
    for attempt in range(attempts):
        matches, observation = scan(directory, selected)
        observations.append(observation)
        for saved, rows in zip(accumulated, matches):
            for row in rows:
                saved[row["report_sha256"]] = row
        pending = [i for i, e in enumerate(selected) if e["signal"] is not None
                   and e["start_ms"] is not None and e["end_ms"] is not None
                   and e["start_ms"] <= e["end_ms"] and not accumulated[i]]
        if not pending or observation["status"] != "scanned" or attempt + 1 == attempts:
            break
        pause(1)
    result["observations"] = observations
    complete = all(o["status"] in ("scanned", "no_attributable_signal_event")
                   and not o.get("errors") for o in observations)
    result["scan_complete"] = complete
    result["crash_reports"] = [dict(event_index=i,
        status=("incomplete" if not complete else
                "matched" if len(rows) == 1 else "ambiguous" if rows else "unavailable"),
        reports=list(rows.values())) for i, rows in enumerate(accumulated)]
    return dict(result, collection_status="observed")


def command(argv, prefix, cwd, *, environment=None, diagnostic_directory=None):
    """Keep the original command failure; diagnostic failure cannot turn it green."""
    try:
        return sdk.command(argv, prefix, cwd, environment=environment)
    except Exception as primary:
        try:
            report = collect(prefix, directory=diagnostic_directory)
            destination = prefix.with_name(prefix.name + "-process-failure.json")
            sdk.write_json(destination, report)
        except Exception as secondary:
            primary.add_note("Failed to retain child-process diagnostics; secondary error is chained.")
            raise primary from secondary
        primary.add_note(f"Child-process diagnostic observation: {destination}")
        raise
