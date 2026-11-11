"""Match an Apple crash report to one failed child and export public fields only.

Schema: https://developer.apple.com/documentation/xcode/interpreting-the-json-format-of-a-crash-report
Raw IPS, register state, ASI, exception messages, paths and device identifiers
are deliberately not exported. Missing/invalid attribution is not a crash cause.
"""
from datetime import datetime, timezone
import hashlib
import re
import signal

from evidence_io import EvidenceIOError, parse_strict_json_bytes

MAX_CRASH_BYTES = 4 * 1024 * 1024
MAX_FRAMES = 32
# ReportCrash can capture the corpse after waitpid has returned. This bounded
# observation allowance does not extend execution or retry the failed command.
MAX_CAPTURE_DELAY_MS = 2000


class CrashFormatError(ValueError):
    """A bounded report cannot support the requested public interpretation."""


def require(value, reason):
    if not value:
        raise CrashFormatError(reason)


def integer(value, maximum=2**64 - 1):
    require(type(value) is int and 0 <= value <= maximum, "invalid_integer")
    return value


def text(value, maximum=512):
    require(isinstance(value, str) and 0 < len(value) <= maximum
            and all(ord(c) >= 32 for c in value), "invalid_text")
    return value


def timestamp(value):
    try:
        value = text(value, 80)
        # IPS separates the numeric zone from the time with a space; Python's
        # ISO parser accepts that form only after removing this one separator.
        if re.fullmatch(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d{1,6})? [+-]\d{4}", value):
            before, zone = value.rsplit(" ", 1)
            value = before + zone
        parsed = datetime.fromisoformat(value)
        require(parsed.tzinfo is not None, "missing_time_zone")
        delta = parsed.astimezone(timezone.utc) - datetime(1970, 1, 1, tzinfo=timezone.utc)
        return (delta.days * 86400 + delta.seconds) * 1000 + delta.microseconds / 1000
    except (ValueError, OverflowError) as error:
        raise CrashFormatError("invalid_timestamp") from error


def stack(report):
    threads, images = report.get("threads"), report.get("usedImages")
    require(isinstance(threads, list) and 0 < len(threads) <= 1024, "invalid_threads")
    index = integer(report.get("faultingThread"), len(threads) - 1)
    thread = threads[index]
    require(isinstance(thread, dict), "invalid_thread")
    frames = thread.get("frames")
    require(isinstance(frames, list) and 0 < len(frames) <= 4096, "invalid_frames")
    require(isinstance(images, list) and 0 < len(images) <= 4096, "invalid_images")
    projected = []
    for frame in frames[:MAX_FRAMES]:
        require(isinstance(frame, dict), "invalid_frame")
        image_index = integer(frame.get("imageIndex"), len(images) - 1)
        image = images[image_index]
        require(isinstance(image, dict), "invalid_image")
        name = text(image.get("name"), 255)
        require("/" not in name and "\\" not in name, "image_name_is_path")
        item = {"image_name": name, "image_offset": integer(frame.get("imageOffset"))}
        if "uuid" in image:
            value = text(image["uuid"], 36)
            require(re.fullmatch(r"[0-9a-fA-F-]{32,36}", value), "invalid_image_uuid")
            item["image_uuid"] = value
        if "symbol" in frame:
            item["symbol"] = text(frame["symbol"])
        if "symbolLocation" in frame:
            item["symbol_offset"] = integer(frame["symbolLocation"])
        projected.append(item)
    return {"faulting_thread_index": index, "frames": projected,
            "total_frame_count": len(frames), "stack_truncated": len(frames) > MAX_FRAMES}


def match_report(raw, event):
    """None is an explicitly unrelated report; malformed input raises instead."""
    require(0 < len(raw) <= MAX_CRASH_BYTES, "report_size_bound")
    first, separator, remainder = raw.partition(b"\n")
    require(separator and len(first) <= 16 * 1024, "missing_ips_objects")
    try:
        meta = parse_strict_json_bytes(first, label="IPS metadata")
        report = parse_strict_json_bytes(remainder, label="IPS crash")
    except EvidenceIOError as error:
        raise CrashFormatError("invalid_json") from error
    require(isinstance(meta, dict) and isinstance(report, dict), "invalid_ips_objects")
    require(meta.get("bug_type") == "309", "not_crash_report")
    if (report.get("pid") != event["pid"] or report.get("parentPid") != event["parent_pid"]
            or report.get("procName") != event["program"] or meta.get("name") != event["program"]):
        return None
    integer(report["pid"], 2**31 - 1)
    integer(report["parentPid"], 2**31 - 1)
    require(event["start_ms"] is not None and event["end_ms"] is not None
            and event["start_ms"] <= event["end_ms"], "unavailable_child_clock")
    launch, captured = timestamp(report.get("procLaunch")), timestamp(report.get("captureTime"))
    if not (event["start_ms"] - 2 <= launch <= event["end_ms"] + 2
            and launch <= captured <= event["end_ms"] + MAX_CAPTURE_DELAY_MS):
        return None
    for field in ("isNonFatal", "isSimulated"):
        require(report.get(field) in (None, False, 0, "false", "0"), "nonfatal_or_simulated")
    exception, termination = report.get("exception"), report.get("termination")
    require(isinstance(exception, dict) and isinstance(termination, dict), "missing_termination")
    require(event["signal"] is not None, "child_not_signaled")
    try:
        expected_signal = signal.Signals(event["signal"]).name
    except ValueError as error:
        raise CrashFormatError("unsupported_signal") from error
    if exception.get("signal") != expected_signal:
        return None
    kind = text(exception.get("type"), 64)
    namespace = text(termination.get("namespace"), 64)
    require(re.fullmatch(r"[A-Z0-9_]+", kind) and re.fullmatch(r"[A-Z0-9_]+", namespace),
            "invalid_exception_category")
    code = integer(termination.get("code"))
    require(namespace != "SIGNAL" or code == event["signal"], "inconsistent_termination_signal")
    return {"report_sha256": hashlib.sha256(raw).hexdigest(), "matched_pid": event["pid"],
            "matched_parent_pid": event["parent_pid"], "exception_type": kind,
            "signal": expected_signal, "termination_namespace": namespace,
            "termination_code": code,
            "capture_after_wait_ms": max(0, captured - event["end_ms"]),
            "capture_delay_bound_ms": MAX_CAPTURE_DELAY_MS, **stack(report)}
