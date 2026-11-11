"""Bounded evaluator-log observations shared by production and diagnostic runs."""
from __future__ import annotations

from pathlib import Path
import re
import time

from evidence_io import consume_regular_snapshot, read_regular_snapshot


class ObservationError(ValueError):
    """Evaluator evidence exceeded a boundary or has an unexpected identity."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ObservationError(message)


_EVICTION_AMOUNT = re.compile(r"[0-9.]+")
_EVICTION_CATEGORY = re.compile(r"(?:Ki|Mi|Gi|Ti)?B ([A-Z_]+)")
_TAINT_STAGE = re.compile(r"Stage([0-9])::")
_TAINT_ITERATION = re.compile(r"\(iteration ([0-9]+)\)")


def observe(evidence: Path, *, pattern: str = "**/*", stdio_prefix: str | None = "query",
            seconds: int = 120, maximum_log_bytes: int = 2 * 1024**3,
            maximum_total_bytes: int = 4 * 1024**3,
            maximum_line_bytes: int = 1024 * 1024, capture_invocation: bool = False) -> dict:
    """Read logs once, with bounded lines/bytes/time; retain receipts on failure too."""
    deadline = time.monotonic() + seconds
    result = {"schema": 1, "logs": [], "query_starts": 0, "query_completions": 0,
              "pause_count": 0, "eviction_pause_count": 0, "eviction_categories": {},
              "first_timestamp": None, "last_timestamp": None, "max_taint_stage_iterations": {},
              "max_heap_bytes_observed": [], "off_heap_mb_observed": [], "evaluator_start_lines": 0,
              "precompiled_query_loads": [], "query_compilations": 0}
    if capture_invocation:
        result["jvm_heap_mb_arguments"] = []
    total_bytes = 0

    def observe(line: bytes) -> None:
        text = line.decode("utf-8", errors="replace")
        stamp = re.match(r"\[([0-9-]{10} [0-9:]{8})\]", text)
        if stamp:
            result["first_timestamp"] = result["first_timestamp"] or stamp[1]
            result["last_timestamp"] = stamp[1]
        if "This is codeql execute queries " in text:
            result["evaluator_start_lines"] += 1
            result["off_heap_mb_observed"].extend(int(value) for value in re.findall(r"--off-heap-ram=([0-9]+)(?:\s|$)", text))
            if capture_invocation:
                result["jvm_heap_mb_arguments"].extend(int(value) for value in
                    re.findall(r"-J-Xmx([0-9]+)M(?:\s|$)", text))
        if "[PROGRESS]" in text:
            result["query_starts"] += "Starting evaluation of " in text
            result["query_completions"] += "Evaluation done; writing results to " in text
            # The first marker and final suffix have the same selection as
            # the former greedy search, without retrying a growing suffix
            # at every repeated marker in a malformed, bounded log line.
            trimmed = text.rstrip()
            marker = "] Loaded "
            start = trimmed.find(marker)
            if start >= 0 and trimmed.endswith(".qlx."):
                loaded = trimmed[start + len(marker):-1]
                if len(loaded) > len(".qlx"):
                    result["precompiled_query_loads"].append(loaded)
        result["query_compilations"] += "Compiling query plan for " in text
        result["pause_count"] += "Pausing evaluation to " in text
        if "Pausing evaluation to evict " in text:
            result["eviction_pause_count"] += 1
            # Consume each maximal numeric run once. Searching the complete
            # old pattern could restart at every dot when its suffix failed.
            found = set()
            for amount in _EVICTION_AMOUNT.finditer(text):
                category = _EVICTION_CATEGORY.match(text, amount.end())
                if category:
                    found.add(category[1])
            for category in found:
                categories = result["eviction_categories"]
                categories[category] = categories.get(category, 0) + 1
        if "TaintReach::" in text:
            stage_match = _TAINT_STAGE.search(text)
            last_iteration = None
            if stage_match:
                for iteration_match in _TAINT_ITERATION.finditer(text, stage_match.end()):
                    last_iteration = iteration_match[1]
            if last_iteration is not None:
                stage, iteration = stage_match[1], last_iteration
                iterations = result["max_taint_stage_iterations"]
                iterations[stage] = max(iterations.get(stage, 0), int(iteration))
        require(time.monotonic() <= deadline, "evaluator observation exceeded its bound")

    paths = sorted((evidence / "evaluator").glob(pattern))
    require(len(paths) <= 128, "evaluator log member census exceeds its bound")
    for path in paths:
        require(not path.is_symlink(), "evaluator log contains a symlink")
        if path.is_dir():
            continue
        pending = bytearray()

        def capture(block: bytes) -> None:
            nonlocal total_bytes
            total_bytes += len(block)
            require(total_bytes <= maximum_total_bytes and time.monotonic() <= deadline,
                    "evaluator observation exceeded its bound")
            lines = (bytes(pending) + block).split(b"\n")
            pending[:] = lines.pop()
            for line in lines:
                require(len(line) <= maximum_line_bytes, "evaluator log line exceeds its bound")
                observe(line)
            require(len(pending) <= maximum_line_bytes, "evaluator log line exceeds its bound")

        snapshot = consume_regular_snapshot(path, maximum=maximum_log_bytes,
                                            label="evaluator log", consume=capture)
        if pending:
            observe(bytes(pending))
        result["logs"].append({"path": path.relative_to(evidence).as_posix(),
                               "bytes": snapshot.size, "sha256": snapshot.sha256})
    for name in (() if stdio_prefix is None else (stdio_prefix + ".stdout", stdio_prefix + ".stderr")):
        path = evidence / name
        if path.exists():
            snapshot = read_regular_snapshot(path, maximum=32 * 1024**2, label="evaluator JVM output")
            # JVM flags occupy one physical line; whitespace must not join
            # unrelated lines or restart a multi-line whitespace search.
            matches = re.findall(rb"(?m)^[ \t]*(?:size_t|uintx) MaxHeapSize[ \t]*:?=[ \t]*([0-9]+)[ \t\r\n]", snapshot.data)
            result["max_heap_bytes_observed"].extend(int(value) for value in matches)
    require(time.monotonic() <= deadline, "evaluator observation exceeded its bound")
    return result


def validate_loads(record: dict, expected: list[str]) -> None:
    observed = record.get("precompiled_query_loads")
    require(isinstance(observed, list) and all(isinstance(item, str) for item in observed)
            and sorted(observed) == sorted(expected) and record.get("query_compilations") == 0,
            "candidate evaluation did not load exactly the 39 admitted precompiled queries")
