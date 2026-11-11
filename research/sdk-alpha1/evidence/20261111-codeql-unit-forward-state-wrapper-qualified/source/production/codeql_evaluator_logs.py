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


class _QueryCompletions:
    """One bounded parser for live progress and retained completion evidence."""

    MAX_LINE_BYTES = 1024
    _COMPLETION = re.compile(
        rb"\[([1-9][0-9]?)/39 eval "
        rb"(?:[0-9]{1,6}(?:\.[0-9]{1,3})?(?:ms|h|m|s)){1,3}"
        rb"\] Evaluation done; writing results to ([^\r\n]+\.bqrs)\."
    )

    def __init__(self, query_paths, *, strict=False, on_progress=None):
        expected = {}
        for relative in query_paths:
            require(len(expected) < 39, "query progress requires exactly 39 query paths")
            require(isinstance(relative, str) and relative.startswith("queries/")
                    and relative.endswith(".ql") and "\\" not in relative
                    and all(part not in ("", ".", "..") for part in relative.split("/"))
                    and all(ord(character) >= 32 and ord(character) != 127 for character in relative),
                    "query progress requires canonical relative query paths")
            encoded = relative.encode("utf-8")
            require(len(encoded) <= 512, "query progress path exceeds its bound")
            result = b"codeql/rust-queries/" + encoded[:-3] + b".bqrs"
            require(result not in expected, "query progress query paths must be unique")
            expected[result] = relative
        require(len(expected) == 39, "query progress requires exactly 39 query paths")
        self._expected = expected
        self._strict = strict
        self._on_progress = on_progress
        self._seen = set()
        self._pending = bytearray()
        self._discarding = False

    def __call__(self, block: bytes) -> None:
        offset = 0
        while offset < len(block):
            newline = block.find(b"\n", offset)
            end = len(block) if newline < 0 else newline
            if not self._discarding:
                if len(self._pending) + end - offset > self.MAX_LINE_BYTES:
                    self._pending.clear()
                    self._discarding = True
                else:
                    self._pending.extend(block[offset:end])
            if newline < 0:
                return
            if not self._discarding:
                self._observe_line(bytes(self._pending))
            self._pending.clear()
            self._discarding = False
            offset = end + 1

    def _observe_line(self, line: bytes) -> None:
        if line.endswith(b"\r"):
            line = line[:-1]
        match = self._COMPLETION.fullmatch(line)
        if match is None or int(match[1]) > 39:
            require(not self._strict or b"Evaluation done; writing results to " not in line,
                    "malformed query completion message")
            return
        result = match[2]
        if result not in self._expected or result in self._seen:
            require(not self._strict, "unknown or duplicate query completion")
            return
        # Reconstruct the count from distinct admitted completion messages.
        # A repeated, reordered or inflated raw counter cannot jump this count.
        self._seen.add(result)
        if self._on_progress is not None:
            self._on_progress(len(self._seen))

    def finish(self) -> list[str]:
        if self._pending and not self._discarding:
            self._observe_line(bytes(self._pending))
        require(self._seen == self._expected.keys(),
                "retained stderr does not complete exactly the 39 admitted queries")
        return sorted(self._expected[result] for result in self._seen)


def read_completion_receipt(path: Path, query_paths, *, maximum_bytes=16 * 1024**2,
                            seconds=30) -> dict:
    """Bind every distinct completion to one bounded snapshot of original stderr.

    The CLI's stderr progress stream can contain completion messages absent
    from its internal evaluator log. Keep the latter's observations intact and
    require the complete admitted query set from this independently retained
    stream. Publication calls this same reader on the uploaded original bytes.
    """
    deadline = time.monotonic() + seconds
    completions = _QueryCompletions(query_paths, strict=True)

    def capture(block: bytes) -> None:
        require(time.monotonic() <= deadline, "query completion read exceeded its bound")
        completions(block)

    snapshot = consume_regular_snapshot(path, maximum=maximum_bytes,
                                        label="query completion stderr", consume=capture)
    queries = completions.finish()
    require(time.monotonic() <= deadline, "query completion read exceeded its bound")
    return {"schema": 1, "source": path.name, "bytes": snapshot.size,
            "sha256": snapshot.sha256, "queries": queries}


class QueryCompletionSink:
    """Retain stderr first, then display bounded progress for an admitted suite.

    Completion admission rereads the original stderr independently; a displayed
    count alone never creates a completion or publication receipt.
    """

    MAX_LINE_BYTES = _QueryCompletions.MAX_LINE_BYTES
    _COMPLETION = _QueryCompletions._COMPLETION

    def __init__(self, write, query_paths):
        require(callable(write), "query progress requires the original stderr sink")
        self._write = write
        self._completions = _QueryCompletions(query_paths, on_progress=self._display)

    @staticmethod
    def _display(count: int) -> None:
        print(f"CodeQL query completions observed: {count}/39", flush=True)

    def __call__(self, block: bytes) -> None:
        # The supervisor applies its existing total-byte limit before this
        # callback. Retain every original byte before parsing or console output;
        # either I/O failure keeps the supervisor's original failure behavior.
        self._write(block)
        self._completions(block)
