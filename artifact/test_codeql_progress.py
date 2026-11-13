from __future__ import annotations

from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import tracemalloc
import unittest
from unittest import mock

from bounded_process import capture_output
import codeql_evaluator_logs as logs


class QueryCompletionReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        artifact = Path(__file__).parent
        cls.queries = sorted(json.loads((artifact / "codeql_rust_queries.json").read_text())["queries"])
        # Unmodified stderr from the pinned 2.27.2 command in the failed wrapper:
        # https://github.com/billlza/q-periapt/actions/runs/43032937156/job/130564344658
        cls.original = (artifact / "codeql-fixtures/rust-analyze-2.27.2.stderr").read_bytes()
        if (len(cls.original) != 22432 or hashlib.sha256(cls.original).hexdigest()
                != "403bb102acebc1ed83ad4d31b54c5c6133ad020a790a49a1d61e88b383448f55"):
            raise AssertionError("the original hosted stderr fixture changed")
        cls.completions = [line for line in cls.original.splitlines(keepends=True)
                           if b"Evaluation done; writing results to " in line]

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "analyze.stderr"
        self.path.write_bytes(self.original)

    def test_original_hosted_stderr_binds_all_39_exact_query_completions(self):
        receipt = logs.read_completion_receipt(self.path, self.queries)
        self.assertEqual(receipt, {
            "schema": 1, "source": "analyze.stderr", "bytes": len(self.original),
            "sha256": hashlib.sha256(self.original).hexdigest(), "queries": self.queries,
        })

    def test_missing_duplicate_unknown_and_malformed_completions_are_rejected(self):
        first, second = self.completions[:2]
        unknown = first.replace(b"codeql/rust-queries/queries/", b"codeql/rust-queries/queries/extra/")
        cases = {
            "missing": self.original.replace(first, b""),
            "replaced_with_duplicate": self.original.replace(first, second),
            "extra_duplicate": self.original + first,
            "unknown": self.original + unknown,
            "forged_prefix": self.original.replace(first, b"::warning::" + first),
            "invalid_counter": self.original.replace(first, first.replace(b"[1/39", b"[40/39")),
        }
        for name, content in cases.items():
            self.path.write_bytes(content)
            with self.subTest(name=name), self.assertRaises(logs.ObservationError):
                logs.read_completion_receipt(self.path, self.queries)

    def test_oversized_completion_lines_cannot_hide_extra_completion_evidence(self):
        first = self.completions[0].rstrip(b"\r\n")
        unknown = first.replace(b"codeql/rust-queries/queries/", b"codeql/rust-queries/queries/extra/")
        malformed = first.replace(b"[1/39", b"[40/39")
        padding = b"x" * (logs.QueryCompletionSink.MAX_LINE_BYTES + 1)
        cases = {
            "duplicate_after_prefix": self.original + padding + first + b"\n",
            "duplicate_before_suffix": first + padding + b"\n" + self.original,
            "unknown_before_prefix": padding + unknown + b"\r\n" + self.original,
            "malformed_after_suffix": self.original + malformed + padding + b"\n",
            "unterminated_after_prefix": self.original + padding + first,
            "unterminated_after_suffix": self.original + first + padding,
        }
        for name, content in cases.items():
            self.path.write_bytes(content)
            with self.subTest(name=name), self.assertRaises(logs.ObservationError):
                logs.read_completion_receipt(self.path, self.queries)

    def test_oversized_completion_marker_is_rejected_at_every_chunk_boundary(self):
        marker = b"Evaluation done; writing results to "
        suffix = self.completions[0].split(marker, 1)[1]
        limit = logs.QueryCompletionSink.MAX_LINE_BYTES
        # Exercise a marker spanning the transition into discard mode, and a
        # marker arriving after that transition. No stream chunk carries the
        # complete marker; the physical line still contains one.
        for prefix_size in (limit - len(marker) // 2, limit + 1):
            for split in range(1, len(marker)):
                parser = logs._QueryCompletions(self.queries, strict=True)
                parser(self.original)
                with self.subTest(prefix_size=prefix_size, split=split), self.assertRaises(logs.ObservationError):
                    parser(b"x" * prefix_size)
                    parser(marker[:split])
                    parser(marker[split:] + suffix)
                    parser.finish()

    def test_buffered_completion_is_rejected_when_a_later_chunk_overflows(self):
        parser = logs._QueryCompletions(self.queries, strict=True)
        parser(self.original)
        parser(self.completions[0].rstrip(b"\r\n"))
        with self.assertRaises(logs.ObservationError):
            parser(b"x" * (logs.QueryCompletionSink.MAX_LINE_BYTES + 1))
            parser.finish()

    def test_unrelated_oversized_diagnostics_keep_original_receipt_and_bounded_memory(self):
        marker = b"Evaluation done; writing results to "
        split = len(marker) // 2
        # Partial markers on separate physical lines must never combine. The
        # final oversized diagnostic has no newline, exercising EOF handling.
        blocks = [b"x" * (2 * 1024**2), marker[:split], b"\r\n",
                  marker[split:] + b"\n", self.original, b"y" * (2 * 1024**2)]
        parser = logs._QueryCompletions(self.queries, strict=True)
        tracemalloc.start()
        try:
            for block in blocks:
                parser(block)
            queries = parser.finish()
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertEqual(queries, self.queries)
        self.assertLess(peak, 256 * 1024)
        content = b"".join(blocks)
        self.path.write_bytes(content)
        receipt = logs.read_completion_receipt(self.path, self.queries)
        self.assertEqual(receipt["queries"], self.queries)
        self.assertEqual(receipt["bytes"], len(content))
        self.assertEqual(receipt["sha256"], hashlib.sha256(content).hexdigest())

    def test_byte_changes_remain_bound_even_when_query_completions_match(self):
        before = logs.read_completion_receipt(self.path, self.queries)
        self.path.write_bytes(self.original + b"additional diagnostic bytes\n")
        after = logs.read_completion_receipt(self.path, self.queries)
        self.assertEqual(before["queries"], after["queries"])
        self.assertNotEqual(before["sha256"], after["sha256"])
        self.assertGreater(after["bytes"], before["bytes"])

    def test_completion_snapshot_keeps_byte_and_time_bounds(self):
        with self.assertRaises(ValueError):
            logs.read_completion_receipt(self.path, self.queries, maximum_bytes=len(self.original) - 1)
        with mock.patch.object(logs.time, "monotonic", side_effect=[0, 31]):
            with self.assertRaisesRegex(logs.ObservationError, "exceeded its bound"):
                logs.read_completion_receipt(self.path, self.queries)

    @unittest.skipUnless(os.name == "posix", "symlink control requires POSIX")
    def test_completion_snapshot_rejects_a_redirected_stderr(self):
        target = self.path.with_name("original.stderr")
        self.path.rename(target)
        self.path.symlink_to(target)
        with self.assertRaises(ValueError):
            logs.read_completion_receipt(self.path, self.queries)


class QueryCompletionProgressTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        manifest = Path(__file__).with_name("codeql_rust_queries.json")
        cls.queries = sorted(json.loads(manifest.read_text())["queries"])
        if len(cls.queries) != 39:
            raise AssertionError("the fixture must use the complete pinned query census")

    def completion(self, index=0, *, count=1, total=39, elapsed="11m9s", ending=b"\n"):
        name = self.queries[index][:-3] + ".bqrs"
        return (f"[{count}/{total} eval {elapsed}] Evaluation done; writing results to "
                f"codeql/rust-queries/{name}.").encode() + ending

    @staticmethod
    def displayed(count):
        return f"CodeQL query completions observed: {count}/39\n"

    def test_chunk_boundaries_crlf_and_reordered_counters_preserve_unique_progress(self):
        retained, console = io.BytesIO(), io.StringIO()
        sink = logs.QueryCompletionSink(retained.write, self.queries)
        first = self.completion(0, count=39, ending=b"\r\n")
        second = self.completion(1, count=2, elapsed="20ms")
        third = self.completion(2, count=1, elapsed="1h2m3s")
        chunks = [first[:3], first[3:-1], first[-1:], second[:19], second[19:], first, third]
        with redirect_stdout(console):
            for chunk in chunks:
                sink(chunk)
        self.assertEqual(retained.getvalue(), b"".join(chunks))
        self.assertEqual(console.getvalue(), "".join(self.displayed(n) for n in (1, 2, 3)))

    def test_forged_prefixes_unknown_paths_and_malformed_counters_are_not_forwarded(self):
        valid = self.completion()
        unknown = valid.replace(self.queries[0][:-3].encode(), b"queries/unknown/Injected")
        absolute = valid.replace(b"codeql/rust-queries/", b"/tmp/codeql/rust-queries/")
        invalid = [
            b"::warning::" + valid,
            valid.rstrip(b"\n") + b" ::error::forged\n",
            b"\x1b[31m" + valid,
            b"\xff\xfe arbitrary bytes\n",
            unknown,
            absolute,
            self.completion(count=0),
            self.completion(count=40),
            self.completion(total=38),
            self.completion(elapsed="not-a-duration"),
            valid.replace(b"Evaluation done;", b"Evaluation failed;"),
            valid.replace(b"Evaluation done;", b"Starting evaluation;"),
        ]
        retained, console = io.BytesIO(), io.StringIO()
        sink = logs.QueryCompletionSink(retained.write, self.queries)
        with redirect_stdout(console):
            for line in invalid:
                sink(line)
            sink(valid)
        self.assertEqual(retained.getvalue(), b"".join(invalid) + valid)
        self.assertEqual(console.getvalue(), self.displayed(1))
        self.assertNotIn("::", console.getvalue())

    def test_oversized_partial_line_has_bounded_memory_and_keeps_every_raw_byte(self):
        retained, console = hashlib.sha256(), io.StringIO()
        sink = logs.QueryCompletionSink(retained.update, self.queries)
        # Allocate the input before measuring the observer. The retained sink
        # hashes chunks, so the measurement concerns parsing rather than storage.
        blocks = [b"x" * sink.MAX_LINE_BYTES, b"y" * (2 * 1024**2),
                  self.completion(0), self.completion(1, count=2)]
        with redirect_stdout(console):
            tracemalloc.start()
            try:
                for block in blocks:
                    sink(block)
                _, peak = tracemalloc.get_traced_memory()
            finally:
                tracemalloc.stop()
        self.assertLess(peak, 256 * 1024)
        self.assertEqual(retained.hexdigest(), hashlib.sha256(b"".join(blocks)).hexdigest())
        self.assertEqual(console.getvalue(), self.displayed(1))

    def test_query_census_is_exact_canonical_unique_and_bounded(self):
        calls = []
        invalid = [
            self.queries[:-1],
            self.queries + ["queries/extra/Extra.ql"],
            [self.queries[0], *self.queries[:-1]],
            ["/absolute.ql", *self.queries[1:]],
            ["queries/../escape.ql", *self.queries[1:]],
            ["queries/back\\slash.ql", *self.queries[1:]],
            ["queries/injected\nline.ql", *self.queries[1:]],
        ]
        for paths in invalid:
            with self.subTest(paths=paths[:1]), self.assertRaises(logs.ObservationError):
                logs.QueryCompletionSink(calls.append, paths)
        yielded = []
        def too_many():
            for number in range(1000000):
                yielded.append(number)
                yield f"queries/example/Query{number}.ql"
        with self.assertRaises(logs.ObservationError):
            logs.QueryCompletionSink(calls.append, too_many())
        self.assertEqual(len(yielded), 40)
        self.assertEqual(calls, [])

    def test_original_sink_failure_propagates_before_any_console_progress(self):
        failure = OSError("retained sink failure fixture")
        received, console = [], io.StringIO()
        def broken(block):
            received.append(block)
            raise failure
        sink = logs.QueryCompletionSink(broken, self.queries)
        line = self.completion()
        with redirect_stdout(console), self.assertRaises(OSError) as caught:
            sink(line)
        self.assertIs(caught.exception, failure)
        self.assertEqual(received, [line])
        self.assertEqual(console.getvalue(), "")

    def test_console_output_is_flushed_only_after_the_raw_chunk_is_retained(self):
        retained = io.BytesIO()
        sink = logs.QueryCompletionSink(retained.write, self.queries)
        line = self.completion()
        def emitted(*args, **kwargs):
            self.assertEqual(retained.getvalue(), line)
            self.assertEqual(args, (self.displayed(1).rstrip("\n"),))
            self.assertEqual(kwargs, {"flush": True})
        with mock.patch("builtins.print", side_effect=emitted) as output:
            sink(line)
        output.assert_called_once()

    def test_output_is_capped_at_39_fixed_template_lines(self):
        retained, console = io.BytesIO(), io.StringIO()
        sink = logs.QueryCompletionSink(retained.write, self.queries)
        lines = [self.completion(index, count=index + 1) for index in range(39)]
        with redirect_stdout(console):
            for line in lines + list(reversed(lines)):
                sink(line)
        self.assertEqual(retained.getvalue(), b"".join(lines + list(reversed(lines))))
        self.assertEqual(console.getvalue(), "".join(self.displayed(n) for n in range(1, 40)))

    @unittest.skipUnless(os.name == "posix" and all(hasattr(os, name) for name in
                         ("waitid", "P_PID", "WEXITED", "WNOHANG", "WNOWAIT")),
                         "live subprocess progress requires POSIX waitid supervision")
    def test_real_child_observes_retained_bytes_and_console_progress_before_exit(self):
        child = (
            "from pathlib import Path\n"
            "import sys, time\n"
            "console, retained, finished = map(Path, sys.argv[1:4])\n"
            "line = sys.argv[4].encode()\n"
            "expected = b'CodeQL query completions observed: 1/39\\n'\n"
            "sys.stderr.buffer.write(line)\n"
            "sys.stderr.buffer.flush()\n"
            "deadline = time.monotonic() + 3\n"
            "while time.monotonic() < deadline:\n"
            "    if console.exists() and console.read_bytes() == expected:\n"
            "        if retained.read_bytes() != line or finished.exists():\n"
            "            raise SystemExit(5)\n"
            "        sys.stdout.buffer.write(b'progress-visible-before-exit\\n')\n"
            "        sys.stdout.buffer.flush()\n"
            "        raise SystemExit(0)\n"
            "    time.sleep(0.01)\n"
            "raise SystemExit(4)\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            console, retained, finished = (root / name for name in ("console.txt", "stderr.bin", "finished"))
            line = self.completion()
            with retained.open("xb", buffering=0) as raw, console.open("x", encoding="utf-8", newline="\n") as display:
                sink = logs.QueryCompletionSink(raw.write, self.queries)
                with redirect_stdout(display):
                    result = capture_output(
                        [sys.executable, "-c", child, str(console), str(retained), str(finished), line.decode()],
                        timeout_seconds=8, maximum_stdout_bytes=4096, maximum_stderr_bytes=4096,
                        stderr_sink=sink)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
            self.assertEqual(result.stdout, b"progress-visible-before-exit\n")
            self.assertFalse(finished.exists())
            finished.write_text("parent completed\n")
            self.assertEqual(retained.read_bytes(), line)
            self.assertEqual(console.read_text(), self.displayed(1))


if __name__ == "__main__":
    unittest.main()
