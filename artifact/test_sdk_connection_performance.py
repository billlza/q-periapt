"""Incomplete or malformed connection captures cannot qualify as timing evidence."""
import copy
import json
import unittest

import sdk_connection_performance as perf


class ConnectionPerformanceTests(unittest.TestCase):
    def rows(self):
        return [{"schema": 1, "kind": "setup", "elapsed_ns": 500}] + [
            {"schema": 1, "kind": "connection", "index": index,
             "phase": "first" if index == 0 else "reconnect", "connect_ns": 100 + index,
             "payload_bytes": [0, 1, 65536], "request_ns": [10 + index, 20 + index, 30 + index],
             "shutdown_ns": 50 + index} for index in range(201)]

    def encode(self, rows):
        return b"\n".join([*(json.dumps(row).encode() for row in rows), perf.MARKER]) + b"\n"

    def test_setup_first_and_reconnect_quantiles_remain_distinct(self):
        summary = perf.summarize(perf.parse_samples(self.encode(self.rows()), 200))
        self.assertEqual(summary["setup_ns"], 500)
        self.assertEqual(summary["first"]["connect_ns"], 100)
        self.assertEqual(summary["reconnect_quantiles_ns"]["connect"], {"p50": 200, "p95": 290, "p99": 298})

    def test_missing_duplicate_reordered_or_unfinished_samples_fail(self):
        rows = self.rows()
        for raw in (self.encode(rows[:-1]), self.encode(rows + rows[-1:]),
                    self.encode([rows[0], rows[2], rows[1], *rows[3:]]),
                    self.encode(rows).replace(perf.MARKER, b"PROBE_FAILURE"),
                    self.encode(rows) + perf.MARKER + b"\n"):
            with self.subTest(raw_size=len(raw)), self.assertRaises(RuntimeError):
                perf.parse_samples(raw, 200)

    def test_time_shape_identity_and_payload_mutations_fail(self):
        for key, value in (("schema", True), ("index", False), ("phase", "first"),
                           ("kind", "ignored"), ("connect_ns", 0), ("connect_ns", True),
                           ("shutdown_ns", 1.5), ("shutdown_ns", 120_000_000_000),
                           ("request_ns", [1, 2]), ("request_ns", [1, -2, 3]),
                           ("payload_bytes", [False, 1, 65536]), ("payload_bytes", [0, 1, 65535])):
            rows = copy.deepcopy(self.rows()); rows[2][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(RuntimeError):
                perf.parse_samples(self.encode(rows), 200)
        for value in (0, True, 1.5, 120_000_000_000):
            rows = self.rows(); rows[0]["elapsed_ns"] = value
            with self.assertRaises(RuntimeError): perf.parse_samples(self.encode(rows), 200)
        with self.assertRaises(ValueError):
            perf.parse_samples(self.encode(self.rows()).replace(b'"elapsed_ns": 500', b'"elapsed_ns": 500, "elapsed_ns": 600'), 200)

    def test_ci_runs_bounded_diagnostic_and_only_uploads_public_observations(self):
        from test_proof_to_byte_release import extract_workflow_job
        job = extract_workflow_job((perf.ROOT / ".github/workflows/ci.yml").read_text(), "bindings-swift")
        step = job[job.index("      - name: Full Swift and Rust connection timing diagnostic"):]
        step = step[:step.index("      - name: Build deterministic Apple XCFramework")]
        self.assertIn("artifact/sdk_connection_performance.py --output target/sdk-connection-performance --reconnects 200", step)
        self.assertIn('RUSTFLAGS: "-D warnings"', step)
        self.assertIn("if: always()", step)
        self.assertIn("target/sdk-connection-performance/boundary/*.stderr", step)
        self.assertNotIn("continue-on-error", step)
        self.assertNotIn("fixtures", step)
        self.assertNotIn("**", step)


if __name__ == "__main__":
    unittest.main()
