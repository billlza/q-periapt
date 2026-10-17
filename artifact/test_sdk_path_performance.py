"""A partial or malformed timing capture must not become successful evidence."""
import copy
import json
import unittest

import sdk_path_performance as perf


class SDKPathPerformanceTests(unittest.TestCase):
    def rows(self):
        return [{"schema": 1, "surface": "c_dynamic", "operation": op, "context_bytes": context,
                 "phase": 0, "warmup_pairs": 64, "legacy_raw_ns": list(range(1, 201)),
                 "owner_raw_ns": list(range(2, 402, 2))} for op, context in perf.CELLS]

    def encode(self, rows):
        return b"\n".join(json.dumps(row).encode() for row in rows)

    def test_real_contract_has_all_seven_cells_and_nearest_rank_quantiles(self):
        rows = perf.parse_samples(self.encode(self.rows()), "c_dynamic", 200, 0)
        summary = perf.summarize(rows)
        self.assertEqual(summary[0]["legacy_ns"], {"p50": 100, "p95": 190, "p99": 198})
        self.assertEqual(summary[0]["ratio_of_quantiles"], {"p50": 2, "p95": 2, "p99": 2})

    def test_missing_duplicate_or_reordered_cells_fail(self):
        rows = self.rows()
        for changed in (rows[:-1], rows + rows[:1], [rows[1], rows[0], *rows[2:]], [rows[0]] * 7):
            with self.subTest(changed=changed[0]["operation"]):
                with self.assertRaises(RuntimeError): perf.parse_samples(self.encode(changed), "c_dynamic", 200, 0)

    def test_bad_time_counts_shapes_and_contracts_fail(self):
        for key, value in (("schema", True), ("phase", 1), ("warmup_pairs", 0), ("context_bytes", False),
                           ("surface", "rust"), ("legacy_raw_ns", [1] * 199),
                           ("owner_raw_ns", [0] * 200), ("owner_raw_ns", [True] * 200),
                           ("owner_raw_ns", [1.5] * 200), ("owner_raw_ns", [1 << 53] * 200)):
            rows = copy.deepcopy(self.rows()); rows[0][key] = value
            with self.subTest(key=key):
                with self.assertRaises(RuntimeError): perf.parse_samples(self.encode(rows), "c_dynamic", 200, 0)


if __name__ == "__main__":
    unittest.main()
