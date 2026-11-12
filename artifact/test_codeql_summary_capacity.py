"""The capacity experiment retains the hosted comparison's original contract."""
from pathlib import Path
import unittest

import codeql_summary_control as control
from test_codeql_summary_control import valid_report


class CapacityProfileTests(unittest.TestCase):
    def test_original_profiles_keep_their_exact_hosted_budget(self):
        for profile, allocation in {"heap-2048": (2048, 10643), "heap-1536": (1536, 11155)}.items():
            self.assertEqual(control.PROFILES[profile], allocation)
            self.assertEqual(control.configuration(profile)["requested_ram_mb"], 14000)

    def test_capacity_profile_has_a_distinct_fixed_budget(self):
        self.assertEqual(control.configuration("memory-56000"), {
            "requested_ram_mb": 56000, "heap_mb": 4096, "native_mb": 50595,
            "reserved_mb": 1309, "threads": 4, "deadline_seconds": 18000,
        })

    def test_memory_is_the_only_evaluator_command_change(self):
        commands = [control.query_command(Path("/tool/codeql"), Path("/case/database"),
                                         Path("/case"), profile, "projection")
                    for profile in ("heap-2048", "memory-56000")]
        fixed = lambda command: [a for a in command if not a.startswith(("-J-Xmx", "--off-heap-ram="))]
        self.assertEqual(fixed(commands[0]), fixed(commands[1]))
        self.assertIn("-J-Xmx4096M", commands[1])
        self.assertIn("--off-heap-ram=50595", commands[1])

    def test_observed_allocation_must_match_the_capacity_profile(self):
        observation = {"schema": 1, "max_heap_bytes_observed": [4096 * 1024**2],
                       "off_heap_mb_observed": [50595], "evaluator_start_lines": 1,
                       "pause_count": 0, "eviction_pause_count": 0}
        control.validate_observations(observation, "memory-56000")
        with self.assertRaises(control.ControlError):
            control.validate_observations(observation, "heap-2048")
        observation["off_heap_mb_observed"] = [10643]
        with self.assertRaises(control.ControlError):
            control.validate_observations(observation, "memory-56000")

    def test_larger_capacity_changes_only_the_native_allocation(self):
        baseline = control.configuration("memory-56000")
        larger = control.configuration("memory-120000")
        self.assertEqual(larger, baseline | {"requested_ram_mb": 120000, "native_mb": 114595})
        commands = [control.query_command(Path("/tool/codeql"), Path("/case/database"),
                                         Path("/case"), profile, "projection")
                    for profile in ("memory-56000", "memory-120000")]
        fixed = lambda command: [a for a in command if not a.startswith("--off-heap-ram=")]
        self.assertEqual(fixed(commands[0]), fixed(commands[1]))
        self.assertIn("--off-heap-ram=114595", commands[1])
        observation = {"schema": 1, "max_heap_bytes_observed": [4096 * 1024**2],
                       "off_heap_mb_observed": [114595], "evaluator_start_lines": 1,
                       "pause_count": 0, "eviction_pause_count": 0}
        control.validate_observations(observation, "memory-120000")
        with self.assertRaises(control.ControlError):
            control.validate_observations(observation, "memory-56000")
        report = valid_report("heap-1536")
        report["profile"] = "memory-120000"
        report["configuration"] = larger
        with self.assertRaisesRegex(control.ControlError, "comparison report identity differs"):
            control.compare_reports(valid_report("heap-2048"), report)

    def test_cpu_control_keeps_every_argument_except_threads(self):
        baseline = control.configuration("memory-120000")
        candidate = control.configuration("memory-120000-threads-16")
        self.assertEqual(candidate, baseline | {"threads": 16})
        commands = [control.query_command(Path("/tool/codeql"), Path("/case/database"),
                                         Path("/case"), profile, "projection")
                    for profile in ("memory-120000", "memory-120000-threads-16")]
        fixed = lambda command: [arg for arg in command if not arg.startswith("--threads=")]
        self.assertEqual(fixed(commands[0]), fixed(commands[1]))
        self.assertIn("--threads=4", commands[0])
        self.assertIn("--threads=16", commands[1])
        for profile in ("heap-2048", "heap-1536", "memory-56000", "memory-120000"):
            self.assertEqual(control.configuration(profile)["threads"], 4)

    def test_cpu_control_cannot_impersonate_the_hosted_comparison(self):
        report = valid_report("heap-1536")
        report["profile"] = "memory-120000-threads-16"
        report["configuration"] = control.configuration(report["profile"])
        with self.assertRaisesRegex(control.ControlError, "comparison report identity differs"):
            control.compare_reports(valid_report("heap-2048"), report)

    def test_capacity_result_cannot_impersonate_the_hosted_comparison(self):
        report = valid_report("heap-1536")
        report["profile"] = "memory-56000"
        report["configuration"] = control.configuration("memory-56000")
        with self.assertRaisesRegex(control.ControlError, "comparison report identity differs"):
            control.compare_reports(valid_report("heap-2048"), report)


if __name__ == "__main__":
    unittest.main()
