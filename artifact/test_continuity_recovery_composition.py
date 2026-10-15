from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import continuity_recovery_composition as composition
import continuity_recovery_proof as proof
from bounded_process import BoundedProcessError


class RecoveryCompositionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.case = proof.certificate("positive", "shared-storage")
        cls.data = proof.load_inputs(proof.ROOT, "shared-storage")["positive"]
        cls.fixture = json.loads((proof.ROOT / "artifact/fixtures/continuity-recovery-composition-v1.json").read_text())

    def records(self):
        # Shape fixtures exercise the composition boundary, not the prover.
        return {node.name: {
            "source_certificate_sha256": self.case.sha256,
            "input_sha256": node.sha256, "dependencies": list(node.dependencies),
            "result": {"returncode": 0, "verified": {node.name: self.fixture["nodes"][node.name]["steps"]}},
        } for node in composition.plan(self.data, self.case)}

    def test_all_generated_inputs_match_the_actual_twenty_replays(self):
        self.assertEqual(self.case.sha256, self.fixture["source_certificate_sha256"])
        nodes = composition.plan(self.data, self.case)
        self.assertEqual(20, len(nodes))
        for node in nodes:
            self.assertEqual(node.sha256, self.fixture["nodes"][node.name]["sha256"])
            self.assertEqual(list(node.dependencies), self.fixture["nodes"][node.name]["dependencies"])
        self.assertEqual(set(self.case.verified), set(composition.combine(self.data, self.records(), self.case)))

    def test_every_missing_or_incomplete_property_is_rejected(self):
        for name in self.case.verified:
            for mode in ("missing", "incomplete"):
                records = self.records()
                if mode == "missing":
                    del records[name]
                else:
                    records[name]["result"]["verified"] = {}
                with self.subTest(name=name, mode=mode), self.assertRaises(composition.CompositionError):
                    composition.combine(self.data, records, self.case)

    def test_wrong_model_cycle_input_and_failed_process_are_rejected(self):
        first = composition.plan(self.data, self.case)[0].name
        for mutation in ("source", "cycle", "input", "exit", "steps", "extra", "malformed"):
            records = self.records()
            if mutation == "source":
                records[first]["source_certificate_sha256"] = "0" * 64
            elif mutation == "cycle":
                records[first]["dependencies"] = [self.case.verified[-1]]
            elif mutation == "input":
                records[first]["input_sha256"] = "0" * 64
            elif mutation == "exit":
                records[first]["result"]["returncode"] = 1
            elif mutation == "steps":
                records[first]["result"]["verified"][first] = True
            elif mutation == "extra":
                records["unexpected"] = records[first]
            else:
                records[first] = None
            with self.subTest(mutation=mutation), self.assertRaises(composition.CompositionError):
                composition.combine(self.data, records, self.case)

    def test_dependency_is_derived_from_source_not_an_untrusted_receipt(self):
        records = self.records()
        later = next(node for node in composition.plan(self.data, self.case) if node.dependencies)
        records[later.name]["dependencies"] = []
        with self.assertRaisesRegex(composition.CompositionError, "dependency graph"):
            composition.combine(self.data, records, self.case)

    def test_changed_source_and_new_global_sources_are_rejected(self):
        with self.assertRaisesRegex(composition.CompositionError, "source certificate"):
            composition.plan(self.data + b"\n", self.case)
        changed = self.data.replace(b"[use_induction, reuse]", b"[use_induction, reuse, sources]", 1)
        self.assertNotEqual(self.data, changed)
        new_case = replace(self.case, sha256=hashlib.sha256(changed).hexdigest())
        with self.assertRaisesRegex(composition.CompositionError, "global source lemmas"):
            composition.plan(changed, new_case)

    def test_timeout_stops_composition_without_accepting_later_parts(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with mock.patch.object(proof, "capture_output", side_effect=BoundedProcessError("timeout", "deadline")) as capture:
                with self.assertRaises(BoundedProcessError):
                    proof.replay("positive", self.data, directory, {"PATH": "/usr/bin"}, "shared-storage")
            self.assertEqual(1, capture.call_count)
            self.assertFalse((directory / "positive/COMPOSITION.json").exists())
            self.assertEqual(900, capture.call_args.kwargs["timeout_seconds"])
            self.assertFalse(any(value.startswith("--prove") for value in capture.call_args.args[0]))
            self.assertNotIn("-A64m", capture.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
