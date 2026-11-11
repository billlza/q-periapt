"""Capsule admission and full-result gates for the experimental summary plan."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import codeql_summary_control as control
import codeql_summary_plan as plan
from evidence_io import EvidenceIOError
from test_codeql_summary_control import COMPILED_HASHES, FULL_SUMMARY, QUERY_HASHES, valid_report


def candidate_report(profile):
    report = valid_report(profile)
    report["summary_plan_mode"] = "all"
    report["summary_plan"] = plan.expected_identity()
    report["summary_plan_after"] = plan.expected_identity()
    report["compiled_query_hashes"][FULL_SUMMARY] = plan.PLAN_SHA256
    command = control.query_command(Path("/tool/codeql"), Path("/case/database"), Path("/case"), profile, "all")
    report["query_command"] = command
    report["evaluation"]["command"] = command
    report["observations"].update(
        precompiled_query_loads=[str((Path("/tool/qlpacks/codeql/rust-queries/0.1.44") / name).with_suffix(".qlx"))
                                 for name in QUERY_HASHES], query_compilations=0)
    return report


class FixedCapsuleTests(unittest.TestCase):
    def test_real_capsule_and_fixed_manifest_have_the_independent_pinned_identity(self):
        self.assertEqual(hashlib.sha256(plan.CAPSULE.read_bytes()).hexdigest(),
                         "ce21381b3bec721aab246b26b84c00834959871235e1e82354addca8a40dcef7")
        identity = plan.expected_identity()
        self.assertEqual(identity["compiler_inputs_digest"], "209f28c6b9e8d5465a3f8417573e42d6")
        self.assertEqual(len(identity["files"]), 16)
        self.assertEqual(identity["stage_count"], 15)
        compiled = dict(COMPILED_HASHES)
        compiled[FULL_SUMMARY] = identity["effective_plan_sha256"]
        self.assertEqual(control.canonical_sha(compiled), plan.COMPILED_INVENTORY_SHA256)

    def test_manifest_mutation_is_rejected_before_it_can_choose_other_members(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "manifest.json"
            value = json.loads(plan.MANIFEST.read_text())
            value["files"]["../../outside"] = value["files"].pop(plan.PLAN_PATH)
            path.write_text(json.dumps(value))
            with patch.object(plan, "MANIFEST", path), self.assertRaisesRegex(plan.PlanError, "manifest digest"):
                plan.manifest()

    def test_header_requires_the_all_compiler_key_and_complete_stage_closure(self):
        files = plan.manifest()["files"]
        stages = [name.removeprefix(".codeql/precompiled/") for name in files if name != plan.PLAN_PATH]
        header = ("inputsDigest: " + plan.COMPILER_INPUTS_DIGEST + "\n"
                  + "".join("- filename: " + name + "\n" for name in stages) + "...\n").encode()
        plan.admit_header(header, files)
        with self.assertRaisesRegex(plan.PlanError, "compiler input key"):
            plan.admit_header(header.replace(plan.COMPILER_INPUTS_DIGEST.encode(), b"0" * 32), files)
        with self.assertRaisesRegex(plan.PlanError, "stage closure"):
            plan.admit_header(header.replace(("- filename: " + stages[-1] + "\n").encode(), b""), files)


class CapsuleFilesystemTests(unittest.TestCase):
    """The capsule is real; only the original source/plan are synthetic fixtures."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.pack, self.evidence = self.root / "pack", self.root / "evidence"
        (self.pack / "queries/summary").mkdir(parents=True)
        (self.pack / ".codeql/precompiled").mkdir(parents=True)
        self.evidence.mkdir()
        self.original = b"synthetic original plan"
        self.source = b"synthetic original full summary source"
        (self.pack / plan.PLAN_PATH).write_bytes(self.original)
        (self.pack / plan.PLAN_PATH).with_suffix(".ql").write_bytes(self.source)
        value = plan.manifest()
        source_hash = hashlib.sha256(self.source).hexdigest()
        value["query_source_sha256"] = source_hash
        for replacement in (patch.object(plan, "manifest", return_value=value),
                            patch.object(plan, "SOURCE_SHA256", source_hash),
                            patch.object(plan, "BUNDLED_PLAN_SHA256", hashlib.sha256(self.original).hexdigest())):
            replacement.start()
            self.addCleanup(replacement.stop)
        self.files = value["files"]
        self.stage = next(name for name in self.files if name != plan.PLAN_PATH)

    def test_install_changes_only_the_fixed_plan_closure_and_preserves_original_bytes(self):
        identity = plan.install(self.pack, self.evidence)
        self.assertEqual(identity, plan.validate(self.pack))
        self.assertEqual((self.pack / plan.PLAN_PATH).with_suffix(".ql").read_bytes(), self.source)
        self.assertEqual((self.evidence / "SUMMARY_PLAN_ORIGINAL.qlx").read_bytes(), self.original)
        self.assertEqual(json.loads((self.evidence / "SUMMARY_PLAN.json").read_text()), identity)
        self.assertEqual({p.relative_to(self.pack).as_posix() for p in self.pack.rglob("*.qlx")}, set(self.files))

    def test_wrong_source_or_original_plan_fails_before_pack_mutation(self):
        (self.pack / plan.PLAN_PATH).with_suffix(".ql").write_bytes(b"changed source")
        with self.assertRaisesRegex(plan.PlanError, "source changed"):
            plan.install(self.pack, self.evidence)
        self.assertEqual((self.pack / plan.PLAN_PATH).read_bytes(), self.original)
        self.assertEqual(list(self.evidence.iterdir()), [])

    def test_bad_capsule_digest_fails_before_pack_mutation(self):
        capsule = self.root / "changed.zip"
        data = bytearray(plan.CAPSULE.read_bytes())
        data[-1] ^= 1
        capsule.write_bytes(data)
        with patch.object(plan, "CAPSULE", capsule), self.assertRaisesRegex(plan.PlanError, "capsule digest"):
            plan.install(self.pack, self.evidence)
        self.assertEqual((self.pack / plan.PLAN_PATH).read_bytes(), self.original)
        self.assertFalse((self.pack / self.stage).exists())

    def test_existing_stage_is_not_overwritten(self):
        path = self.pack / self.stage
        path.write_bytes(b"existing stage")
        with self.assertRaisesRegex(plan.PlanError, "already exists"):
            plan.install(self.pack, self.evidence)
        self.assertEqual(path.read_bytes(), b"existing stage")
        self.assertEqual((self.pack / plan.PLAN_PATH).read_bytes(), self.original)

    def test_missing_changed_or_symlinked_stage_fails_postcheck(self):
        plan.install(self.pack, self.evidence)
        stage = self.pack / self.stage
        original = stage.read_bytes()
        stage.unlink()
        with self.assertRaises((EvidenceIOError, OSError)):
            plan.validate(self.pack)
        stage.write_bytes(b"changed stage")
        with self.assertRaisesRegex(plan.PlanError, "effective summary plan member"):
            plan.validate(self.pack)
        stage.unlink()
        outside = self.root / "same-stage"
        outside.write_bytes(original)
        stage.symlink_to(outside)
        with self.assertRaises((EvidenceIOError, OSError)):
            plan.validate(self.pack)

    def test_symlinked_stage_parent_is_rejected_before_any_write(self):
        directory = self.pack / ".codeql/precompiled"
        directory.rmdir()
        outside = self.root / "outside"
        outside.mkdir()
        directory.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(plan.PlanError, "parent"):
            plan.install(self.pack, self.evidence)
        self.assertEqual(list(outside.iterdir()), [])

    def test_reinstallation_and_source_change_after_install_are_rejected(self):
        plan.install(self.pack, self.evidence)
        with self.assertRaisesRegex(plan.PlanError, "original bundled summary plan"):
            plan.install(self.pack, self.evidence)
        (self.pack / plan.PLAN_PATH).with_suffix(".ql").write_bytes(b"changed source")
        with self.assertRaisesRegex(plan.PlanError, "source changed"):
            plan.validate(self.pack)


class CandidateResultAdmissionTests(unittest.TestCase):
    def test_complete_pair_retains_full_39_and_original_38_semantic_requirements(self):
        result = control.compare_reports(candidate_report("heap-2048"), candidate_report("heap-1536"), "all")
        self.assertTrue(result["completed"])
        self.assertEqual(result["query_count"], 39)
        self.assertEqual(result["retained_result_count"], 38)
        self.assertEqual(result["summary_plan_mode"], "all")
        self.assertFalse(result["production_default_validated"])
        self.assertFalse(result["sarif_published"])

    def test_default_comparison_does_not_admit_candidate_or_mixed_plan_modes(self):
        with self.assertRaisesRegex(control.ControlError, "plan mode"):
            control.compare_reports(candidate_report("heap-2048"), candidate_report("heap-1536"))
        with self.assertRaisesRegex(control.ControlError, "plan mode"):
            control.compare_reports(candidate_report("heap-2048"), valid_report("heap-1536"), "all")

    def test_missing_or_changed_postcheck_and_another_changed_query_are_rejected(self):
        for mutation in ("missing_postcheck", "changed_stage", "changed_query", "compiler_fallback", "missing_load"):
            with self.subTest(mutation=mutation):
                a, b = candidate_report("heap-2048"), candidate_report("heap-1536")
                if mutation == "missing_postcheck":
                    b.pop("summary_plan_after")
                elif mutation == "changed_stage":
                    name = next(name for name in b["summary_plan_after"]["files"] if name != plan.PLAN_PATH)
                    b["summary_plan_after"]["files"][name]["sha256"] = "f" * 64
                elif mutation == "changed_query":
                    for report in (a, b):
                        report["compiled_query_hashes"][next(name for name in QUERY_HASHES if name != FULL_SUMMARY)] = "f" * 64
                elif mutation == "compiler_fallback":
                    b["observations"]["query_compilations"] = 1
                else:
                    b["observations"]["precompiled_query_loads"].pop()
                with self.assertRaises(control.ControlError):
                    control.compare_reports(a, b, "all")

    def test_candidate_timeout_partial_results_or_semantic_change_still_fail(self):
        for mutation in ("timeout", "missing_summary", "retained_mismatch", "pair_mismatch"):
            with self.subTest(mutation=mutation):
                a, b = candidate_report("heap-2048"), candidate_report("heap-1536")
                if mutation == "timeout":
                    b["evaluation"].update(returncode=None, stopped="timeout")
                    b["completed"] = False
                elif mutation == "missing_summary":
                    b["results"].pop(FULL_SUMMARY)
                elif mutation == "retained_mismatch":
                    query = next(iter(b["retained_results"]))
                    b["results"][query]["semantic_sha256"] = "f" * 64
                else:
                    b["results"][FULL_SUMMARY]["semantic_sha256"] = "f" * 64
                with self.assertRaises(control.ControlError):
                    control.compare_reports(a, b, "all")

    def test_all_command_changes_only_the_explicit_plan_mode(self):
        args = (Path("/tool/codeql"), Path("/case/database"), Path("/case"), "heap-2048")
        original, candidate = control.query_command(*args), control.query_command(*args, "all")
        self.assertEqual([(a, b) for a, b in zip(original, candidate) if a != b],
                         [("--dynamic-join-order-mode=none", "--dynamic-join-order-mode=all")])

    def test_real_evaluator_timeout_remains_primary_when_stage_postcheck_also_fails(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            output = root / "case"
            queries = {name: Path("/unused/queries") / name for name in QUERY_HASHES}
            compiled = dict(COMPILED_HASHES)
            compiled[FULL_SUMMARY] = plan.PLAN_SHA256
            paths = {str(path): QUERY_HASHES[name] for name, path in queries.items()}
            paths.update({str(path.with_suffix(".qlx")): compiled[name] for name, path in queries.items()})
            real_sha, real_run = control.sha, control.run_queries
            def digest(path):
                return paths[str(path)] if str(path) in paths else real_sha(path)
            def run(command, evidence, environment):
                return real_run([sys.executable, "-c", "import time;print('retained evaluator output',flush=True);time.sleep(60)"],
                                evidence, environment, 1)
            with patch.dict(os.environ, {"RUNNER_TEMP": str(root)}), \
                    patch.object(control, "prepare_database", return_value=(output / "database", {})), \
                    patch.object(control, "admit_tool", return_value=(queries, {}, QUERY_HASHES, COMPILED_HASHES, control.SOURCE_ALLOCATION)), \
                    patch.object(control, "sha", side_effect=digest), \
                    patch.object(plan, "install", return_value=plan.expected_identity()), \
                    patch.object(plan, "validate", side_effect=FileNotFoundError("missing candidate stage")), \
                    patch.object(control, "jvm_probe", return_value=valid_report("heap-2048")["jvm_admission"]), \
                    patch.object(control, "decode_retained_results", return_value={}), \
                    patch.object(control, "evaluator_observations", return_value={}), \
                    patch.object(control, "run_queries", side_effect=run):
                with self.assertRaisesRegex(RuntimeError, "Retained SummaryStats control failed"):
                    control.evaluate(Path("/unused/codeql"), Path("/unused/bundle"), output, "heap-2048", "all")
            report = json.loads((output / "evidence/RESULT.json").read_text())
            self.assertEqual(report["failure"]["type"], "BoundedProcessError")
            self.assertEqual(report["failure"]["phase"], "evaluate")
            self.assertEqual(report["evaluation"]["stopped"], "timeout")
            self.assertEqual(report["summary_plan_after_failure"]["type"], "FileNotFoundError")
            self.assertFalse(report["completed"])
            self.assertIn("retained evaluator output", (output / "evidence/query.stdout").read_text())


if __name__ == "__main__":
    unittest.main()
