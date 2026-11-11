"""Scheduling and publication contracts shared by the CodeQL workflows."""
from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github/workflows"


def mapping(text: str, key: str, indentation: int = 0) -> str:
    """Read one block in the repository's block-style workflow mappings."""
    lines = text.splitlines(keepends=True)
    prefix = " " * indentation + key + ":"
    starts = [index for index, line in enumerate(lines)
              if line.startswith(prefix) and line[len(prefix):].strip() == ""]
    if len(starts) != 1:
        raise AssertionError(f"expected one workflow mapping: {key}")
    start = starts[0]
    for end in range(start + 1, len(lines)):
        line = lines[end]
        if line.strip() and not line.lstrip().startswith("#") \
                and len(line) - len(line.lstrip()) <= indentation:
            return "".join(lines[start:end])
    return "".join(lines[start:])


def keys(block: str, indentation: int) -> set[str]:
    return set(re.findall(r"^" + " " * indentation + r"([a-z_][a-z0-9_-]*):", block, re.MULTILINE))


class CodeQLWorkflowContractTests(unittest.TestCase):
    def read(self, name: str) -> str:
        return (WORKFLOWS / name).read_text(encoding="utf-8")

    def test_candidate_ci_has_one_automatic_matrix_without_losing_release_or_pr_checks(self) -> None:
        workflow = self.read("ci.yml")
        triggers = mapping(workflow, "on")
        self.assertEqual(keys(triggers, 2), {"push", "pull_request", "workflow_dispatch"})
        push = mapping(triggers, "push", 2)
        self.assertEqual(re.findall(r"^    branches: (.+)$", push, re.MULTILINE), ["[main]"])
        self.assertEqual(re.findall(r"^    tags: (.+)$", push, re.MULTILINE), ["['**']"])
        # Required jobs must still run for every PR; path filters would leave
        # protected contexts pending on unrelated-looking source changes.
        self.assertEqual(keys(mapping(triggers, "pull_request", 2), 4), set())
        self.assertIn("unittest discover -s artifact -p 'test_*.py' -v", workflow)

    def test_production_codeql_keeps_pr_main_and_periodic_coverage(self) -> None:
        triggers = mapping(self.read("codeql.yml"), "on")
        self.assertEqual(keys(triggers, 2), {"push", "pull_request", "schedule", "workflow_dispatch"})
        for event in ("push", "pull_request"):
            block = mapping(triggers, event, 2)
            self.assertEqual(keys(block, 4), {"branches"})
            self.assertIn("branches: [main]", block)

    def test_retained_auxiliary_diagnostics_require_an_explicit_dispatch(self) -> None:
        for filename in ("codeql-memory-control.yml", "codeql-log-recovery.yml"):
            with self.subTest(workflow=filename):
                self.assertEqual(keys(mapping(self.read(filename), "on"), 2), {"workflow_dispatch"})

    def test_projection_push_is_an_explicit_opt_in_with_an_unambiguous_plan(self) -> None:
        workflow = self.read("codeql-summary-control.yml")
        triggers = mapping(workflow, "on")
        self.assertEqual(keys(triggers, 2), {"push", "workflow_dispatch"})
        push = mapping(triggers, "push", 2)
        self.assertEqual(re.findall(r"^    branches: (.+)$", push, re.MULTILINE),
                         ["[diagnostic/codeql-summary-projection]"])
        dispatch = mapping(triggers, "workflow_dispatch", 2)
        self.assertIn("options: [none, all, projection]", dispatch)
        self.assertIn("required: true", dispatch)
        self.assertIn("default: none", dispatch)
        self.assertIn("SUMMARY_PLAN_MODE: ${{ (github.event_name == 'push' && "
                      "github.ref_name == 'diagnostic/codeql-summary-projection' && 'projection') "
                      "|| inputs.summary_plan_mode }}", mapping(workflow, "env"))
        self.assertNotIn("diagnostic/codeql-summary-joins", workflow)
        self.assertNotIn("diagnostic/codeql-summary-cache", workflow)

    def test_both_summary_workers_receive_the_same_projection_capsule_and_mode(self) -> None:
        workflow = self.read("codeql-summary-control.yml")
        runtime_files = {
            "artifact/codeql_summary_projection.py",
            "artifact/codeql_summary_projection.json",
            "artifact/codeql_summary_projection_dependencies.json.gz",
            "artifact/codeql_summary_projection.patch",
            "artifact/codeql-summary-projection-plan.zip",
            "artifact/codeql-summary-projection-plan.LICENSE",
            "artifact/codeql_summary_plan.py",
            "artifact/codeql_summary_dynamic_plan.json",
            "artifact/codeql-summary-dynamic-plan.zip",
        }
        for name in ("evaluate", "compare"):
            job = mapping(workflow, name, 2)
            with self.subTest(job=name):
                paths = set(re.findall(r"^            (artifact/\S+)$", job, re.MULTILINE))
                self.assertLessEqual(runtime_files, paths)
                self.assertEqual(job.count('--summary-plan-mode "$SUMMARY_PLAN_MODE"'), 1)
                self.assertNotIn("continue-on-error:", job)
        evaluate = mapping(workflow, "evaluate", 2)
        self.assertIn("artifact/test_codeql_summary_projection.py", evaluate)
        self.assertRegex(evaluate, r"run: sh artifact/python-run.sh -m unittest -v [^\n]+ test_codeql_summary_projection\n")

    def test_summary_comparison_keeps_both_fresh_complete_results_and_failure_evidence(self) -> None:
        workflow = self.read("codeql-summary-control.yml")
        evaluate = mapping(workflow, "evaluate", 2)
        compare = mapping(workflow, "compare", 2)
        self.assertIn("profile: [heap-2048, heap-1536]", evaluate)
        self.assertIn("fail-fast: false", evaluate)
        self.assertIn("Run all 39 queries", evaluate)
        self.assertIn("    needs: evaluate\n", compare)
        self.assertIn("    if: always()\n", compare)
        self.assertIn("Admit identical inputs and all 39 complete fresh semantic results", compare)
        for profile in ("heap-2048", "heap-1536"):
            self.assertIn("name: codeql-summary-control-" + profile, compare)
            self.assertIn("/" + profile + "/RESULT.json", compare)
        self.assertIn("if-no-files-found: error", evaluate)
        self.assertIn("if-no-files-found: error", compare)

    def test_rust_publication_waits_for_every_profile_and_validation_before_upload(self) -> None:
        job = mapping(self.read("codeql.yml"), "rust-publication", 2)
        header, steps = job.split("    steps:\n", 1)
        self.assertIn("needs: [rust, rust-macos-prepare, rust-macos-analyze]", header)
        # A producer failure must prevent publication, including when receipts
        # from an earlier successful run attempt are still downloadable.
        self.assertNotIn("if:", header)
        self.assertNotIn("continue-on-error:", job)
        validation = steps.index("artifact/codeql_rust_publication.py")
        uploads = list(re.finditer(r"uses: github/codeql-action/upload-sarif@", steps))
        self.assertEqual(len(uploads), 3)
        self.assertTrue(all(upload.start() > validation for upload in uploads))
        for category in ("/language:rust", "/language:rust/target:wasm", "/language:rust/target:macos"):
            self.assertEqual(len(re.findall(r"^          category: " + re.escape(category) + "$",
                                           steps, re.MULTILINE)), 1)


if __name__ == "__main__":
    unittest.main()
