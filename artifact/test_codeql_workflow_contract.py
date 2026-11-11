"""Scheduling and publication contracts shared by the CodeQL workflows."""
from __future__ import annotations

from pathlib import Path
import json
import os
import re
import subprocess
import tempfile
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

    def test_non_rust_checkout_keeps_sources_and_omits_only_historical_zip_files(self) -> None:
        workflow = self.read("codeql.yml")
        analysis = mapping(workflow, "analyze", 2)
        self.assertIn("          filter: blob:none\n", analysis)
        self.assertIn("          sparse-checkout-cone-mode: false\n", analysis)
        sparse = re.search(r"^          sparse-checkout: \|\n((?:^            .+\n)+)",
                           analysis, re.MULTILINE)
        self.assertIsNotNone(sparse)
        patterns = [line.strip() for line in sparse[1].splitlines()]
        self.assertEqual(patterns, ["/*", "!/research/sdk-alpha1/evidence/**/*.zip",
                                    "/research/sdk-alpha1/evidence/**/"])
        self.assertEqual(analysis.count("      - uses: actions/checkout@"), 1)
        checkout = analysis[analysis.index("      - uses: actions/checkout@"):]
        checkout = checkout.split("\n      - ", 1)[0]
        environment = mapping(checkout, "env", 8)
        entries = re.findall(r"^          (GIT_CONFIG_[A-Z0-9_]+): (.+)$",
                             environment, re.MULTILINE)
        checkout_environment = {key: json.loads(value) if value.startswith('"') else value
                                for key, value in entries}
        self.assertEqual(len(entries), len(checkout_environment))
        # Rust's producer/importer/publisher check every tracked byte and reject
        # skip-worktree. Keep their full checkout and provenance contract intact.
        for name in ("rust", "rust-macos-prepare", "rust-macos-analyze", "rust-publication"):
            job = mapping(workflow, name, 2)
            self.assertNotIn("sparse-checkout:", job)
            self.assertNotIn("filter:", job)

        kept = {
            "Cargo.toml", "Cargo.lock", ".github/workflows/codeql.yml",
            "crates/core/src/lib.rs", "bindings/swift/Package.swift",
            "artifact/codeql-summary-projection-plan.zip",
            "artifact/codeql-summary-dynamic-plan.zip",
            "paper/continuity/artifacts/record/source.rs",
            "paper/continuity/artifacts/record/SOURCE_PINS.json",
            "research/sdk-alpha1/evidence/old/consumer-Cargo.lock",
            "research/sdk-alpha1/evidence/old/source.rs",
            "research/sdk-alpha1/evidence/old/run.log",
            "research/sdk-alpha1/evidence/archive.zip/source.rs",
            "research/sdk-alpha1/evidence/archive.zip/nested/.source.py",
            "research/sdk-alpha1/evidence/old/case.ZIP",
            "research/sdk-alpha1/evidence/old/run.zip.sha256",
            "research/sdk-alpha1/evidence-prefix/retained.zip",
            "research/other/retained.zip",
        }
        omitted = {"research/sdk-alpha1/evidence/top.zip",
                   "research/sdk-alpha1/evidence/old/run.zip",
                   "research/sdk-alpha1/evidence/archive.zip/nested/run.zip"}
        for ignore_case in ("false", "true"):
            with self.subTest(repository_ignore_case=ignore_case), \
                    tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)

                def git(*arguments: str, checkout: bool = False) -> str:
                    environment = {**os.environ, **checkout_environment} if checkout else None
                    return subprocess.run(["git", "-C", str(root), *arguments], check=True,
                                          capture_output=True, text=True, timeout=10,
                                          env=environment).stdout

                git("init", "-q")
                for relative in kept | omitted:
                    path = root / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text("fixture\n", encoding="utf-8")
                git("add", "--all")
                tree = git("write-tree").strip()
                git("config", "core.ignoreCase", ignore_case)
                self.assertEqual(git("config", "--get", "core.ignoreCase").strip(), ignore_case)
                git("config", "core.sparseCheckout", "true")
                git("config", "core.sparseCheckoutCone", "false")
                (root / ".git/info/sparse-checkout").write_text("\n".join(patterns) + "\n")
                git("read-tree", "-mu", tree, checkout=True)
                self.assertEqual({path for path in kept | omitted if (root / path).is_file()}, kept)
                self.assertEqual(set(git("ls-files").splitlines()), kept | omitted)
                skipped = {record[2:] for record in git("ls-files", "-t").splitlines()
                           if record.startswith("S ")}
                self.assertEqual(skipped, omitted)

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
            "artifact/codeql_evaluator_logs.py",
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
        self.assertIn("artifact/test_codeql_progress.py", evaluate)
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

    def test_production_jobs_queue_independently_without_cancelling_running_analysis(self) -> None:
        workflow = self.read("codeql.yml")
        self.assertNotIn("concurrency", keys(workflow, 0))
        expected_groups = {
            "analyze": "analyze-${{ matrix.language }}",
            "rust": "rust-${{ matrix.profile }}",
            "rust-macos-prepare": "rust-macos-prepare",
            "rust-macos-analyze": "rust-macos-analyze",
            "rust-publication": "rust-publication",
        }
        self.assertEqual(keys(mapping(workflow, "jobs"), 2), set(expected_groups))
        groups = []
        for name, suffix in expected_groups.items():
            with self.subTest(job=name):
                job = mapping(workflow, name, 2)
                header = job.split("    steps:\n", 1)[0]
                concurrency = mapping(header, "concurrency", 4)
                self.assertEqual(keys(concurrency, 6), {"group", "cancel-in-progress"})
                group = re.findall(r"^      group: (.+)$", concurrency, re.MULTILINE)
                self.assertEqual(group, ["codeql-${{ github.workflow }}-${{ github.ref }}-" + suffix])
                self.assertIn("      cancel-in-progress: false\n", concurrency)
                groups.extend(group)
        self.assertEqual(len(groups), len(set(groups)))

    def test_all_production_targets_and_publication_use_the_authenticated_projection(self) -> None:
        workflow = self.read("codeql.yml")
        manifest = json.loads((ROOT / "artifact/codeql_summary_projection.json").read_text(encoding="utf-8"))
        archive = "$RUNNER_TEMP/codeql-bundle-rust-linux64.tar.zst"
        url = ("https://github.com/github/codeql-action/releases/download/codeql-bundle-v"
               + manifest["codeql_version"] + "/codeql-bundle-rust-linux64.tar.zst")
        for name, source_step in (("rust", "prepare"), ("rust-macos-analyze", "import")):
            with self.subTest(job=name):
                job = mapping(workflow, name, 2)
                marker = "      - name: Download the authenticated projection runtime\n"
                self.assertEqual(job.count(marker), 1)
                download = job.split(marker, 1)[1].split("      - ", 1)[0]
                self.assertIn("        timeout-minutes: 12\n", download)
                self.assertIn("          set -eu\n", download)
                self.assertIn('CODEQL_ARCHIVE="' + archive + '"', download)
                self.assertIn("curl --fail --location --proto '=https' --proto-redir '=https'", download)
                self.assertIn("--connect-timeout 30 --max-time 600 --max-filesize "
                              + str(manifest["tool_bundle_bytes"]), download)
                self.assertIn("'" + url + "'", download)
                self.assertIn('test "$(stat --format=\'%s\' "$CODEQL_ARCHIVE")" = '
                              + str(manifest["tool_bundle_bytes"]), download)
                self.assertIn("'" + manifest["tool_bundle_sha256"] + "'", download)
                self.assertIn('"$CODEQL_ARCHIVE" | sha256sum --check --strict', download)
                analysis = job.index("artifact/codeql_rust_profile.py analyze")
                self.assertLess(job.index("artifact/codeql_rust_profile.py " + source_step), job.index(marker))
                self.assertLess(job.index(marker), analysis)
                self.assertEqual(job.count("--summary-plan-mode projection"), 1)
                self.assertEqual(job.count('--tool-archive "' + archive + '"'), 1)
                self.assertGreater(job.index("--summary-plan-mode projection"), analysis)
                self.assertNotIn("continue-on-error:", job)
                self.assertIn("/analysis-plan/evaluator/**", job)
        preparation = mapping(workflow, "rust-macos-prepare", 2)
        self.assertNotIn("--summary-plan-mode", preparation)
        self.assertNotIn("--tool-archive", preparation)
        publication = mapping(workflow, "rust-publication", 2)
        self.assertEqual(publication.count("--summary-plan-mode projection"), 1)
        self.assertGreater(publication.index("--summary-plan-mode projection"),
                           publication.index("artifact/codeql_rust_publication.py"))

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
