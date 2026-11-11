"""Projection boundaries with simulated CodeQL commands and one real stdin child."""
from __future__ import annotations

from contextlib import ExitStack
import copy
import dataclasses
import hashlib
import json
import os
from pathlib import Path
import tempfile
import sys
import unittest
from unittest.mock import patch

import codeql_rust_plan as plan
import codeql_rust_profile as profile
from bounded_process import capture_output
from test_codeql_rust_profile import sarif


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def replace_fixture(path: Path, data: bytes) -> None:
    """Replace a fixture inode to exercise validation beyond read-only modes."""
    path.unlink()
    write(path, data)


@unittest.skipUnless(os.name == "posix" and hasattr(os, "geteuid"),
                     "private runtime ownership, mode and descriptor admission require POSIX")
class ProductionProjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.source = self.root / "source"
        self.source.mkdir()
        self.runner = self.root / "runner"
        self.runner.mkdir()
        self.output = self.runner / "qperiapt-codeql-native"
        self.run = profile.ProfileRun(self.source, self.output, Path("/old/codeql"), {
            "HOME": "/inherited/home", "CODEQL_DIST": "/wrong/distribution",
            "CODEQL_JAVA_HOME": "/wrong/java", "JAVA_TOOL_OPTIONS": "unadmitted",
            "LD_PRELOAD": "/unadmitted.so", "PATH": "/unadmitted/bin",
            "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2",
            "CODEQL_EXPECTED_COMMIT": "a" * 40, "RUNNER_TRACKING_ID": "fixture-runner",
        })
        self.run.configuration = dataclasses.replace(
            self.run.configuration, database=self.runner / "database", runner_temp=self.runner)
        write(self.run.configuration.database / "codeql-database.yml",
              b'---\nsourceLocationPrefix: "/source"\noverlayBaseDatabase: false\noverlayDatabase: false\n')
        profile.sdk.write_json(self.run.evidence / "PROFILE.json", {
            "profile": "native", "target": profile.TARGETS["native"], "source_commit": "a" * 40,
            "run_id": "123", "run_attempt": "1", "active_target_quality_passed": True,
        })
        self.query_names = json.loads(plan.projection.QUERY_MANIFEST.read_text())["queries"]
        self.sources = {name: ("// fixture " + name + "\n").encode() for name in self.query_names}
        self.queries = {name: digest(data) for name, data in self.sources.items()}
        self.query_manifest = self.source / "artifact/codeql_rust_queries.json"
        write(self.query_manifest, json.dumps({
            "codeql_version": "2.27.2", "query_pack": "0.1.44", "queries": self.queries,
        }).encode())
        self.archive = self.root / "fixed.tar.zst"
        self.archive_bytes = b"admitted archive fixture"
        self.archive.write_bytes(self.archive_bytes)
        self.identity = plan.expected_identity()
        self.identity.update(query_manifest_sha256=digest(self.query_manifest.read_bytes()),
                             tool_bundle_bytes=len(self.archive_bytes),
                             tool_bundle_sha256=digest(self.archive_bytes))
        self.launcher = b"#!/bin/sh\n# fixture\n"
        self.jar = b"fixed runtime fixture"
        self.runtime = {
            "codeql": {"bytes": len(self.launcher), "sha256": digest(self.launcher), "mode": 0o755},
            "tools/codeql.jar": {"bytes": len(self.jar), "sha256": digest(self.jar), "mode": 0o644},
        }
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.multiple(
            plan, LAUNCHER_SHA256=digest(self.launcher),
            RUNTIME_INVENTORY_SHA256=plan.canonical_sha(self.runtime),
            RUNTIME_FILE_COUNT=2, RUNTIME_TOTAL_BYTES=len(self.launcher) + len(self.jar)))
        self.stack.enter_context(patch.object(plan, "expected_identity", return_value=self.identity))
        self.stack.enter_context(patch.object(plan.projection, "QUERY_MANIFEST", self.query_manifest))
        self.install = self.stack.enter_context(patch.object(
            plan.projection, "install", side_effect=self.install_plan))
        self.validate = self.stack.enter_context(patch.object(
            plan.projection, "validate", return_value=self.identity))
        self.stack.enter_context(patch.object(profile.quality, "require_clean_checkout"))
        self.stack.enter_context(patch.dict(os.environ, {
            "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2", "CODEQL_EXPECTED_COMMIT": "a" * 40,
        }))
        self.stack.enter_context(patch.object(
            plan.quality, "hosted_configuration", return_value=self.run.configuration))
        self.command = self.stack.enter_context(patch.object(
            self.run, "command", side_effect=self.command_fixture))
        self.inject = None

    @property
    def private_root(self) -> Path:
        return self.output / "analysis-plan"

    @property
    def pack(self) -> Path:
        return self.private_root / "tool/codeql" / plan.PACK_RELATIVE

    def install_plan(self, pack: Path, evidence: Path) -> dict:
        self.assertEqual(pack, self.pack)
        plan.write_json(evidence / "SUMMARY_PLAN.json", self.identity)
        return self.identity

    def command_fixture(self, label: str, argv: list[str], **kwargs) -> bytes:
        if label == "plan-extract":
            self.assertEqual(os.read(kwargs["stdin_fd"], 1000), self.archive_bytes)
            self.assertIn("--same-permissions", argv)
            launcher = self.private_root / "tool/codeql/codeql"
            write(launcher, self.launcher)
            launcher.chmod(0o755)
            jar = self.private_root / "tool/codeql/tools/codeql.jar"
            write(jar, self.jar)
            jar.chmod(0o644)
            for name, data in self.sources.items():
                write(self.pack / name, data)
                write((self.pack / name).with_suffix(".qlx"), b"fixed compiled fixture")
            return b""
        if label == "plan-version":
            # CodeQL 2.27.2 version/RAM commands do not accept pack-manager
            # options. The private configuration belongs to query resolution
            # and analysis, whose checks below must keep it attached.
            self.assertEqual(argv, [str(self.private_root / "tool/codeql/codeql"),
                                    "version", "--format=terse"])
            return b"2.27.2\n"
        if label == "resolve-suite":
            self.assertIn("--qlconfig-file=" + str(self.private_root / "qlconfig.yml"), argv)
            return json.dumps([str(self.pack / name) for name in self.queries]).encode()
        if label == "resolve-analysis-ram":
            self.assertFalse(any(argument.startswith("--qlconfig-file") for argument in argv))
            return b'["-J-Xmx3356M", "--off-heap-ram=9329"]'
        self.assertEqual(label, "analyze")
        self.assertEqual(argv[1:3], ["database", "analyze"])
        self.assertIn("--qlconfig-file=" + str(self.private_root / "qlconfig.yml"), argv)
        self.assertEqual(kwargs["seconds"], 18000)
        for option in ("--threads=4", "--ram=14000", "--off-heap-ram=9329"):
            self.assertIn(option, argv)
        self.assertFalse(any(argument.startswith("--evaluator-log-level") for argument in argv))
        for name in self.queries:
            if self.inject == "missing_result" and name == "queries/summary/SummaryStats.ql":
                continue
            write(self.run.configuration.database / "results/codeql/rust-queries" /
                  Path(name).with_suffix(".bqrs"), b"fresh complete BQRS fixture")
        write(self.run.evidence / "results.sarif", json.dumps(sarif()).encode())
        lines = [
            "[2026-11-11 12:00:00] This is codeql execute queries -J-Xmx3356M --off-heap-ram=9329",
        ]
        for name in self.queries:
            lines.extend([
                "[PROGRESS] Loaded " + str((self.pack / name).with_suffix(".qlx")) + ".",
                "[PROGRESS] Starting evaluation of " + name + ".",
                "[PROGRESS] Evaluation done; writing results to " + name + ".bqrs",
            ])
        if self.inject == "implicit_compile":
            lines.append("[PROGRESS] Compiling query plan for SummaryStats.ql")
        if self.inject == "extra_load":
            lines.append("[PROGRESS] Loaded /other/query.qlx.")
        if self.inject == "wrong_heap":
            lines[0] = lines[0].replace("3356", "3355")
        data = ("\n".join(lines) + "\n").encode()
        write(self.private_root / "evaluator/execute-queries-fixture.log", data)
        write(self.private_root / "evaluator/database-analyze-fixture.log", data)
        if self.inject in ("runtime_mutation", "primary_and_postcheck_failure"):
            write(self.private_root / "tool/codeql/tools/codeql.jar", b"different runtime")
        if self.inject == "qlconfig_mutation":
            configuration = self.private_root / "qlconfig.yml"
            self.assertEqual(configuration.stat().st_mode & 0o222, 0)
            replace_fixture(configuration, b"registries: []\n")
        if self.inject == "primary_and_postcheck_failure":
            raise RuntimeError("primary evaluator failure")
        if self.inject == "derived_metadata":
            metadata = self.run.configuration.database / "codeql-database.yml"
            metadata.write_bytes(metadata.read_bytes() + b"baselineLinesOfCode: 53\n")
        return b""

    def analyze(self) -> dict:
        profile.analyze(self.run, Path("/old/pack"), summary_plan_mode="projection",
                        tool_archive=self.archive)
        return json.loads((self.run.evidence / "ANALYSIS.json").read_text())

    def test_full_success_binds_runtime_plan_memory_logs_results_and_publication(self) -> None:
        analysis = self.analyze()
        self.assertEqual(analysis["schema"], 3)
        self.assertEqual(analysis["summary_plan_mode"], "projection")
        self.assertEqual(set(analysis["query_result_sha256"]), set(self.queries))
        self.install.assert_called_once_with(self.pack, self.run.evidence)
        self.validate.assert_called_once_with(self.pack)
        for name in ("HOME", "CODEQL_DIST", "CODEQL_JAVA_HOME", "JAVA_TOOL_OPTIONS", "LD_PRELOAD"):
            self.assertNotIn(name, self.run.environment)
        self.assertEqual(self.run.environment["RUNNER_TRACKING_ID"], "fixture-runner")
        self.assertEqual(self.run.environment["PATH"], "/usr/bin:/bin")
        plan.validate_publication(self.run.evidence, analysis, expected_mode="projection")
        record = json.loads((self.run.evidence / plan.PLAN_RECEIPT).read_text())
        self.assertEqual(record["observations"]["query_completions"], 39)
        self.assertEqual(len(record["observations"]["logs"]), 1)
        self.assertEqual(record["observations"]["jvm_heap_mb_arguments"], [3356])
        self.assertEqual(record["observations"]["off_heap_mb_observed"], [9329])
        with self.assertRaisesRegex(ValueError, "default production"):
            plan.validate_publication(self.run.evidence, analysis)

    def test_derived_metadata_keeps_both_snapshots_and_stable_source_identity(self) -> None:
        self.inject = "derived_metadata"
        analysis = self.analyze()
        plan.validate_publication(self.run.evidence, analysis, expected_mode="projection")
        record = json.loads((self.run.evidence / plan.PLAN_RECEIPT).read_text())
        self.assertNotEqual(record["database_before"]["metadata_sha256"],
                            record["database_after"]["metadata_sha256"])
        self.assertEqual(record["database_before"]["source_root"], record["database_after"]["source_root"])

    def test_rebound_receipt_cannot_change_any_admitted_identity_or_command(self) -> None:
        analysis = self.analyze()
        path = self.run.evidence / plan.PLAN_RECEIPT
        original = json.loads(path.read_text())
        self.assertEqual(path.stat().st_mode & 0o222, 0)

        def set_path(value, keys, replacement):
            for key in keys[:-1]:
                value = value[key]
            value[keys[-1]] = replacement

        mutations = [
            ("schema", lambda value: set_path(value, ("schema",), True)),
            ("mode", lambda value: set_path(value, ("summary_plan_mode",), "all")),
            ("attempt", lambda value: set_path(value, ("run_attempt",), "1")),
            ("before_key", lambda value: set_path(value, ("summary_plan_before", "compiler_inputs_digest"),
                                                   "70fcc50bc6a1479b6fc92e9f1d624e0e")),
            ("after_capsule", lambda value: set_path(value, ("summary_plan_after", "capsule_sha256"), "f" * 64)),
            ("bundle", lambda value: set_path(value, ("tool", "tool_bundle_sha256"), "f" * 64)),
            ("suite", lambda value: set_path(value, ("suite_sha256",), "f" * 64)),
            ("qlconfig", lambda value: set_path(value, ("qlconfig_sha256",), "f" * 64)),
            ("threat_model", lambda value: value["query_command"].remove("--threat-model=local")),
            ("compilation", lambda value: set_path(value, ("observations", "query_compilations"), 1)),
            ("completion", lambda value: set_path(value, ("observations", "query_completions"), 38)),
            ("heap", lambda value: set_path(value, ("observations", "jvm_heap_mb_arguments"), [3355])),
            ("overlay", lambda value: set_path(value, ("database_after", "overlay"), True)),
        ]
        for name, mutate in mutations:
            changed = copy.deepcopy(original)
            mutate(changed)
            replace_fixture(path, json.dumps(changed).encode())
            rebound = dict(analysis, analysis_plan_sha256=digest(path.read_bytes()))
            with self.subTest(name=name), self.assertRaises(ValueError):
                plan.validate_publication(self.run.evidence, rebound, expected_mode="projection")

    def test_complete_runtime_inventory_is_independently_required_by_publication(self) -> None:
        analysis = self.analyze()
        runtime_path = self.run.evidence / plan.RUNTIME_RECEIPT
        reduced = {"codeql": self.runtime["codeql"]}
        self.assertEqual(runtime_path.stat().st_mode & 0o222, 0)
        replace_fixture(runtime_path, json.dumps({"schema": 1, "files": reduced}).encode())
        path = self.run.evidence / plan.PLAN_RECEIPT
        record = json.loads(path.read_text())
        record["runtime_receipt_sha256"] = digest(runtime_path.read_bytes())
        record["tool"]["runtime_inventory_sha256"] = plan.canonical_sha(reduced)
        self.assertEqual(path.stat().st_mode & 0o222, 0)
        replace_fixture(path, json.dumps(record).encode())
        analysis["analysis_plan_sha256"] = digest(path.read_bytes())
        with self.assertRaisesRegex(ValueError, "complete official"):
            plan.validate_publication(self.run.evidence, analysis, expected_mode="projection")

    def test_implicit_compilation_blocks_plan_and_analysis_completion(self) -> None:
        self.inject = "implicit_compile"
        with self.assertRaisesRegex(ValueError, "precompiled queries"):
            self.analyze()
        self.assertFalse((self.run.evidence / plan.PLAN_RECEIPT).exists())
        self.assertFalse((self.run.evidence / "ANALYSIS.json").exists())

    def test_extra_precompiled_load_is_rejected(self) -> None:
        self.inject = "extra_load"
        with self.assertRaisesRegex(ValueError, "precompiled queries"):
            self.analyze()

    def test_actual_evaluator_heap_must_match_the_resolved_allocation(self) -> None:
        self.inject = "wrong_heap"
        with self.assertRaisesRegex(ValueError, "invocation allocation"):
            self.analyze()

    def test_missing_full_summary_blocks_success_after_command_and_postcheck_succeed(self) -> None:
        self.inject = "missing_result"
        with self.assertRaises(ValueError):
            self.analyze()
        self.assertTrue((self.run.evidence / "ANALYSIS_PLAN_AFTER.json").exists())
        self.assertFalse((self.run.evidence / "ANALYSIS.json").exists())

    def test_runtime_mutation_blocks_success_and_retains_postcheck_failure(self) -> None:
        self.inject = "runtime_mutation"
        with self.assertRaisesRegex(ValueError, "runtime"):
            self.analyze()
        self.assertTrue((self.run.evidence / "ANALYSIS_PLAN_FAILURE.json").exists())
        self.assertFalse((self.run.evidence / "ANALYSIS.json").exists())

    def test_private_qlconfig_mutation_blocks_success(self) -> None:
        self.inject = "qlconfig_mutation"
        with self.assertRaisesRegex(ValueError, "QL configuration"):
            self.analyze()
        self.assertFalse((self.run.evidence / "ANALYSIS.json").exists())

    def test_primary_evaluator_failure_survives_a_second_postcheck_failure(self) -> None:
        self.inject = "primary_and_postcheck_failure"
        with self.assertRaisesRegex(RuntimeError, "primary evaluator failure"):
            self.analyze()
        failure = json.loads((self.run.evidence / "ANALYSIS_PLAN_FAILURE.json").read_text())
        self.assertTrue(failure["primary_analysis_failed"])
        self.assertFalse((self.run.evidence / "ANALYSIS.json").exists())

    def test_wrong_archive_is_rejected_before_any_command_or_plan_install(self) -> None:
        self.archive.write_bytes(b"wrong archive")
        with self.assertRaisesRegex(ValueError, "archive differs"):
            self.analyze()
        self.command.assert_not_called()
        self.install.assert_not_called()

    def test_archive_path_replacement_cannot_change_the_held_descriptor(self) -> None:
        destination = self.root / "tool"

        def command(label, argv, **kwargs):
            self.archive.write_bytes(b"changed after authenticated snapshot")
            self.assertEqual(os.read(kwargs["stdin_fd"], 1000), self.archive_bytes)
            (destination / "codeql").mkdir()

        self.assertEqual(plan.extract_runtime(self.archive, destination, command), destination / "codeql")

    @unittest.skipUnless(os.name == "posix" and all(hasattr(os, name) for name in
                         ("geteuid", "waitid", "P_PID", "WEXITED", "WNOHANG", "WNOWAIT")),
                         "descriptor subprocess supervision requires POSIX waitid")
    def test_archive_descriptor_meets_the_real_bounded_child_contract_and_is_cleaned(self) -> None:
        destination = self.root / "tool"
        observed = []

        def command(label, argv, **kwargs):
            metadata = os.fstat(kwargs["stdin_fd"])
            self.assertEqual(metadata.st_nlink, 1)
            self.assertEqual(metadata.st_mode & 0o777, 0o600)
            result = capture_output([
                sys.executable, "-I", "-S", "-B", "-c",
                "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())",
            ], timeout_seconds=5, maximum_stdout_bytes=1024, maximum_stderr_bytes=1024,
                stdin_fd=kwargs["stdin_fd"], environment={"PATH": "/usr/bin:/bin"})
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout, self.archive_bytes)
            observed.append(result.stdout)
            (destination / "codeql").mkdir()

        plan.extract_runtime(self.archive, destination, command)
        self.assertEqual(observed, [self.archive_bytes])
        self.assertEqual({path.name for path in destination.iterdir()}, {"codeql"})

    def test_stale_query_results_are_rejected_before_runtime_extraction(self) -> None:
        write(self.run.configuration.database / "results/codeql/rust-queries/stale.bqrs", b"stale")
        with self.assertRaisesRegex(ValueError, "fresh query results"):
            self.analyze()
        self.command.assert_not_called()

    def test_database_configuration_and_overlay_inputs_are_rejected(self) -> None:
        for relative in plan.UNADMITTED_DATABASE_PATHS:
            path = self.run.configuration.database / relative
            write(path, b"{}")
            with self.subTest(relative=relative), self.assertRaisesRegex(ValueError, "unadmitted configuration"):
                plan.admit_database(self.run.configuration.database)
            path.unlink()
        metadata = self.run.configuration.database / "codeql-database.yml"
        metadata.write_bytes(metadata.read_bytes().replace(b"overlayBaseDatabase: false",
                                                           b"overlayBaseDatabase: true"))
        with self.assertRaisesRegex(ValueError, "non-overlay"):
            plan.admit_database(self.run.configuration.database)

    def test_unknown_mode_or_missing_explicit_archive_is_rejected_before_commands(self) -> None:
        for mode, archive in (("all", self.archive), ("projection", None), ("none", self.archive)):
            with self.subTest(mode=mode), self.assertRaisesRegex(ValueError, "explicit fixed tool archive"):
                profile.analyze(self.run, Path("/old/pack"), summary_plan_mode=mode, tool_archive=archive)
        self.command.assert_not_called()


class FixedProductionIdentityTests(unittest.TestCase):
    def test_controlled_environment_keeps_explicit_inputs_without_a_home_override(self) -> None:
        inherited = {"HOME": "/inherited/home", "PATH": "/unadmitted/bin",
                     "CODEQL_DIST": "/wrong", "CODEQL_JAVA_HOME": "/wrong/java",
                     "JAVA_TOOL_OPTIONS": "unadmitted", "LD_PRELOAD": "/wrong.so",
                     "RUNNER_TRACKING_ID": "fixture", "GITHUB_RUN_ID": "123",
                     "GITHUB_RUN_ATTEMPT": "2", "CODEQL_EXPECTED_COMMIT": "a" * 40}
        temporary = Path("private-temporary")
        actual = plan.controlled_environment(inherited, temporary)
        self.assertEqual(actual, {
            "PATH": "/usr/bin:/bin", "TMPDIR": str(temporary),
            "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC",
            "RUNNER_TRACKING_ID": "fixture", "GITHUB_RUN_ID": "123",
            "GITHUB_RUN_ATTEMPT": "2", "CODEQL_EXPECTED_COMMIT": "a" * 40,
        })
        self.assertEqual(inherited["HOME"], "/inherited/home")

    def test_fixed_production_identity_requires_the_stage34_manifest_and_compiler_key(self) -> None:
        identity = plan.expected_identity()
        self.assertEqual(identity["manifest_sha256"], plan.PRODUCTION_MANIFEST_SHA256)
        self.assertEqual(identity["compiler_inputs_digest"], plan.STAGE34_COMPILER_KEY)
        changed = dict(identity, compiler_inputs_digest="70fcc50bc6a1479b6fc92e9f1d624e0e")
        with patch.object(plan.projection, "expected_identity", return_value=changed):
            with self.assertRaisesRegex(ValueError, "Stage3/Stage4"):
                plan.expected_identity()

    def test_launcher_only_inventory_cannot_claim_the_official_runtime(self) -> None:
        with self.assertRaisesRegex(ValueError, "complete official"):
            plan.validate_runtime_inventory({
                "codeql": {"bytes": 1, "sha256": plan.LAUNCHER_SHA256, "mode": 0o755},
            })

    def test_default_publication_does_not_read_projection_assets_or_accept_plan_receipts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with patch.object(plan, "expected_identity") as expected:
                plan.validate_publication(directory, {"schema": 2})
                expected.assert_not_called()
                (directory / "SUMMARY_PLAN.json").write_text("{}")
                with self.assertRaisesRegex(ValueError, "default production"):
                    plan.validate_publication(directory, {"schema": 2})
                expected.assert_not_called()


if __name__ == "__main__":
    unittest.main()
