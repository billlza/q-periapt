from __future__ import annotations

import copy
import contextlib
import dataclasses
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from bounded_process import BoundedProcessError
import codeql_rust_profile as profile_module
from codeql_rust_profile import ProfileRun, compiler_commands, extract_database, prepared_consumers, validate_query_inventory, validate_sarif


def sarif(profile="native"):
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "CodeQL", "semanticVersion": "2.27.2"}},
             "automationDetails": {"id": {"native": "/language:rust/", "wasm": "/language:rust/target:wasm/",
                                           "macos": "/language:rust/target:macos/"}[profile]},
             "invocations": [{"executionSuccessful": True}], "results": []}]}


class RustProfileTests(unittest.TestCase):
    def test_native_category_preserves_main_identity_without_accepting_other_targets(self) -> None:
        expected = {"native": "/language:rust", "wasm": "/language:rust/target:wasm",
                    "macos": "/language:rust/target:macos"}
        for name, category in expected.items():
            with self.subTest(profile=name):
                self.assertEqual(profile_module.sarif_category(name), category)
                validate_sarif(sarif(name), name)
            for wrong in set(expected.values()) - {category} | {"/language:rust/target:native"}:
                changed = sarif(name)
                changed["runs"][0]["automationDetails"]["id"] = wrong + "/"
                with self.subTest(profile=name, wrong=wrong), self.assertRaisesRegex(ValueError, "different target"):
                    validate_sarif(changed, name)
        with self.assertRaisesRegex(ValueError, "unknown"):
            validate_sarif(sarif(), "unreviewed")

    def test_linux_memory_policy_uses_the_actual_dataset_and_preserves_the_total_request(self) -> None:
        for profile in ("native", "wasm", "macos"):
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                run = ProfileRun(root, root / "run", Path(sys.executable), dict(os.environ))
                resolution = ["-J-Xmx3356M", "--off-heap-ram=9329"]
                with mock.patch.object(run, "command", return_value=json.dumps(resolution).encode()) as command:
                    arguments = profile_module.analysis_memory_arguments(run, profile)
                self.assertEqual(arguments, ["--ram=14000", "--off-heap-ram=9329"])
                self.assertEqual(command.call_args.args[0], "resolve-analysis-ram")
                self.assertEqual(command.call_args.args[1], [
                    str(run.codeql), "resolve", "ram",
                    "--dataset=" + str(run.configuration.database / "db-rust"),
                    "--ram=14000", "--off-heap-ram=9329", "--format=json"])
                receipt = json.loads((run.evidence / "QUERY_MEMORY.json").read_text())
                self.assertEqual(receipt["profile"], profile)
                self.assertEqual(receipt["heap_mb"], 3356)
                self.assertEqual(receipt["resolved_arguments"], resolution)
                profile_module.validate_linux_query_memory(receipt, profile)
                self.assertFalse((run.evidence / "ANALYSIS.json").exists())

    def test_macos_origin_remains_native_and_analysis_requires_linux(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run = ProfileRun(root, root / "run", Path(sys.executable), {}, host="darwin")
            self.assertEqual(profile_module.profile_host("macos"), "darwin")
            self.assertEqual(profile_module.analysis_host("macos"), "linux")
            with mock.patch.object(run, "command") as command, self.assertRaisesRegex(ValueError, "different host"):
                profile_module.analysis_memory_arguments(run, "macos")
            command.assert_not_called()
            self.assertFalse((run.evidence / "QUERY_MEMORY.json").exists())

    def test_linux_memory_resolution_cannot_silently_use_default_or_invalid_allocation(self) -> None:
        invalid = [None, {}, [], ["-J-Xmx3072M"], [True, "--off-heap-ram=9329"],
                   ["-J-Xmx5668M", "--off-heap-ram=6733"],
                   ["-J-Xmx4672M", "--off-heap-ram=9329"],
                   ["-J-Xmx0M", "--off-heap-ram=9329"],
                   ["-J-Xmx03072M", "--off-heap-ram=9329"],
                   ["-J-Xmx3072M", "--off-heap-ram=9329", "--threads=1"]]
        for profile in ("native", "wasm", "macos"):
            for resolution in invalid:
                with self.subTest(profile=profile, resolution=resolution), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    run = ProfileRun(root, root / "run", Path(sys.executable), {})
                    with mock.patch.object(run, "command", return_value=json.dumps(resolution).encode()), \
                            self.assertRaises(ValueError):
                        profile_module.analysis_memory_arguments(run, profile)
                    self.assertFalse((run.evidence / "QUERY_MEMORY.json").exists())
                    self.assertFalse((run.evidence / "ANALYSIS.json").exists())

    def test_linux_memory_resolution_failure_preserves_failed_state(self) -> None:
        for profile in ("native", "wasm", "macos"):
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                run = ProfileRun(root, root / "run", Path(sys.executable), {})
                with mock.patch.object(run, "command", side_effect=ValueError("resolver failed")), \
                        self.assertRaisesRegex(ValueError, "resolver failed"):
                    profile_module.analysis_memory_arguments(run, profile)
                self.assertFalse((run.evidence / "QUERY_MEMORY.json").exists())
                self.assertFalse((run.evidence / "ANALYSIS.json").exists())

    def test_linux_allocation_record_is_an_exact_typed_profile_description(self) -> None:
        for profile in ("native", "wasm", "macos"):
            receipt = profile_module.linux_query_memory(["-J-Xmx3072M", "--off-heap-ram=9329"], profile)
            profile_module.validate_linux_query_memory(receipt, profile)
            for key, value in (("schema", True), ("heap_mb", 3072.0), ("requested_ram_mb", 15000),
                               ("off_heap_ram_mb", 6733), ("remaining_budget_mb", 1600),
                               ("profile", "native" if profile == "wasm" else "wasm"),
                               ("codeql_version", "2.27.3")):
                with self.subTest(profile=profile, key=key), self.assertRaises(ValueError):
                    profile_module.validate_linux_query_memory(dict(receipt, **{key: value}), profile)
        for profile in ("unreviewed",):
            with self.subTest(profile=profile), self.assertRaisesRegex(ValueError, "Linux analysis profile"):
                profile_module.linux_query_memory(["-J-Xmx3072M", "--off-heap-ram=9329"], profile)

    def test_analysis_keeps_profile_category_full_suite_and_memory_evidence(self) -> None:
        self._check_analysis_evidence()

    def test_analysis_evidence_with_symlinked_temporary_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve(strict=True)
            physical = parent / "private" / "var"
            physical.mkdir(parents=True)
            alias = parent / "var"
            alias.symlink_to(physical, target_is_directory=True)
            with mock.patch.object(tempfile, "tempdir", str(alias)):
                self._check_analysis_evidence()

    def _check_analysis_evidence(self) -> None:
        categories = {"native": "/language:rust", "wasm": "/language:rust/target:wasm",
                      "macos": "/language:rust/target:macos"}
        for name, complete in ((name, complete) for name in categories for complete in (True, False)):
            with self.subTest(profile=name, complete=complete), tempfile.TemporaryDirectory() as temporary:
                # The production entry point resolves its query pack before
                # analysis. Keep this fixture canonical under macOS /var aliases.
                root = Path(temporary).resolve(strict=True)
                pack = root / "query-pack"
                pinned = json.loads((profile_module.ROOT / "artifact/codeql_rust_queries.json").read_text())
                inventory = {}
                for relative in pinned["queries"]:
                    path = pack / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text("// query fixture " + relative)
                    inventory[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
                (root / "artifact").mkdir()
                (root / "artifact/codeql_rust_queries.json").write_text(json.dumps(dict(pinned, queries=inventory)))
                run = ProfileRun(root, root / "run", Path(sys.executable), {},
                                 host="linux")
                run.configuration = dataclasses.replace(run.configuration, database=root / "database")
                (run.evidence / "PROFILE.json").write_text(json.dumps({
                    "profile": name, "target": profile_module.TARGETS[name],
                    "source_commit": "a" * 40, "run_id": "123", "run_attempt": "1",
                    "active_target_quality_passed": True}))
                if name == "macos":
                    from test_codeql_rust_transfer import profile_fixture, record_fixture
                    extraction = profile_fixture()
                    (run.evidence / "PROFILE.json").write_text(json.dumps(extraction))
                    record = record_fixture(extraction, hashlib.sha256((run.evidence / "PROFILE.json").read_bytes()).hexdigest())
                    (run.evidence / "TRANSFER.json").write_text(json.dumps(record))
                def command(label, argv, **kwargs):
                    if label == "resolve-suite":
                        return json.dumps([str(pack / name) for name in inventory]).encode()
                    if label == "resolve-analysis-ram":
                        return b'["-J-Xmx3356M", "--off-heap-ram=9329"]'
                    self.assertEqual(label, "analyze")
                    self.assertEqual(argv[1:3], ["database", "analyze"])
                    self.assertIn(str(pack / "codeql-suites/rust-security-extended.qls"), argv)
                    self.assertIn(f"--ram={run.configuration.ram_mb}", argv)
                    self.assertIn("--off-heap-ram=9329", argv)
                    self.assertIn(f"--threads={run.configuration.threads}", argv)
                    self.assertIn("--threat-model=local", argv)
                    self.assertIn("--sarif-category=" + categories[name], argv)
                    self.assertEqual(kwargs["seconds"], 18000)
                    for relative in inventory:
                        if not complete and relative == "queries/summary/SummaryStats.ql":
                            continue
                        result = run.configuration.database / "results/codeql/rust-queries" / Path(relative).with_suffix(".bqrs")
                        result.parent.mkdir(parents=True, exist_ok=True)
                        result.write_bytes(b"complete fixture result")
                    (run.evidence / "results.sarif").write_text(json.dumps(sarif(name)))
                    return b""
                with mock.patch.object(run, "command", side_effect=command), \
                        mock.patch.object(profile_module.quality, "require_clean_checkout"), \
                        mock.patch.dict(os.environ, {"GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2",
                            "CODEQL_EXPECTED_COMMIT": "a" * 40, "CODEQL_TRANSFER_ATTEMPT": "1",
                            "CODEQL_TRANSFER_SHA256": hashlib.sha256((run.evidence / "TRANSFER.json").read_bytes()).hexdigest()
                            if name == "macos" else ""}):
                    if complete:
                        profile_module.analyze(run, pack)
                    else:
                        with self.assertRaises(ValueError):
                            profile_module.analyze(run, pack)
                self.assertTrue((run.evidence / "QUERY_MEMORY.json").is_file())
                self.assertEqual((run.evidence / "ANALYSIS.json").exists(), complete)
                if complete:
                    result = json.loads((run.evidence / "ANALYSIS.json").read_text())
                    self.assertEqual(set(result["query_result_sha256"]), set(inventory))
                    self.assertEqual(result["query_memory_sha256"],
                                     hashlib.sha256((run.evidence / "QUERY_MEMORY.json").read_bytes()).hexdigest())
                    self.assertEqual(result["schema"], 2)
                    self.assertEqual(result["run_attempt"], "2")
                    self.assertEqual(result["analysis_host"], "linux")
                    self.assertEqual(json.loads((run.evidence / "PROFILE.json").read_text())["run_attempt"], "1")
                    self.assertEqual("transfer_sha256" in result, name == "macos")

    def test_analysis_rejects_queries_outside_the_pinned_pack(self) -> None:
        for escape in ("direct", "symlink"):
            with self.subTest(escape=escape), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve(strict=True)
                pack = root / "query-pack"
                pack.mkdir()
                queries = []
                for index in range(38):
                    query = pack / f"query-{index}.ql"
                    query.write_text("// contained fixture query")
                    queries.append(str(query))
                outside = root / "outside.ql"
                outside.write_text("// query outside the pinned pack")
                if escape == "symlink":
                    alias = pack / "escape.ql"
                    alias.symlink_to(outside)
                    queries.append(str(alias))
                else:
                    queries.append(str(outside))
                run = ProfileRun(root, root / "run", Path(sys.executable), {}, host="linux")
                (run.evidence / "PROFILE.json").write_text(json.dumps({
                    "profile": "native", "target": profile_module.TARGETS["native"],
                    "source_commit": "a" * 40, "run_id": "123", "run_attempt": "1",
                    "active_target_quality_passed": True}))
                with mock.patch.object(run, "command", return_value=json.dumps(queries).encode()) as command, \
                        mock.patch.object(profile_module.quality, "require_clean_checkout"), \
                        mock.patch.dict(os.environ, {"GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1",
                                                    "CODEQL_EXPECTED_COMMIT": "a" * 40}), \
                        self.assertRaisesRegex(ValueError, "query outside pinned Rust pack"):
                    profile_module.analyze(run, pack)
                command.assert_called_once()
                self.assertEqual(command.call_args.args[0], "resolve-suite")
                for receipt in ("QUERY_INVENTORY.json", "QUERY_MEMORY.json", "ANALYSIS.json"):
                    self.assertFalse((run.evidence / receipt).exists())

    def _check_analysis_snapshot_binding(self, replacement: str | None) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            # Match the production entry point's canonical query-pack path,
            # including a macOS temporary parent reached through /var aliases.
            root = Path(temporary).resolve(strict=True)
            pack = root / "query-pack"
            pinned = json.loads((profile_module.ROOT / "artifact/codeql_rust_queries.json").read_text())
            inventory = {}
            for relative in pinned["queries"]:
                path = pack / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("// query fixture " + relative)
                inventory[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
            (root / "artifact").mkdir()
            (root / "artifact/codeql_rust_queries.json").write_text(json.dumps(dict(pinned, queries=inventory)))
            run = ProfileRun(root, root / "run", Path(sys.executable), {}, host="linux")
            run.configuration = dataclasses.replace(run.configuration, database=root / "database")
            extraction = {
                "profile": "native", "target": profile_module.TARGETS["native"],
                "source_commit": "a" * 40, "run_id": "123", "run_attempt": "1",
                "active_target_quality_passed": True,
            }
            original = {
                "PROFILE.json": json.dumps(extraction).encode(),
                "results.sarif": json.dumps(sarif()).encode(),
            }
            (run.evidence / "PROFILE.json").write_bytes(original["PROFILE.json"])

            def command(label, _argv, **_kwargs):
                if label == "resolve-suite":
                    return json.dumps([str(pack / name) for name in inventory]).encode()
                if label == "resolve-analysis-ram":
                    return b'["-J-Xmx3356M", "--off-heap-ram=9329"]'
                self.assertEqual(label, "analyze")
                for relative in inventory:
                    result = run.configuration.database / "results/codeql/rust-queries" / Path(relative).with_suffix(".bqrs")
                    result.parent.mkdir(parents=True, exist_ok=True)
                    result.write_bytes(b"complete fixture result")
                (run.evidence / "results.sarif").write_bytes(original["results.sarif"])
                return b""

            checkout_checks = 0

            def require_clean_checkout(commit):
                nonlocal checkout_checks
                self.assertEqual(commit, "a" * 40)
                checkout_checks += 1
                if checkout_checks == 2 and replacement is not None:
                    # Replace the real path after analyze has validated its
                    # bytes, before ANALYSIS.json records their identity.
                    changed = json.loads(original[replacement])
                    if replacement == "PROFILE.json":
                        changed["active_target_quality_passed"] = False
                    else:
                        changed["runs"][0]["invocations"][0]["executionSuccessful"] = False
                        with self.assertRaisesRegex(ValueError, "unsuccessful"):
                            validate_sarif(changed, "native")
                    staged = run.evidence / "replacement.json"
                    staged.write_text(json.dumps(changed))
                    os.replace(staged, run.evidence / replacement)

            with mock.patch.object(run, "command", side_effect=command), \
                    mock.patch.object(profile_module.quality, "require_clean_checkout", side_effect=require_clean_checkout), \
                    mock.patch.dict(os.environ, {"GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2",
                        "CODEQL_EXPECTED_COMMIT": "a" * 40}):
                profile_module.analyze(run, pack)
            self.assertEqual(checkout_checks, 2)
            if replacement is not None:
                self.assertNotEqual((run.evidence / replacement).read_bytes(), original[replacement])
            analysis = json.loads((run.evidence / "ANALYSIS.json").read_text())
            self.assertIs(analysis["completed"], True)
            self.assertEqual(analysis["source_commit"], "a" * 40)
            self.assertIs(analysis["upload_performed"], False)
            for filename, key in (("PROFILE.json", "profile_sha256"), ("results.sarif", "sarif_sha256")):
                self.assertEqual(analysis[key], hashlib.sha256(original[filename]).hexdigest(),
                                 filename + " receipt must identify the bytes actually validated")

    def test_analysis_receipt_identifies_validated_stable_inputs(self) -> None:
        self._check_analysis_snapshot_binding(None)

    def test_analysis_receipt_identifies_validated_profile_after_path_replacement(self) -> None:
        self._check_analysis_snapshot_binding("PROFILE.json")

    def test_analysis_receipt_identifies_validated_sarif_after_path_replacement(self) -> None:
        self._check_analysis_snapshot_binding("results.sarif")

    def test_analysis_snapshot_receipts_with_symlinked_temporary_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve(strict=True)
            physical = parent / "private" / "var"
            physical.mkdir(parents=True)
            alias = parent / "var"
            alias.symlink_to(physical, target_is_directory=True)
            for replacement in (None, "PROFILE.json", "results.sarif"):
                with self.subTest(replacement=replacement), mock.patch.object(tempfile, "tempdir", str(alias)):
                    self._check_analysis_snapshot_binding(replacement)

    def _check_clang_selection(self, *, symlink: bool) -> None:
        class SetupComplete(Exception):
            pass

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            caller, root, sysroot = (base / name for name in ("caller", "checkout", "sysroot"))
            (sysroot / "lib/rustlib/src/rust/library").mkdir(parents=True)
            for directory, selected in ((caller, "caller"), (root, "checkout")):
                tools = directory / "bin"
                tools.mkdir(parents=True)
                launcher = tools / ("compiler" if symlink and directory == caller else "clang")
                launcher.write_text('#!/bin/sh\nprintf \'wasm32 ' + selected + ' %s\\n\' "${0##*/}"\n')
                launcher.chmod(0o700)
                if launcher.name != "clang":
                    (tools / "clang").symlink_to(launcher.name)
            environment = dict(os.environ, PATH="bin")
            run = ProfileRun(root, base / "run", Path(sys.executable), environment)
            real_command = run.command

            def command(label, argv, **kwargs):
                if label == "codeql-version":
                    return b"2.27.2\n"
                if label == "rust-version":
                    return b"rustc 1.98.1 (48a229cea 2026-09-01)\nhost: x86_64-unknown-linux-gnu\n"
                if label == "rust-sysroot":
                    return os.fsencode(sysroot)
                self.assertEqual(label, "clang-targets")
                return real_command(label, argv, **kwargs)

            with (
                contextlib.chdir(caller),
                mock.patch.dict(os.environ, PATH="bin"),
                mock.patch.object(profile_module.quality, "require_repository_target_absent"),
                mock.patch.object(profile_module.quality, "require_clean_checkout"),
                mock.patch.object(profile_module.quality, "tracked_rust_paths", return_value=[]),
                mock.patch.object(run, "command", side_effect=command),
                mock.patch.object(profile_module, "install_metadata_adapter", side_effect=SetupComplete),
                self.assertRaises(SetupComplete),
            ):
                profile_module.prepare(run, "wasm", "a" * 40)
            self.assertEqual((run.evidence / "clang-targets.stdout").read_bytes(), b"wasm32 caller clang\n")
            selected = run.environment["CC_wasm32_unknown_unknown"]
            self.assertEqual(selected, str(caller / "bin/clang"))
            consumer = root / "nested-consumer"
            consumer.mkdir()
            self.assertEqual(real_command("clang-consumer", [selected, "--print-targets"], cwd=consumer),
                             b"wasm32 caller clang\n")
            self.assertFalse((run.evidence / "ANALYSIS.json").exists())

    def test_clang_selection_survives_repository_and_consumer_cwd_changes(self) -> None:
        self._check_clang_selection(symlink=False)

    def test_clang_selection_preserves_multicall_symlink_name(self) -> None:
        self._check_clang_selection(symlink=True)

    def test_extraction_inputs_survive_quality_failure_without_certifying_profile(self) -> None:
        for passed in (False, True):
            with self.subTest(passed=passed), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                (root / "src").mkdir()
                data = b"pub fn operation() {}\n"
                (root / "src/lib.rs").write_bytes(data)
                source = {"src/lib.rs": hashlib.sha256(data).hexdigest()}
                locks = list(profile_module.WORKSPACE_LOCKFILES)
                for lock in locks:
                    path = root / lock
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text("version = 4\n")
                sysroot = root / "sysroot"
                (sysroot / "lib/rustlib/src/rust/library").mkdir(parents=True)
                shutil.copytree(profile_module.ROOT / "artifact/codeql-rust-quality",
                                root / "artifact/codeql-rust-quality")
                run = ProfileRun(root, root / "run", Path(sys.executable), {}, host="darwin")
                def command(label, *_args, **_kwargs):
                    return {
                        "codeql-version": b"2.27.2\n",
                        "rust-version": b"rustc 1.98.1 (48a229cea 2026-09-01)\nhost: aarch64-apple-darwin\n",
                        "rust-sysroot": os.fsencode(sysroot),
                    }.get(label, b"compiler output")
                def check_quality(actual_run, compiled, sources, profile):
                    inputs = json.loads((run.evidence / "EXTRACTION_INPUTS.json").read_text())
                    self.assertIs(actual_run, run)
                    self.assertEqual((compiled, sources, profile), (source, source, "macos"))
                    self.assertEqual(inputs["source_sha256"], source)
                    self.assertEqual(inputs["compiled_sources"], source)
                    self.assertEqual(inputs["source_commit"], "a" * 40)
                    self.assertEqual((inputs["run_id"], inputs["run_attempt"]), ("123", "1"))
                    self.assertEqual((inputs["query_threads"], inputs["query_ram_mb"]), (2, 5500))
                    self.assertFalse(inputs["active_target_quality_passed"])
                    self.assertFalse(inputs["paired_target_quality_passed"])
                    self.assertFalse((run.evidence / "PROFILE.json").exists())
                    if not passed:
                        raise RuntimeError("quality query timed out")
                    for name in ("MacroCalls.json", "ExtractedPaths.json"):
                        (run.evidence / name).write_text("[]\n")
                    return {"checked": 1}
                with contextlib.ExitStack() as stack:
                    stack.enter_context(mock.patch.dict(os.environ, GITHUB_RUN_ID="123", GITHUB_RUN_ATTEMPT="1"))
                    for owner, name, kwargs in (
                        (profile_module.quality, "require_repository_target_absent", {}),
                        (profile_module.quality, "require_clean_checkout", {}),
                        (profile_module.quality, "tracked_rust_paths", {"return_value": source}),
                        (run, "command", {"side_effect": command}),
                        (profile_module, "install_metadata_adapter", {}),
                        (profile_module, "run_git_bytes", {"return_value": "\n".join(locks).encode()}),
                        (profile_module, "prepared_consumers", {"side_effect": lambda _: contextlib.nullcontext()}),
                        (profile_module, "collect_compiled_sources", {"return_value": source}),
                        (profile_module, "extract_database", {}),
                        (profile_module, "collect_quality", {"side_effect": check_quality}),
                    ):
                        stack.enter_context(mock.patch.object(owner, name, **kwargs))
                    if passed:
                        profile_module.prepare(run, "macos", "a" * 40)
                    else:
                        with self.assertRaisesRegex(RuntimeError, "quality query timed out"):
                            profile_module.prepare(run, "macos", "a" * 40)
                self.assertTrue((run.evidence / "EXTRACTION_INPUTS.json").is_file())
                self.assertEqual((run.evidence / "PROFILE.json").exists(), passed)
                if passed:
                    profile = json.loads((run.evidence / "PROFILE.json").read_text())
                    self.assertTrue(profile["active_target_quality_passed"])
                    self.assertEqual(profile["metrics"], {"checked": 1})

    def test_target_commands_select_actual_supported_compilation_paths(self) -> None:
        root = Path("/source")
        wasm = compiler_commands(root, "wasm")
        self.assertEqual(len(wasm), 2)
        self.assertIn("browser-continuity", wasm[0][2])
        self.assertIn("--tests", wasm[1][2])
        native = compiler_commands(root, "native")
        self.assertEqual(compiler_commands(root, "macos"), native)
        self.assertEqual({label for label, _cwd, _args in native},
                         {"workspace", "engine", "independent-peer", "reference-account",
                          "spqr", "whole-kem", "continuity-c", "sdk-rust"})
        for label, relative in (("independent-peer", "research/continuity-openssl-peer/native"),
                                ("reference-account", "research/continuity-reference-app")):
            self.assertIn((label, root / relative, ["--all-targets", "--all-features"]), native)
            self.assertNotIn(label, {name for name, _cwd, _args in wasm})
        with self.assertRaisesRegex(ValueError, "unknown"):
            compiler_commands(root, "unexpected")

    def test_workspace_lock_inventory_rejects_missing_added_and_substituted_roots(self) -> None:
        expected = profile_module.WORKSPACE_LOCKFILES
        with mock.patch.object(profile_module, "run_git_bytes", return_value="\n".join(expected).encode()):
            self.assertEqual(profile_module.tracked_lockfiles(Path("/source")), expected)
        changed = [expected[:index] + expected[index + 1:] for index in range(len(expected))]
        changed.extend((expected + ("unreviewed/Cargo.lock",), expected + (expected[-1],),
                        expected[:-1] + ("unreviewed/Cargo.lock",),
                        expected + ("paper/unreviewed/Cargo.lock",)))
        for paths in changed:
            with self.subTest(paths=paths), mock.patch.object(
                    profile_module, "run_git_bytes", return_value="\n".join(paths).encode()):
                with self.assertRaisesRegex(ValueError, "workspace lock inventory differs"):
                    profile_module.tracked_lockfiles(Path("/source"))

    @contextlib.contextmanager
    def archived_lock_inventory_fixture(self, *, git_index=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            expected = profile_module.WORKSPACE_LOCKFILES
            archives = {}
            for relative in profile_module.ARCHIVE_LOCKFILES:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                payload = ("retained source lock: " + relative + "\n").encode()
                path.write_bytes(payload)
                archives[relative] = hashlib.sha256(payload).hexdigest()
            tracked = tuple(sorted((*expected, *archives)))
            if git_index:
                for relative in expected:
                    path = root / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text("version = 4\n")
                subprocess.run(["/usr/bin/git", "init", "-q", str(root)], check=True, capture_output=True)
                profile_module.run_git_bytes(root, ["add", "--", *tracked])
            inventory_context = contextlib.nullcontext() if git_index else mock.patch.object(
                profile_module, "run_git_bytes", return_value="\n".join(tracked).encode())
            with mock.patch.object(profile_module, "ARCHIVE_LOCKFILES", archives), inventory_context:
                yield root, expected, archives

    def test_workspace_lock_inventory_keeps_pinned_archives_out_of_fetch_roots(self) -> None:
        with self.archived_lock_inventory_fixture() as (root, expected, archives):
            self.assertEqual(profile_module.tracked_lockfiles(root), expected)
            self.assertTrue(set(expected).isdisjoint(archives))

    def test_workspace_lock_inventory_uses_actual_git_suffix_matching(self) -> None:
        with self.archived_lock_inventory_fixture(git_index=True) as (root, expected, _archives):
            retained = "research/sdk-alpha1/evidence/20261110-native-distribution/consumer-Cargo.lock"
            tracked = profile_module.run_git_bytes(root, ["ls-files", "--", "*Cargo.lock"]).decode().splitlines()
            self.assertIn(retained, tracked)
            # The prefixed manifest is retained evidence; Cargo.toml would
            # instead activate an unreviewed workspace next to this snapshot.
            (root / retained).with_name("consumer-Cargo.toml").write_text("[workspace]\n")
            self.assertEqual(profile_module.tracked_lockfiles(root), expected)
            unexpected = root / "research/unreviewed/consumer-Cargo.lock"
            unexpected.parent.mkdir(parents=True)
            unexpected.write_text("version = 4\n")
            profile_module.run_git_bytes(root, ["add", "--", str(unexpected.relative_to(root))])
            with self.assertRaisesRegex(ValueError, "workspace lock inventory differs"):
                profile_module.tracked_lockfiles(root)

    def test_workspace_lock_inventory_rejects_changed_archive_bytes(self) -> None:
        with self.archived_lock_inventory_fixture() as (root, _expected, archives):
            for relative in archives:
                with self.subTest(archive=relative):
                    path = root / relative
                    original = path.read_bytes()
                    path.write_bytes(original + b"changed\n")
                    with self.assertRaisesRegex(ValueError, "archived lock snapshot differs"):
                        profile_module.tracked_lockfiles(root)
                    path.write_bytes(original)

    def test_workspace_lock_inventory_rejects_adjacent_archive_manifests(self) -> None:
        with self.archived_lock_inventory_fixture() as (root, _expected, archives):
            for relative in archives:
                manifest = (root / relative).with_name("Cargo.toml")
                for kind in ("regular", "dangling-symlink"):
                    with self.subTest(archive=relative, manifest=kind):
                        if kind == "regular":
                            manifest.write_text("[workspace]\n")
                        else:
                            manifest.symlink_to("absent-manifest")
                        with self.assertRaisesRegex(ValueError, "archived lock has an adjacent Cargo.toml"):
                            profile_module.tracked_lockfiles(root)
                        manifest.unlink()

    def test_macos_extraction_uses_its_own_finite_resource_budget(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run = ProfileRun(root, root / "run", Path(sys.executable), dict(os.environ), host="darwin")
            with mock.patch.object(run, "command") as command:
                extract_database(run, root / "database-cluster/rust")
            argv = command.call_args.args[1]
            self.assertIn("--threads=2", argv)
            self.assertIn("--ram=5500", argv)
            self.assertNotIn("--ram=14000", argv)

    def test_macos_rejects_an_intel_compiler_before_fetch_or_extraction(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run = ProfileRun(root, root / "run", Path(sys.executable), dict(os.environ), host="darwin")
            compiler = b"rustc 1.98.1 (48a229cea 2026-09-01)\nhost: x86_64-apple-darwin\n"
            with mock.patch.object(profile_module.quality, "require_repository_target_absent"), \
                    mock.patch.object(profile_module.quality, "require_clean_checkout"), \
                    mock.patch.object(profile_module.quality, "tracked_rust_paths", return_value=[]), \
                    mock.patch.object(run, "command", side_effect=[b"2.27.2\n", compiler]) as command:
                with self.assertRaisesRegex(ValueError, "compiler or host"):
                    profile_module.prepare(run, "macos", "a" * 40)
            self.assertEqual([call.args[0] for call in command.call_args_list], ["codeql-version", "rust-version"])

    def test_profile_host_selection_never_falls_back_for_unknown_profiles(self) -> None:
        self.assertEqual(profile_module.profile_host("macos"), "darwin")
        self.assertEqual(profile_module.profile_host("wasm"), "linux")
        with self.assertRaisesRegex(ValueError, "unknown"):
            profile_module.profile_host("intel-mac")

    def test_nonzero_child_preserves_outputs_and_never_reports_success(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run = ProfileRun(root, root / "run", Path(sys.executable), dict(os.environ))
            with self.assertRaisesRegex(ValueError, "command failed"):
                run.command("failure", [sys.executable, "-c", "print('kept output');raise SystemExit(7)"])
            self.assertEqual((run.evidence / "failure.stdout").read_text(), "kept output\n")
            self.assertEqual(json.loads((run.evidence / "failure.json").read_text())["returncode"], 7)
            self.assertFalse((run.evidence / "ANALYSIS.json").exists())

    def test_timeout_records_cleanup_and_remains_a_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run = ProfileRun(root, root / "run", Path(sys.executable), dict(os.environ))
            with self.assertRaises(BoundedProcessError):
                run.command("timeout", [sys.executable, "-c",
                            "import sys,time;print('query started',flush=True);"
                            "print('query diagnostic',file=sys.stderr,flush=True);time.sleep(5)"], seconds=1)
            record = json.loads((run.evidence / "timeout.json").read_text())
            launch = json.loads((run.evidence / "timeout.started.json").read_text())
            self.assertEqual(record["invoked_at_utc"], launch["invoked_at_utc"])
            self.assertEqual(datetime.fromisoformat(record["finished_at_utc"]).tzinfo, timezone.utc)
            self.assertFalse(record["completed"])
            self.assertEqual(record["boundary"], "timeout")
            self.assertFalse(record["cleanup_ambiguous"])
            self.assertEqual((run.evidence / "timeout.stdout").read_text(), "query started\n")
            self.assertEqual((run.evidence / "timeout.stderr").read_text(), "query diagnostic\n")
            self.assertFalse((run.evidence / "ANALYSIS.json").exists())

    def test_command_invocation_is_visible_to_the_child_before_completion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = dict(os.environ, CODEQL_EXPECTED_COMMIT="a" * 40,
                               GITHUB_RUN_ID="123", GITHUB_RUN_ATTEMPT="2")
            run = ProfileRun(root, root / "run", Path(sys.executable), environment)
            launch_path = run.evidence / "observe.started.json"
            completion_path = run.evidence / "observe.json"
            command = [sys.executable, "-c",
                       "import json, pathlib, sys; "
                       "value=json.loads(pathlib.Path(sys.argv[1]).read_text()); "
                       "assert not pathlib.Path(sys.argv[2]).exists(); "
                       "print(value['source_commit'], value['run_id'], value['run_attempt'])",
                       str(launch_path), str(completion_path)]
            self.assertEqual(run.command("observe", command, seconds=10), ("a" * 40 + " 123 2\n").encode())
            launch = json.loads(launch_path.read_text())
            final = json.loads(completion_path.read_text())
            self.assertEqual(launch["argv"], command)
            self.assertEqual(launch["maximum_seconds"], 10)
            self.assertEqual(datetime.fromisoformat(launch["invoked_at_utc"]).tzinfo, timezone.utc)
            self.assertEqual(final["invoked_at_utc"], launch["invoked_at_utc"])
            self.assertEqual(final["returncode"], 0)
            self.assertNotIn("completed", launch)
            self.assertFalse((run.evidence / "ANALYSIS.json").exists())

    def test_interrupted_worker_retains_invocation_without_fabricating_completion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run = ProfileRun(root, root / "run", Path(sys.executable), dict(os.environ))
            with mock.patch.object(profile_module, "capture_output", side_effect=KeyboardInterrupt), \
                    self.assertRaises(KeyboardInterrupt):
                run.command("interrupted", [sys.executable, "-c", "pass"])
            self.assertTrue((run.evidence / "interrupted.started.json").is_file())
            self.assertFalse((run.evidence / "interrupted.json").exists())
            self.assertFalse((run.evidence / "ANALYSIS.json").exists())

    def test_full_and_reduced_summary_queries_are_both_required_by_the_pinned_suite(self) -> None:
        pinned = json.loads((profile_module.ROOT / "artifact/codeql_rust_queries.json").read_text())
        inventory = pinned["queries"]
        self.assertEqual(len(inventory), 39)
        self.assertIn("queries/summary/SummaryStatsReduced.ql", inventory)
        validate_query_inventory(inventory, pinned)
        missing_full = dict(inventory)
        del missing_full["queries/summary/SummaryStats.ql"]
        with self.assertRaisesRegex(ValueError, "full summary query is missing"):
            validate_query_inventory(missing_full, dict(pinned, queries=missing_full))
        for path in ("queries/summary/SummaryStatsReduced.ql", "queries/summary/SummaryStats.ql"):
            changed = dict(inventory)
            changed[path] = "0" * 64
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "query bytes differ"):
                validate_query_inventory(changed, pinned)
        missing_reduced = dict(inventory)
        del missing_reduced["queries/summary/SummaryStatsReduced.ql"]
        with self.assertRaisesRegex(ValueError, "query bytes differ"):
            validate_query_inventory(missing_reduced, pinned)

    def test_resumption_requires_existing_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(ValueError, "missing"):
                ProfileRun(root, root / "missing", Path(sys.executable), dict(os.environ), resume=True)

    def test_database_parent_exists_before_codeql_runs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run = ProfileRun(root, root / "run", Path(sys.executable), dict(os.environ))
            database = root / "database-cluster" / "rust"
            def check_parent(_label, argv):
                self.assertTrue(database.parent.is_dir())
                self.assertFalse(database.exists())
                self.assertIn(str(database), argv)
            with mock.patch.object(run, "command", side_effect=check_parent) as command:
                extract_database(run, database)
            command.assert_called_once()

    def test_database_parent_is_not_reused_or_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run = ProfileRun(root, root / "run", Path(sys.executable), dict(os.environ))
            database = root / "database-cluster" / "rust"
            database.parent.mkdir()
            marker = database.parent / "existing-state"
            marker.write_text("preserve")
            with mock.patch.object(run, "command") as command, self.assertRaises(FileExistsError):
                extract_database(run, database)
            command.assert_not_called()
            self.assertEqual(marker.read_text(), "preserve")

    def test_consumer_inputs_survive_extraction_and_are_removed_on_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run = ProfileRun(root, root / "run", Path(sys.executable), dict(os.environ))
            state = []
            with mock.patch.object(profile_module.consumers, "prepare", side_effect=lambda *_a, **_kw: state.append("prepared")), \
                    mock.patch.object(run, "command", side_effect=lambda *_a, **_kw: state.append("removed")) as remove:
                with self.assertRaisesRegex(RuntimeError, "extraction failed"):
                    with prepared_consumers(run):
                        self.assertEqual(state, ["prepared"])
                        remove.assert_not_called()
                        raise RuntimeError("extraction failed")
            self.assertEqual(state, ["prepared", "removed"])

    def test_failed_consumer_preparation_is_not_removed_twice(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run = ProfileRun(root, root / "run", Path(sys.executable), dict(os.environ))
            with mock.patch.object(profile_module.consumers, "prepare", side_effect=ValueError("preparation failed")), \
                    mock.patch.object(run, "command") as remove:
                with self.assertRaisesRegex(ValueError, "preparation failed"):
                    with prepared_consumers(run):
                        self.fail("failed preparation entered extraction")
                remove.assert_not_called()

    def test_wrong_target_tool_failure_or_warning_sarif_is_rejected(self) -> None:
        validate_sarif(sarif(), "native")
        variants = []
        other = sarif("wasm"); variants.append(other)
        other = sarif(); other["runs"][0]["tool"]["driver"]["semanticVersion"] = "2.27.1"; variants.append(other)
        other = sarif(); other["runs"][0]["invocations"][0]["executionSuccessful"] = False; variants.append(other)
        other = sarif(); other["runs"][0]["invocations"][0]["toolExecutionNotifications"] = [{"level": "warning"}]; variants.append(other)
        other = sarif(); other["runs"].append(copy.deepcopy(other["runs"][0])); variants.append(other)
        for value in variants:
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_sarif(value, "native")


if __name__ == "__main__":
    unittest.main()
