from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from bounded_process import BoundedProcessError
import codeql_rust_profile as profile_module
from codeql_rust_profile import ProfileRun, compiler_commands, extract_database, prepared_consumers, validate_sarif


def sarif(profile="native"):
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "CodeQL", "semanticVersion": "2.27.2"}},
             "automationDetails": {"id": f"/language:rust/target:{profile}/"},
             "invocations": [{"executionSuccessful": True}], "results": []}]}


class RustProfileTests(unittest.TestCase):
    def test_target_commands_select_actual_supported_compilation_paths(self) -> None:
        root = Path("/source")
        wasm = compiler_commands(root, "wasm")
        self.assertEqual(len(wasm), 2)
        self.assertIn("browser-continuity", wasm[0][2])
        self.assertIn("--tests", wasm[1][2])
        native = compiler_commands(root, "native")
        self.assertEqual({label for label, _cwd, _args in native},
                         {"workspace", "engine", "spqr", "whole-kem", "continuity-c", "sdk-rust"})
        with self.assertRaisesRegex(ValueError, "unknown"):
            compiler_commands(root, "unexpected")

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
                run.command("timeout", [sys.executable, "-c", "import time;time.sleep(5)"], seconds=0.05)
            record = json.loads((run.evidence / "timeout.json").read_text())
            self.assertFalse(record["completed"])
            self.assertIn("cleanup_ambiguous", record)

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
