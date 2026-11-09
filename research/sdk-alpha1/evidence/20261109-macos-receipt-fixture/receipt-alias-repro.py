"""Exercise the three original receipt tests under a real temporary-path alias."""

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

import test_codeql_rust_profile


METHODS = (
    "test_analysis_receipt_identifies_validated_stable_inputs",
    "test_analysis_receipt_identifies_validated_profile_after_path_replacement",
    "test_analysis_receipt_identifies_validated_sarif_after_path_replacement",
)

with tempfile.TemporaryDirectory() as temporary:
    parent = Path(temporary).resolve(strict=True)
    physical = parent / "private" / "var"
    physical.mkdir(parents=True)
    alias = parent / "var"
    alias.symlink_to(physical, target_is_directory=True)
    assert alias.is_symlink() and alias != alias.resolve(strict=True)
    with mock.patch.object(tempfile, "tempdir", str(alias)):
        suite = unittest.TestSuite(
            test_codeql_rust_profile.RustProfileTests(method) for method in METHODS
        )
        result = unittest.TextTestRunner(verbosity=2).run(suite)

print(json.dumps({
    "test_fixture": "real symlinked temporary parent (var -> private/var)",
    "codeql_execution": "existing mocked query/receipt unit fixtures",
    "tests_run": result.testsRun,
    "errors": [{"test": test.id(), "traceback": traceback}
               for test, traceback in result.errors],
    "failures": [{"test": test.id(), "traceback": traceback}
                 for test, traceback in result.failures],
    "skipped": [{"test": test.id(), "reason": reason}
                for test, reason in result.skipped],
    "successful": result.wasSuccessful(),
}, sort_keys=True))
sys.exit(0 if result.wasSuccessful() else 1)
