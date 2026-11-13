"""Synthetic evidence rejection tests; real cryptographic evidence comes from CLI runs."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

from continuity_independent_python import DIRECTORY_CLI_PUBLIC_FILES, verify_directory_cli_result

spec = importlib.util.spec_from_file_location("directory_cli_checks",
    Path(__file__).resolve().parents[1] / "research/continuity-openssl-peer/directory_cli_checks.py")
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)


def trace():
    def row(verb, last, exit=0, result=None, error="refused", middle=()):
        return {"arguments": [verb, *middle, last], "exit": exit,
                "stdout": json.dumps(result if result is not None else {}) if exit == 0 else "",
                "stderr": "" if exit == 0 else "Error: " + error + "\n"}
    rows = [row("prepare-key", "@directory.key"), row("show-key", "@directory.key"),
            row("init", "8"), row("init", "8"), row("inspect", "@verify-export1/publication.json"),
            row("issue", "@unused.bin", 1, error="Unauthorized"), row("issue", "@occupied.bin", 1),
            row("lookup", "@first.bin", result={"historical": True, "cancelled": False}),
            row("check-historical-receipt", "@first.bin"), row("issue", "@first-retry.bin"),
            row("issue", "@changed.bin", 1, error="Conflict"),
            row("inspect", "@reuse-classical.json"), row("inspect", "@reuse-pq.json"),
            row("inspect", "@fresh-pair.json"),
            row("issue", "@reuse-classical-before-cancel.bin", 1, error="KeyAlreadyReserved"),
            row("issue", "@reuse-pq-before-cancel.bin", 1, error="KeyAlreadyReserved"),
            row("check-receipt", "@first.bin", result={"signature_and_scope": True}),
            row("issue", "@duplicate.bin", 1, error="KeyAlreadyReserved"),
            row("cancel", "@issue-first.json", 1, error='"Approval scope differs from the independently selected operation"'),
            row("cancel", "@cancel-first.json", result={"cancelled": True}),
            row("cancel", "@cancel-first.json", result={"cancelled": True}),
            row("lookup", "@cancelled.bin", result={"historical": True, "cancelled": True}),
            row("issue", "@reactivated.bin", 1, error="Cancelled"),
            row("issue", "@reassigned.bin", 1, error="KeyAlreadyReserved"),
            row("issue", "@reuse-classical-after-cancel.bin", 1, error="KeyAlreadyReserved"),
            row("issue", "@reuse-pq-after-cancel.bin", 1, error="KeyAlreadyReserved"),
            row("issue", "@fresh-pair-after-cancel.bin"), row("issue", "@fork.bin"),
            row("prove-conflict", "@proof", 1, middle=("@pin", "@first.bin", "@first-retry.bin")),
            row("prove-conflict", "@proof", middle=("@pin", "@first.bin", "@fork.bin")),
            row("check-conflict", "@proof/conflict.bin")]
    history = [row("check-historical-receipt", receipt, exit, middle=(pin,)) for pin, receipt, exit in (
        ("@pin.json", "@receipt.bin", 0), ("@pin.json", "@bad-signature.bin", 1),
        ("@wrong-service.json", "@receipt.bin", 1), ("@wrong-key.json", "@receipt.bin", 1))]
    return rows, history


class DirectoryCliEvidenceTests(unittest.TestCase):
    def test_missing_duplicate_or_wrong_boundary_is_rejected(self):
        rows, history = trace()
        checks.validate_trace(rows, history)
        for index in (6, 7, 9, 10, 14, 15, 19, 20, 24, 25, 26, 27, 29):
            missing = copy.deepcopy(rows)
            del missing[index]
            with self.subTest(index=index), self.assertRaises(ValueError):
                checks.validate_trace(missing, history)
        wrong = copy.deepcopy(rows)
        wrong[24]["stderr"] = "Error: Unauthorized\n"
        with self.assertRaises(ValueError):
            checks.validate_trace(wrong, history)
        repeated = copy.deepcopy(rows)
        repeated[24] = copy.deepcopy(repeated[25])
        with self.assertRaises(ValueError):
            checks.validate_trace(repeated, history)

    def test_labels_do_not_prove_after_cancellation_order(self):
        rows, history = trace()
        rows[14], rows[24] = rows[24], rows[14]
        with self.assertRaises(ValueError):
            checks.validate_trace(rows, history)

    def test_historical_scope_cannot_add_private_input_or_drop_refusal(self):
        rows, history = trace()
        for index in range(4):
            altered = copy.deepcopy(history)
            altered[index]["arguments"].append("@directory.redb")
            with self.subTest(index=index), self.assertRaises(ValueError):
                checks.validate_trace(rows, altered)
        altered = copy.deepcopy(history)
        altered[3].update(exit=0, stdout="{}", stderr="")
        with self.assertRaises(ValueError):
            checks.validate_trace(rows, altered)

    def test_installed_receipt_cannot_promote_boundary_or_change_input_identity(self):
        source = {"reader.py": "a" * 64}
        public = {name: "b" * 64 for name in DIRECTORY_CLI_PUBLIC_FILES}
        implementation = "/isolated/qperiapt_continuity_reference/directory_lease.py"
        result = {"schema": "qperiapt-independent-directory-cli/1", "completed": True,
                  "source_sha256": source, "public_files": public, "implementation": implementation,
                  "verified_original_receipts": 3, "exact_retry": True, "canonical_conflict_matched": True,
                  "cli_processes": 31, "historical_processes": 4,
                  "negative_controls": ["bad-signature", "wrong-service", "wrong-public-key",
                                        "exact-retry-is-not-conflict", "bad-pq-signature"],
                  "historical_only": True, "current_authorization_or_consumption": False,
                  "session_qualified": False, "release_claim_eligible": False,
                  "directory_cli": "source-build", "provider": {"cryptography": "50.0.0"}}
        verify_directory_cli_result(result, source, public, implementation)
        for field, value in (("completed", 1), ("verified_original_receipts", True), ("cli_processes", 30),
                             ("cli_processes", 32), ("historical_processes", 3), ("negative_controls", []),
                             ("public_files", {}), ("source_sha256", {}), ("implementation", "/checkout/module.py"),
                             ("directory_cli", "installed-rust"), ("current_authorization_or_consumption", True),
                             ("release_claim_eligible", True), ("canonical_conflict_matched", False)):
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                verify_directory_cli_result(dict(result, **{field: value}), source, public, implementation)


if __name__ == "__main__":
    unittest.main()
