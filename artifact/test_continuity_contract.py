"""Contract comparison must not turn incomplete or altered descriptors into a pass."""
import contextlib
import copy
import io
import json
from pathlib import Path
import signal
import tempfile
import unittest
from unittest.mock import patch

import bounded_process
from bounded_process import BoundedResult

import continuity_contract as contract
from evidence_io import parse_strict_json_bytes


class ContinuityWireContractTests(unittest.TestCase):
    def setUp(self):
        self.expected = parse_strict_json_bytes(contract.snapshot(contract.BUDGETS).data, label="budgets")

    def test_complete_exact_descriptor_matches(self):
        self.assertEqual(contract.compare(self.expected, copy.deepcopy(self.expected)), self.expected)

    def test_release_requires_explicit_stage_and_preserves_input_descriptors(self):
        frozen = copy.deepcopy(self.expected)
        frozen["frozen_product_contract"] = True
        original = copy.deepcopy(frozen)
        actual = copy.deepcopy(frozen)
        self.assertIs(contract.validate(frozen, stage="release"), frozen)
        self.assertIs(contract.compare(frozen, actual, stage="release"), actual)
        self.assertEqual(frozen, original)
        self.assertEqual(actual, original)
        for kwargs in ({}, {"stage": "candidate"}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                contract.compare(frozen, actual, **kwargs)
        with self.assertRaises(ValueError):
            contract.compare(self.expected, self.expected, stage="release")
        for expected, observed in ((self.expected, frozen), (frozen, self.expected)):
            with self.subTest(expected=expected["frozen_product_contract"]), self.assertRaises(ValueError):
                contract.compare(expected, observed, stage="release")

    def test_stage_and_freeze_state_are_closed_and_exactly_typed(self):
        for stage in (None, True, "", "auto", "Release", []):
            with self.subTest(stage=stage), self.assertRaisesRegex(ValueError, "stage"):
                contract.validate(self.expected, stage=stage)
        for stage in ("candidate", "release"):
            for frozen in (0, 1, 0.0, 1.0, None, "false", "true"):
                changed = dict(self.expected, frozen_product_contract=frozen)
                with self.subTest(stage=stage, frozen=frozen), self.assertRaises(ValueError):
                    contract.compare(changed, changed, stage=stage)

    def test_release_keeps_complete_schema_limits_and_profile_commitment(self):
        frozen = copy.deepcopy(self.expected)
        frozen["frozen_product_contract"] = True
        mutations = [dict(frozen, schema_version=True), dict(frozen, schema_version=2),
                     dict(frozen, package_version="0.2.0"),
                     dict(frozen, rekey_profile_sha3_256="0" * 64),
                     dict(frozen, signature_context="bad\0context"),
                     dict(frozen, signature_purposes={"First": 1, "Second": 1}),
                     dict(frozen, maximums=dict(frozen["maximums"], plaintext_bytes=True))]
        for changed in mutations:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                contract.compare(changed, copy.deepcopy(changed), stage="release")
        for name in contract.LIMITS:
            changed = copy.deepcopy(frozen)
            changed["maximums"][name] += 1
            with self.subTest(limit=name), self.assertRaisesRegex(ValueError, "compiled contract differs"):
                contract.compare(frozen, changed, stage="release")

    def test_main_stage_selection_reports_only_validated_freeze_without_release_claim(self):
        cases = [(None, False, False, True), ("candidate", False, False, True),
                 ("release", True, True, True), (None, True, True, False),
                 ("release", False, False, False), ("release", True, False, False),
                 ("release", False, True, False)]
        for stage, reviewed_frozen, compiled_frozen, succeeds in cases:
            with self.subTest(stage=stage, reviewed=reviewed_frozen, compiled=compiled_frozen), \
                    tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                budgets = root / "budgets.json"
                reviewed = dict(self.expected, frozen_product_contract=reviewed_frozen)
                original = json.dumps(reviewed).encode()
                budgets.write_bytes(original)
                executable = root / "consumer"
                executable.write_bytes(b"compiled contract fixture")
                output = root / "output"
                argv = ["continuity_contract", "--consumer", str(executable), "--output", str(output)]
                if stage is not None:
                    argv.extend(["--stage", stage])
                result = BoundedResult(returncode=0, stderr=b"", stdout=json.dumps(
                    dict(self.expected, frozen_product_contract=compiled_frozen)).encode())
                with patch("sys.argv", argv), patch.object(contract, "BUDGETS", budgets), \
                        patch.object(contract, "capture_output", return_value=result), \
                        contextlib.redirect_stdout(io.StringIO()):
                    if succeeds:
                        contract.main()
                    else:
                        with self.assertRaises(ValueError):
                            contract.main()
                report = json.loads((output / "CONTRACT.json").read_bytes())
                self.assertEqual(report["stage"], stage or "candidate")
                self.assertIs(report["completed"], succeeds)
                self.assertIs(report["release_claim_eligible"], False)
                if succeeds:
                    self.assertIs(report["frozen_product_contract"], compiled_frozen)
                    self.assertEqual(report["contract"], reviewed)
                else:
                    self.assertNotIn("frozen_product_contract", report)
                    self.assertNotIn("contract", report)
                self.assertEqual(budgets.read_bytes(), original)
                self.assertEqual(executable.read_bytes(), b"compiled contract fixture")

    def test_main_rejects_unknown_stage_before_executing_consumer(self):
        with patch("sys.argv", ["continuity_contract", "--consumer", "/unused/consumer",
                                "--output", "/unused/output", "--stage", "auto"]), \
                patch.object(contract, "capture_output") as capture, \
                contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            contract.main()
        self.assertEqual(raised.exception.code, 2)
        capture.assert_not_called()

    def test_each_limit_change_is_rejected(self):
        for name in contract.LIMITS:
            changed = copy.deepcopy(self.expected)
            changed["maximums"][name] += 1
            with self.subTest(limit=name), self.assertRaisesRegex(ValueError, "compiled contract differs"):
                contract.compare(self.expected, changed)

    def test_each_signature_purpose_change_or_omission_is_rejected(self):
        for name in self.expected["signature_purposes"]:
            for change in ("number", "remove", "rename"):
                changed = copy.deepcopy(self.expected)
                purposes = changed["signature_purposes"]
                if change == "number":
                    purposes[name] += 128
                elif change == "remove":
                    del purposes[name]
                else:
                    purposes[name + "Changed"] = purposes.pop(name)
                with self.subTest(purpose=name, change=change), self.assertRaisesRegex(
                    ValueError, "compiled contract differs"
                ):
                    contract.compare(self.expected, changed)
        changed = copy.deepcopy(self.expected)
        changed["signature_purposes"]["UnreviewedPurpose"] = 255
        with self.assertRaisesRegex(ValueError, "compiled contract differs"):
            contract.compare(self.expected, changed)

    def test_invalid_or_repeated_signature_purpose_bytes_are_rejected(self):
        for value in (True, 1.0, 0, -1, 256, "1"):
            changed = copy.deepcopy(self.expected)
            changed["signature_purposes"]["Credential"] = value
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "purpose name or byte"):
                contract.compare(changed, copy.deepcopy(changed))
        for purposes in ({}, [], {"bad name": 1}, {"First": 1, "Second": 1}):
            changed = copy.deepcopy(self.expected)
            changed["signature_purposes"] = purposes
            with self.subTest(purposes=purposes), self.assertRaisesRegex(ValueError, "purpose"):
                contract.compare(changed, copy.deepcopy(changed))

    def test_old_descriptor_does_not_qualify_the_complete_purpose_contract(self):
        changed = copy.deepcopy(self.expected)
        changed["schema_version"] = 1
        with self.assertRaisesRegex(ValueError, "contract schema differs"):
            contract.compare(changed, copy.deepcopy(changed))
        del changed["signature_purposes"]
        with self.assertRaisesRegex(ValueError, "contract fields differ"):
            contract.compare(changed, copy.deepcopy(changed))

    def test_previous_descriptor_without_fanout_quota_is_not_current_contract(self):
        previous = copy.deepcopy(self.expected)
        previous["schema_version"] = 2
        previous["maximums"] = {
            name: value for name, value in previous["maximums"].items()
            if name != "retained_fanout_records"
        }
        with self.assertRaisesRegex(ValueError, "contract schema differs"):
            contract.compare(previous, copy.deepcopy(previous))

        incomplete = copy.deepcopy(self.expected)
        del incomplete["maximums"]["retained_fanout_records"]
        with self.assertRaisesRegex(ValueError, "contract limit fields differ"):
            contract.compare(incomplete, copy.deepcopy(incomplete))

    def test_boolean_float_empty_and_unknown_limits_are_not_integers(self):
        for value in (True, 1.0, 0, -1, 2**32, "16384"):
            changed = copy.deepcopy(self.expected)
            changed["maximums"]["plaintext_bytes"] = value
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "bounded integer"):
                contract.compare(self.expected, changed)
        for operation in ("remove", "extra"):
            changed = copy.deepcopy(self.expected)
            if operation == "remove":
                del changed["maximums"]["prekey_records"]
            else:
                changed["maximums"]["unsigned_send_default"] = 64
            with self.subTest(operation=operation), self.assertRaisesRegex(ValueError, "limit fields"):
                contract.compare(self.expected, changed)

    def test_profile_commitment_and_unfrozen_boundary_are_independently_checked(self):
        for field, value in (("rekey_profile", self.expected["rekey_profile"] + ";changed"),
                             ("rekey_profile_sha3_256", "0" * 64), ("frozen_product_contract", True),
                             ("schema_version", True), ("signature_context", "bad\0context")):
            changed = copy.deepcopy(self.expected)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                contract.compare(self.expected, changed)
        # A malformed reviewed document is not accepted even if the program copies it.
        changed = copy.deepcopy(self.expected)
        changed["rekey_profile_sha3_256"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "profile commitment"):
            contract.compare(changed, changed)

    def test_main_preserves_contract_rejection_when_report_creation_also_fails(self):
        changed = copy.deepcopy(self.expected)
        changed["maximums"]["plaintext_bytes"] += 1
        stdout = json.dumps(changed).encode("utf-8")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            consumer = root / "consumer"
            consumer.write_bytes(b"contract consumer fixture")
            output = root / "output"
            retained = output / "CONTRACT.json"
            marker = b"existing evidence must not be overwritten"

            def consume(*args, **kwargs):
                retained.write_bytes(marker)
                return BoundedResult(returncode=0, stdout=stdout, stderr=b"")

            logged = io.StringIO()
            with patch("sys.argv", ["continuity_contract", "--consumer", str(consumer),
                                    "--output", str(output)]), \
                    patch.object(contract, "capture_output", side_effect=consume) as capture, \
                    contextlib.redirect_stdout(logged), \
                    self.assertRaisesRegex(ValueError, "compiled contract differs") as raised:
                contract.main()
            capture.assert_called_once_with(
                [str(consumer)], timeout_seconds=30,
                maximum_stdout_bytes=65536, maximum_stderr_bytes=65536)
            self.assertIn("could not retain Continuity contract evidence",
                          raised.exception.__notes__[0])
            self.assertIn("CONTRACT.json", raised.exception.__notes__[0])
            self.assertEqual(retained.read_bytes(), marker)
            self.assertEqual((output / "consumer.stdout").read_bytes(), stdout)
            self.assertEqual((output / "consumer.stderr").read_bytes(), b"")
            self.assertEqual(logged.getvalue(), "")

    def test_main_rejects_report_creation_failure_after_valid_contract(self):
        stdout = json.dumps(self.expected).encode("utf-8")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            consumer = root / "consumer"
            consumer.write_bytes(b"contract consumer fixture")
            output = root / "output"
            retained = output / "CONTRACT.json"
            marker = b"existing evidence must not be overwritten"

            def consume(*args, **kwargs):
                retained.write_bytes(marker)
                return BoundedResult(returncode=0, stdout=stdout, stderr=b"")

            logged = io.StringIO()
            with patch("sys.argv", ["continuity_contract", "--consumer", str(consumer),
                                    "--output", str(output)]), \
                    patch.object(contract, "capture_output", side_effect=consume) as capture, \
                    contextlib.redirect_stdout(logged), \
                    self.assertRaises(FileExistsError):
                contract.main()
            capture.assert_called_once_with(
                [str(consumer)], timeout_seconds=30,
                maximum_stdout_bytes=65536, maximum_stderr_bytes=65536)
            self.assertEqual(retained.read_bytes(), marker)
            self.assertEqual((output / "consumer.stdout").read_bytes(), stdout)
            self.assertEqual((output / "consumer.stderr").read_bytes(), b"")
            self.assertEqual(logged.getvalue(), "")

    def test_main_preserves_cancellation_and_attempts_incomplete_evidence(self):
        for failure_type in (KeyboardInterrupt, bounded_process._TerminationSignal):
            for report_collision in (False, True):
                with self.subTest(failure=failure_type.__name__, report_collision=report_collision):
                    failure = (KeyboardInterrupt("contract verification interrupted")
                               if failure_type is KeyboardInterrupt
                               else bounded_process._TerminationSignal(signal.SIGTERM))
                    with tempfile.TemporaryDirectory() as temporary:
                        root = Path(temporary).resolve()
                        consumer = root / "consumer"
                        consumer.write_bytes(b"contract consumer fixture")
                        output = root / "output"
                        retained = output / "CONTRACT.json"
                        marker = b"existing evidence must not be overwritten"

                        def interrupt(*args, **kwargs):
                            if report_collision:
                                retained.write_bytes(marker)
                            raise failure

                        logged = io.StringIO()
                        with patch("sys.argv", ["continuity_contract", "--consumer", str(consumer),
                                                "--output", str(output)]), \
                                patch.object(contract, "capture_output", side_effect=interrupt), \
                                contextlib.redirect_stdout(logged), \
                                self.assertRaises(failure_type) as raised:
                            contract.main()
                        self.assertIs(raised.exception, failure)
                        if isinstance(failure, SystemExit):
                            self.assertEqual(raised.exception.code, 128 + signal.SIGTERM)
                        if report_collision:
                            self.assertEqual(retained.read_bytes(), marker)
                            self.assertIn("could not retain Continuity contract evidence",
                                          raised.exception.__notes__[0])
                        else:
                            report = parse_strict_json_bytes(retained.read_bytes(), label="contract report")
                            self.assertFalse(report["completed"])
                            self.assertFalse(report["release_claim_eligible"])
                            self.assertEqual(report["failure"], str(failure))
                            self.assertNotIn("contract", report)
                        self.assertEqual({entry.name for entry in output.iterdir()}, {"CONTRACT.json"})
                        self.assertEqual(logged.getvalue(), "")


if __name__ == "__main__":
    unittest.main(warnings="error")
