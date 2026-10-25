"""Reject partial or contradictory original lifecycle qualification receipts."""
import importlib.util
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest import mock
from continuity_independent_composition import verify_composition, verify_capacity


class CompositionSchedulingTests(unittest.TestCase):
    def setUp(self):
        source = Path(__file__).resolve().parent.parent / "research/continuity-openssl-peer/policy_composition_checks.py"
        spec = importlib.util.spec_from_file_location("composition_scheduling_test", source)
        self.driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.driver)

    def test_independent_profiles_overlap_with_bounded_concurrency_and_stable_order(self):
        barrier = threading.Barrier(2, timeout=5)
        guard = threading.Lock()
        active, peak, observed = 0, 0, []

        def profile(args, members, witnessed):
            nonlocal active, peak
            self.assertIs(args, sentinel)
            with guard:
                active += 1
                peak = max(peak, active)
                observed.append((members, witnessed))
            try:
                barrier.wait()
                return members, witnessed
            finally:
                with guard:
                    active -= 1

        sentinel = object()
        with mock.patch.object(self.driver, "run_profile", side_effect=profile):
            result = self.driver.run_profiles(sentinel)
        expected = [(3, False), (3, True), (32, False), (32, True)]
        self.assertEqual(result, expected)
        self.assertCountEqual(observed, expected)
        self.assertEqual((peak, active), (2, 0))

    def test_any_profile_failure_is_propagated_without_a_complete_result(self):
        observed = []
        failure = ValueError("original profile assertion failed")

        def profile(_args, members, witnessed):
            observed.append((members, witnessed))
            if (members, witnessed) == (32, False):
                raise failure
            return members, witnessed

        with mock.patch.object(self.driver, "run_profile", side_effect=profile):
            with self.assertRaises(ValueError) as caught:
                self.driver.run_profiles(object())
        self.assertIs(caught.exception, failure)
        self.assertCountEqual(observed, [(3, False), (3, True), (32, False), (32, True)])


class NativeTranscriptTests(unittest.TestCase):
    def setUp(self):
        source = Path(__file__).resolve().parent.parent / "research/continuity-openssl-peer/run.py"
        spec = importlib.util.spec_from_file_location("independent_transcript_test", source)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.native = module.Counterpart.__new__(module.Counterpart)
        self.native.cases = Path(temporary.name)
        self.native.commands = []
        self.native.process = SimpleNamespace(pid=123)
        self.transfers = []
        def transfer(wire):
            self.transfers.append(wire)
            return b"\x01reply"
        self.native.transfer = transfer

    def test_reused_name_preserves_original_bytes_before_native_dispatch(self):
        self.native.exchange_record("approval", 41, b"original")
        before = list(self.native.commands)
        with self.assertRaises(FileExistsError):
            self.native.exchange_record("approval", 43, b"replacement")
        self.assertEqual(self.transfers, [b"\x29original"])
        self.assertEqual(self.native.commands, before)
        self.assertEqual((self.native.cases / "approval.input").read_bytes(), b"original")
        self.assertEqual((self.native.cases / "approval.output").read_bytes(), b"\x01reply")

    def test_existing_output_is_not_overwritten_or_dispatched(self):
        path = self.native.cases / "approval.output"
        path.write_bytes(b"retained response")
        with self.assertRaises(FileExistsError):
            self.native.exchange_record("approval", 41, b"request")
        self.assertEqual(path.read_bytes(), b"retained response")
        self.assertEqual(self.transfers, [])
        self.assertEqual(self.native.commands, [])

    def test_transport_failure_preserves_request_without_success_receipt(self):
        def unavailable(wire):
            raise TimeoutError("native output deadline")
        self.native.transfer = unavailable
        with self.assertRaisesRegex(TimeoutError, "native output deadline"):
            self.native.exchange_record("approval", 41, b"request")
        self.assertEqual((self.native.cases / "approval.input").read_bytes(), b"request")
        self.assertEqual((self.native.cases / "approval.output").read_bytes(), b"")
        self.assertEqual(self.native.commands, [])


class CompositionCapacityTests(unittest.TestCase):
    def report(self):
        cases = ["history-duplicate-active-proof", "history-invalid-discriminator", "history-alias-without-active",
            "history-cannot-expand-business", "R-allocation-cannot-fund-send", "history-full-field-capacity",
            "history-truncated-proof", "history-wrong-journal", "history-allocation-cannot-fund-send"]
        return {"profiles": [{"witnessed": w, "members": 32, "traffic_bytes": 2031616, "rows": 123,
            "native_trusted_time": 355, "workers": 39 if w else 36, "process_kills": 8 if w else 7,
            **{k: "a" * 64 for k in ("journal", "native_journal", "session", "original_message_sha256", "original_last_message_sha256")},
            "original_inventory": {"traffic_bytes": 2031616, "outboxes": 123,
                "epoch_record_hashes": [[0, "b" * 64], [1, "c" * 64]]},
            "roster_payload_bytes": 3100000, "roster_intent_bytes": 3100500,
            "refusals": [{"case": c, "type": "ValueError", "error": "refused"} for c in cases],
            "policy_composition": {"history_policy": 3, "active_policy": 5, "prepared_proofs": 2 if w else 3,
                "pending_bytes": 3200000 if w else 3300000, "committed_bytes": 3200000, "business_unchanged": True,
                "adoptions": [{"version": v, "at": t, "operation": str(v) * 64}
                    for v, t in ((2, 190), (3, 250), (4, 340), (5, 355))]}} for w in (False, True)]}

    def test_complete_full_store_receipt(self):
        verify_capacity(self.report())

    def test_partial_history_or_business_cannot_qualify(self):
        for mutate in (lambda r: r.update(rows=122), lambda r: r["original_inventory"].update(outboxes=1),
                       lambda r: r["original_inventory"]["epoch_record_hashes"].pop(),
                       lambda r: r["policy_composition"].update(prepared_proofs=2),
                       lambda r: r["policy_composition"].update(business_unchanged=1),
                       lambda r: r["policy_composition"].update(history_policy=5),
                       lambda r: r["policy_composition"].update(pending_bytes=3200000),
                       lambda r: r["policy_composition"]["adoptions"].pop(),
                       lambda r: r["refusals"].pop()):
            value = self.report(); mutate(value["profiles"][0])
            with self.assertRaises(ValueError): verify_capacity(value)

    def test_witness_target_is_exact_and_cohort_complete(self):
        for mutate in (lambda r: r["profiles"].pop(),
                       lambda r: r["profiles"][1]["policy_composition"].update(pending_bytes=3300000),
                       lambda r: r["profiles"][1].update(process_kills=0)):
            value = self.report(); mutate(value)
            with self.assertRaises(ValueError): verify_capacity(value)


class CompositionReceiptTests(unittest.TestCase):
    def report(self):
        rows = []
        denials = ["removed-peer-denies-next-id", "removed-peer-denies-old-output",
                  "removed-peer-denies-old-input", "removed-peer-denies-fresh-input"]
        for n, witnessed in ((3, False), (3, True), (32, False), (32, True)):
            refused = denials + ["reservation-remains-exclusive", "P-approval-before-R-refused",
                "expired-P-not-extended-by-G", "root-signed-old-generation-resurrection-refused"]
            for cycle in (1, 2):
                refused += [f"cycle-{cycle}-{s}" for s in ("P-blocks-G", "expired-C-still-denied", "G-blocks-P")]
                if witnessed:
                    refused += [f"cycle-{cycle}-{s}" for s in ("lost-G-commit-reply", "lost-G-ACK-reply")]
            if witnessed:
                refused += ["R-under-P-lost-commit", "remove-peer-lost-commit"]
            rows.append({"members": n, "witnessed": witnessed, "workers": 91 if witnessed else 81,
                "process_kills": 15, "confirmed_epoch": 1,
                **{k: "a" * 64 for k in ("journal", "native_journal", "session", "original_wire_sha256")},
                "policies": [{"version": 2, "at": 190, "operation": "1" * 64},
                             {"version": 3, "at": 250, "operation": "2" * 64}],
                "credentials": [{"cycle": 1, "at": 210, "operation": "3" * 64},
                                {"cycle": 2, "at": 310, "operation": "4" * 64}],
                "issuer_requests":[dict(cycle=c,at=at,operation=op*64,policy_version=c+1,policy_statement='e'*64,
                    original_certificate_sha256='a'*64,previous_certificate_sha256=before*64,successor_certificate_sha256=after*64,
                    journal_unchanged=True,refusals=['credential coordination remains pending' if witnessed else 'credential renewal remains pending',
                    'credential request operation already retained','closed registration owner'])
                    for c,at,op,before,after in [(1,210,'3','a','b'),(2,310,'4','b','c')]],
                "denied_operations": refused,
                "after_credentials": {"roster_operation": "5" * 64, "final_policy_version": 4,
                    "final_roster_version": 19, "final_native_time": 355, "retained_policy_proof_version": 3,
                    "refusals": [{"case": c, "error": "refused", "type": "ValueError"} for c in
                        ("old-R-proof-cannot-authorize-new-R", "R-proof-cannot-be-removed",
                         "R-proof-cannot-be-substituted", "policy-envelope-cannot-be-stripped")],
                    "peer_removal": {"kind": "actual_common_account_peer_removal", "target_version": 19,
                        "positive_native_receive": True, "same_generation_resurrection_refused": True,
                        "original_enrollment_retained": True, "denied_operations": denials,
                        "before_wire_sha256": "b" * 64, "after_wire_sha256": "c" * 64,
                        "target_sha256": "d" * 64}}})
        return {"profiles": rows}

    def test_complete_composition_receipt(self):
        verify_composition(self.report())

    def test_missing_or_rebound_credential_request_is_rejected(self):
        for mutate in (lambda r:r['issuer_requests'].pop(),
                       lambda r:r['issuer_requests'][0].update(journal_unchanged=False),
                       lambda r:r['issuer_requests'][0]['refusals'].pop(),
                       lambda r:r['issuer_requests'][1].update(original_certificate_sha256='c'*64),
                       lambda r:r['issuer_requests'][1].update(previous_certificate_sha256='a'*64)):
            value=self.report();mutate(value['profiles'][0])
            with self.assertRaises(ValueError):verify_composition(value)

    def test_partial_cohort_or_false_workload(self):
        for mutate in (lambda r: r["profiles"].pop(),
                       lambda r: r["profiles"][0].update(process_kills=0),
                       lambda r: r["profiles"][0].update(confirmed_epoch=True),
                       lambda r: r["profiles"][1].update(witnessed=1),
                       lambda r: r["profiles"][3].update(workers=81)):
            value = self.report(); mutate(value)
            with self.assertRaises(ValueError): verify_composition(value)

    def test_history_cannot_substitute_for_current_authority(self):
        for mutate in (lambda r: r.update(retained_policy_proof_version=4),
                       lambda r: r.update(final_native_time=170),
                       lambda r: r["refusals"].pop(),
                       lambda r: r["refusals"][0].update(error=""),
                       lambda r: r.update(roster_operation="1" * 64)):
            value = self.report(); mutate(value["profiles"][0]["after_credentials"])
            with self.assertRaises(ValueError): verify_composition(value)

    def test_removed_peer_requires_positive_and_fresh_negative_controls(self):
        for name, replacement in (("positive_native_receive", False), ("after_wire_sha256", "b" * 64),
                                   ("same_generation_resurrection_refused", False),
                                   ("denied_operations", []), ("original_enrollment_retained", 1)):
            value = self.report(); value["profiles"][0]["after_credentials"]["peer_removal"][name] = replacement
            with self.assertRaises(ValueError): verify_composition(value)

    def test_missing_unknown_commit_or_expiry_rejection(self):
        for name in ("R-under-P-lost-commit", "cycle-1-lost-G-ACK-reply", "expired-P-not-extended-by-G"):
            value = self.report(); value["profiles"][1]["denied_operations"].remove(name)
            with self.assertRaises(ValueError): verify_composition(value)


if __name__ == "__main__":
    unittest.main()
