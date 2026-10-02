"""Reject incomplete loss accounting and claims beyond executed recovery history."""
import json
from pathlib import Path
import tempfile
import unittest
import continuity_c_recovery as recovery

STDOUT = (f"test {recovery.TEST} ... ok\n"
          "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 6 filtered out;\n").encode()


def evidence(root):
    right = root / "responder"; right.mkdir()
    left = root / "initiator"; left.mkdir()
    mid = lambda epoch, seq, tail: epoch.to_bytes(8, "big").hex() + seq.to_bytes(8, "big").hex() + tail * 16
    r = {"schema_version": 1, "scope": recovery.SCOPE, "session": "11" * 32, "context": "22" * 32,
         "report": "33" * 32, "peer_account": "44" * 32, "peer_device": "55" * 16,
         "old_incoming": mid(0, 0, "66"), "incoming": [mid(1, 0, "77"), mid(1, 2, "88")],
         "unconfirmed": mid(1, 0, "99"), "old_resolution": "aa" * 32,
         "reserved_positive_case_executed": False, "release_claim_eligible": False}
    for name in ("completed", "revoked_operation_refused", "owner_kinds_separated", "report_exit_reconciled",
                 "ack_exit_reconciled", "original_report_unchanged", "catalogue_retired", "archive_metadata_only",
                 "cancelled_cleanup_unfrozen"):
        r[name] = True
    wire = b"QPCMSG03unit-readback-fixture"
    (right / "cleanup-unconfirmed-wire").write_bytes(wire)
    archive = b"QPCSCA01" + b"x" * 354
    (right / "native-closure-archive").write_bytes(archive)
    (right / "c-closure-archive").write_bytes(archive)
    rows = ["QPC-C-LOSS/1", "report " + r["report"],
            f"header {r['session']} {r['context']} {r['peer_account']} {r['peer_device']} 2 1 1 1 1 1 2 0 2",
            f"epoch 0 0 0 0 0 1 1 1 1 {r['old_resolution']} 0 1 0",
            f"delivery 0 0 {r['old_incoming']} 0 {len(recovery.PAYLOAD)}",
            f"epoch 1 1 0 1 0 3 0 0 0 {'0' * 64} 1 2 1",
            f"unconfirmed 1 0 {r['unconfirmed']} {recovery.ciphertext_digest(wire)}",
            f"delivery 1 0 {r['incoming'][0]} 0 {len(recovery.PAYLOAD)}",
            f"delivery 1 1 {r['incoming'][1]} 2 {len(recovery.PAYLOAD)}", "skipped 1 0 1"]
    (right / "c-loss-report").write_text("\n".join(rows) + "\n")
    outcomes = {"kind": "operational-owner-not-recovery\n", "denied": "rejected:603\n", "list-before": "catalogue:1\n",
                "missing": "missing-session-refused\n", "tamper": "tampered-archive-refused\n",
                "cancel": "cancelled-cleanup-not-frozen\n", "freeze": "", "ack-crash": "",
                "finish": "original-report-closed-retired\n", "list-after": "catalogue:0\n",
                "archive": "archive-closed-metadata-only\n", "list-final": "catalogue:0\n"}
    for name, value in outcomes.items():
        (right / f"c-recovery-{name}.stdout").write_text(value)
        (right / f"c-recovery-{name}.stderr").write_bytes(b"")
    (left / "c-recovery-bootstrap.stdout").write_text(r["session"] + "\n")
    (left / "c-recovery-bootstrap.stderr").write_bytes(b"")
    (root / "c-recovery-public-result.json").write_text(json.dumps(r))
    return r


class ContinuityCRecoveryTests(unittest.TestCase):
    def test_language_scope_is_explicit_and_accounting_is_not_relabelled(self):
        import continuity_swift_consumer as swift
        for language in ("Swift", "Kotlin"):
            with self.subTest(language=language), tempfile.TemporaryDirectory() as folder:
                root = Path(folder); report = evidence(root)
                def verify():
                    if language == "Swift":
                        return swift.verify_recovery_execution(STDOUT, root)
                    return recovery.verify_execution(STDOUT, root, language=language)
                with self.assertRaisesRegex(ValueError, "outcome, scope"):
                    verify()
                report["scope"] = recovery.SCOPE.replace("installed C recovery", "installed " + language + " recovery")
                (root / "c-recovery-public-result.json").write_text(json.dumps(report))
                observed = verify()
                self.assertIn("responder/c-loss-report", observed["public_readbacks"])
                if language == "Swift":
                    self.assertIn("c-recovery-public-result.json", observed["public_readbacks"])
                with self.assertRaisesRegex(ValueError, "outcome, scope"):
                    recovery.verify_execution(STDOUT, root)
                with self.assertRaisesRegex(ValueError, "unsupported recovery language"):
                    recovery.verify_execution(STDOUT, root, language="unknown")
                other = "Kotlin" if language == "Swift" else "Swift"
                with self.assertRaisesRegex(ValueError, "outcome, scope"):
                    recovery.verify_execution(STDOUT, root, language=other)
                loss = root / "responder/c-loss-report"
                loss.write_bytes(loss.read_bytes().replace(b"skipped 1 0 1\n", b""))
                with self.assertRaisesRegex(ValueError, "complete loss accounting"):
                    verify()

    def test_each_loss_row_ciphertext_and_archive_must_match(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); evidence(root)
            result = recovery.verify_execution(STDOUT, root)
            self.assertEqual(len(result["command_logs"]), 26)
            self.assertEqual(len(result["public_readbacks"]), 4)
            path = root / "responder/c-loss-report"; original = path.read_bytes()
            for altered in (original.replace(b"skipped 1 0 1\n", b""), original.replace(b" 2 0 2\n", b" 0 0 2\n"),
                            original.replace(b"delivery 0 0", b"delivery 1 0")):
                path.write_bytes(altered)
                with self.subTest(change=altered), self.assertRaisesRegex(ValueError, "complete loss accounting"):
                    recovery.verify_execution(STDOUT, root)
            path.write_bytes(original)
            wire = root / "responder/cleanup-unconfirmed-wire"; data = wire.read_bytes(); wire.write_bytes(data + b"!")
            with self.assertRaisesRegex(ValueError, "complete loss accounting"):
                recovery.verify_execution(STDOUT, root)
            wire.write_bytes(data)
            (root / "responder/c-closure-archive").write_bytes(b"QPCSCA01" + b"y" * 354)
            with self.assertRaisesRegex(ValueError, "archive differs"):
                recovery.verify_execution(STDOUT, root)

    def test_unexecuted_cases_and_missing_failure_outcomes_are_not_success(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); report = evidence(root)
            for output in (b"", STDOUT + STDOUT, STDOUT.replace(b"6 filtered out", b"5 filtered out")):
                with self.subTest(output=output), self.assertRaises(ValueError):
                    recovery.verify_execution(output, root)
            report_file = root / "c-recovery-public-result.json"
            for name, value in (("schema_version", True), ("completed", 1), ("archive_metadata_only", False),
                                ("cancelled_cleanup_unfrozen", False), ("reserved_positive_case_executed", True),
                                ("release_claim_eligible", True), ("scope", "required witness qualified")):
                report_file.write_text(json.dumps(dict(report, **{name: value})))
                with self.subTest(name=name), self.assertRaises(ValueError):
                    recovery.verify_execution(STDOUT, root)
            report_file.write_text(json.dumps(report))
            (root / "responder/c-recovery-denied.stdout").write_text("opened\n")
            with self.assertRaisesRegex(ValueError, "command outcome"):
                recovery.verify_execution(STDOUT, root)


if __name__ == "__main__":
    unittest.main(warnings="error")
