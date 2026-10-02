"""Reject broken witness transcript semantics; signatures stay native-endpoint checks."""
import json
from pathlib import Path
import tempfile
import unittest

import continuity_c_witness as w


def fixture(subjects=2):
    authority = b"a" * 32
    rows = []
    def entry(subject, operation, challenge, outcome, head, last, delivered):
        command = w.commit(b"Q-PERIAPT-CONTINUITY-ANCHOR-COMMAND/v1", authority + subject + operation)
        request = b"QPANRQ01" + authority + subject + command + challenge + operation
        reply = (b"QPANRS01" + authority + subject + w.commit(b"Q-PERIAPT-CONTINUITY-ANCHOR-REQUEST/v1", request)
                 + command + bytes([outcome]) + head + bytes([bool(last)]) + (last if last else bytes(32)))
        rows.append(bytes([delivered]) + len(request).to_bytes(4, "big") + request + bytes(3373)
                    + len(reply).to_bytes(4, "big") + reply + bytes(3373))
        return command
    for ordinal in range(1, subjects + 1):
        subject = bytes([ordinal]) * 96
        original = (1).to_bytes(8, "big") * 2 + bytes([ordinal + 2]) * 32
        target = (1).to_bytes(8, "big") + (2).to_bytes(8, "big") + bytes([ordinal + 4]) * 32
        query, advance = b"\x01" + bytes(96), b"\x02" + original + target
        entry(subject, query, bytes([10 * ordinal]) * 32, 1, original, None, 1)
        command = w.commit(b"Q-PERIAPT-CONTINUITY-ANCHOR-COMMAND/v1", authority + subject + advance)
        entry(subject, advance, bytes([10 * ordinal + 1]) * 32, 2, target, command, 0)
        entry(subject, advance, bytes([10 * ordinal + 2]) * 32, 3, target, command, 1)
    return authority, rows


class ContinuityCWitnessTests(unittest.TestCase):
    def test_account_subject_census_requires_explicit_three_device_scope(self):
        authority, rows = fixture(3)
        data = b"".join(rows)
        with self.assertRaises(ValueError):
            w.transcript(data, authority, expected_lost_advances=3)
        result = w.transcript(data, authority, expected_lost_advances=3, expected_subjects=3)
        self.assertEqual(result["subjects"], 3)
        self.assertEqual(len(result["lost_commands"]), 3)
        for count in (0, 1, 4, True, None):
            with self.subTest(count=count), self.assertRaisesRegex(ValueError, "subject census"):
                w.transcript(data, authority, expected_subjects=count)

    def test_export_replays_selected_bytes_before_publishing_completion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "report").write_bytes(b"public test fixture")
            (root / "secret.key").write_bytes(b"unselected test fixture")
            result = {"public_readbacks": {"report": w.sdk.snapshot(root / "report").sha256},
                      "command_logs": {}}
            failed = root / "failed-export"
            with self.assertRaisesRegex(ValueError, "cannot replay"):
                w.export_selected(result, root, failed, "export boundary unit fixture",
                                  replay=lambda _: dict(result, inconsistent=True))
            self.assertFalse((failed / "PUBLIC_FILES.json").exists())
            self.assertFalse((failed / "secret.key").exists())
            complete = root / "complete-export"
            def replay(path):
                self.assertEqual((path / "report").read_bytes(), b"public test fixture")
                return result
            exported = w.export_selected(result, root, complete, "export boundary unit fixture", replay=replay)
            self.assertEqual(exported, result["public_readbacks"])
            self.assertTrue(json.loads((complete / "PUBLIC_FILES.json").read_text())["completed"])
            self.assertFalse((complete / "secret.key").exists())

    def test_partial_reply_must_match_the_original_committed_advance(self):
        authority, rows = fixture()
        data = b"".join(rows)
        w.transcript(data, authority)
        prefix = (3659).to_bytes(4, "big") + rows[1][3675:3675 + 1800]
        w.cancelled_reply_prefix(prefix, data)
        for altered in (b"", prefix[:-1], prefix + b"x", bytes(1804),
                        (3659).to_bytes(4, "big") + rows[4][3675:3675 + 1800]):
            with self.subTest(prefix=altered[:12]), self.assertRaises(ValueError):
                w.cancelled_reply_prefix(altered, data)
        for altered in (b"", data[:-1], b"".join(rows[:3])):
            with self.subTest(transcript=altered[:12]), self.assertRaises(ValueError):
                w.cancelled_reply_prefix(prefix, altered)

    def test_cancellation_cannot_be_relabelled_from_timeout_or_missing_outcome(self):
        for value in (0, 25, 999):
            self.assertEqual(w.cancellation_latency(f"witness-cancelled-outcome-unavailable:{value}\n".encode()), value)
        for value in (b"", b"consumed\n", b"witness-outcome-unavailable\n",
                      b"witness-cancelled-outcome-unavailable:1000\n",
                      b"witness-cancelled-outcome-unavailable:-1\n",
                      b"witness-cancelled-outcome-unavailable:025\n"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                w.cancellation_latency(value)

    def test_two_lost_advances_reconcile_without_a_second_mutation(self):
        authority, rows = fixture()
        result = w.transcript(b"".join(rows), authority)
        self.assertEqual(result["exchanges"], 6)
        self.assertEqual(result["logical_advances"], 2)
        self.assertEqual(result["subjects"], 2)
        self.assertEqual(result["fresh_challenges"], 6)
        self.assertEqual(len(result["lost_commands"]), 2)
        for data in (b"", b"".join(rows)[:-1], b"".join(rows[:-1]), b"".join(rows + [rows[0]]),
                     b"".join([rows[1], rows[0], *rows[2:]])):
            with self.subTest(data=data[:12]), self.assertRaises(ValueError):
                w.transcript(data, authority)

    def test_each_attempt_and_target_is_bound_to_its_original_command(self):
        authority, rows = fixture()
        # Wire framing, public authority, challenge, command and response binding;
        # signature bytes are deliberately outside this metadata verifier's scope.
        for row, offset in ((0, 0), (0, 1), (0, 1 + 4 + 8), (1, 1 + 4 + 136),
                            (1, 1 + 4 + 200 + 49), (2, 3675 + 4 + 136),
                            (2, 3675 + 4 + 168), (2, 3675 + 4 + 200),
                            (2, 3675 + 4 + 201), (2, 3675 + 4 + 249)):
            changed = list(rows); altered = bytearray(changed[row]); altered[offset] ^= 1; changed[row] = bytes(altered)
            with self.subTest(row=row, offset=offset), self.assertRaises(ValueError):
                w.transcript(b"".join(changed), authority)
        with self.assertRaises(ValueError):
            w.transcript(b"".join(rows), b"b" * 32)

    def test_report_cannot_promote_missing_execution_or_wrong_scope_to_success(self):
        stdout = (f"test {w.TEST} ... ok\n"
                  "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 10 filtered out;\n").encode()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for output in (b"", stdout + stdout, stdout.replace(b"10 filtered out", b"2 filtered out")):
                self.assertNotEqual(output, stdout)
                with self.subTest(output=output), self.assertRaises(ValueError):
                    w.verify_execution(output, root)
            for report in ({"completed": True}, {"completed": 1}, {"release_claim_eligible": True}):
                (root / "c-witness-public-result.json").write_text(json.dumps(report))
                with self.subTest(report=report), self.assertRaises(ValueError):
                    w.verify_execution(stdout, root)
                destination = root / "public-export"
                with self.subTest(export=report), self.assertRaises(ValueError):
                    w.export_public(stdout, root, destination)
                self.assertFalse(destination.exists(), "invalid execution produced public success evidence")

    def test_witness_language_cannot_be_inferred_from_a_passing_test_name(self):
        stdout = (f"test {w.TEST} ... ok\n"
                  "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 10 filtered out;\n").encode()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = {name: "11" * (16 if name == "peer_device" else 32)
                      for name in ("session", "message", "unknown", "context", "peer_account", "peer_device", "report")}
            report.update(schema_version=2, completed=True, witness_exchanges=274,
                          lost_advances=2, release_claim_eligible=False)
            for language in ("Swift", "Kotlin"):
                with self.subTest(language=language):
                    report["language"] = language
                    (root / "c-witness-public-result.json").write_text(json.dumps(report))
                    with self.assertRaisesRegex(ValueError, "result or release claim"):
                        w.verify_execution(stdout, root)
                    other = "Kotlin" if language == "Swift" else "Swift"
                    with self.assertRaisesRegex(ValueError, "result or release claim"):
                        w.verify_execution(stdout, root, language=other)
                    with self.assertRaisesRegex(ValueError, "unsupported witness language"):
                        w.verify_execution(stdout, root, language="unknown")
                    report["language"] = "C"
                    (root / "c-witness-public-result.json").write_text(json.dumps(report))
                    with self.assertRaisesRegex(ValueError, "result or release claim"):
                        w.verify_execution(stdout, root, language=language)



if __name__ == "__main__":
    unittest.main(warnings="error")
