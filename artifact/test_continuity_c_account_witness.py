"""Incomplete witness-phase accounting cannot qualify a foreign cleanup run."""
import json
from pathlib import Path
import tempfile
import unittest

import continuity_c_account_witness as account


class AccountWitnessTests(unittest.TestCase):
    def setUp(self):
        # Stage-parser fixture only: no signature or protocol/runtime claim.
        self.rows = [bytes([int(index % 3 != 1)]) + bytes(account.witness.RECORD_BYTES - 1) for index in range(12)]
        self.wire = b"".join(self.rows)
        self.data = "".join(f"{phase} {index * 3} {index * 3 + 3} {index * 3 + 1}\n"
                            for index, phase in enumerate(account.PHASES)).encode()

    def test_every_lost_response_belongs_to_its_original_phase(self):
        result = account.stages(self.data, self.wire)
        self.assertEqual(list(result), list(account.PHASES))
        self.assertEqual([row["lost_exchange"] for row in result.values()], [1, 4, 7, 10])

    def test_missing_repeated_or_relabelled_phases_are_refused(self):
        for data in (b"", self.data.split(b"\n", 1)[1], self.data + b"freeze 0 3 1\n",
                     self.data.replace(b"freeze 3 6 4", b"reservation 3 6 4"),
                     self.data.replace(b"freeze 3 6 4", b"freeze 0 3 1"), self.data[:-1]):
            with self.subTest(data=data), self.assertRaises(ValueError):
                account.stages(data, self.wire)

    def test_unmeasured_or_substituted_losses_are_refused(self):
        rows = list(self.rows); rows[0] = b"\x00" + rows[0][1:]
        more = b"".join(rows)
        rows = list(self.rows); rows[1] = b"\x01" + rows[1][1:]
        missing = b"".join(rows)
        for data, wire in ((self.data, more), (self.data, missing), (self.data, self.wire[:-1]),
                           (self.data.replace(b"retirement 9 12 10", b"retirement 9 13 10"), self.wire),
                           (self.data.replace(b"freeze 3 6 4", b"freeze 3 6 3"), self.wire)):
            with self.subTest(data=data), self.assertRaises(ValueError):
                account.stages(data, wire)

    def test_summary_and_wrong_target_do_not_replace_execution(self):
        correct = (f"test {account.TEST} ... ok\n"
                   "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 4 filtered out;\n").encode()
        with tempfile.TemporaryDirectory() as folder:
            for data in (b"", correct + correct, correct.replace(b"4 filtered", b"5 filtered"),
                         correct.replace(b"0 ignored", b"1 ignored")):
                with self.subTest(data=data), self.assertRaisesRegex(ValueError, "completely"):
                    account.verify_execution(data, Path(folder))

    def test_foreign_language_and_release_scope_cannot_be_relabelled(self):
        stdout = (f"test {account.TEST} ... ok\n"
                  "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 4 filtered out;\n").encode()
        base = dict(schema_version=1, completed=True, language="C", batch="11" * 32, report="22" * 32,
                    witness_exchanges=12, lost_advances=4, release_claim_eligible=False)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for changed, language in ((base, "Swift"), (base, "Kotlin"),
                                      (list(base), "C"),
                                      (dict(base, release_claim_eligible=True), "C"),
                                      (dict(base, lost_advances=True), "C"),
                                      (dict(base, completed=1), "C")):
                (root / "account-witness-result.json").write_text(json.dumps(changed))
                with self.subTest(changed=changed, language=language), self.assertRaisesRegex(ValueError, "scope differs"):
                    account.verify_execution(stdout, root, language=language)
