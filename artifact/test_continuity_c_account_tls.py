"""TLS cleanup evidence must retain carrier, original phases and language scope."""
import json
from pathlib import Path
import tempfile
import unittest

import continuity_c_account_tls as tls
import continuity_c_account_witness as witness


class AccountTlsTests(unittest.TestCase):
    def setUp(self):
        # Parser-only metadata, not a fabricated TLS/signature execution.
        before = 0
        rows = []
        for label, admitted in tls.PHASES.items():
            after = before + int(admitted)
            rows.append(f"{label} {before} {after} 0\n")
            before = after
        self.data = "".join(rows).encode()

    def test_every_phase_keeps_its_admission_boundary(self):
        checked = tls.phases(self.data)
        self.assertEqual(list(checked), list(tls.PHASES))
        self.assertEqual(checked["retired-unavailable"]["after_last_admission"], 5)
        self.assertTrue(all(row["plaintext_exchanges"] == 0 for row in checked.values()))

    def test_skipped_reordered_or_plaintext_phases_cannot_qualify(self):
        for data in (self.data[:-1], self.data.split(b"\n", 1)[1], self.data + b"freeze 1 2 0\n",
                     self.data.replace(b"wrong-pin", b"wrong-name"),
                     self.data.replace(b"bootstrap 0 1 0", b"bootstrap 0 1 1")):
            with self.subTest(data=data), self.assertRaises(ValueError):
                tls.phases(data)

    def test_pre_admission_refusals_cannot_reach_the_store(self):
        for data in (self.data.replace(b"missing 1 1 0", b"missing 1 2 0"),
                     self.data.replace(b"freeze 1 2 0", b"freeze 1 1 0"),
                     self.data.replace(b"freeze 1 2 0", b"freeze 0 2 0"),
                     self.data.replace(b"bootstrap 0 1 0", b"bootstrap 0 4097 0")):
            with self.subTest(data=data), self.assertRaises(ValueError):
                tls.phases(data)

    def test_account_helper_requires_both_carriers(self):
        from continuity_package import TESTS
        names = sorted({witness.TEST, tls.TEST, witness.TLS_LOSS_TEST} | {"fixture::" + name for name in TESTS})
        data = ("".join(name + ": test\n" for name in names) + "\n6 tests, 0 benchmarks\n").encode()
        witness.helper_inventory(data)
        for broken in (data.replace((tls.TEST + ": test\n").encode(), b""), data + data,
                       data.replace(b"6 tests", b"5 tests")):
            with self.subTest(broken=broken), self.assertRaises(ValueError):
                witness.helper_inventory(broken)

    def test_wrong_target_or_omitted_test_cannot_qualify(self):
        data = (f"test {tls.TEST} ... ok\n"
                "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 5 filtered out;\n").encode()
        with tempfile.TemporaryDirectory() as folder:
            for broken in (b"", data + data, data.replace(b"5 filtered", b"4 filtered"),
                           data.replace(tls.TEST.encode(), witness.TEST.encode())):
                with self.subTest(broken=broken), self.assertRaisesRegex(ValueError, "completely"):
                    tls.verify_execution(broken, Path(folder))

    def test_setup_carrier_and_language_cannot_be_relabelled(self):
        data = (f"test {tls.TEST} ... ok\n"
                "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 5 filtered out;\n").encode()
        base = dict(schema_version=1, language="C", completed=True, batch="11" * 32, report="22" * 32,
                    carrier="q-periapt-anchor/1", reservation_carrier="signed-tcp", witness_exchanges=5,
                    rejected_connections=2, release_claim_eligible=False)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for record, language in ((base, "Swift"), (base, "Kotlin"), (list(base), "C"),
                    (dict(base, reservation_carrier="mutual-tls"), "C"), (dict(base, completed=1), "C"),
                    (dict(base, release_claim_eligible=True), "C"), (dict(base, rejected_connections=True), "C")):
                (root / "account-tls-result.json").write_text(json.dumps(record))
                with self.subTest(record=record, language=language), self.assertRaisesRegex(ValueError, "scope differs"):
                    tls.verify_execution(data, root, language=language)
