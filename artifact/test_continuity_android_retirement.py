"""Real archived consumer records and explicit failure controls for the package gate."""
from pathlib import Path
import tempfile
import unittest
import zipfile

import continuity_android_contract as contract
import continuity_android_retirement as retirement
import rust_sdk_profile as sdk

ROOT = sdk.ROOT
ARCHIVE = ROOT / "research/sdk-alpha1/evidence/20261012-android-replacement/CAPTURE.zip"


class AndroidRetirementTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        with zipfile.ZipFile(ARCHIVE) as archive:
            prefix = "host/debug/"
            for name in archive.namelist():
                if name.startswith(prefix):
                    relative = Path(name.removeprefix(prefix))
                    self.assertFalse(relative.is_absolute() or ".." in relative.parts)
                    target = self.base / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(archive.read(name))
        self.stdout = (self.base / "execution.stdout").read_bytes()
        self.cases = self.base / "cases"

    def test_complete_real_execution_and_exact_public_export(self):
        result = retirement.verify_execution(self.stdout, self.cases, catalog=contract.RETIREMENT_TESTS)
        self.assertEqual(sum(r["foreign_processes"] for r in result.values()), 64)
        exported = self.base / "exported"
        for trust, record in result.items():
            self.assertEqual(record["total_counterparty_effects"], 2)
            for name in record["public_readbacks"]:
                sdk.copy(self.cases / ("signed-" + trust) / name, exported / ("signed-" + trust) / name)
        self.assertEqual(retirement.verify_execution(self.stdout, exported, catalog=contract.RETIREMENT_TESTS), result)

    def test_changed_originals_successor_and_effects_are_rejected(self):
        case = self.cases / "signed-fixed"
        for name in ("retirement-verified", "retirement-wrong-purpose", "retirement-journal-unknown",
                     "inputs/retirement-ack", "successor/original.identity", "successor/reopened.request",
                     "successor/inputs/enrollment-intent", "successor/peer-connected", "successor/peer-acknowledged",
                     "successor/effect-after", "successor/effect-count", "retirement-effect-after-successor"):
            with self.subTest(record=name):
                path = case / name
                original = path.read_bytes()
                changed = bytearray(original)
                # The reader checks the signed body's purpose/binding. Native
                # execution, not public grammar inspection, authenticates signatures.
                changed[4 if name == "inputs/retirement-ack" else -1] ^= 1
                path.write_bytes(changed)
                with self.assertRaises(ValueError): retirement.verify_execution(self.stdout, self.cases, catalog=contract.RETIREMENT_TESTS)
                path.write_bytes(original)

    def test_missing_report_and_missing_counterparty_admission_are_rejected(self):
        for name in ("retirement-complete-report", "successor/roster-peer-admitted.stdout"):
            path = self.cases / "signed-fixed" / name
            original = path.read_bytes()
            path.unlink()
            with self.assertRaises((ValueError, OSError)): retirement.verify_execution(self.stdout, self.cases, catalog=contract.RETIREMENT_TESTS)
            path.write_bytes(original)

    def test_process_diagnostics_and_cut_as_success_are_rejected(self):
        for name, changed in (("retirement-report-unknown.stdout", b"fixed:retired-owned-report-unknown:passed\n"),
                              ("retirement-verified.stderr", b"WARNING in native method"),
                              ("successor/peer-acknowledged.stdout", b"")):
            path = self.cases / "signed-fixed" / name
            original = path.read_bytes()
            path.write_bytes(changed)
            with self.assertRaises(ValueError): retirement.verify_execution(self.stdout, self.cases, catalog=contract.RETIREMENT_TESTS)
            path.write_bytes(original)

    def test_complete_current_catalog_cannot_use_historical_census(self):
        contract.verify_single(self.stdout, retirement.TEST, catalog=contract.RETIREMENT_TESTS)
        with self.assertRaises(ValueError): retirement.verify_execution(self.stdout, self.cases)
        for changed in (self.stdout.replace(b"24 filtered", b"23 filtered"),
                        self.stdout.replace(b"1 passed", b"0 passed"),
                        self.stdout.replace(b"0 ignored", b"1 ignored")):
            with self.assertRaises(ValueError): retirement.verify_execution(changed, self.cases, catalog=contract.RETIREMENT_TESTS)
        with self.assertRaises(ValueError): contract.verify_single(self.stdout, retirement.TEST, catalog=contract.ROSTER_TESTS)


if __name__ == "__main__":
    unittest.main()
