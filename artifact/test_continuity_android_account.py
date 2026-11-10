"""Reader rejection controls over retained process results, not new crypto proof."""
from pathlib import Path
import shutil
import tempfile
import unittest
import zipfile
import continuity_android_account as account
import continuity_android_contract as contract
import rust_sdk_profile as sdk


class AndroidAccountTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.root = Path(temporary.name)
        archive = sdk.ROOT / 'research/sdk-alpha1/evidence/20261012-android-account/HOST_CAPTURE.zip'
        with zipfile.ZipFile(archive) as bundle:
            for name in bundle.namelist():
                if name.startswith(('public/', 'execution/')):
                    path = cls.root / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(bundle.read(name))

    def test_both_builds_and_trust_profiles(self):
        for profile in ('debug', 'release'):
            result = account.verify_execution((self.root/'execution'/f'{profile}-execution.stdout').read_bytes(), self.root/'public'/profile,catalog=contract.ACCOUNT_TESTS)
            self.assertEqual(set(result), {'fixed', 'recoverable'})
            self.assertEqual(sum(row['foreign_processes'] for row in result.values()), 54)

    def test_mutated_identity_outcome_effect_or_diagnostic_is_refused(self):
        stdout = (self.root/'execution/debug-execution.stdout').read_bytes()
        changes = {
            'sessions': lambda b: b[:32]*2,
            'original-operation': lambda b: bytes(len(b)),
            'unknown': lambda b: bytes(4),
            'concurrent-cancel': lambda b: bytes(4),
            'cancel-committed': lambda b: bytes(33),
            'retained-0': lambda b: b[:84]+(1).to_bytes(4,'big'),
            'delivered-1': lambda b: b[:16]+bytes(32)+b[48:],
            'effect-before-retry': lambda b: b[:-1]+bytes([b[-1]^1]),
            'concurrent-cancel.stderr': lambda b: b'JNI warning\n',
            'cancel-resumed-0.stdout': lambda b: b'',
        }
        for name, change in changes.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as t:
                copied = Path(t)/'public';shutil.copytree(self.root/'public/debug',copied)
                target = copied/'fixed'/name;old = target.read_bytes();new = change(old)
                self.assertNotEqual(old,new);target.write_bytes(new)
                with self.assertRaises(ValueError):account.verify_execution(stdout,copied,catalog=contract.ACCOUNT_TESTS)

    def test_execution_identity_and_workload_are_required(self):
        stdout = (self.root/'execution/debug-execution.stdout').read_bytes()
        for old,new in ((b'1 passed',b'0 passed'), (b'0 ignored',b'1 ignored'),
                        (account.TEST.encode(),b'other_test'), (b'qualified account fixed:',b'qualified other fixed:')):
            with self.subTest(old=old), self.assertRaises(ValueError):
                account.verify_execution(stdout.replace(old,new),self.root/'public/debug',catalog=contract.ACCOUNT_TESTS)


if __name__ == '__main__':unittest.main()
