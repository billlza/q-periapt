"""Reject altered retained recovery evidence; these are not new protocol runs."""
from pathlib import Path
import json
import shutil
import tempfile
import unittest
import zipfile

import continuity_android_recovery as recovery
import continuity_android_recovery_records as records
import continuity_android_contract as contract
import rust_sdk_profile as sdk


class AndroidRecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.root = Path(temporary.name)
        archive = sdk.ROOT / 'research/sdk-alpha1/evidence/20261012-android-recovery/HOST_CAPTURE.zip'
        with zipfile.ZipFile(archive) as bundle:
            for name in bundle.namelist():
                if name.startswith('execution/'):
                    path = cls.root / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(bundle.read(name))
        cls.root /= 'execution'

    def path(self, suffix, profile='debug'):
        return self.root / ('android-jni-' + profile + '-recovery-' + suffix)

    def reports(self, profile='debug'):
        value = json.loads((self.root / ('ANDROID_RECOVERY_' + profile.upper() + '.json')).read_text())
        return {row['batch']: row['public_readbacks']['c-account-loss-report']
                for row in value['native_oracles']}

    def witness(self, path):
        return records.dispatches(path, expected_java=44, expected_c=18, account_reports=self.reports())

    def test_both_profiles_replay_complete_native_and_java_records(self):
        for profile in ('debug', 'release'):
            with self.subTest(profile=profile):
                value = json.loads((self.root / ('ANDROID_RECOVERY_' + profile.upper() + '.json')).read_text())
                self.assertIs(value['completed'], True)
                self.assertEqual(value['first_use'], records.first_use(
                    self.path('first-use.stdout', profile).read_bytes(), self.path('first-use-public', profile), catalog=contract.RECOVERY_TESTS))
                self.assertEqual(value['witness'], records.dispatches(self.path('witness-calls', profile),
                    expected_java=44, expected_c=18, account_reports=self.reports(profile)))
                self.assertEqual(value['committed_members'], records.dispatches(self.path('result-calls', profile),
                    expected_java=18, expected_c=0))
                for i, (_, verify) in enumerate(recovery.WITNESS_CASES):
                    checked = verify(self.path(f'witness-{i}.stdout', profile).read_bytes(),
                                     self.path(f'oracle-{i}', profile), language='C')
                    self.assertEqual(value['native_oracles'][i],
                                     {k: v for k, v in checked.items() if k not in ('scope', 'language')})

    def test_original_identity_role_and_process_completion_are_required(self):
        for change in ('identity', 'role', 'completion', 'missing-process', 'acknowledgement'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as t:
                target = Path(t) / 'calls'
                shutil.copytree(self.path('witness-calls'), target)
                path = next(p for p in target.iterdir()
                    if json.loads((p / 'dispatch.json').read_text())['mode'] == 'recover-account-ack')
                if change in ('identity', 'role'):
                    row = json.loads((path / 'dispatch.json').read_text())
                    if change == 'identity':
                        row['original_id'] = 'f' * 64
                    else:
                        row.update(role='C operational/reference', original_id=None)
                        for file in path.iterdir():
                            if file.name != 'dispatch.json':
                                file.unlink()
                    (path / 'dispatch.json').write_text(json.dumps(row))
                elif change == 'completion':
                    (path / 'completed.txt').write_bytes(b'\x00')
                elif change == 'missing-process':
                    shutil.rmtree(path)
                else:
                    (path / 'result.txt').write_text('account-acknowledged:' + 'f' * 64 + '\n')
                with self.assertRaises(ValueError):
                    self.witness(target)

    def test_consistently_truncated_report_still_fails_native_comparison(self):
        with tempfile.TemporaryDirectory() as t:
            target = Path(t) / 'calls'
            shutil.copytree(self.path('witness-calls'), target)
            changed = 0
            for path in target.glob('*/account-report.txt'):
                lines = path.read_bytes().splitlines(keepends=True)
                self.assertTrue(lines[-1].startswith(b'skipped '))
                path.write_bytes(b''.join(lines[:-1]))
                changed += 1
            self.assertGreater(changed, 0)
            with self.assertRaisesRegex(ValueError, 'complete native accounting'):
                self.witness(target)

    def test_complete_oracle_census_is_required(self):
        expected = self.reports()
        expected.pop(next(iter(expected)))
        with self.assertRaises(ValueError):
            records.dispatches(self.path('witness-calls'), expected_java=44, expected_c=18,
                               account_reports=expected)

    def test_unknown_cannot_be_relabelled_confirmed(self):
        with tempfile.TemporaryDirectory() as t:
            target = Path(t) / 'calls'
            shutil.copytree(self.path('result-calls'), target)
            changed = 0
            for path in target.iterdir():
                if json.loads((path / 'dispatch.json').read_text())['mode'] == 'recover-account-settled-retire':
                    for name in ('result.txt', 'reconciliation.txt'):
                        original = (path / name).read_bytes()
                        self.assertIn(b' 4\n', original)
                        (path / name).write_bytes(original.replace(b' 4\n', b' 2\n'))
                    changed += 1
            self.assertEqual(changed, 2)
            with self.assertRaisesRegex(ValueError, 'unknown member relabeled consumed'):
                records.dispatches(target, expected_java=18, expected_c=0)

    def test_first_use_archive_counter_report_and_refusal_are_bound(self):
        changes = {
            'recovery-restored-0': lambda b: bytes(len(b)),
            'recovery-next-after': lambda b: bytes([b[0] ^ 1]) + b[1:],
            'recovery-ack-1': lambda b: bytes(len(b)),
            'recovery-tamper-0': lambda b: bytes(4),
            'recovery-final-results': lambda b: b[:-4] + (4).to_bytes(4, 'big'),
            'recovery-account-retired': lambda b: bytes(4),
            'recovery-frozen-0.stderr': lambda b: b'JNI warning\n',
        }
        for name, mutate in changes.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as t:
                target = Path(t) / 'public'
                shutil.copytree(self.path('first-use-public'), target)
                path = target / 'fixed' / name
                original = path.read_bytes()
                altered = mutate(original)
                self.assertNotEqual(original, altered)
                path.write_bytes(altered)
                with self.assertRaises(ValueError):
                    records.first_use(self.path('first-use.stdout').read_bytes(), target)


if __name__ == '__main__':
    unittest.main()
