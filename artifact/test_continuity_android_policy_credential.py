"""Retained real P/G records and adversarial mutations of the qualification reader."""
from pathlib import Path
import shutil
import tempfile
import unittest
import zipfile
import continuity_android_policy_credential as q
import rust_sdk_profile as sdk


class PolicyCredentialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temp = tempfile.TemporaryDirectory(); cls.addClassCleanup(temp.cleanup); cls.root = Path(temp.name)
        for archive in ('HOST_REQUIRED_CAPTURE.zip', 'HOST_REMAINING_CAPTURE.zip'):
            with zipfile.ZipFile(sdk.ROOT / 'research/sdk-alpha1/evidence/20261013-policy-credential-bindings' / archive) as bundle:
                for name in bundle.namelist():
                    path = cls.root / name
                    if not path.is_relative_to(cls.root) or '..' in Path(name).parts: raise ValueError('archive member')
                    path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(bundle.read(name))

    def verify(self, root, label='signed-fixed'):
        carrier, profile = label.split('-')
        return q.verify_execution((self.root / label / 'execution/execution.stdout').read_bytes(), root, profile, carrier)

    def test_all_routes_keep_original_operation_and_business_effect(self):
        for label in q.TESTS:
            value = self.verify(self.root / label / 'public', label)
            self.assertEqual(value['foreign_processes'], 46 if label.startswith('local-') else 60)
            self.assertEqual(value['business_effects'], 1)
            self.assertTrue(value['next_issuer_predecessor_advanced'])

    def test_local_completion_keeps_consuming_activation_separate_from_passive_history(self):
        for name in ('credential-local-activated', 'credential-local-activated-replayed', 'credential-historical'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                root = Path(temp) / 'public'; shutil.copytree(self.root / 'local-fixed/public', root)
                path = root / 'local-fixed' / name; value = bytearray(path.read_bytes()); value[0] ^= 1; path.write_bytes(value)
                with self.assertRaises(ValueError): self.verify(root, 'local-fixed')

    def test_refuse_wrong_policy_domain_request_scope_predecessor_or_tail(self):
        changes = [('credential-proposal', 7), ('credential-proposal', 296), ('credential-proposal', 297),
                   ('credential-request', 64), ('credential-request', 128), ('credential-request', 168),
                   ('credential-request', 33119), ('credential-next-request', 208), ('credential-next-request', 304),
                   ('credential-terminal', 4), ('credential-active-identity', 0), ('policy-effect-after', 0)]
        for name, offset in changes:
            with self.subTest(name=name, offset=offset), tempfile.TemporaryDirectory() as temp:
                root = Path(temp) / 'public'; shutil.copytree(self.root / 'signed-fixed/public', root)
                path = root / 'signed-fixed' / name; value = bytearray(path.read_bytes()); value[offset] ^= 1; path.write_bytes(value)
                with self.assertRaises(ValueError): self.verify(root)

    def test_refuse_missing_process_or_fresh_historical_commit(self):
        for name in ('credential-request.stdout', 'credential-peer-admit.stderr', 'credential-historical-transcript'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                root = Path(temp) / 'public'; shutil.copytree(self.root / 'signed-fixed/public', root)
                path = root / 'signed-fixed' / name
                if name.endswith('transcript'):
                    value = bytearray(path.read_bytes()); value[205] = 5; path.write_bytes(value)
                else: path.write_bytes(b'unexpected\n')
                with self.assertRaises(ValueError): self.verify(root)


if __name__ == '__main__': unittest.main()
