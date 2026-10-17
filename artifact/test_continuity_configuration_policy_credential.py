"""Real public C/Swift P/G readbacks and adversarial reader controls, not new protocol runs."""
from pathlib import Path
import shutil
import tempfile
import unittest
import zipfile
import continuity_configuration_policy_credential as qualification
import rust_sdk_profile as sdk

ARCHIVE = sdk.ROOT / 'research/sdk-alpha1/evidence/20261013-swift-policy-credential/HOST_CAPTURE.zip'


def fixture(destination: Path, language: str, route: str) -> bytes:
    prefix = language.lower() + '/' + route
    with zipfile.ZipFile(ARCHIVE) as archive:
        for name in archive.namelist():
            start = prefix + '/public/'
            if name.startswith(start):
                relative = Path(name.removeprefix(start))
                if relative.is_absolute() or '..' in relative.parts: raise ValueError('archive path')
                target = destination / relative; target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.read(name))
        return archive.read(prefix + '/execution/execution.stdout')


class PolicyCredentialTests(unittest.TestCase):
    def verify(self, stdout, root, language='Swift', route='signed-fixed'):
        carrier, profile = route.split('-')
        return qualification.verify_execution(stdout, root, language=language, carrier=carrier, profile=profile)

    def test_all_eight_original_issuer_and_message_routes(self):
        for language in ('C', 'Swift'):
            for route in qualification.TESTS:
                with self.subTest(language=language, route=route), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory); stdout = fixture(root, language, route)
                    value = self.verify(stdout, root, language, route)
                    self.assertTrue(value['completed']); self.assertEqual(value['business_effects'], 1)

    def test_issuer_identity_original_policy_current_policy_and_predecessor_are_required(self):
        changes = [('credential-request', 32), ('credential-request', 96), ('credential-request', 128),
                   ('credential-request', 168), ('credential-request', 200), ('credential-request', 33119),
                   ('credential-next-request', 208), ('credential-next-request', 304),
                   ('credential-proposal', 7), ('credential-proposal', 296), ('credential-proposal', 297),
                   ('credential-recovered', 72), ('credential-renewed-identity', 0)]
        for name, offset in changes:
            with self.subTest(name=name, offset=offset), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); stdout = fixture(root, 'Swift', 'signed-fixed')
                path = root / 'signed-fixed/credential' / name
                value = bytearray(path.read_bytes()); value[offset] ^= 1; path.write_bytes(value)
                with self.assertRaises(ValueError): self.verify(stdout, root)

    def test_refuses_new_commit_in_history_and_incomplete_or_private_outputs(self):
        for change in ('history-commit', 'missing-process', 'second-effect', 'private-output', 'ignored-test', 'old-catalog'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); stdout = fixture(root, 'Swift', 'signed-fixed'); folder = root / 'signed-fixed'
                if change == 'history-commit':
                    path = folder / 'credential/credential-historical-transcript'; data = bytearray(path.read_bytes()); data[205] = 5; path.write_bytes(data)
                elif change == 'missing-process': (folder / 'credential/credential-unknown.stdout').write_bytes(b'')
                elif change == 'second-effect': (folder / 'effect.bin').write_bytes(b'another business effect')
                elif change == 'private-output': (folder / 'credential/private.key').write_bytes(b'not admissible')
                elif change == 'ignored-test': stdout = stdout.replace(b'0 ignored', b'1 ignored')
                else: stdout = stdout.replace(b'10 filtered out', b'6 filtered out')
                with self.assertRaises(ValueError): self.verify(stdout, root)


if __name__ == '__main__': unittest.main()
