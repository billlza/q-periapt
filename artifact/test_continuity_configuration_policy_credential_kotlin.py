"""Actual installed Kotlin Serial/G1 P/G receipts and garbage-collection controls."""
from pathlib import Path
import tempfile
import unittest
import zipfile
import continuity_configuration_policy_credential as qualification
import rust_sdk_profile as sdk

ARCHIVE = sdk.ROOT / 'research/sdk-alpha1/evidence/20261014-kotlin-policy-credential/CAPTURE.zip'


def fixture(destination, collector, route):
    prefix = collector + '/' + route + '/'
    with zipfile.ZipFile(ARCHIVE) as archive:
        for name in archive.namelist():
            if name.startswith(prefix + 'public/'):
                relative = Path(name.removeprefix(prefix + 'public/'))
                if relative.is_absolute() or '..' in relative.parts: raise ValueError('capture path')
                target = destination / relative; target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.read(name))
        return archive.read(prefix + 'execution.stdout')


class KotlinPolicyCredentialTests(unittest.TestCase):
    def verify(self, stdout, path, route='signed-fixed'):
        carrier, profile = route.split('-')
        return qualification.verify_execution(stdout, path, language='Kotlin', carrier=carrier, profile=profile)

    def test_eight_installed_issuer_and_original_message_routes(self):
        for collector in ('serial', 'g1'):
            for route in qualification.TESTS:
                with self.subTest(collector=collector, route=route), tempfile.TemporaryDirectory() as directory:
                    path = Path(directory); stdout = fixture(path, collector, route)
                    self.assertEqual(self.verify(stdout, path, route)['business_effects'], 1)

    def test_gc_proof_cannot_be_omitted_or_replaced_by_close_success(self):
        for offset, value in ((0, bytes(8)), (8, bytes(4)), (8, (33).to_bytes(4, 'big')), (12, (64).to_bytes(4, 'big'))):
            with self.subTest(offset=offset, value=value), tempfile.TemporaryDirectory() as directory:
                path = Path(directory); stdout = fixture(path, 'serial', 'signed-fixed')
                receipt = path / 'signed-fixed/registry-gc.bin'; raw = bytearray(receipt.read_bytes()); raw[offset:offset+len(value)] = value
                receipt.write_bytes(raw)
                with self.assertRaisesRegex(ValueError, 'collection or slot'): self.verify(stdout, path)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory); stdout = fixture(path, 'g1', 'signed-fixed')
            (path / 'signed-fixed/registry-gc.bin').unlink()
            with self.assertRaisesRegex(ValueError, 'inventory'): self.verify(stdout, path)

    def test_policy_request_or_credential_predecessor_cannot_be_swapped(self):
        for name, offset in (('credential-request', 96), ('credential-request', 168), ('credential-next-request', 208), ('credential-proposal', 7)):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                path = Path(directory); stdout = fixture(path, 'serial', 'signed-fixed')
                receipt = path / 'signed-fixed/credential' / name; raw = bytearray(receipt.read_bytes()); raw[offset] ^= 1; receipt.write_bytes(raw)
                with self.assertRaises(ValueError): self.verify(stdout, path)



class KotlinCollectorRoutingTests(unittest.TestCase):
    def test_canonical_foreign_collector_calls_use_disjoint_labels(self):
        import hashlib
        from unittest.mock import patch
        import continuity_first_configuration as configuration
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); outside = root / 'outside'; outside.mkdir(); output = root / 'output'; output.mkdir()
            helper, client, receiver = (root / name for name in ('helper', 'client', 'receiver'))
            for path in (helper, client, receiver): path.write_bytes(path.name.encode())
            def identity(path): return {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
            native = {'first_configuration': {'completed': True, 'short_header_guard': True, 'language': 'C',
                'binaries': {'helper': identity(helper), 'receiver': identity(receiver)}}, 'binaries': {'C_client': identity(receiver)}}
            labels = set()
            def run(command, label, *, runtime):
                self.assertNotIn(label, labels, 'second collector reuses the first collector output prefix')
                labels.add(label)
                (Path(runtime['QPERIAPT_MANAGED_CONFIGURATION_EVIDENCE']) / 'proof.bin').write_bytes(b'routing-only')
                return b'isolated routing stub; not protocol evidence'
            # Only routing is under test here. Real protocol receipts are checked above.
            with patch.object(configuration, '_qualify', side_effect=lambda *args, **kwargs: {}), \
                 patch.object(qualification, 'verify_execution', return_value={'public_readbacks': {'proof.bin': hashlib.sha256(b'routing-only').hexdigest()}}):
                for collector in ('Serial', 'G1'):
                    configuration.qualify_foreign(outside, output, 'debug', {'TEST_COLLECTOR': collector}, native,
                        run, client, language='Kotlin', collector=collector)
            self.assertEqual(len(labels), 8)
            self.assertTrue(all(any('-' + collector + '-' in label for collector in ('serial', 'g1')) for label in labels))
            self.assertEqual(len(list(output.iterdir())), 8)


if __name__ == '__main__': unittest.main()
