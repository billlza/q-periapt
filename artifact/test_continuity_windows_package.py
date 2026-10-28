"""Reject archive substitution and checkout dependencies in the Windows input boundary."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import continuity_package_archive as archive
from evidence_io import EvidenceIOError
from installed_rust_graph import verify_resolution
from continuity_windows_network_review import load_profiles, review, review_split


class InstalledWindowsInputs(unittest.TestCase):
    def test_exact_archive_rejects_changed_bytes_inventory_and_traversal_before_writing(self):
        files = {'include/qpc_owner.h': b'public header', 'lib/client.dll': b'fixture, not a DLL'}
        hashes = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive.unpack(archive.archive(files), hashes, root / 'valid')
            self.assertEqual((root / 'valid/include/qpc_owner.h').read_bytes(), files['include/qpc_owner.h'])
            changed = dict(files, **{'lib/client.dll': b'substituted'})
            for index, candidate in enumerate((changed, {'extra': b'unknown'}, {'../outside': b'escape'})):
                expected = hashes if index < 2 else {'../outside': hashlib.sha256(b'escape').hexdigest()}
                target = root / f'refused-{index}'
                with self.assertRaises(ValueError):
                    archive.unpack(archive.archive(candidate), expected, target)
                self.assertFalse(target.exists())
            self.assertFalse((root / 'outside').exists())

    def test_consumer_rejects_checkout_path_mixed_version_and_external_lock_substitution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            name, consumer = 'q-periapt-example', 'q-periapt-consumer'
            good = {'packages': [
                {'name': consumer, 'source': None, 'manifest_path': str(root / 'Cargo.toml')},
                {'name': name, 'source': None, 'version': '0.2.0',
                 'manifest_path': str(root / 'packages/q-periapt-example-0.2.0/Cargo.toml')}]}
            lock = ('version = 4\n[[package]]\nname="external"\nversion="1.0.0"\n'
                    'source="registry+https://github.com/rust-lang/crates.io-index"\nchecksum="' + 'a'*64 + '"\n').encode()
            def check(metadata, selected_lock=lock):
                return verify_resolution(metadata, root, selected_lock, lock,
                    consumer_name=consumer, versions={name: '0.2.0'})
            self.assertEqual(check(good)['product_crates'], 1)
            for field, value in (('manifest_path', str(root / 'checkout/Cargo.toml')), ('version', '0.1.5'), ('source', 'registry+wrong')):
                changed = copy.deepcopy(good)
                changed['packages'][1][field] = value
                with self.assertRaises(ValueError):
                    check(changed)
            with self.assertRaises(ValueError):
                check(good, lock.replace(b'a'*64, b'b'*64))


class WindowsProfileAdmission(unittest.TestCase):
    head = 'a' * 40

    def report(self, profiles):
        # These are admission fixtures, not executable lifecycle evidence.
        return {'schema': 1, 'profiles': {profile: {} for profile in profiles},
                'input_sha256': 'b' * 64,
                'input': {'source_commit': self.head, 'sdk_commit': 'c' * 40},
                'rustc': 'rustc 1.98.1 (48a229cea 2026-09-01)\nhost: x86_64-pc-windows-msvc\n'}

    def write(self, root, report):
        root.mkdir(exist_ok=True)
        (root / 'RESULT.json').write_text(json.dumps(report))

    def test_complete_legacy_and_separate_profiles_bind_original_receipt_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write(root, self.report(('debug', 'release')))
            reports, hashes = load_profiles({'debug': root, 'release': root}, self.head)
            self.assertIs(reports['debug'], reports['release'])
            self.assertEqual(set(hashes.values()), {hashlib.sha256((root / 'RESULT.json').read_bytes()).hexdigest()})
            inputs = {profile: root / profile for profile in ('debug', 'release')}
            for profile, path in inputs.items():
                self.write(path, self.report((profile,)))
            reports, hashes = load_profiles(inputs, self.head)
            self.assertEqual(set(reports), {'debug', 'release'})
            self.assertEqual(hashes, {profile: hashlib.sha256((path / 'RESULT.json').read_bytes()).hexdigest()
                                      for profile, path in inputs.items()})

    def test_split_rejects_mixed_source_producer_compiler_and_profile_before_public_verification(self):
        mutations = [
            ('source', lambda row: row['input'].update(source_commit='d' * 40)),
            ('digest', lambda row: row.update(input_sha256='d' * 64)),
            ('producer', lambda row: row['input'].update(sdk_commit='d' * 40)),
            ('schema', lambda row: row.update(schema=2)),
            ('compiler', lambda row: row.update(rustc=row['rustc'].replace('1.98.1', '1.98.0'))),
            ('wrong-profile', lambda row: row.update(profiles={'debug': {}})),
            ('extra-profile', lambda row: row['profiles'].update(debug={})),
            ('empty-profile', lambda row: row.update(profiles={})),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            debug, release, output = root / 'debug', root / 'release', root / 'review.json'
            self.write(debug, self.report(('debug',)))
            for name, mutate in mutations:
                with self.subTest(name=name):
                    changed = self.report(('release',))
                    mutate(changed)
                    self.write(release, changed)
                    with self.assertRaises(ValueError):
                        review_split(debug, release, output, self.head)
                    self.assertFalse(output.exists())

    def test_partial_duplicate_missing_or_swapped_profile_cannot_be_complete_review(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            debug, release, output = root / 'debug', root / 'release', root / 'review.json'
            self.write(debug, self.report(('debug',)))
            self.write(release, self.report(('release',)))
            for invoke in (
                lambda: review(debug, output, self.head),
                lambda: review_split(debug, debug, output, self.head),
                lambda: review_split(release, debug, output, self.head),
                lambda: load_profiles({'debug': debug}, self.head),
            ):
                with self.subTest(invoke=invoke), self.assertRaises(ValueError):
                    invoke()
                self.assertFalse(output.exists())
            with self.assertRaises(EvidenceIOError) as missing:
                review_split(debug, root / 'absent', output, self.head)
            self.assertIsInstance(missing.exception.__cause__, FileNotFoundError)
            self.assertFalse(output.exists())

    def test_matching_malformed_digest_does_not_authorize_a_pair(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for profile in ('debug', 'release'):
                report = self.report((profile,))
                report['input_sha256'] = 'not-a-digest'
                self.write(root / profile, report)
            output = root / 'review.json'
            with self.assertRaises(ValueError):
                review_split(root / 'debug', root / 'release', output, self.head)
            self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
