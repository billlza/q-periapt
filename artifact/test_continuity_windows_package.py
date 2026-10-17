"""Reject archive substitution and checkout dependencies in the Windows input boundary."""
import copy
import hashlib
from pathlib import Path
import tempfile
import unittest

import continuity_package_archive as archive
from installed_rust_graph import verify_resolution


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


if __name__ == '__main__':
    unittest.main()
