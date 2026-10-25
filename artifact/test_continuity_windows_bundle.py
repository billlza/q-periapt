"""A multi-package closure retains per-component and whole-archive bounds."""
import hashlib
import io
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import continuity_package_archive as archive
import continuity_windows_bundle as windows


def cohort():
    versions = {name: windows.SDK_VERSION for name in windows.CONSUMER_CRATES}
    versions[windows.NAME] = windows.CANDIDATE_VERSION
    limits = windows.components(versions)
    files = {prefix + 'Cargo.toml': b'fixture' for prefix in limits if prefix}
    files['client.c'] = b'fixture, not executed C'
    return versions, limits, files


def raw_archive(files):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as z:
        for name, value in files.items():
            entry = zipfile.ZipInfo(name)
            entry.create_system = 3
            entry.external_attr = (stat.S_IFREG | 0o644) << 16
            z.writestr(entry, value)
    return buffer.getvalue()


def hashes(files):
    return {name: hashlib.sha256(value).hexdigest() for name, value in files.items()}


class WindowsBundleTests(unittest.TestCase):
    def test_cohort_above_single_package_bound_preserves_every_member(self):
        _, limits, files = cohort()
        # Reproduce the 1040-file aggregate boundary without dropping any source.
        first, second = [p for p in limits if p][:2]
        for i in range(600): files[first + f'src/{i}.rs'] = b'first component'
        for i in range(1040 - len(files)): files[second + f'src/{i}.rs'] = b'second component'
        self.assertEqual(len(files), 1040)
        with self.assertRaisesRegex(ValueError, 'member count exceeds bound'):
            archive.archive(files)
        payload = archive.archive(files, components=limits)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(ValueError, 'member count exceeds bound'):
                archive.unpack(payload, hashes(files), root/'single')
            self.assertFalse((root/'single').exists())
            archive.unpack(payload, hashes(files), root/'cohort', components=limits)
            actual = {p.relative_to(root/'cohort').as_posix(): p.read_bytes() for p in (root/'cohort').rglob('*') if p.is_file()}
            self.assertEqual(actual, files)

    def assert_rejected(self, files, limits, message):
        with self.assertRaisesRegex(ValueError, message):
            archive.archive(files, components=limits)
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory)/'output'
            with self.assertRaisesRegex(ValueError, message):
                archive.unpack(raw_archive(files), hashes(files), destination, components=limits)
            self.assertFalse(destination.exists())

    def test_each_crate_retains_the_1024_member_limit(self):
        _, limits, files = cohort(); prefix = next(p for p in limits if p)
        for i in range(1024): files[prefix + f'{i}.rs'] = b''
        self.assert_rejected(files, limits, 'component member count')

    def test_facade_is_bounded_separately(self):
        _, limits, files = cohort()
        for i in range(256): files[f'{i}.c'] = b''
        self.assert_rejected(files, limits, 'component member count')

    def test_missing_and_unknown_packages_are_rejected(self):
        _, limits, files = cohort(); first = next(p for p in limits if p)
        absent = dict(files); del absent[first+'Cargo.toml']
        self.assert_rejected(absent, limits, 'component member count')
        files['packages/unexpected-0.0.0/src.rs'] = b''
        self.assert_rejected(files, limits, 'unknown component')

    def test_mixed_or_extra_versions_cannot_select_another_cohort(self):
        versions, _, _ = cohort()
        for bad in (dict(versions, **{windows.NAME: 'other'}), dict(versions, foreign='0.0.0'), {}, []):
            with self.assertRaises(ValueError): windows.components(bad)

    def test_component_policy_itself_is_bounded_and_unambiguous(self):
        for limits in ({'': True}, {'': 1025}, {'': 0}, {'../': 1},
                       {'packages/': 1, 'packages/crate/': 1}, {f'{i}/': 1 for i in range(17)}):
            with self.assertRaises(ValueError): archive.archive({'file': b''}, components=limits)

    def test_total_expanded_size_still_applies_to_the_whole_cohort(self):
        _, limits, files = cohort(); files['client.c'] = b'x' * 128
        with patch.object(archive, 'MAX_PACKAGE', 100):
            with self.assertRaisesRegex(ValueError, 'expanded package'):
                archive.archive(files, components=limits)
        self.assertEqual(archive.MAX_PACKAGE, 64 * 1024**2)

    def test_hash_inventory_and_path_checks_still_precede_any_output(self):
        _, limits, files = cohort(); payload = archive.archive(files, components=limits)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            altered = hashes(files); altered['client.c'] = '0' * 64
            for index, expected in enumerate((altered, {k:v for k,v in altered.items() if k!='client.c'})):
                with self.assertRaises(ValueError): archive.unpack(payload, expected, root/str(index), components=limits)
                self.assertFalse((root/str(index)).exists())
            files['../escape'] = b'bad'
            with self.assertRaisesRegex(ValueError, 'canonical'):
                archive.unpack(raw_archive(files), hashes(files), root/'traversal', components=limits)
            self.assertFalse((root/'traversal').exists())
            self.assertFalse((root/'escape').exists())
