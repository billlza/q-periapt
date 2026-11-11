"""Transport controls for the fixed retained database; local input is not a fallback."""

from contextlib import ExitStack, contextmanager
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import codeql_summary_control as control
from test_codeql_summary_control import archive_bytes, database_members, digest, zip_member


class LocalArchiveInputTests(unittest.TestCase):
    @contextmanager
    def fixture(self):
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            root = Path(temporary)
            inner = archive_bytes(database_members())
            outer = archive_bytes([zip_member(control.INNER_MEMBER, inner)])
            source = dict(control.SOURCE, artifact_bytes=len(outer), artifact_sha256=digest(outer))
            stack.enter_context(patch.object(control, 'SOURCE', source))
            stack.enter_context(patch.object(control, 'INNER_BYTES', len(inner)))
            stack.enter_context(patch.object(control, 'INNER_SHA256', digest(inner)))
            inventory = control.restore_database(io.BytesIO(inner), root / 'reference')
            identity = control.input_identity(inventory)
            stack.enter_context(patch.object(control, 'INPUT_IDENTITY', identity))
            local = root / 'source.zip'
            local.write_bytes(outer)
            yield root, local, outer, identity

    def output(self, root, name):
        path = root / name
        path.mkdir()
        (path / 'evidence').mkdir()
        return path

    def test_explicit_local_and_default_transfer_restore_identical_inputs(self):
        with self.fixture() as (root, local, outer, expected):
            first = self.output(root, 'local')
            with patch.object(control, 'download', side_effect=AssertionError('local input must not download')):
                _, first_identity = control.prepare_database(first, retained_archive=local)
            second = self.output(root, 'network')
            with patch.object(control, 'download', side_effect=lambda path: path.write_bytes(outer)) as download:
                _, second_identity = control.prepare_database(second)
            download.assert_called_once_with(second / 'diagnostics.zip')
            self.assertEqual(first_identity, expected)
            self.assertEqual(second_identity, expected)
            self.assertEqual(local.read_bytes(), outer)
            first_receipt = json.loads((first / 'evidence/SOURCE_TRANSPORT.json').read_text())
            second_receipt = json.loads((second / 'evidence/SOURCE_TRANSPORT.json').read_text())
            self.assertEqual(first_receipt.pop('transport'), 'local_archive')
            self.assertEqual(second_receipt.pop('transport'), 'github_artifact')
            self.assertEqual(first_receipt, second_receipt)
            self.assertFalse((first / 'diagnostics.zip').exists())

    def test_wrong_bytes_reject_before_parsing_without_network_fallback(self):
        with self.fixture() as (root, local, outer, _):
            local.write_bytes(bytes([outer[0] ^ 1]) + outer[1:])
            output = self.output(root, 'wrong')
            with patch.object(control, 'download', side_effect=AssertionError('no fallback')) as download, \
                 patch.object(control.zipfile, 'ZipFile', side_effect=AssertionError('must authenticate first')):
                with self.assertRaisesRegex(control.ControlError, 'outer artifact identity differs'):
                    control.prepare_database(output, retained_archive=local)
            download.assert_not_called()
            self.assertFalse((output / 'retained-database.zip').exists())
            self.assertFalse((output / 'evidence/SOURCE_TRANSPORT.json').exists())

    def test_missing_or_symlink_source_rejects_without_network_fallback(self):
        with self.fixture() as (root, local, _, _):
            link = root / 'source-link.zip'
            link.symlink_to(local)
            for number, source in enumerate([link, root / 'missing.zip']):
                with self.subTest(source=source.name):
                    output = self.output(root, 'invalid-' + str(number))
                    with patch.object(control, 'download', side_effect=AssertionError('no fallback')) as download:
                        with self.assertRaises((control.ControlError, OSError)):
                            control.prepare_database(output, retained_archive=source)
                    download.assert_not_called()
                    self.assertFalse((output / 'database').exists())

    def test_authenticated_outer_still_requires_exact_inner_identity(self):
        with self.fixture() as (root, local, _, _):
            output = self.output(root, 'inner-mismatch')
            with patch.object(control, 'INNER_SHA256', '0' * 64):
                with self.assertRaisesRegex(control.ControlError, 'retained database ZIP identity differs'):
                    control.prepare_database(output, retained_archive=local)
            self.assertFalse((output / 'database').exists())
            self.assertFalse((output / 'evidence/SOURCE_TRANSPORT.json').exists())

    def test_authenticated_archives_still_require_complete_database_inventory(self):
        with self.fixture() as (root, local, _, expected):
            output = self.output(root, 'inventory-mismatch')
            wrong = dict(expected, cache_inventory_sha256='0' * 64)
            with patch.object(control, 'INPUT_IDENTITY', wrong):
                with self.assertRaisesRegex(control.ControlError, 'database/cache/result inventory differs'):
                    control.prepare_database(output, retained_archive=local)
            self.assertTrue((output / 'evidence/DATABASE_INPUTS.json').exists())
            self.assertFalse((output / 'evidence/SOURCE_TRANSPORT.json').exists())


if __name__ == '__main__':
    unittest.main()
