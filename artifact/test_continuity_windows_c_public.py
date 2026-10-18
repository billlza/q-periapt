"""Public C exports must replay, omit private stores and reject substitutions."""
import copy
from pathlib import Path
import tempfile
import unittest

import continuity_windows_c_public as public
from test_continuity_c_consumer import STDOUT, evidence
from test_continuity_c_account import STDOUT as ACCOUNT_STDOUT, fixture as account_fixture


class CPublicExportTests(unittest.TestCase):
    def test_account_count_is_not_a_file_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / 'source'
            source.mkdir()
            account_fixture(source)
            target = base / 'export'
            receipt = public.capture_case('account', ACCOUNT_STDOUT, source, target)
            checked = public.review_case('account', ACCOUNT_STDOUT, target, receipt)
            self.assertEqual(checked['application_readbacks'], 5)
            self.assertEqual(len(checked['command_logs']), 62)

    def test_export_replays_original_reader_without_private_store(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / 'source'
            source.mkdir()
            evidence(source)
            (source / 'initiator/private-store').write_bytes(b'not public')
            target = base / 'export'
            receipt = public.capture_case('client', STDOUT, source, target)
            self.assertEqual(public.review_case('client', STDOUT, target, receipt), receipt['verification'])
            self.assertFalse((target / 'initiator/private-store').exists())
            (target / 'initiator/private-store').write_bytes(b'unexpected')
            with self.assertRaisesRegex(ValueError, 'inventory differs'):
                public.review_case('client', STDOUT, target, receipt)

    def test_changed_message_and_forged_receipt_cannot_replace_contract(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / 'source'
            source.mkdir()
            evidence(source)
            target = base / 'export'
            receipt = public.capture_case('client', STDOUT, source, target)
            name = next(name for name in receipt['files'] if '/application-' in name)
            changed = target / name
            changed.write_bytes(changed.read_bytes()[:-1] + b'!')
            with self.assertRaisesRegex(ValueError, 'bytes changed'):
                public.review_case('client', STDOUT, target, receipt)
            forged = copy.deepcopy(receipt)
            item = public.sdk.snapshot(changed)
            forged['files'][name] = {'sha256': item.sha256, 'bytes': item.size}
            with self.assertRaisesRegex(ValueError, 'application readback differs'):
                public.review_case('client', STDOUT, target, forged)

    def test_missing_command_or_skipped_execution_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / 'source'
            source.mkdir()
            evidence(source)
            target = base / 'export'
            receipt = public.capture_case('client', STDOUT, source, target)
            with self.assertRaisesRegex(ValueError, 'not executed completely'):
                public.review_case('client', STDOUT.replace(b'0 ignored', b'1 ignored'), target, receipt)
            (target / 'initiator/c-self-check.stdout').unlink()
            with self.assertRaisesRegex(ValueError, 'inventory differs'):
                public.review_case('client', STDOUT, target, receipt)


if __name__ == '__main__':
    unittest.main()
