"""Public C exports must replay, omit private stores and reject substitutions."""
import copy
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import continuity_windows_c_public as public
from test_continuity_c_consumer import STDOUT, evidence
from test_continuity_c_account import STDOUT as ACCOUNT_STDOUT, fixture as account_fixture


class CPublicExportTests(unittest.TestCase):
    def test_non_posix_import_does_not_enable_process_management(self):
        # A fresh interpreter avoids a cached POSIX module concealing the
        # Windows import failure. No child command may be launched by it.
        script = '''
import os, signal, subprocess, sys
sys.path.insert(0, sys.argv[1])
os.name = "nt"
if hasattr(signal, "SIGHUP"):
    del signal.SIGHUP
import bounded_process
def forbidden(*args, **kwargs):
    raise AssertionError("unsupported process launch attempted")
subprocess.Popen = forbidden
try:
    bounded_process.capture_output([sys.executable, "-c", "pass"], timeout_seconds=1,
                                  maximum_stdout_bytes=100, maximum_stderr_bytes=100)
except bounded_process.BoundedProcessError as error:
    assert error.kind == "start" and "POSIX host" in str(error)
else:
    raise AssertionError("unsupported operation accepted")
'''
        result = subprocess.run([sys.executable, '-I', '-B', '-c', script,
                                 str(Path(__file__).resolve().parent)],
                                capture_output=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stdout, b'')

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
            log = source / 'initiator/c-self-check.stdout'
            log.write_bytes(b'self-check-passed\r\n')
            with self.assertRaisesRegex(ValueError, 'command output or diagnostic differs'):
                public.capture_case('client', STDOUT, source, base / 'crlf-refused')
            self.assertFalse((base / 'crlf-refused').exists())
            (target / 'initiator/c-self-check.stdout').unlink()
            with self.assertRaisesRegex(ValueError, 'inventory differs'):
                public.review_case('client', STDOUT, target, receipt)


if __name__ == '__main__':
    unittest.main()
