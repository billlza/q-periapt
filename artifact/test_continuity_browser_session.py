"""The real transcript must retain process, message, package and failure boundaries."""
import copy
import hashlib
import json
from pathlib import Path, PurePosixPath
import tempfile
import unittest
import zipfile

from continuity_browser_session_records import verify_forward as verify

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'research/sdk-alpha1/evidence/20261029-installed-browser-native-session'


class InstalledBrowserNativeSession(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        manifest = json.loads((EVIDENCE / 'STRICT_CAPTURE.json').read_text())
        archive = EVIDENCE / 'STRICT_CAPTURE.zip'
        self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), manifest['archive_sha256'])
        with zipfile.ZipFile(archive) as capture:
            self.assertEqual(len(capture.infolist()), len(manifest['members']))
            self.assertEqual(set(capture.namelist()), set(manifest['members']))
            for item in capture.infolist():
                path = PurePosixPath(item.filename)
                self.assertFalse(path.is_absolute() or '..' in path.parts)
                self.assertLessEqual(item.file_size, 1024 * 1024)
                if path.parts[0] != 'public':
                    continue
                data = capture.read(item)
                self.assertEqual(hashlib.sha256(data).hexdigest(), manifest['members'][item.filename]['sha256'])
                target = self.root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
        self.public = self.root / 'public'
        self.report = json.loads((self.public / 'RESULT.json').read_text())

    def test_actual_installed_browser_transcript(self):
        verify(self.report, self.public)

    def test_new_journal_or_session_cannot_replace_recovery(self):
        for key in ('journal', 'session'):
            changed = copy.deepcopy(self.report)
            changed['after_restart'][key][0] ^= 1
            with self.subTest(key=key), self.assertRaises(ValueError):
                verify(changed, self.public)

    def test_acknowledged_before_retry_cannot_replace_unknown_delivery(self):
        changed = copy.deepcopy(self.report)
        changed['after_restart']['before'] = 3
        with self.assertRaises(ValueError):
            verify(changed, self.public)

    def test_process_close_or_same_pid_cannot_replace_sigkill_restart(self):
        for key, value in (('exit', 0), ('pid', self.report['native_second']['pid'])):
            changed = copy.deepcopy(self.report)
            changed['native_first'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                verify(changed, self.public)

    def test_missing_or_changed_original_wire_is_rejected(self):
        path = self.public / '007.request'
        original = path.read_bytes()
        path.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
        with self.assertRaises(ValueError):
            verify(self.report, self.public)

    def test_replaced_error_or_skipped_command_is_rejected(self):
        changed = copy.deepcopy(self.report)
        changed['before_restart']['failure']['code'] = 'InvalidInput'
        with self.assertRaises(ValueError):
            verify(changed, self.public)
        changed = copy.deepcopy(self.report)
        changed['commands'].pop()
        with self.assertRaises(ValueError):
            verify(changed, self.public)

    def test_native_effect_readback_is_required(self):
        (self.public / 'effect-lost.bin').write_bytes(b'an unrelated delivery')
        with self.assertRaises(ValueError):
            verify(self.report, self.public)

    def test_coordinated_identity_substitution_cannot_replace_captured_identity(self):
        for key in ('journal', 'session'):
            changed = copy.deepcopy(self.report)
            changed['before_restart'][key][0] ^= 1
            changed['after_restart'][key][0] ^= 1
            with self.subTest(key=key), self.assertRaises(ValueError):
                verify(changed, self.public)

    def test_report_message_ids_must_match_captured_browser_results(self):
        for phase, key in (('before_restart', 'first'), ('before_restart', 'lost'),
                           ('after_restart', 'last')):
            changed = copy.deepcopy(self.report)
            changed[phase][key][0] ^= 1
            with self.subTest(key=key), self.assertRaises(ValueError):
                verify(changed, self.public)

    def test_report_lease_observations_cannot_be_rewritten(self):
        changed = copy.deepcopy(self.report)
        changed['after_restart']['leases'][-1]['elapsed_ms'] += 1
        with self.assertRaises(ValueError):
            verify(changed, self.public)

    def test_hash_bound_browser_output_must_be_one_successful_matching_phase(self):
        path = self.public / 'logs/browser-activate.stdout'
        original = path.read_bytes()
        text = original.decode()
        value = json.loads(text.split('### Result\n', 1)[1].split('\n### ', 1)[0])
        wrong_phase = copy.deepcopy(value)
        wrong_phase['phase'] = 'resume'
        wrong_status = copy.deepcopy(value)
        wrong_status['status'] = 'FAILED'
        changed_result = copy.deepcopy(value)
        changed_result['result']['journal'][0] ^= 1
        bodies = [b'no result\n', original + b'\n### Result\n{}',
                  original + b'\n### Error\noperation failed']
        bodies += [('### Result\n' + json.dumps(item)).encode()
                   for item in (wrong_phase, wrong_status, changed_result)]
        try:
            for body in bodies:
                path.write_bytes(body)
                changed = copy.deepcopy(self.report)
                row = next(row for row in changed['commands'] if row['label'] == 'browser-activate')
                row['stdout_sha256'] = hashlib.sha256(body).hexdigest()
                with self.subTest(body=body[:80]), self.assertRaises(ValueError):
                    verify(changed, self.public)
        finally:
            path.write_bytes(original)

    def test_ci_executes_the_installed_session_workload(self):
        workflow = (ROOT / '.github/workflows/ci.yml').read_text()
        job = workflow.split('  bindings-wasm:\n', 1)[1].split('\n  fuzz:', 1)[0]
        step = job.split('      - name: Exercise installed browser communication and complete native process restart\n', 1)[1].split('\n      - name:', 1)[0]
        self.assertIn('sh artifact/python-run.sh artifact/continuity_browser_session.py', step)
        self.assertIn('--receipt target/sdk-wasm-package/INSTALLED_CONSUMER.json', step)
        self.assertIn('--provider-root "$RUNNER_TEMP/browser-native-provider"', step)
        self.assertIn('target/browser-native-session/public/', job)


if __name__ == '__main__':
    unittest.main()
