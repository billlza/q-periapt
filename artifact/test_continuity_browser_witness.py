"""Mutation checks against captured installed required-Witness browser execution."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import tempfile
import unittest
import zipfile

from continuity_browser_session_records import verify

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'research/sdk-alpha1/evidence/20261029-installed-browser-required-witness'


class InstalledBrowserWitness(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.public = Path(temporary.name).resolve(strict=True)
        manifest = json.loads((EVIDENCE / 'CAPTURE.json').read_text())
        archive = EVIDENCE / 'CAPTURE.zip'
        self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), manifest['archive_sha256'])
        with zipfile.ZipFile(archive) as capture:
            self.assertEqual({i.filename for i in capture.infolist() if not i.is_dir()}, set(manifest['members']))
            for item in capture.infolist():
                if item.is_dir(): continue
                path = PurePosixPath(item.filename)
                self.assertFalse(path.is_absolute() or '..' in path.parts)
                self.assertLessEqual(item.file_size, 2 * 1024 * 1024)
                data = capture.read(item)
                self.assertEqual(hashlib.sha256(data).hexdigest(), manifest['members'][item.filename]['sha256'])
                if path.parts[:2] != ('release', 'public'): continue
                target = self.public / Path(*path.parts[2:])
                target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(data)
        self.report = json.loads((self.public / 'RESULT.json').read_text())
        self.witness = self.report['required_witness']

    def rejects(self, message):
        with self.assertRaisesRegex(ValueError, message): verify(self.report, self.public)

    def test_actual_installed_required_witness_receipt(self):
        verify(self.report, self.public)

    def test_local_profile_does_not_qualify_required_witness(self):
        self.report['policy_profile'] = 'local'
        self.rejects('required witness profile')

    def test_unreported_native_build_profile_is_rejected(self):
        del self.report['native_build_profile']
        self.rejects('native witness build profile')

    def test_missing_witness_cannot_leave_an_open_owner(self):
        self.witness['missing']['failure']['closed'] = False
        self.rejects('live or downgraded owner')

    def test_activating_installation_cannot_recreate_genesis(self):
        self.report['before_restart']['activation_resume']['phase'] = 2
        # Keep the raw phase and its hash-bound summary coherent, so this
        # mutation reaches the durable-selection check it is meant to test.
        path = self.public / 'logs/browser-activate.stdout'
        text = path.read_text()
        prefix, result = text.split('### Result\n', 1)
        body, separator, suffix = result.partition('\n### ')
        value = json.loads(body)
        value['result']['activation_resume']['phase'] = 2
        data = (prefix + '### Result\n' + json.dumps(value) + separator + suffix).encode()
        path.write_bytes(data)
        row = next(row for row in self.report['commands'] if row['label'] == 'browser-activate')
        row['stdout_sha256'] = hashlib.sha256(data).hexdigest()
        self.rejects('durable selection')

    def test_wrong_genesis_cannot_be_relabelled_enrolled(self):
        self.witness['browser_enrollment']['head'][0] ^= 1
        self.rejects('separate browser genesis approval')

    def test_witness_process_restart_cannot_be_a_reused_pid(self):
        self.witness['services'][2]['pid'] = self.witness['services'][1]['pid']
        self.rejects('process restart')

    def test_witness_key_replacement_is_rejected(self):
        name = next(iter(self.witness['key_hashes_after']))
        self.witness['key_hashes_after'][name] = '00' * 32
        self.rejects('identity or keys')

    def test_offline_http_failure_must_match_actual_browser_capture(self):
        path = self.public / 'witness-offline.json'; value = json.loads(path.read_text())
        value['http_errors'] = []; path.write_text(json.dumps(value))
        self.rejects('actual browser output')

    def test_no_receipt_cannot_be_relabelled_authenticated_denial(self):
        row = next(r for r in self.witness['frames'] if r['result'] == 'no-reply')
        row['result'] = 'verified-reply'
        self.rejects('unenrolled|response|receipt|reply')

    def test_witness_signature_capture_cannot_be_changed(self):
        row = next(r for r in self.witness['frames'] if r['result'] == 'verified-reply')
        path = self.public / f"witness-{row['sequence']:03}.response"
        raw = path.read_bytes(); path.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
        self.rejects('response|reply')


if __name__ == '__main__': unittest.main()
