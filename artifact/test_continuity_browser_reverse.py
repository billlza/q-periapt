"""Mutate the actual bidirectional receipt at its recovery and effect boundaries."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import tempfile
import unittest
import zipfile

from continuity_browser_session_records import verify

ROOT=Path(__file__).resolve().parents[1]
EVIDENCE=ROOT/'research/sdk-alpha1/evidence/20261029-installed-browser-bidirectional'


class InstalledBrowserReverseConsumption(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.directory=Path(temporary.name).resolve(strict=True)
        manifest=json.loads((EVIDENCE/'CAPTURE.json').read_text())
        archive=EVIDENCE/'CAPTURE.zip'
        self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(),manifest['archive_sha256'])
        with zipfile.ZipFile(archive) as capture:
            self.assertEqual({i.filename for i in capture.infolist() if not i.is_dir()},set(manifest['members']))
            for item in capture.infolist():
                if item.is_dir():continue
                path=PurePosixPath(item.filename)
                self.assertFalse(path.is_absolute() or '..' in path.parts)
                self.assertLessEqual(item.file_size,1024*1024)
                data=capture.read(item)
                self.assertEqual(hashlib.sha256(data).hexdigest(),manifest['members'][item.filename]['sha256'])
                if path.parts[:2] != ('browser-native-bidirectional','public'):continue
                target=self.directory/Path(*path.parts[1:])
                target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
        self.public=self.directory/'public'
        self.report=json.loads((self.public/'RESULT.json').read_text())
        self.reverse=self.report['reverse_application']

    def test_actual_installed_bidirectional_receipt(self):
        verify(self.report,self.public)

    def test_legacy_forward_receipt_is_not_bidirectional_qualification(self):
        self.report['schema_version']=1
        with self.assertRaisesRegex(ValueError,'current transcript schema'):
            verify(self.report,self.public)

    def test_sender_cannot_infer_consumption_from_host_commit(self):
        self.reverse['before_retry']='Acknowledged'
        with self.assertRaisesRegex(ValueError,'sender inferred'):
            verify(self.report,self.public)

    def test_worker_cut_cannot_have_a_fabricated_ack(self):
        (self.public/'reverse/002.response').write_bytes((self.public/'reverse/001.response').read_bytes())
        with self.assertRaisesRegex(ValueError,'ACK was fabricated'):
            verify(self.report,self.public)

    def test_new_ciphertext_cannot_replace_original_native_retry(self):
        path=self.public/'reverse/002.request';raw=path.read_bytes()
        changed=raw[:-1]+bytes([raw[-1]^1]);path.write_bytes(changed)
        self.reverse['frames'][1]['request_sha256']=hashlib.sha256(changed).hexdigest()
        with self.assertRaisesRegex(ValueError,'retry replaced original'):
            verify(self.report,self.public)

    def test_retry_cannot_create_a_second_business_effect(self):
        row=self.reverse['steps']['retry']['effect'];row['applications']=2
        for effect in self.reverse['steps']['retry']['effects']:
            if effect['message']==row['message']:effect['applications']=2
        with self.assertRaisesRegex(ValueError,'host consumption or durable deduplication'):
            verify(self.report,self.public)

    def test_durable_callback_retry_cannot_be_omitted(self):
        row=self.reverse['steps']['retry']['effect'];row['calls']=1
        for effect in self.reverse['steps']['retry']['effects']:
            if effect['message']==row['message']:effect['calls']=1
        with self.assertRaisesRegex(ValueError,'host consumption or durable deduplication'):
            verify(self.report,self.public)

    def test_worker_lease_must_be_released_at_the_cut(self):
        self.reverse['steps']['cut']['leases'][-1]['count']=1
        with self.assertRaisesRegex(ValueError,'retained its original owner lease'):
            verify(self.report,self.public)

    def test_transport_failure_cannot_be_relabelled_success(self):
        command=next(r for r in self.reverse['commands'] if r['label']=='reverse-native-deliver-cut')
        command['exit']=command['expected_exit']=0
        with self.assertRaisesRegex(ValueError,'command did not execute as expected'):
            verify(self.report,self.public)


if __name__=='__main__':unittest.main()
