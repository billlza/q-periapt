"""Rejection controls against retained browser outputs and actual request bytes."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

import continuity_browser_records as records
import continuity_browser_creation as creation
import rust_sdk_profile as sdk


class BrowserEnrollmentRecordsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = sdk.ROOT / 'research/sdk-alpha1/evidence/20261013-browser-enrollment-creation/CAPTURE.zip'
        with zipfile.ZipFile(path) as archive:
            cls.creation = json.loads(archive.read('browser2/RESULT.json'))
            cls.late = json.loads(archive.read('late2/RESULT.json'))
            cls.failed_late = json.loads(archive.read('late1/RESULT.json'))
            cls.requests = {row['name']: archive.read('browser2/' + row['name'])
                            for row in cls.creation['captures']}

    def test_retained_real_records_and_failed_control(self):
        records.creation(self.creation)
        records.late(self.late)
        with self.assertRaises(ValueError):
            records.late(self.failed_late)

    def test_original_storage_and_request_cannot_be_substituted(self):
        for mutation in ('wrap', 'database', 'request', 'wrong-intent', 'extractable'):
            value = copy.deepcopy(self.creation)
            row = next(row for row in value['cases'] if row['case'] == 'ready-published')
            if mutation == 'wrap':
                row['after']['wrap_sha256'] = '00' * 32
            elif mutation == 'database':
                row['after']['database_id'] = '00' * 32
            elif mutation == 'request':
                row['reopened']['sha256'] = '00' * 32
            elif mutation == 'wrong-intent':
                row['wrong'] = 'accepted'
            else:
                row['before']['vault_extractable'] = True
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                records.creation(value)

    def test_real_cut_and_explicit_corruption_rejection_required(self):
        for name in records.CASES:
            value = copy.deepcopy(self.creation)
            value['cases'] = [row for row in value['cases'] if row['case'] != name]
            with self.subTest(missing=name), self.assertRaises(ValueError):
                records.creation(value)
        value = copy.deepcopy(self.creation)
        row = next(row for row in value['cases'] if row['case'] == 'delete-enrollment')
        row['unchanged'] = False
        with self.assertRaises(ValueError):
            records.creation(value)

    def test_caller_deadline_is_not_native_completion(self):
        for mutation in ('code', 'causes', 'concurrent', 'release_observations', 'elapsed_ms'):
            value = copy.deepcopy(self.late)
            value['cases'][0][mutation] = {
                'code': 'Closed', 'causes': ['OpenUnknown'], 'concurrent': 'accepted',
                'release_observations': [1], 'elapsed_ms': 1}[mutation]
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                records.late(value)

    def test_capture_hash_length_and_inventory_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, data in self.requests.items():
                (root / name).write_bytes(data)
            files = records.request_files(self.creation, root)
            self.assertEqual(len(files), 19)
            original = files[0].read_bytes()
            for data in (original[:-1], bytes([original[0] ^ 1]) + original[1:]):
                files[0].write_bytes(data)
                with self.assertRaises(ValueError):
                    records.request_files(self.creation, root)
            files[0].write_bytes(original)
            (root / 'extra.bin').write_bytes(original)
            with self.assertRaises(ValueError):
                records.request_files(self.creation, root)

    def test_cli_error_and_diagnostics_never_become_success(self):
        with self.assertRaises(ValueError):
            records.cli_result(b'### Error\ncommand failed')
        envelope = {'status': 'CONTINUITY_BROWSER_CREATION_PASS', 'diagnostics': ['uncaught error'],
                    'results': {'creation': self.creation, 'late': self.late}}
        with self.assertRaises(ValueError):
            records.cli_result(('### Result\n' + json.dumps(envelope)).encode())

    def test_installed_binding_rejects_repository_local_consumer(self):
        with tempfile.TemporaryDirectory(dir=sdk.ROOT / 'target') as directory:
            root = Path(directory).resolve()
            installed = root / 'node_modules' / creation.package.NAME
            installed.mkdir(parents=True)
            receipt = root / 'receipt.json'
            receipt.write_text(json.dumps({'installed': str(installed)}))
            with self.assertRaisesRegex(ValueError, 'not an external installation'):
                creation.installed_binding(receipt)

    def test_installed_binding_rejects_uncompleted_or_unbound_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            installed = root / 'node_modules' / creation.package.NAME
            installed.mkdir(parents=True)
            receipt = root / 'receipt.json'
            original = {'installed': str(installed), 'source_bound': True,
                        'sources_unchanged': True, 'installed_node_tests': 'passed'}
            for key, value in [('source_bound', False), ('sources_unchanged', False),
                               ('installed_node_tests', 'not-run')]:
                receipt.write_text(json.dumps({**original, key: value}))
                with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'receipt is incomplete'):
                    creation.installed_binding(receipt)


if __name__ == '__main__':
    unittest.main()
