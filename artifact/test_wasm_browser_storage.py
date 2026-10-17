"""Rejection controls over retained real browser records, not mocked storage."""
import copy
import json
from pathlib import Path
import unittest
import zipfile

import rust_sdk_profile as sdk
import wasm_browser_storage as browser


class BrowserStorageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = sdk.ROOT / 'research/sdk-alpha1/evidence/20261012-browser-policy-storage'
        cls.raw = {name: (cls.evidence / (name + '.stdout')).read_bytes()
                   for name in ('storage-acceptance.js', 'storage-quota-acceptance.js')}
        cls.core = browser.result(cls.raw['storage-acceptance.js'], 'BROWSER_POLICY_STORAGE_PASS')
        cls.quota = browser.result(cls.raw['storage-quota-acceptance.js'], 'BROWSER_POLICY_QUOTA_PASS')

    def check_rejected(self, value, marker):
        with self.assertRaises(ValueError):
            browser.result(('### Result\n' + json.dumps(value) + '\n### Ran Playwright code\n').encode(), marker)

    def test_complete_actual_capture(self):
        receipt = json.loads((self.evidence / 'BROWSER_STORAGE.json').read_text())
        self.assertIs(receipt['completed'], True)
        self.assertEqual(receipt['storage-acceptance.js'], self.core)
        self.assertEqual(receipt['storage-quota-acceptance.js'], self.quota)

    def test_worker_cut_and_release_observation_required(self):
        for mutation in ('missing-cut', 'held-lease'):
            value = copy.deepcopy(self.core)
            selected = next(row for row in value['cases'] if row['command'] == 'Worker-termination')
            if mutation == 'missing-cut':
                value['cases'].remove(selected)
            else:
                selected['leaseObservations'][-1]['remaining'] = 1
            with self.subTest(mutation=mutation):
                self.check_rejected(value, 'BROWSER_POLICY_STORAGE_PASS')

    def test_actual_crypto_abort_and_close_race_required(self):
        for command in ('crypto', 'abort', 'close-update'):
            value = copy.deepcopy(self.core)
            value['cases'].remove(next(row for row in value['cases'] if row['command'] == command))
            with self.subTest(command=command):
                self.check_rejected(value, 'BROWSER_POLICY_STORAGE_PASS')

    def test_quota_pressure_scopes_and_all_failures_required(self):
        for mutation in ('no-quota', 'nonempty-origin', 'missing-reopen', 'wrong-pressure', 'changed-state', 'live-owner'):
            value = copy.deepcopy(self.quota)
            if mutation == 'no-quota':
                value['contexts'][0]['constrained']['overrideActive'] = False
            elif mutation == 'nonempty-origin':
                value['contexts'][0]['initialUsage']['usage'] = 1
            elif mutation == 'wrong-pressure':
                value['pressurePattern'] = 'zero-filled'
            else:
                if mutation == 'missing-reopen':
                    row = next(row for row in value['results'] if row['scenario'] == 'creation-reopen' and row['command'] == 'open')
                    row['code'] = 'Storage'
                elif mutation == 'changed-state':
                    row = next(row for row in value['results'] if row['scenario'] == 'replacement' and row['command'] == 'open')
                    row['state'] = '00' * 36
                else:
                    row = next(row for row in value['results'] if row['scenario'] == 'replacement' and row['command'] == 'state')
                    row['code'] = 'Busy'
            with self.subTest(mutation=mutation):
                self.check_rejected(value, 'BROWSER_POLICY_QUOTA_PASS')

    def test_failed_or_diagnostic_output_is_not_a_pass(self):
        for marker, source in [('BROWSER_POLICY_STORAGE_PASS', self.core), ('BROWSER_POLICY_QUOTA_PASS', self.quota)]:
            value = copy.deepcopy(source)
            value['diagnostics'] = ['uncaught storage error']
            self.check_rejected(value, marker)
        with self.assertRaises(ValueError):
            browser.result(b'### Error\nfailed', 'BROWSER_POLICY_STORAGE_PASS')

    def test_ci_executes_browser_before_minimum_node_consumer(self):
        from test_proof_to_byte_release import extract_workflow_job
        job = extract_workflow_job((sdk.ROOT / '.github/workflows/ci.yml').read_text(), 'bindings-wasm')
        self.assertIn('@playwright/cli@0.1.22', job)
        self.assertIn('artifact/wasm_browser_storage.py', job)
        self.assertIn('--receipt target/sdk-wasm-package/INSTALLED_CONSUMER.json', job)
        self.assertIn('target/sdk-wasm-browser/*.json', job)
        self.assertLess(job.index('artifact/wasm_browser_storage.py'), job.index('node-version: "24.0.0"'))
        self.assertNotIn('continue-on-error:', job)

    def test_native_receipt_deadline_capture_and_rejections(self):
        evidence = sdk.ROOT / 'research/sdk-alpha1/evidence/20261013-browser-policy-receipts'
        with zipfile.ZipFile(evidence / 'CAPTURE.zip') as archive:
            raw = archive.read('qualification/storage-deadline-acceptance.js.stdout')
            red = json.loads(archive.read('red/RESULT.json'))
        marker = 'BROWSER_POLICY_DEADLINE_PASS'
        current = browser.result(raw, marker)
        self.assertIs(current['held_until_receipt'], True)
        red.update(status=marker, diagnostics=[])
        self.check_rejected(red, marker)
        for mutation in ('missing-open', 'early-owner', 'no-close-receipt', 'early-deadline',
                         'missing-state', 'wrong-state', 'live-owner'):
            value = copy.deepcopy(current)
            transaction, opening = value['cases']
            if mutation == 'missing-open':
                value['cases'].remove(opening)
            elif mutation == 'early-owner':
                transaction['early_owner_admitted'] = True
            elif mutation == 'no-close-receipt':
                opening['cleanup'] = ['OpenUnknown']
            elif mutation == 'early-deadline':
                transaction['elapsed_ms'] = 0
            elif mutation == 'missing-state':
                del opening['before'], opening['after']
            elif mutation == 'wrong-state':
                opening['after'] = transaction['after']
            else:
                transaction['closed_error'] = 'Busy'
            with self.subTest(mutation=mutation):
                self.check_rejected(value, marker)


if __name__ == '__main__':
    unittest.main()
