"""Transport evidence rejects real failures without trusting a server-only 200.

Chromium no-store streams can reach EOF while DevTools reports ERR_ABORTED:
https://github.com/microsoft/playwright/issues/42742
The installed-SDK fragmented-response regression reproduces this observation.
These mutations require actual client completion plus the exact signed reply;
changing cache policy, unbounded arrayBuffer reads, and blanket error filtering
are not substitutes for that evidence.
"""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from continuity_browser_session_records import transport_requests

ROOT = Path(__file__).resolve().parents[1]


class TransportEvidence(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.public = Path(temporary.name)
        self.origin = 'http://127.0.0.1:12345'
        self.request, self.reply = b'r' * 3674, b's' * 3659
        self.request_sha = hashlib.sha256(self.request).hexdigest()
        self.reply_sha = hashlib.sha256(self.reply).hexdigest()
        (self.public / 'witness-001.request').write_bytes(self.request)
        (self.public / 'witness-001.response').write_bytes(self.reply)
        self.frames = [{'sequence': 1, 'request_sha256': self.request_sha,
                        'response_sha256': self.reply_sha, 'http_status': 200,
                        'request_dual_signature_verified': True, 'reply_dual_signature_verified': True,
                        'result': 'verified-reply', 'phase': 'normal'}]
        self.receipt = {'url': self.origin + '/witness', 'request_sha256': self.request_sha,
                        'request_bytes': 3674, 'response_sha256': self.reply_sha,
                        'response_bytes': 3659, 'result': 'fulfilled'}
        event = {'url': self.origin + '/witness', 'failure': {'errorText': 'net::ERR_ABORTED'}}
        self.value = {'phase': 'activate', 'transport_receipts': [self.receipt], 'requests': [event],
                      'request_diagnostics': [{**event, 'response_status': 200, 'body_hex': self.request.hex()}]}

    def read(self, value=None):
        return transport_requests(self.value if value is None else value, self.public, self.origin, self.frames)

    def test_exact_fulfilled_reply_explains_only_its_original_observer_event(self):
        original = copy.deepcopy(self.value)
        self.assertEqual(self.read(), [])
        self.assertEqual(self.value, original, 'raw failure evidence was modified')

    def test_server_success_without_client_completion_refuses(self):
        for receipts in ([], None, [{k:v for k,v in self.receipt.items() if not k.startswith('response_')}
                                    | {'result': 'rejected', 'error_code': 'Cancelled'}]):
            value = copy.deepcopy(self.value); value['transport_receipts'] = receipts
            with self.subTest(receipts=receipts), self.assertRaises(ValueError):
                self.read(value)

    def test_wrong_response_length_digest_or_origin_refuses(self):
        for key, value in (('response_bytes', 1800), ('response_bytes', True),
                           ('response_sha256', '00' * 32), ('request_sha256', '00' * 32),
                           ('url', 'http://example.invalid/witness')):
            changed = copy.deepcopy(self.value); changed['transport_receipts'][0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): self.read(changed)

    def test_changed_server_bytes_or_missing_signature_verification_refuses(self):
        for key in ('request_dual_signature_verified', 'reply_dual_signature_verified'):
            self.frames[0][key] = False
            with self.subTest(key=key), self.assertRaises(ValueError): self.read()
            self.frames[0][key] = True
        (self.public / 'witness-001.response').write_bytes(b'x' * 3659)
        with self.assertRaises(ValueError): self.read()

    def test_duplicate_client_or_observer_receipts_refuse(self):
        for client in (True, False):
            value = copy.deepcopy(self.value)
            if client: value['transport_receipts'] *= 2
            else:
                value['requests'] *= 2; value['request_diagnostics'] *= 2
            with self.subTest(client=client), self.assertRaises(ValueError): self.read(value)

    def test_other_errors_http_failures_and_unrelated_requests_are_retained(self):
        for url, error, status in ((self.origin + '/witness', 'net::ERR_FAILED', 200),
                                   (self.origin + '/other', 'net::ERR_ABORTED', 200),
                                   (self.origin + '/witness', 'net::ERR_ABORTED', 503)):
            value = copy.deepcopy(self.value)
            event = {'url': url, 'failure': {'errorText': error}}
            value['requests'] = [event]
            value['request_diagnostics'] = [{**event, 'response_status': status, 'body_hex': self.request.hex()}]
            self.assertEqual(self.read(value), [event])

    def test_wrong_event_body_or_missing_details_refuse(self):
        changed = copy.deepcopy(self.value); changed['request_diagnostics'][0]['body_hex'] = (b'x' * 3674).hex()
        with self.assertRaises(ValueError): self.read(changed)
        changed['request_diagnostics'] = []
        with self.assertRaises(ValueError): self.read(changed)

    def test_real_lost_peer_reply_cannot_be_explained_by_witness_receipt(self):
        value = copy.deepcopy(self.value)
        event = {'url': self.origin + '/exchange/drop-once', 'failure': {'errorText': 'net::ERR_EMPTY_RESPONSE'}}
        value['requests'].append(event); value['request_diagnostics'].append({**event, 'response_status': None})
        self.assertEqual(self.read(value), [event])


class ObserverContract(unittest.TestCase):
    def test_original_promise_and_rejection_survive_observation_and_observer_errors_fail(self):
        source = (ROOT / 'research/continuity-reference-app/tests/browser_session/transport-receipts.js').read_text()
        source = source.replace("import {HttpExchange} from '/pkg/bounded-fetch.js';", 'const HttpExchange = globalThis.TestExchange;')
        script = r'''
const assert = require('node:assert/strict');
const {createHash} = require('node:crypto');
const source = JSON.parse(require('node:fs').readFileSync(0,'utf8'));
class Exchange {
  static start() {return new Exchange();}
  reply() {return this.promise;}
}
globalThis.TestExchange = Exchange;
(async () => {
  const {takeTransportReceipts} = await import('data:text/javascript;base64,'+Buffer.from(source).toString('base64'));
  const request=new Uint8Array(3674), response=new Uint8Array(3659);
  const good=Exchange.start('http://127.0.0.1:1/witness',request,10000,()=>false,1);
  good.promise=Promise.resolve(response);assert.strictEqual(good.reply(),good.promise);
  assert.strictEqual(await good.promise,response);
  let rows=await takeTransportReceipts();assert.equal(rows.length,1);assert.equal(rows[0].result,'fulfilled');
  assert.equal(rows[0].response_sha256,createHash('sha256').update(response).digest('hex'));
  const bad=Exchange.start('http://127.0.0.1:1/witness',request,10000,()=>false,1);
  const failure=Object.assign(new Error('original cancellation'),{code:'Cancelled'});
  bad.promise=Promise.reject(failure);assert.strictEqual(bad.reply(),bad.promise);
  await assert.rejects(bad.promise,e=>e===failure);
  rows=await takeTransportReceipts();assert.equal(rows[0].result,'rejected');assert.equal(rows[0].error_code,'Cancelled');
  const originalCrypto=globalThis.crypto;
  Object.defineProperty(globalThis,'crypto',{value:{subtle:{digest:()=>Promise.reject(new Error('hash failed'))}},configurable:true});
  const observed=Exchange.start('http://127.0.0.1:1/witness',request,10000,()=>false,1);
  observed.promise=Promise.resolve(response);assert.strictEqual(observed.reply(),observed.promise);
  assert.strictEqual(await observed.promise,response);
  await assert.rejects(takeTransportReceipts(),/witness observation failed/);
  Object.defineProperty(globalThis,'crypto',{value:originalCrypto,configurable:true});
})().catch(error=>{console.error(error);process.exitCode=1;});
'''
        result = subprocess.run(['node', '--unhandled-rejections=strict', '-e', script],
                                input=json.dumps(source), text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stderr, '')


if __name__ == '__main__': unittest.main()
