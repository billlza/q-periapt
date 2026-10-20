// SPDX-License-Identifier: Apache-2.0 OR MIT
// Controller/DOM boundary only. This is not browser Passkey or signature evidence.
import test from 'node:test';
import assert from 'node:assert/strict';
import {withDOM} from './dom-fixture.mjs';
import {createHash} from 'node:crypto';
import {grantUI} from '../../web/grant.mjs';
import {base64, encode, parse} from '../../web/transport.mjs';
import {fixture, response, bytes} from './grant-fixture.mjs';

test('grant controls show the exact decision and update uncertain state without issuing on query', async () => withDOM(async el => {
  const calls = [], downloads = []; let issued;
  const c = fixture(async (path, request) => {
    calls.push(path);
    if (path.endsWith('/status')) return {value: {state: 'Issued', response: base64(new TextEncoder().encode(issued))}};
    issued = response(request); throw new Error('response lost');
  });
  let state = {model: c.enrollment, selected: c.key, disposition: {state: 'Issued'}, observation: c.root, issued: c.issued};
  const clicks = new Map(), changes = new Map();
  const ui = grantUI({state: () => state, bind: (id, fn) => clicks.set(id, fn), change: (id, fn) => changes.set(id, fn),
    download: (name, text) => downloads.push({name, text}), fingerprint: async b => createHash('sha256').update(b).digest('hex')});
  ui.controls(); assert.equal(el('prepare-grant').disabled, true);
  const report = new TextEncoder().encode(encode(c.report));
  el('grant-file').files = [{size: report.length, arrayBuffer: async () => report.buffer}];
  await changes.get('grant-file')();
  el('grant-target').value = base64(bytes(30)); await changes.get('grant-target')();
  assert.equal(el('prepare-grant').disabled, false);
  await clicks.get('prepare-grant')();
  assert.equal(calls.length, 0); assert.equal(el('submit-grant').disabled, false);
  assert.match(el('grant-detail').textContent, /9007199254740994/);
  const decision = encode(c.records.grants()[0].request), hash = createHash('sha256').update(decision).digest('hex');
  assert.ok(el('grant-detail').textContent.includes(hash)); assert.match(el('grant-state').textContent, /Prepared/);
  await clicks.get('save-grant-request')(); assert.equal(downloads[0].text, decision);
  await assert.rejects(clicks.get('submit-grant')(), /lost/); ui.controls();
  assert.match(el('grant-state').textContent, /Submitted/); assert.match(el('submit-grant').textContent, /original approved/);
  await clicks.get('refresh-grant')();
  assert.deepEqual(calls, ['/api/enrollment/credential-grant', '/api/enrollment/credential-grant/status']);
  assert.match(el('grant-state').textContent, /Issued/); assert.equal(el('submit-grant').disabled, true);
  assert.equal(el('save-grant').disabled, false); await clicks.get('save-grant')(); assert.equal(downloads[1].text, issued);
  assert.deepEqual(parse(downloads[0].text), c.records.grants()[0].request);
  state = {model: null, selected: '', disposition: null, observation: null, issued: null}; ui.controls();
  assert.equal(el('grant-state').textContent, ''); assert.equal(el('submit-grant').disabled, true);
  assert.equal(el('save-grant').disabled, true); assert.ok(!el('grant-detail').textContent.includes(hash));
}));

test('failed cancellation disables signing and keeps the original query and cancellation controls', async () => withDOM(async el => {
  const c = fixture(async path => { assert.ok(path.endsWith('/cancel')); throw new Error('reply lost'); });
  const key = c.prepare(), clicks = new Map(), changes = new Map();
  const ui = grantUI({state: () => ({model: c.enrollment, selected: c.key, disposition: {state: 'Issued'}, observation: c.root, issued: c.issued}),
    bind: (id, fn) => clicks.set(id, fn), change: (id, fn) => changes.set(id, fn), download: () => {}, fingerprint: async () => 'fingerprint'});
  ui.controls(); el('grants').value = key; await changes.get('grants')();
  await assert.rejects(clicks.get('cancel-grant')(), /lost/); ui.controls();
  assert.match(el('grant-state').textContent, /CancelRequested/);
  assert.equal(el('submit-grant').disabled, true); assert.equal(el('refresh-grant').disabled, false);
  assert.equal(el('cancel-grant').disabled, false); assert.equal(c.records.findGrant(key).response, null);
}));
