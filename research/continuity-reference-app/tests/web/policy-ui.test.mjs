// SPDX-License-Identifier: Apache-2.0 OR MIT
// DOM/controller substitutes, not a real user's Passkey or cryptographic proof.
import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {policyUI} from '../../web/policy.mjs';
import {base64, encode} from '../../web/transport.mjs';
import {fixture, response} from './policy-fixture.mjs';
import {bytes} from './grant-fixture.mjs';
import {withDOM} from './dom-fixture.mjs';
test('policy UI separates verified review from approval and exports original JSON and raw signature', async () => withDOM(async el => {
  const calls = [], downloads = []; let issued;
  const c = fixture(async (path, request) => {
    calls.push(path);
    if (path.endsWith('/preview')) return {value: {state: 'Absent', review: c.review}};
    if (path.endsWith('/status')) return {value: {state: 'Issued', response: base64(new TextEncoder().encode(issued))}};
    issued = response(request, c.review); throw new Error('reply lost');
  });
  let state = {model: c.enrollment, selected: c.key, disposition: {state: 'Issued'}, observation: {...c.root, suspended: true}, issued: c.issued};
  const clicks = new Map(), changes = new Map();
  const ui = policyUI({state: () => state, bind: (id, fn) => clicks.set(id, fn), change: (id, fn) => changes.set(id, fn),
    download: (name, text, type) => downloads.push({name, text, type}), fingerprint: async b => createHash('sha256').update(b).digest('hex')});
  ui.controls();
  for (const [key, value] of [['policy-file', c.report], ['policy-inputs', c.inputs]]) {
    const b = new TextEncoder().encode(encode(value)); el(key).files = [{size: b.length, arrayBuffer: async () => b.buffer}]; await changes.get(key)();
  }
  assert.equal(calls.length, 0);
  el('policy-current').value = base64(bytes(30)); await changes.get('policy-current')();
  assert.equal(el('prepare-policy').disabled, false); await clicks.get('prepare-policy')();
  assert.deepEqual(calls, ['/api/enrollment/policy-approval/preview']);
  const decision = encode(c.records.policyApprovals()[0].request), hash = createHash('sha256').update(decision).digest('hex');
  assert.ok(el('policy-detail').textContent.includes(hash)); assert.match(el('policy-detail').textContent, /1970-01-01T00:50:00/);
  assert.match(el('policy-detail').textContent, /9007199254740994/); assert.match(el('policy-state').textContent, /Prepared/);
  await clicks.get('save-policy-request')(); assert.equal(downloads[0].text, decision);
  await assert.rejects(clicks.get('submit-policy')(), /lost/); ui.controls(); assert.match(el('policy-state').textContent, /Submitted/);
  await clicks.get('refresh-policy')(); assert.equal(el('submit-policy').disabled, true);
  await clicks.get('save-policy')(); assert.equal(downloads[1].text, issued);
  await clicks.get('save-policy-signature')(); assert.deepEqual(downloads[2].text, Uint8Array.from([5, 6]));
  assert.equal(downloads[2].type, 'application/octet-stream');
  // A native select change rejected by the outer cross-tab lock cannot alter
  // the controller's selected credential when controls are restored.
  el('policy-current').value = ''; ui.controls(); assert.equal(el('policy-current').value, base64(bytes(30)));
  state = {model: null, selected: '', disposition: null}; ui.controls();
  assert.equal(el('policy-state').textContent, ''); assert.equal(el('submit-policy').disabled, true);
  assert.ok(!el('policy-detail').textContent.includes(hash));
}));
test('policy cancellation failure keeps query available and disables approval', async () => withDOM(async el => {
  const c = fixture(async path => {
    if (path.endsWith('/preview')) return {value: {state: 'Absent', review: c.review}};
    throw new Error('cancel response lost');
  });
  const key = await c.prepare(), clicks = new Map(), changes = new Map();
  const ui = policyUI({state: () => ({model: c.enrollment, selected: c.key, disposition: {state: 'Issued'}, issued: c.issued}),
    bind: (id, fn) => clicks.set(id, fn), change: (id, fn) => changes.set(id, fn), download: () => {}, fingerprint: async () => 'hash'});
  ui.controls(); el('policies').value = key; await changes.get('policies')();
  await assert.rejects(clicks.get('cancel-policy')(), /lost/); ui.controls();
  assert.equal(el('submit-policy').disabled, true); assert.equal(el('refresh-policy').disabled, false);
  assert.equal(el('cancel-policy').disabled, false); assert.match(el('policy-state').textContent, /CancelRequested/);
}));

test('restoring an altered review never enables the approval control', async () => withDOM(async el => {
  const c = fixture(async () => ({value: {state: 'Absent', review: c.review}}));
  const key = await c.prepare(), data = c.records.read();
  data.policy_approvals[0].review.valid_until = 4000; c.records.save(data);
  const changes = new Map();
  const ui = policyUI({state: () => ({model: c.enrollment, selected: c.key, disposition: {state: 'Issued'}, issued: c.issued}),
    bind: () => {}, change: (id, fn) => changes.set(id, fn), download: () => {}, fingerprint: async () => 'hash'});
  ui.controls(); el('policies').value = key;
  await assert.rejects(changes.get('policies')(), /review differs/);
  ui.controls();
  assert.equal(el('submit-policy').disabled, true);
  assert.match(el('policy-detail').textContent, /not yet reverified/);
  assert.equal(el('refresh-policy').disabled, false);
}));
