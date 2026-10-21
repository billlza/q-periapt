// SPDX-License-Identifier: Apache-2.0 OR MIT
// Controller/DOM/HTTP substitutes; live account and SDK proofs are separate.
import test from 'node:test';
import assert from 'node:assert/strict';
import {enrollmentUI} from '../../web/enrollment.mjs';
import {base64, encode, parse} from '../../web/transport.mjs';
import {withDOM} from './dom-fixture.mjs';
import {fixture, bytes} from './grant-fixture.mjs';

test('replacement control starts with no old proof and requires a separate explicit approval', async () => withDOM(async el => {
  const c = fixture(), previous = {localStorage: globalThis.localStorage, location: globalThis.location, fetch: globalThis.fetch};
  const calls = []; let next = null, approved = false;
  globalThis.localStorage = c.storage; globalThis.location = {origin: c.records.origin};
  globalThis.fetch = async (path, options) => {
    const body = options.body === undefined ? null : parse(options.body); calls.push(path);
    let result;
    if (path === '/api/me') result = {application_id: c.records.application};
    else if (path === '/api/enrollment/status') {
      result = next && base64(body.operation) === base64(next.operation)
        ? {state: approved ? 'Approved' : 'Invited', invitation: next}
        : {state: 'Issued', current: c.root, response: base64(new TextEncoder().encode(c.issued))};
    } else if (path === '/api/enrollment/replace-device') {
      const retained = c.records.find(base64(body.request_id));
      assert.equal(retained.kind, 'replace'); assert.equal(retained.request, null); assert.equal(retained.invitation, null);
      next = {...c.invitation, operation: bytes(21), request_id: body.request_id, predecessor: body.predecessor, generation: 2};
      result = next;
    } else if (path === '/api/enrollment/approve') {
      assert.equal(body.request, 'Ag'); approved = true; return new Response(null, {status: 204});
    } else throw new Error(`Unexpected endpoint: ${path}`);
    return new Response(encode(result), {headers: {'content-type': 'application/json'}});
  };
  try {
    const account = {application_id: c.records.application}, ui = enrollmentUI(work => work(), () => account);
    ui.render(account); assert.equal(el('replace-device').disabled, true);
    el('operations').value = c.key; await el('operations').dispatch('change');
    assert.equal(el('replace-device').disabled, false);
    const old = c.records.export();
    el('request-file').files = [{size: 1, arrayBuffer: async () => Uint8Array.from([1]).buffer}];
    await el('request-file').dispatch('change');
    await el('replace-device').dispatch('click');
    assert.equal(c.records.read().schema, 5);
    assert.equal(el('approve-request').disabled, true);
    assert.equal(el('issue-device').disabled, true);
    assert.equal(el('reapprove-request').disabled, true);
    assert.equal(el('replace-device').disabled, true);
    assert.equal(c.records.find(c.key).request, 'AQ');
    assert.deepEqual(c.records.read().operations[0], parse(old).operations[0]);
    assert.match(el('operation-detail').textContent, /generation 2/);
    assert.match(el('operation-detail').textContent, /fresh device keys/);
    assert.ok(!calls.includes('/api/enrollment/approve'));
    el('request-file').files = [{size: 1, arrayBuffer: async () => Uint8Array.from([2]).buffer}];
    await el('request-file').dispatch('change');
    assert.equal(el('approve-request').disabled, false);
    await el('approve-request').dispatch('click');
    assert.equal(el('issue-device').disabled, false);
    assert.equal(c.records.find(base64(next.request_id)).request, 'Ag');
  } finally { Object.assign(globalThis, previous); }
}));
