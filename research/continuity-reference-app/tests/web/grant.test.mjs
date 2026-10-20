// SPDX-License-Identifier: Apache-2.0 OR MIT
import test from 'node:test';
import assert from 'node:assert/strict';
import {base64, encode, parse} from '../../web/transport.mjs';
import {Records} from '../../web/enrollment-records.mjs';
import {Enrollment} from '../../web/enrollment-model.mjs';
import {Grants} from '../../web/grant-model.mjs';
import {fixture, response, bytes, Storage} from './grant-fixture.mjs';

test('schema3 preserves enrollment and extension history including later extension updates', () => {
  const c = fixture(), schema2 = c.records.export(), key = c.prepare();
  assert.equal(c.records.read().schema, 3); assert.equal(c.records.findGrant(key).state, 'Prepared');
  assert.deepEqual(c.records.read().operations, parse(schema2).operations);
  assert.deepEqual(c.records.extensions(), parse(schema2).extensions);
  const saved = c.records.export(); assert.equal(c.prepare(), key); assert.equal(c.records.export(), saved);
  c.records.merge(c.schema1); c.records.merge(schema2); assert.equal(c.records.export(), saved);
  const next = structuredClone(c.records.extensions()[0]); next.request.request_id = bytes(31);
  next.request.previous_extension = bytes(30); next.request.predecessor = c.root.roster.checkpoint;
  next.request.valid_until = 4000; next.response = null;
  c.records.addExtension(next); assert.equal(c.records.read().schema, 3); assert.equal(c.records.grants().length, 1);
  c.records.completeExtension(base64(bytes(31)), encode({request: next.request, root_revision: 1, certificate: 'Bg', roster: 'Bw',
    checkpoint: {version: 9007199254740995n, digest: bytes(8)}}));
  assert.equal(c.records.findGrant(key).state, 'Prepared');
});

test('lost issuance response is recovered by a read-only query with exact bytes', async () => {
  const calls = []; let original;
  const c = fixture(async (path, request) => {
    calls.push(path);
    if (path.endsWith('/status')) return {value: {state: 'Issued', response: base64(new TextEncoder().encode(original))}};
    original = response(request); throw new Error('response lost after commit');
  });
  const key = c.prepare(); await assert.rejects(c.model.submit(key), /lost/);
  assert.equal(c.records.findGrant(key).state, 'Submitted');
  const reopened = new Grants(new Enrollment(new Records(c.storage, c.records.origin, c.records.application), c.enrollment.api));
  assert.equal(await reopened.refresh(key), 'Issued'); assert.equal(c.records.findGrant(key).response, original);
  assert.deepEqual(calls, ['/api/enrollment/credential-grant', '/api/enrollment/credential-grant/status']);
  await assert.rejects(reopened.submit(key)); assert.equal(calls.length, 2);
});

test('absent and pending observations never dispatch issuance or change the target', async () => {
  const calls = []; let state = 'Absent';
  const c = fixture(async (path, request) => { calls.push({path, request: encode(request)}); return {value: {state}}; });
  const key = c.prepare(), before = encode(c.records.findGrant(key).request);
  assert.equal(await c.model.refresh(key), 'Absent'); assert.equal(c.records.findGrant(key).state, 'Prepared');
  state = 'Pending'; assert.equal(await c.model.refresh(key), 'Pending'); assert.equal(c.records.findGrant(key).state, 'Submitted');
  c.root.roster.checkpoint.version += 1n;
  assert.throws(() => c.prepare(), /differs/); assert.equal(encode(c.records.findGrant(key).request), before);
  assert.ok(calls.every(c => c.path.endsWith('/status') && c.request === before));
});

test('lost cancellation before first dispatch remains closed to later issuance', async () => {
  const calls = []; let closed = false;
  const c = fixture(async path => {
    calls.push(path);
    if (path.endsWith('/status')) return {value: {state: closed ? 'Closed' : 'Absent'}};
    assert.ok(path.endsWith('/cancel')); closed = true; throw new Error('cancellation reply lost');
  });
  const key = c.prepare(); await assert.rejects(c.model.cancel(key), /lost/);
  assert.equal(c.records.findGrant(key).state, 'CancelRequested');
  await assert.rejects(c.model.submit(key)); assert.equal(calls.length, 1);
  assert.equal(await c.model.refresh(key), 'Closed'); assert.equal(c.records.findGrant(key).state, 'Closed');
  await assert.rejects(c.model.submit(key)); assert.equal(calls.length, 2);
});

test('issuance winning a cancellation race is retrieved without resubmission', async () => {
  let original; const calls = [];
  const c = fixture(async (path, request) => {
    calls.push(path); original ??= response(request);
    if (path.endsWith('/cancel')) throw new Error('already issued');
    assert.ok(path.endsWith('/status')); return {value: {state: 'Issued', response: base64(new TextEncoder().encode(original))}};
  });
  const key = c.prepare(); await assert.rejects(c.model.cancel(key), /issued/);
  assert.equal(c.records.findGrant(key).state, 'CancelRequested');
  await c.model.refresh(key); assert.equal(c.records.findGrant(key).response, original);
  assert.deepEqual(calls, ['/api/enrollment/credential-grant/cancel', '/api/enrollment/credential-grant/status']);
});

test('quota failure blocks dispatch; post-response failure preserves the original decision', async () => {
  let calls = 0, original;
  const c = fixture(async (_path, request) => { calls++; original = response(request); c.storage.fail = true; return {text: original}; });
  const key = c.prepare(), saved = c.records.export(); c.storage.fail = true;
  await assert.rejects(c.model.submit(key), /quota/); assert.equal(calls, 0); assert.equal(c.records.export(), saved);
  c.storage.fail = false; await assert.rejects(c.model.submit(key), /quota/);
  assert.equal(calls, 1); assert.equal(c.records.findGrant(key).state, 'Submitted');
  c.storage.fail = false; c.enrollment.api = async path => {
    assert.ok(path.endsWith('/status')); return {value: {state: 'Issued', response: base64(new TextEncoder().encode(original))}};
  };
  await c.model.refresh(key); assert.equal(c.records.findGrant(key).response, original);
});

test('forged reports and wrong host selections fail before retention or HTTP', () => {
  for (const mutate of [c => c.report.application = bytes(90), c => c.report.enrollment = bytes(90),
    c => c.report.original_certificate = 'Cg', c => c.report.previous_certificate = 'Cw',
    c => c.report.current_policy.digest = bytes(90), c => delete c.report.current_policy_authorization,
    c => c.report.original_roster = base64(bytes(1, 16385)), c => c.selections.previous = base64(bytes(30)),
    c => c.selections.successor = null, c => c.selections.original = base64(bytes(30)),
    c => c.root.suspended = true, c => c.root.revision = 2, c => c.root.family = bytes(90),
    c => c.root.roster.checkpoint.version = 1]) {
    const c = fixture(), before = c.records.export(); mutate(c);
    assert.throws(() => c.prepare()); assert.equal(c.records.export(), before);
  }
});

test('unrelated or changed results cannot replace the exact original result', async () => {
  let changed = {};
  const c = fixture(async (_path, request) => ({text: response(request, changed)}));
  const key = c.prepare(); changed = {operation: bytes(90)};
  await assert.rejects(c.model.submit(key), /changed/); assert.equal(c.records.findGrant(key).state, 'Submitted');
  changed = {}; await c.model.submit(key); const saved = c.records.export();
  c.enrollment.api = async () => ({value: {state: 'Issued', response: base64(new TextEncoder().encode(response(c.records.findGrant(key).request, {grant: 'Bg'})))}});
  await assert.rejects(c.model.refresh(key), /changed/); assert.equal(c.records.export(), saved);
  c.enrollment.api = async () => ({value: {state: 'Absent'}});
  await assert.rejects(c.model.refresh(key), /lost/); assert.equal(c.records.export(), saved);
});

test('backup roundtrip refuses unknown fields and preserves terminal local history', async () => {
  const c = fixture(async (_path, request) => ({text: response(request)})), key = c.prepare();
  const prepared = c.records.export(); await c.model.submit(key); const saved = c.records.export();
  const restored = new Records(new Storage(), c.records.origin, c.records.application);
  restored.merge(saved); restored.merge(c.schema1); assert.equal(restored.export(), saved);
  assert.throws(() => restored.merge(prepared), /conflicts/); assert.equal(restored.export(), saved);
  for (const mutate of [v => v.schema = '3', v => v.grants[0].request.reset = true,
    v => delete v.grants[0].request.previous_extension, v => v.grants[0].response = null,
    v => v.extensions = [], v => v.grants[0].enrollment_response = c.issued.replace('"root_revision":1', '"root_revision":2')]) {
    const bad = parse(saved); mutate(bad); assert.throws(() => restored.merge(encode(bad))); assert.equal(restored.export(), saved);
  }
  assert.equal(restored.findGrant(key).request.target_checkpoint.version, 9007199254740994n);
});
