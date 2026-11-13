// SPDX-License-Identifier: Apache-2.0 OR MIT
// Recovery/model counterexamples with explicit HTTP/storage substitutes.
// Real host signatures, browser authentication and client adoption are separate.
import test from 'node:test';
import assert from 'node:assert/strict';
import {base64, encode, parse} from '../../web/transport.mjs';
import {Records} from '../../web/enrollment-records.mjs';
import {Enrollment} from '../../web/enrollment-model.mjs';
import {Extensions, expiryUTC} from '../../web/extension-model.mjs';
const bytes = (n, size = 32) => Array(size).fill(n);
class Storage {
  data = new Map(); fail = false;
  getItem(key) { return this.data.has(key) ? this.data.get(key) : null; }
  setItem(key, text) { if (this.fail) throw new Error('quota failure'); this.data.set(key, text); }
}
function fixture(api = async () => { throw new Error('unexpected HTTP'); }) {
  const storage = new Storage(), records = new Records(storage, 'http://localhost:8087', base64(bytes(1)));
  const invitation = {operation: bytes(20), request_id: bytes(10), application: bytes(1), root_revision: 1,
    root: base64(bytes(2, 1985)), family: bytes(3), device: bytes(4, 16), generation: 1,
    valid_from: 100, valid_until: 1000, deadline: 400, predecessor: null};
  records.add({kind: 'invite', request_id: bytes(10), previous: null, predecessor: null, request: 'AQ', invitation});
  let next = 30;
  const enrollment = new Enrollment(records, api, () => bytes(next++));
  const root = {revision: 1, account: bytes(5), public_key: invitation.root, family: bytes(3), suspended: false,
    roster: {checkpoint: {version: 9007199254740993n, digest: bytes(6)}, bytes: 'AQ'}};
  return {storage, records, enrollment, root, key: base64(bytes(10)), model: new Extensions(enrollment, () => 2000)};
}
function response(request, changes = {}) {
  return encode({request, root_revision: 1, certificate: 'AQ', roster: 'Ag',
    checkpoint: {version: BigInt(request.predecessor.version) + 1n, digest: bytes(7)}, ...changes});
}

test('schema-1 reads preserve bytes; explicit preparation upgrades without sending authority', () => {
  const c = fixture(), original = c.records.export();
  assert.deepEqual(c.records.extensions(), []); assert.equal(c.storage.getItem(c.records.key), original);
  const key = c.model.prepare(c.key, c.root, null, 3000), row = c.records.findExtension(key);
  const upgraded = c.records.read(); assert.equal(upgraded.schema, 2);
  assert.deepEqual(upgraded.operations, parse(original).operations); assert.equal(row.response, null);
  c.root.roster.checkpoint.version += 1n;
  assert.equal(c.records.findExtension(key).request.predecessor.version, 9007199254740993n);
  assert.equal(row.request.previous_extension, null); assert.equal(row.request.valid_until, 3000);
});

test('lost response reopens and retries the exact decision even after its expiry', async () => {
  const sent = []; let lost = true, issued;
  const c = fixture(async (path, body) => {
    assert.equal(path, '/api/enrollment/extend-credential'); sent.push(encode(body));
    issued ??= ' \n' + response(body) + '\n';
    if (lost) { lost = false; throw new Error('response lost after commit'); }
    return {text: issued};
  });
  const key = c.model.prepare(c.key, c.root, null, 3000);
  await assert.rejects(c.model.submit(key), /response lost/);
  assert.equal(c.records.findExtension(key).response, null);
  const reopened = new Extensions(new Enrollment(c.records, c.enrollment.api, () => { throw new Error('no new correlation'); }), () => 4000);
  assert.equal(await reopened.submit(key), issued); assert.equal(await reopened.submit(key), issued);
  assert.equal(c.records.findExtension(key).response, issued); assert.ok(sent.every(s => s === sent[0]));
});

test('storage failures before send and after host commit retain the original recoverable request', async () => {
  let calls = 0;
  const c = fixture(async (_path, body) => { calls++; c.storage.fail = true; return {text: response(body)}; });
  const before = c.records.export(); c.storage.fail = true;
  assert.throws(() => c.model.prepare(c.key, c.root, null, 3000), /quota/); assert.equal(calls, 0);
  assert.equal(c.records.export(), before); c.storage.fail = false;
  const key = c.model.prepare(c.key, c.root, null, 3000), pending = c.records.export();
  await assert.rejects(c.model.submit(key), /quota/); assert.equal(c.records.export(), pending); assert.equal(calls, 1);
  c.storage.fail = false; c.enrollment.api = async (_path, body) => ({text: response(body)});
  await c.model.submit(key); assert.notEqual(c.records.findExtension(key).response, null);
});

test('changed request, root or successor checkpoint cannot replace the retained result', async () => {
  const c = fixture(), key = c.model.prepare(c.key, c.root, null, 3000), pending = c.records.export();
  for (const change of [r => ({request: {...r, valid_until: 3001}}), () => ({root_revision: 2}),
    r => ({checkpoint: r.predecessor}), () => ({checkpoint: null})]) {
    c.enrollment.api = async (_path, body) => ({text: response(body, change(body))});
    await assert.rejects(c.model.submit(key)); assert.equal(c.records.export(), pending);
  }
  c.enrollment.api = async (_path, body) => ({text: response(body)}); await c.model.submit(key);
  const complete = c.records.export();
  c.enrollment.api = async (_path, body) => ({text: ' ' + response(body)});
  await assert.rejects(c.model.submit(key), /changed the original/); assert.equal(c.records.export(), complete);
});

test('a later extension explicitly selects a completed predecessor of the same device', async () => {
  const c = fixture(async (_path, body) => ({text: response(body)}));
  const first = c.model.prepare(c.key, c.root, null, 3000);
  assert.throws(() => c.model.prepare(c.key, c.root, first, 4000), /completed extension/);
  await c.model.submit(first); c.root.roster.checkpoint = {version: 9007199254740994n, digest: bytes(7)};
  const second = c.model.prepare(c.key, c.root, first, 4000);
  assert.deepEqual(c.records.findExtension(second).request.previous_extension, c.records.findExtension(first).request.request_id);
  assert.throws(() => c.model.prepare(c.key, c.root, first, 2999), /extend/);
  c.enrollment.api = async () => { throw new Error('stale current member'); };
  await assert.rejects(c.model.submit(second), /stale/); assert.equal(c.records.extensions().length, 2);
  assert.equal(c.records.findExtension(second).response, null); assert.notEqual(c.records.findExtension(first).response, null);
});

test('invalid authority and expiry fail before retaining or sending a decision', () => {
  const c = fixture(), before = c.records.export();
  for (const change of [r => r.suspended = true, r => r.roster = null, r => r.family = bytes(9),
    r => r.public_key = base64(bytes(9, 1985)), r => r.revision = 2,
    r => r.roster.checkpoint.version = 18446744073709551615n]) {
    const root = structuredClone(c.root); change(root);
    assert.throws(() => c.model.prepare(c.key, root, null, 3000)); assert.equal(c.records.export(), before);
  }
  for (const until of [true, NaN, Infinity, 2000, 999, 3000.5, 18446744073709551615n]) {
    assert.throws(() => c.model.prepare(c.key, c.root, null, until)); assert.equal(c.records.export(), before);
  }
});

test('schema-2 backups preserve original history and refuse conflicts, cycles and foreign scope', async () => {
  const c = fixture(async (_path, body) => ({text: response(body)})), old = c.records.export();
  const key = c.model.prepare(c.key, c.root, null, 3000); await c.model.submit(key);
  const saved = c.records.export(), restored = new Records(new Storage(), c.records.origin, c.records.application);
  restored.merge(saved); restored.merge(old); restored.merge(saved); assert.equal(restored.export(), saved);
  for (const change of [r => r.origin = 'http://localhost:8088', r => r.extensions[0].request.valid_until = 4000,
    r => r.extensions[0].request.request_id = bytes(10), r => r.extensions[0].request.previous_extension = bytes(30),
    r => r.extensions[0].response = null, r => r.operations = []]) {
    const bad = parse(saved); change(bad); assert.throws(() => restored.merge(encode(bad))); assert.equal(restored.export(), saved);
  }
});

test('UTC input is exact across time zones and rejects normalized or ambiguous input', () => {
  assert.equal(expiryUTC('2026-10-25T01:30'), Date.UTC(2026, 9, 25, 1, 30) / 1000);
  assert.equal(expiryUTC('2026-10-25T01:30:17'), Date.UTC(2026, 9, 25, 1, 30, 17) / 1000);
  for (const value of ['2026-02-31T01:30', '2026-10-25T01:30Z', '2026-10-25T01:30+01:00', '', '2026-10-25', '2026-10-25T25:00']) assert.throws(() => expiryUTC(value));
});
