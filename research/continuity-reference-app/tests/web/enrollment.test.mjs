// SPDX-License-Identifier: Apache-2.0 OR MIT
// Browser-model regressions with explicit in-memory storage/HTTP substitutes.
// These do not claim a real browser, WebAuthn authenticator or SDK acceptance.
import test from 'node:test';
import assert from 'node:assert/strict';
import {parse, encode, base64, unbase64} from '../../web/transport.mjs';
import {Records} from '../../web/enrollment-records.mjs';
import {Enrollment} from '../../web/enrollment-model.mjs';
const bytes = (n, size = 32) => Array(size).fill(n);
const app = base64(bytes(1)), origin = 'http://localhost:8087';
class Storage {
  data = new Map(); fail = false;
  getItem(key) { return this.data.has(key) ? this.data.get(key) : null; }
  setItem(key, value) { if (this.fail) throw new Error('test storage quota'); this.data.set(key, value); }
}
function fixture(api) {
  const storage = new Storage(), records = new Records(storage, origin, app);
  let next = 10;
  const model = new Enrollment(records, api, () => bytes(next++));
  return {storage, records, model};
}
function invite(correlation, overrides = {}) {
  return {operation: bytes(20), request_id: correlation, application: bytes(1), root_revision: 1,
    root: base64(bytes(2, 1985)), family: bytes(3), device: bytes(4, 16), generation: 1,
    valid_from: 100, valid_until: 1000, deadline: 400, predecessor: null, ...overrides};
}
function root(checkpoint = null) {
  return {revision: 1, account: bytes(5), public_key: base64(bytes(2, 1985)), family: bytes(3), suspended: false,
    roster: checkpoint === null ? null : {checkpoint, bytes: base64(bytes(6))}};
}
async function prepared(api) {
  const context = fixture(async (path, body) => path.endsWith('/invite') ? {value: invite(body.request_id)} : api(path, body));
  const key = context.model.newInvitation(); await context.model.recover(key);
  context.model.retainProof(key, new Uint8Array([7, 8, 9]));
  return {...context, key};
}

function issuedStatus(row, observed) {
  return {state: 'Issued', current: observed, response: base64(new TextEncoder().encode(encode({
    operation: row.invitation.operation, root_revision: row.invitation.root_revision,
    certificate: 'AQ', roster: 'Ag', checkpoint: observed.roster.checkpoint,
  })))};
}

test('replacement persists exact predecessor before HTTP and recovers a lost response without old proof', async () => {
  const sent = []; let lost = true;
  const c = await prepared(async (path, body) => {
    sent.push({path, body: encode(body)});
    assert.equal(path, '/api/enrollment/replace-device');
    if (lost) { lost = false; throw new Error('replacement response lost'); }
    return {value: invite(body.request_id, {operation: bytes(21), generation: 2, predecessor: body.predecessor, valid_from: 200, valid_until: 2000})};
  });
  const old = c.records.find(c.key), oldBytes = encode(old), observed = root({version: 9007199254740993n, digest: bytes(9)});
  const status = issuedStatus(old, observed);
  const key = c.model.replacement(c.key, observed, status);
  assert.equal(c.records.read().schema, 5);
  assert.equal(c.records.find(key).request, null);
  assert.throws(() => c.model.replacement(c.key, observed, status), /unresolved replacement/);
  await assert.rejects(c.model.recover(key), /response lost/);
  observed.roster.checkpoint.version++;
  const restarted = new Enrollment(c.records, c.model.api, () => { throw new Error('no new identity'); });
  await restarted.recover(key);
  assert.deepEqual(sent[0], sent[1]);
  assert.equal(encode(c.records.find(c.key)), oldBytes);
  assert.equal(c.records.find(key).invitation.generation, 2);
  assert.equal(c.records.find(key).request, null);
  assert.throws(() => restarted.reapproval(key, observed, new Uint8Array([8])), /fresh replacement/);
  restarted.retainProof(key, new Uint8Array([9]));
  assert.equal(c.records.find(key).request, 'CQ');
  assert.equal(c.records.find(c.key).request, old.request);
  const restored = fixture(() => { throw new Error('import does not send'); });
  restored.records.merge(c.records.export());
  assert.equal(restored.records.export(), c.records.export());
  const downgrade = parse(c.records.export()); downgrade.schema = 4;
  assert.throws(() => restored.records.decode(encode(downgrade)), /Unknown recovery operation/);
});

test('replacement refuses missing issuance, unsafe roots, exhausted generations and retargeted replies', async () => {
  let changes = {};
  const c = await prepared(async (_path, body) => ({value: invite(body.request_id, {operation: bytes(21), generation: 2, predecessor: body.predecessor, ...changes})}));
  const old = c.records.find(c.key), observed = root({version: 2, digest: bytes(9)}), status = issuedStatus(old, observed);
  assert.throws(() => c.model.replacement(c.key, observed, {state: 'Approved'}), /issued operation/);
  assert.throws(() => c.model.replacement(c.key, root(), status), /does not authorize/);
  assert.throws(() => c.model.replacement(c.key, {...observed, suspended: true}, status), /does not authorize/);
  c.storage.fail = true;
  assert.throws(() => c.model.replacement(c.key, observed, status), /quota/);
  c.storage.fail = false;
  assert.equal(c.records.read().schema, 1);
  const key = c.model.replacement(c.key, observed, status);
  for (const bad of [{generation: 1}, {generation: 3}, {device: bytes(99, 16)}, {root: base64(bytes(99, 1985))}, {predecessor: null}, {operation: old.invitation.operation}]) {
    changes = bad;
    await assert.rejects(c.model.recover(key), /replacement intent/);
    assert.equal(c.records.find(key).invitation, null);
  }
  changes = {}; await c.model.recover(key);
  const missing = parse(c.records.export()); missing.operations.shift();
  assert.throws(() => c.records.decode(encode(missing)), /source is absent/);
  const large = fixture(() => { throw new Error('no send'); });
  large.records.add({...old, invitation: {...old.invitation, generation: 18446744073709551614n}});
  assert.throws(() => large.model.replacement(c.key, observed, status), /generation exhausted/);
});

test('u64 integers remain exact through parsing, request encoding and recovery storage', () => {
  const value = parse('{"version":18446744073709551615,"safe":9007199254740991,"next":9007199254740993}');
  assert.equal(value.version, 18446744073709551615n);
  assert.equal(value.next, 9007199254740993n);
  assert.equal(encode(value), '{"version":18446744073709551615,"safe":9007199254740991,"next":9007199254740993}');
  assert.throws(() => encode({version: Number.MAX_SAFE_INTEGER + 1}), /inexact/);
  assert.throws(() => parse('{"version":1.5}'), /integer/);
  const {records} = fixture(() => { throw new Error('no HTTP expected'); });
  const row = {kind: 'invite', request_id: bytes(10), previous: null, predecessor: null, request: null,
    invitation: invite(bytes(10), {root_revision: value.version, generation: value.next, predecessor: {version: value.version, digest: bytes(9)}})};
  records.add(row);
  assert.deepEqual(records.read().operations[0], row);
});

test('authority export retains the host account and exact revision without selecting a current roster', () => {
  const {model} = fixture(() => { throw new Error('export does not perform HTTP'); });
  const observed = root({version: 2, digest: bytes(9)}); observed.revision = 18446744073709551615n;
  const profile = model.authorityProfile(observed);
  assert.deepEqual(Object.keys(profile).sort(), ['application', 'family', 'root', 'root_revision', 'schema']);
  assert.equal(profile.schema, 'qperiapt-host-authority/1'); assert.deepEqual(profile.application, bytes(1));
  assert.equal(profile.root, observed.public_key); assert.equal(parse(encode(profile)).root_revision, observed.revision);
  assert.deepEqual(profile.family, observed.family);
});

test('unknown invitation response retains its original correlation across a new model', async () => {
  const sent = []; let lost = true;
  const api = async (path, body) => { sent.push({path, body}); if (lost) { lost = false; throw new Error('response lost after host commit'); } return {value: invite(body.request_id)}; };
  const {records, model} = fixture(api), key = model.newInvitation();
  await assert.rejects(model.recover(key), /response lost/);
  assert.throws(() => model.newInvitation(), /unresolved/);
  const reopened = new Enrollment(records, api, () => { throw new Error('must not generate another correlation'); });
  await reopened.recover(key);
  assert.deepEqual(sent[0], sent[1]);
  assert.equal(records.read().operations.length, 1);
  assert.equal(base64(records.find(key).request_id), key);
});

test('storage failure before send prevents HTTP; failed response save retains the original pending record', async () => {
  let calls = 0, storage;
  const context = fixture(async (_path, body) => { calls++; storage.fail = true; return {value: invite(body.request_id)}; });
  storage = context.storage; storage.fail = true;
  assert.throws(() => context.model.newInvitation(), /quota/);
  assert.equal(calls, 0); assert.equal(context.records.read().operations.length, 0);
  storage.fail = false; const key = context.model.newInvitation();
  await assert.rejects(context.model.recover(key), /quota/);
  storage.fail = false;
  assert.equal(context.records.find(key).invitation, null);
  await new Enrollment(context.records, async (_path, body) => ({value: invite(body.request_id)})).recover(key);
  assert.equal(context.records.read().operations.length, 1);
});

test('a retained proof cannot be replaced, including before an approval retry', async () => {
  const sent = [], context = await prepared(async (path, body) => { sent.push({path, body}); return {status: 204}; });
  assert.throws(() => context.model.retainProof(context.key, new Uint8Array([99])), /different request/);
  await context.model.approve(context.key); await context.model.approve(context.key);
  assert.deepEqual(sent[0], sent[1]);
  assert.deepEqual(unbase64(sent[0].body.request, 8192), new Uint8Array([7, 8, 9]));
});

test('reapproval retry retains the explicitly selected u64 predecessor and original request', async () => {
  let lose = true; const sent = [];
  const context = await prepared(async (path, body) => {
    sent.push({path, body});
    if (lose) { lose = false; throw new Error('unknown reapproval response'); }
    return {value: invite(body.request_id, {operation: bytes(21), predecessor: body.predecessor})};
  });
  const predecessor = {version: 9007199254740993n, digest: bytes(9)};
  const key = context.model.reapproval(context.key, root(predecessor));
  await assert.rejects(context.model.recover(key), /unknown reapproval/);
  predecessor.version = 9007199254740994n; // A newer observation cannot retarget the retained operation.
  await context.model.recover(key);
  assert.deepEqual(sent[0], sent[1]);
  assert.equal(sent[1].body.predecessor.version, 9007199254740993n);
  assert.equal(sent[1].body.request, context.records.find(context.key).request);
  assert.notEqual(sent[1].body.previous, context.records.find(key).invitation.operation);
  assert.equal(context.records.find(context.key).invitation.operation[0], 20);
});

test('a stale reapproval attempt does not block a new explicit decision for the original device', async () => {
  const context = await prepared(async (_path, body) => {
    if (body.predecessor.version === 1) throw new Error('host rejected stale predecessor');
    return {value: invite(body.request_id, {operation: bytes(21), predecessor: body.predecessor})};
  });
  const first = context.model.reapproval(context.key, root({version: 1, digest: bytes(8)}));
  await assert.rejects(context.model.recover(first), /stale predecessor/);
  const second = context.model.reapproval(context.key, root({version: 2, digest: bytes(9)}));
  assert.notEqual(first, second); await context.model.recover(second);
  assert.equal(context.records.find(first).invitation, null);
  assert.deepEqual(context.records.find(first).previous, context.records.find(second).previous);
  assert.equal(context.records.find(first).request, context.records.find(second).request);
  assert.equal(context.records.read().operations.length, 3);
});

test('a separately selected reapproval proof never overwrites the original submitted request', async () => {
  const context = await prepared(async () => { throw new Error('approval is a separate HTTP step'); });
  const original = context.records.find(context.key).request;
  const replacement = new Uint8Array([77, 88, 99]);
  const next = context.model.reapproval(context.key, root(), replacement);
  assert.equal(context.records.find(context.key).request, original);
  assert.equal(context.records.find(next).request, base64(replacement));
  assert.notEqual(context.records.find(next).request, original);
  // Only the server may allow this while the source is still unapproved. An
  // already Approved source rejects differing proof bytes in native/TCP tests.
});

test('historical issuance stays byte-exact and does not select its own current roster', async () => {
  const historical = '{"operation":' + JSON.stringify(bytes(20)) + ',"root_revision":1,"certificate":"AQ","roster":"Ag","checkpoint":{"version":1,"digest":' + JSON.stringify(bytes(8)) + '}}';
  const current = root({version: 2, digest: bytes(9)}); current.suspended = true;
  const context = await prepared(async path => path.endsWith('/status') ? {value: {state: 'Issued', response: base64(new TextEncoder().encode(historical)), current}} : {value: parse(historical), text: historical});
  const status = await context.model.status(context.key);
  assert.equal(context.model.issuedText(context.key, status.response), historical);
  assert.equal(await context.model.issue(context.key), historical);
  assert.equal(status.current.roster.checkpoint.version, 2);
  assert.equal(status.current.suspended, true);
  assert.throws(() => context.model.reapproval(context.key, current), /does not authorize/);
});

test('status does not silently follow a historical successor or create another grant', async () => {
  const successor = invite(bytes(30), {operation: bytes(31)});
  const context = await prepared(async () => ({value: {state: 'Reapproved', successor}}));
  const status = await context.model.status(context.key);
  assert.equal(context.records.read().operations.length, 1);
  const next = context.model.selectSuccessor(context.key, status);
  assert.equal(context.records.read().operations.length, 2);
  assert.equal(next, base64(bytes(30)));
  assert.equal(context.model.selectSuccessor(context.key, status), next);
  assert.equal(context.records.read().operations.length, 2);
});

test('wrong-account responses, corrupt storage and conflicting imports never reset original records', async () => {
  const context = fixture(async (_path, body) => ({value: invite(body.request_id, {application: bytes(99)})}));
  const key = context.model.newInvitation();
  await assert.rejects(context.model.recover(key), /another account/);
  assert.equal(context.records.find(key).invitation, null);
  const saved = context.records.export();
  const foreign = parse(saved); foreign.application = base64(bytes(2));
  assert.throws(() => context.records.merge(encode(foreign)), /another origin, account or schema/);
  assert.equal(context.records.export(), saved);
  const conflict = parse(saved); conflict.operations[0].invitation = invite(bytes(10));
  assert.throws(() => context.records.merge(encode(conflict)), /conflicts/);
  assert.equal(context.records.export(), saved);
  context.storage.setItem(context.records.key, '{broken');
  assert.throws(() => context.records.read());
  assert.throws(() => context.model.newInvitation());
  assert.equal(context.storage.getItem(context.records.key), '{broken');
});

test('recovery file merge is bounded, scope-bound and idempotent', async () => {
  const context = await prepared(async () => { throw new Error('no HTTP expected'); });
  const saved = context.records.export(), restored = new Records(new Storage(), origin, app);
  restored.merge(saved); restored.merge(saved);
  assert.deepEqual(restored.read(), context.records.read());
  const duplicate = parse(saved); duplicate.operations.push(duplicate.operations[0]);
  assert.throws(() => restored.merge(encode(duplicate)), /Duplicate/);
  assert.throws(() => restored.merge(' '.repeat(4 * 1024 * 1024 + 1)), /bound/);
  assert.deepEqual(restored.read(), context.records.read());
});
