// SPDX-License-Identifier: Apache-2.0 OR MIT
import test from 'node:test';
import assert from 'node:assert/strict';
import {base64, encode, parse} from '../../web/transport.mjs';
import {PolicyApprovals} from '../../web/policy-model.mjs';
import {Records} from '../../web/enrollment-records.mjs';
import {Grants} from '../../web/grant-model.mjs';
import {fixture, response} from './policy-fixture.mjs';
import {bytes, Storage, fixture as grantFixture} from './grant-fixture.mjs';
const preview = c => ({value: {state: 'Absent', review: c.review}});
const history = text => ({value: {state: 'Issued', response: base64(new TextEncoder().encode(text))}});

test('policy preparation and older backup imports retain schema5 replacement history', async () => {
  const c = fixture(async () => preview(c)), old = c.records.export();
  const replacement = c.enrollment.replacement(c.key, c.root, {state: 'Issued', response: base64(new TextEncoder().encode(c.issued))});
  const row = c.records.find(replacement);
  assert.equal(c.records.read().schema, 5);
  const policy = await c.prepare();
  assert.equal(c.records.read().schema, 5);
  assert.deepEqual(c.records.find(replacement), row);
  assert.equal(c.records.findPolicyApproval(policy).state, 'Prepared');
  c.records.merge(old);
  assert.equal(c.records.read().schema, 5);
  const imported = new Records(new Storage(), c.records.origin, c.records.application);
  imported.merge(c.records.export());
  assert.equal(imported.export(), c.records.export());
});

test('policy preparation only previews; schema4 keeps all older histories and the exact u64 request', async () => {
  const calls = [], c = fixture(async path => { calls.push(path); return preview(c); });
  const old = c.records.export(), before = c.storage.getItem(c.records.key);
  c.records.read(); assert.equal(c.storage.getItem(c.records.key), before);
  const key = await c.prepare();
  assert.deepEqual(calls, ['/api/enrollment/policy-approval/preview']);
  assert.equal(c.records.read().schema, 4);
  assert.deepEqual(c.records.read().operations, parse(old).operations);
  assert.deepEqual(c.records.extensions(), parse(old).extensions);
  assert.equal(c.records.findPolicyApproval(key).request.retained.scope.current_roster.version, 9007199254740994n);
  assert.equal(c.records.findPolicyApproval(key).state, 'Prepared');
  assert.equal(await c.prepare(), key); assert.equal(calls.length, 2);
  const other = new Records(new Storage(), c.records.origin, c.records.application);
  other.merge(c.records.export()); other.merge(old); other.merge(c.schema1);
  assert.equal(other.export(), c.records.export()); assert.equal(other.key, c.records.key);
  // A later G operation and a later credential must not downgrade or lose P.
  const g = grantFixture(), gkey = new Grants(c.enrollment).prepare(c.key, g.root, g.report, g.selections, c.issued);
  assert.equal(c.records.findGrant(gkey).state, 'Prepared');
  const ext = structuredClone(c.records.extensions()[0]); ext.request.request_id = bytes(31);
  ext.request.previous_extension = bytes(30); ext.request.valid_until = 4000; ext.response = null;
  c.records.addExtension(ext);
  assert.equal(c.records.read().schema, 4); assert.equal(c.records.findPolicyApproval(key).state, 'Prepared');
  c.records.merge(old); assert.equal(c.records.policyApprovals().length, 1); assert.equal(c.records.grants().length, 1);
});

test('unknown policy issuance recovers byte-exact original result after reopening without another signature', async () => {
  const calls = []; let issued;
  const c = fixture(async (path, request) => {
    calls.push(path);
    if (path.endsWith('/preview')) return preview(c);
    if (path.endsWith('/status')) return history(issued);
    issued = response(request, c.review); throw new Error('reply lost');
  });
  const key = await c.prepare(), backup = c.records.export();
  await assert.rejects(c.model.submit(key), /lost/);
  const reopened = new PolicyApprovals(c.enrollment);
  assert.equal(c.records.findPolicyApproval(key).state, 'Submitted');
  assert.equal(await reopened.refresh(key), 'Issued');
  assert.equal(c.records.findPolicyApproval(key).response, issued);
  await reopened.refresh(key);
  assert.equal(calls.filter(p => p === '/api/enrollment/policy-approval').length, 1);
  assert.throws(() => c.records.merge(backup), /conflicts/);
  await assert.rejects(reopened.cancel(key), /cannot be cancelled/);
});

test('preview reconstructs Pending, Issued and Closed history without dispatching new issuance', async () => {
  for (const state of ['Pending', 'Issued', 'Closed']) {
    const calls = [];
    const c = fixture(async (path, request) => {
      calls.push(path);
      if (path.endsWith('/preview')) return {value: state === 'Closed' ? {state} : {state, review: c.review}};
      assert.ok(path.endsWith('/status')); return history(response(request, c.review));
    });
    const key = await c.prepare(), row = c.records.findPolicyApproval(key);
    assert.equal(row.state, state === 'Pending' ? 'Submitted' : state);
    assert.deepEqual(calls, ['/api/enrollment/policy-approval/preview', ...(state === 'Issued' ? ['/api/enrollment/policy-approval/status'] : [])]);
    assert.equal(row.review === null, state === 'Closed');
    if (state === 'Closed') await assert.rejects(c.model.submit(key), /reviewed/);
  }
});

test('policy cancellation retains uncertain intent and an issuance race is reconciled by query', async () => {
  let cancelled = false;
  const c = fixture(async (path, request) => {
    if (path.endsWith('/preview')) return preview(c);
    if (path.endsWith('/cancel')) { cancelled = true; throw new Error('reply lost'); }
    assert.ok(path.endsWith('/status')); return history(response(request, c.review));
  });
  const key = await c.prepare(); await assert.rejects(c.model.cancel(key), /lost/);
  assert.equal(cancelled, true); assert.equal(c.records.findPolicyApproval(key).state, 'CancelRequested');
  await assert.rejects(c.model.submit(key), /reviewed/);
  await c.model.refresh(key); assert.equal(c.records.findPolicyApproval(key).state, 'Issued');
  const d = fixture(async path => {
    if (path.endsWith('/preview')) return preview(d);
    if (path.endsWith('/cancel')) return {status: 204};
    return {value: {state: 'Closed'}};
  });
  const closed = await d.prepare(); await d.model.cancel(closed); await d.model.refresh(closed);
  await d.model.cancel(closed); assert.equal(d.records.findPolicyApproval(closed).state, 'Closed');
  await assert.rejects(d.model.submit(closed), /reviewed/);
});

test('policy storage failure prevents signing and post-commit storage failure preserves original intent', async () => {
  let issues = 0, issued;
  const c = fixture(async (path, request) => {
    if (path.endsWith('/preview')) return preview(c);
    if (path.endsWith('/status')) return history(issued);
    issues++; issued = response(request, c.review); c.storage.fail = true; return {text: issued};
  });
  c.storage.fail = true; await assert.rejects(c.prepare(), /quota/); c.storage.fail = false;
  assert.equal(c.records.policyApprovals().length, 0);
  const key = await c.prepare(); c.storage.fail = true;
  await assert.rejects(c.model.submit(key), /quota/); assert.equal(issues, 0);
  c.storage.fail = false; await assert.rejects(c.model.submit(key), /quota/);
  assert.equal(issues, 1); c.storage.fail = false;
  assert.equal(c.records.findPolicyApproval(key).state, 'Submitted');
  await c.model.refresh(key); assert.equal(c.records.findPolicyApproval(key).response, issued);
});

test('wrong policy sources and credential ancestry are rejected before preview', async () => {
  const cases = [
    c => { c.report.enrollment = bytes(99); },
    c => { c.inputs.family = bytes(99); },
    c => { delete c.report.scope.previous_authorization; },
    c => { c.inputs.target.pins.policy_version = 1; },
    c => { c.inputs.previous.pins.policy_digest = bytes(99); },
    c => { c.inputs.target.pins.sdk_root = base64(bytes(9, 1952)); },
    c => { c.report.current_certificate = 'Ag'; },
    c => { c.selections.current = null; },
    c => { c.report.scope.current_roster.version = 1; },
    c => { c.report.scope.current_roster.digest = bytes(99); },
  ];
  for (const change of cases) {
    const c = fixture(); change(c); await assert.rejects(c.prepare());
    assert.equal(c.records.policyApprovals().length, 0);
  }
});

test('a mismatched host review or result cannot replace the original policy decision', async () => {
  for (const change of [v => v.target.digest = bytes(90), v => v.statement = [], v => v.valid_until = 1, v => v.witness_required = true]) {
    const c = fixture(async () => { const review = structuredClone(c.review); change(review); return {value: {state: 'Absent', review}}; });
    await assert.rejects(c.prepare()); assert.equal(c.records.policyApprovals().length, 0);
  }
  for (const change of [{statement: bytes(90)}, {journal: bytes(90)}, {target: {version: 3, digest: bytes(61)}}]) {
    const c = fixture(async (path, request) => path.endsWith('/preview') ? preview(c) : {text: response(request, c.review, change)});
    const key = await c.prepare(); await assert.rejects(c.model.submit(key), /changed/);
    assert.equal(c.records.findPolicyApproval(key).state, 'Submitted');
  }
  let status = {state: 'Pending', statement: bytes(90)};
  const c = fixture(async path => path.endsWith('/preview') ? preview(c) : {value: status});
  const key = await c.prepare(); await assert.rejects(c.model.refresh(key), /changed/);
  status = {state: 'Closed'}; await c.model.refresh(key);
  status = {state: 'Absent'}; await assert.rejects(c.model.refresh(key), /lost/);
  assert.equal(c.records.findPolicyApproval(key).state, 'Closed');
});

test('policy backups reject unknown fields, duplicate identities, foreign accounts and quota overflow without eviction', async () => {
  const c = fixture(async () => preview(c)); await c.prepare(); const saved = c.records.export();
  for (const change of [
    v => v.policy_approvals[0].request.current_extension = undefined,
    v => v.policy_approvals[0].review = null,
    v => v.policy_approvals[0].extra = true,
    v => v.policy_approvals.push(v.policy_approvals[0]),
    v => v.application = base64(bytes(90)),
  ]) {
    const data = parse(saved); change(data); assert.throws(() => c.records.merge(encode(data)));
    assert.equal(c.records.export(), saved);
  }
  const data = parse(saved);
  while (data.operations.length + data.extensions.length + data.policy_approvals.length <= 512) {
    const row = structuredClone(data.operations[0]), n = data.operations.length + 100;
    row.request_id = bytes(0); row.request_id[0] = n & 255; row.request_id[1] = n >> 8;
    row.invitation = null; data.operations.push(row);
  }
  assert.throws(() => c.records.save(data), /capacity/); assert.equal(c.records.export(), saved);
});

test('unsigned backup review metadata cannot authorize signing before host comparison', async () => {
  let issues = 0;
  const c = fixture(async path => {
    if (path.endsWith('/preview')) return preview(c);
    issues++; throw new Error('unexpected signing request');
  });
  const key = await c.prepare(), data = c.records.read();
  data.policy_approvals[0].review.valid_until = 4000;
  c.records.save(data); // Structurally valid; this does not authenticate the review.
  await assert.rejects(new PolicyApprovals(c.enrollment).review(key), /review differs/);
  await assert.rejects(c.model.submit(key), /review differs/);
  assert.equal(issues, 0); assert.equal(c.records.findPolicyApproval(key).state, 'Prepared');
});
