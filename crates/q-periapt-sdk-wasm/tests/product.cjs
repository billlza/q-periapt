// SPDX-License-Identifier: Apache-2.0 OR MIT
// Run against a real wasm-pack --target nodejs build; fixtures are public KAT data.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const fixtureDir = process.env.QPERIAPT_SDK_FIXTURES || path.join(__dirname, '../../../bindings');
const fixture = JSON.parse(fs.readFileSync(path.join(fixtureDir, 'signed-policy-vectors.json')));
const decode = value => Uint8Array.from(Buffer.from(value, 'hex'));
if (process.argv.includes('--without-entropy')) {
  Object.defineProperty(globalThis, 'crypto', { value: undefined, configurable: true });
}
const sdk = process.env.QPERIAPT_SDK_PACKAGE ? require(process.env.QPERIAPT_SDK_PACKAGE)
  : require(path.resolve(process.argv[2] || path.join(__dirname, '../pkg-node/q_periapt_sdk_wasm.js')));
const { QPeriaptExpert } = process.env.QPERIAPT_SDK_PACKAGE
  ? require(`${process.env.QPERIAPT_SDK_PACKAGE}/expert`) : sdk;
if (process.env.QPERIAPT_SDK_PACKAGE) {
  assert.equal('QPeriaptExpert' in sdk, false);
  assert.deepEqual(Object.keys(sdk).sort(), ['QPeriaptDerivedKey', 'QPeriaptEncapsulation',
    'QPeriaptKey', 'QPeriaptKeyPurpose', 'QPeriaptPolicyUpdate', 'QPeriaptRuntime', 'QPeriaptSecret']);
}
const { QPeriaptRuntime } = sdk;
assert.deepEqual([sdk.QPeriaptKeyPurpose.InitiatorTraffic, sdk.QPeriaptKeyPurpose.ResponderTraffic,
  sdk.QPeriaptKeyPurpose.InitiatorConfirmation, sdk.QPeriaptKeyPurpose.ResponderConfirmation,
  sdk.QPeriaptKeyPurpose.Exporter], [1, 2, 3, 4, 5]);
const policy = new TextEncoder().encode(fixture.policy_toml);
const signature = decode(fixture.signature);
const root = decode(fixture.verification_key);
const create = (previous = new Uint8Array()) => new QPeriaptRuntime(policy, signature, root, previous, 1, 1);
const runtime = create();
if (process.argv.includes('--without-entropy')) {
  assert.throws(() => runtime.generate_key(), /entropy unavailable/);
  assert.throws(() => runtime.generate_key(), /entropy unavailable/); // slot released
  const peer = decode(process.env.QPERIAPT_TEST_PUBLIC_KEY);
  for (let i = 0; i < 3; i++) assert.throws(() => runtime.encapsulate(peer, new Uint8Array()), /entropy unavailable/);
  const expanded = new Uint8Array(2440);
  expanded.set([0x51, 0x50, 0x4b, 1, 1, 2, 1, 0]);
  assert.throws(() => QPeriaptExpert.import_expanded(runtime, expanded), /entropy unavailable/);
  assert.throws(() => QPeriaptExpert.import_expanded(runtime, expanded), /entropy unavailable/); // import quota released
  expanded.fill(0);
  runtime.close(); runtime.free();
  console.log('WASM_ENTROPY_FAILURE_PASS');
  process.exit(0);
}
const stored = runtime.trusted_state();
let coerced = false;
const coercible = { valueOf() { coerced = true; return 1; } };
for (const value of [0, -1, 1.5, NaN, Infinity, 4294967297, '1', true, null, undefined, 1n, coercible]) {
  for (const limits of [[value, 1], [1, value]]) {
    assert.throws(() => new QPeriaptRuntime(policy, signature, root, new Uint8Array(), ...limits), /invalid runtime limits/);
  }
}
assert.throws(() => new QPeriaptRuntime(policy, signature, root, new Uint8Array(), 1025, 1), /invalid runtime limits/);
assert.throws(() => new QPeriaptRuntime(policy, signature, root, new Uint8Array(), 1, 65), /invalid runtime limits/);
assert.equal(coerced, false);
const maximum = new QPeriaptRuntime(policy, signature, root, new Uint8Array(), 1024, 64);
maximum.close(); maximum.free();
assert.equal(stored.length, 36);
const second = create(stored); second.close(); second.free();
assert.throws(() => create(new Uint8Array(4)), /invalid input length/);
assert.throws(() => create(new Uint8Array(36)), /policy denied/);
const future = stored.slice(); future[3] = 3;
assert.throws(() => create(future), /policy denied/);
const badSignature = signature.slice(); badSignature[0] ^= 1;
assert.throws(() => new QPeriaptRuntime(policy, badSignature, root, new Uint8Array(), 1, 1), /policy denied/);
assert.throws(() => new QPeriaptRuntime(new Uint8Array(65537), signature, root, new Uint8Array(), 1, 1), /invalid input length/);
const key = runtime.generate_key();
assert.equal('sk' in key, false);
assert.equal('mlkem768_keypair' in sdk, false);
assert.equal('combine' in sdk, false);
assert.throws(() => runtime.generate_key(), /resource limit/);
const publicKey = key.public_key();
assert.equal(publicKey.length, 1216);
for (const length of [0, 136, 4096, 65536]) {
  const context = new Uint8Array(length).fill(0x53);
  const result = runtime.encapsulate(publicKey, context);
  assert.equal('secret' in result, false);
  const ciphertext = result.ciphertext();
  const encapsulated = result.take_secret();
  assert.throws(() => result.take_secret(), /closed/);
  const recovered = key.decapsulate(ciphertext, context);
  const a = encapsulated.export_for_protocol();
  const b = recovered.export_for_protocol();
  assert.deepEqual(a, b);
  const label = new TextEncoder().encode('app/v1/aes256');
  let previous = new Uint8Array(32);
  for (const purpose of [1, 2, 3, 4, 5]) {
    const left = encapsulated.derive_key(purpose, label, context);
    const right = recovered.derive_key(purpose, label, context);
    const x = left.export_for_protocol(), y = right.export_for_protocol();
    assert.deepEqual(x, y);
    assert.notDeepEqual(x, previous);
    previous.fill(0); previous = x.slice(); x.fill(0); y.fill(0);
    left.close(); right.close();
    assert.throws(() => left.export_for_protocol(), /closed/);
    left.free(); right.free();
  }
  previous.fill(0);
  for (const purpose of [0, 6, -1, 1.5, NaN, Infinity, 4294967295, 4294967297, '1', true, null, undefined, 1n, coercible]) assert.throws(() => encapsulated.derive_key(purpose, label, context), /invalid key purpose/);
  assert.equal(coerced, false);
  assert.throws(() => encapsulated.derive_key(1, new Uint8Array(), context), /invalid input length/);
  assert.throws(() => encapsulated.derive_key(1, new Uint8Array(256), context), /invalid input length/);
  assert.throws(() => encapsulated.derive_key(1, new Uint8Array([0]), context), /invalid key purpose/);
  assert.throws(() => encapsulated.derive_key(1, label, new Uint8Array(65537)), /invalid input length/);
  const corrupt = ciphertext.slice(); corrupt[0] ^= 1;
  const rejected = key.decapsulate(corrupt, context);
  const rejectionBytes = rejected.export_for_protocol();
  assert.notDeepEqual(rejectionBytes, a);
  a.fill(0); b.fill(0); rejectionBytes.fill(0);
  corrupt.fill(0, 1088);
  assert.throws(() => key.decapsulate(corrupt, context), /invalid public key share/);
  for (const owned of [encapsulated, recovered, rejected]) {
    owned.close(); owned.close();
    assert.throws(() => owned.export_for_protocol(), /closed/);
    owned.free();
  }
  result.close(); result.free();
}
assert.throws(() => runtime.encapsulate(publicKey, new Uint8Array(65537)), /invalid input length/);
assert.throws(() => runtime.encapsulate({}, new Uint8Array()), /expected Uint8Array/);
key.close(); key.close();
assert.throws(() => key.public_key(), /closed/);
const replacement = runtime.generate_key();
const retainedResult = runtime.encapsulate(replacement.public_key(), new Uint8Array());
const retainedSecret = retainedResult.take_secret();
const retainedDerived = retainedSecret.derive_key(5, new Uint8Array([65]), new Uint8Array());
runtime.close(); runtime.close();
assert.throws(() => runtime.trusted_state(), /closed/);
assert.throws(() => replacement.public_key(), /closed/);
assert.throws(() => runtime.generate_key(), /closed/);
assert.throws(() => retainedSecret.export_for_protocol(), /closed/);
assert.throws(() => retainedDerived.export_for_protocol(), /closed/);
retainedDerived.close(); retainedDerived.free();
retainedSecret.close(); retainedSecret.free(); retainedResult.free();
replacement.close(); replacement.free(); key.free(); runtime.free();
{
  const current = create();
  assert.equal(current.is_enabled(), true);
  const original = current.generate_key();
  const publicBytes = original.public_key();
  const exported = QPeriaptExpert.export_expanded(original);
  assert.equal(exported.length, 2440);
  original.close(); original.free();
  assert.throws(() => QPeriaptExpert.import_expanded(current, new Uint8Array(64)), /invalid input length/);
  exported[0] ^= 1;
  assert.throws(() => QPeriaptExpert.import_expanded(current, exported), /invalid private-key/);
  exported[0] ^= 1;
  const imported = QPeriaptExpert.import_expanded(current, exported);
  exported.fill(0);
  assert.deepEqual(imported.public_key(), publicBytes);
  const enc = current.encapsulate(publicBytes, new Uint8Array([42]));
  const left = enc.take_secret();
  const right = imported.decapsulate(enc.ciphertext(), new Uint8Array([42]));
  const a = left.export_for_protocol(), b = right.export_for_protocol();
  assert.deepEqual(a, b); a.fill(0); b.fill(0);
  const revoked = JSON.parse(fs.readFileSync(path.join(fixtureDir, 'sdk-policy-revocation-vectors.json')));
  const allowed = JSON.parse(fs.readFileSync(path.join(fixtureDir, 'sdk-policy-update-vectors.json')));
  const revokePolicy = new TextEncoder().encode(revoked.policy_toml), revokeSignature = decode(revoked.signature);
  const update = current.prepare_policy_update(revokePolicy, revokeSignature);
  const states = update.states();
  assert.equal(states.length, 72);
  assert.deepEqual(states.slice(0, 36), current.trusted_state());
  const persisted = states.slice(36); // test-only in-memory persistence
  const disabled = update.activate_after_persist();
  assert.equal(disabled.is_enabled(), false);
  assert.throws(() => disabled.generate_key(), /policy denied/);
  assert.throws(() => imported.public_key(), /closed/);
  assert.throws(() => current.trusted_state(), /closed/);
  assert.throws(() => right.export_for_protocol(), /closed/);
  assert.throws(() => update.activate_after_persist(), /closed/);
  update.close(); update.free(); current.close(); current.free();
  assert.equal(disabled.is_enabled(), false);
  const recovered = new QPeriaptRuntime(revokePolicy, revokeSignature, root, persisted, 1, 1);
  assert.equal(recovered.is_enabled(), false);
  const enable = recovered.prepare_policy_update(new TextEncoder().encode(allowed.policy_toml), decode(allowed.signature));
  const nextState = enable.states().slice(36);
  const next = enable.activate_after_persist();
  assert.equal(next.is_enabled(), true);
  assert.deepEqual(next.trusted_state(), nextState);
  const key = next.generate_key(); key.close(); key.free();
  for (const owned of [left, right, enc, imported, disabled, recovered, enable, next]) {
    owned.close(); owned.free();
  }
}
const child = spawnSync(process.execPath, [__filename, process.argv[2] || path.join(__dirname, '../pkg-node/q_periapt_sdk_wasm.js'), '--without-entropy'], {
  encoding: 'utf8', timeout: 30000, maxBuffer: 1024 * 1024,
  env: { ...process.env, QPERIAPT_TEST_PUBLIC_KEY: Buffer.from(publicKey).toString('hex') }
});
assert.ifError(child.error);
assert.equal(child.status, 0, child.stdout + child.stderr);
assert.equal(child.stderr, '');
assert.match(child.stdout, /WASM_ENTROPY_FAILURE_PASS/);
console.log('WASM_PRODUCT_LIFECYCLE_POLICY_ROUNDTRIP_FAILURE_PASS');
