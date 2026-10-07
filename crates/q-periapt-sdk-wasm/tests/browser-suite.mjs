// SPDX-License-Identifier: Apache-2.0 OR MIT
// The same real installed-package contract runs in each isolated execution realm.
export async function runAcceptance(mode, realm) {
  let assertions = 0;
  function check(condition, message) {
    if (!condition) throw new Error(message);
    assertions++;
  }
  function throws(operation, pattern) {
    let failure;
    try { operation(); } catch (error) { failure = error; }
    check(failure instanceof Error && pattern.test(failure.message), `Expected ${pattern}, got ${failure}`);
  }
  async function fixture(name) {
    const response = await fetch(`/fixtures/${name}.json`);
    check(response.ok, `fixture fetch failed: ${response.status}`);
    return response.json();
  }
  const hex = text => Uint8Array.from(text.match(/../g), byte => parseInt(byte, 16));
  const utf8 = text => new TextEncoder().encode(text);
  const owners = [];
  function own(owner) { owners.push(owner); return owner; }
  async function run() {
    check(realm === 'window' ? typeof Window === 'function' && globalThis instanceof Window
      : realm === 'worker' && typeof DedicatedWorkerGlobalScope === 'function'
        && globalThis instanceof DedicatedWorkerGlobalScope, 'unexpected execution realm');
    check(['roundtrip', 'no-entropy', 'throwing-entropy', 'init-fail', 'no-wasm'].includes(mode), 'unknown mode');
    const prefix = mode === 'init-fail' ? '/broken' : '';
    const sdk = await import(`${prefix}/node_modules/q-periapt-sdk-wasm/web/index.js`);
    const { QPeriaptExpert } = await import(`${prefix}/node_modules/q-periapt-sdk-wasm/web/expert.js`);
    check(Object.keys(sdk).sort().join(',') === ['QPeriaptDerivedKey', 'QPeriaptEncapsulation',
      'QPeriaptKey', 'QPeriaptKeyPurpose', 'QPeriaptPolicyUpdate', 'QPeriaptRuntime',
      'QPeriaptSecret', 'default'].join(','), 'unexpected default browser exports');
    if (mode === 'no-wasm') Object.defineProperty(globalThis, 'WebAssembly', { value: undefined });
    const first = sdk.default(), second = sdk.default();
    check(first === second, 'concurrent initializers did not share a promise');
    if (mode === 'init-fail' || mode === 'no-wasm') {
      const results = await Promise.allSettled([first, second, sdk.default()]);
      check(results.every(item => item.status === 'rejected'), 'initialization failure was hidden');
      check(results[0].reason === results[1].reason && results[0].reason === results[2].reason,
        'failed initialization unexpectedly retried');
      return;
    }
    const initialized = await Promise.all([first, second]);
    check(initialized.every(value => value === undefined), 'initializer exposed raw WASM exports');
    const f = await fixture('signed-policy-vectors');
    const args = [utf8(f.policy_toml), hex(f.signature), hex(f.verification_key), new Uint8Array()];
    const create = (...limits) => new sdk.QPeriaptRuntime(...args, ...limits);
    const runtime = own(create(2, 1));
    if (mode === 'no-entropy' || mode === 'throwing-entropy') {
      const publicKey = own(runtime.generate_key()).public_key();
      Object.defineProperty(globalThis, 'crypto', { value: mode === 'no-entropy' ? undefined
        : { getRandomValues() { throw new Error('injected WebCrypto provider failure'); } } });
      for (let i = 0; i < 3; i++) throws(() => runtime.generate_key(), /entropy unavailable/);
      for (let i = 0; i < 3; i++) throws(() => runtime.encapsulate(publicKey, new Uint8Array()), /entropy unavailable/);
      const expanded = new Uint8Array(2440); expanded.set([0x51, 0x50, 0x4b, 1, 1, 2, 1, 0]);
      for (let i = 0; i < 3; i++) throws(() => QPeriaptExpert.import_expanded(runtime, expanded), /entropy unavailable/);
      return;
    }
    check(isSecureContext && typeof crypto.getRandomValues === 'function', 'secure WebCrypto unavailable');
    let coerced = false;
    const coercible = { valueOf() { coerced = true; return 1; } };
    for (const value of [0, -1, 1.5, 4294967297, NaN, Infinity, '1', true, null, undefined, 1n, coercible]) {
      throws(() => create(value, 1), /invalid runtime limits/);
      throws(() => create(1, value), /invalid runtime limits/);
    }
    const signature = args[1].slice(); signature[0] ^= 1;
    throws(() => new sdk.QPeriaptRuntime(args[0], signature, args[2], args[3], 1, 1), /policy denied/);
    const key = own(runtime.generate_key());
    check(!('sk' in key), 'default private getter is present');
    const bytes = QPeriaptExpert.export_expanded(key);
    const imported = own(QPeriaptExpert.import_expanded(runtime, bytes)); bytes.fill(0);
    throws(() => runtime.generate_key(), /resource limit/);
    let retained;
    for (const length of [0, 136, 65536]) {
      const context = new Uint8Array(length).fill(0x53);
      const encapsulation = own(runtime.encapsulate(key.public_key(), context));
      const left = own(encapsulation.take_secret());
      throws(() => encapsulation.take_secret(), /closed/);
      const right = own(imported.decapsulate(encapsulation.ciphertext(), context));
      for (const purpose of [1, 2, 3, 4, 5]) {
        const a = own(left.derive_key(purpose, utf8('browser/v1'), context));
        const b = own(right.derive_key(purpose, utf8('browser/v1'), context));
        const x = a.export_for_protocol(), y = b.export_for_protocol();
        check(x.length === 32 && x.every((byte, i) => byte === y[i]), 'derived peer key mismatch');
        x.fill(0); y.fill(0); a.close(); b.close();
        throws(() => a.export_for_protocol(), /closed/);
      }
      throws(() => left.derive_key(coercible, utf8('browser/v1'), context), /invalid key purpose/);
      throws(() => left.derive_key('1', utf8('browser/v1'), context), /invalid key purpose/);
      retained = right;
    }
    check(!coerced, 'numeric validation invoked coercion hooks');
    throws(() => runtime.encapsulate(key.public_key(), new Uint8Array(65537)), /invalid input length/);
    const revoke = await fixture('sdk-policy-revocation-vectors');
    const update = own(runtime.prepare_policy_update(utf8(revoke.policy_toml), hex(revoke.signature)));
    check(update.states().length === 72, 'policy states length differs');
    const disabled = own(update.activate_after_persist()); // fixture-only in-memory persistence
    check(!disabled.is_enabled(), 'signed revocation did not disable runtime');
    throws(() => disabled.generate_key(), /policy denied/);
    throws(() => key.public_key(), /closed/);
    throws(() => runtime.trusted_state(), /closed/);
    throws(() => retained.export_for_protocol(), /closed/);
  }
  const errors = [];
  try { await run(); } catch (error) { errors.push({ error: String(error), stack: error.stack }); }
  for (const owner of owners.reverse()) {
    try { owner.close(); owner.free(); } catch (error) { errors.push({ error: String(error), stack: error.stack }); }
  }
  return { status: errors.length ? 'fail' : 'pass', mode, realm,
    assertions, errors, userAgent: navigator.userAgent };
}
