// SPDX-License-Identifier: Apache-2.0 OR MIT
// Shared installed Node/browser regression: input hooks must not strand a Rust borrow.
export function checkInputOwners(sdk, fixture, check, extraCases = []) {
  const hex = text => Uint8Array.from(text.match(/../g), byte => parseInt(byte, 16));
  const policy = new TextEncoder().encode(fixture.policy_toml);
  const signature = hex(fixture.signature), root = hex(fixture.verification_key);
  const context = new Uint8Array([5, 7, 11]);
  const label = new TextEncoder().encode('input/v1');
  const cases = [
    ['plain', true, value => value],
    ['throwing-length', true, (value, hook) => Object.defineProperty(value, 'length', {get: hook})],
    ['false-length', true, value => Object.defineProperty(value, 'length', {value: 0})],
    ['subclass-hooks', true, (value, hook) => {
      class Input extends Uint8Array {}
      const input = new Input(value);
      for (const name of ['length', 'buffer', 'byteLength', 'byteOffset', 'constructor', Symbol.iterator, Symbol.toStringTag]) {
        Object.defineProperty(input, name, {get: hook});
      }
      return input;
    }],
    ['proxy', false, (value, hook) => new Proxy(value, {get: hook, getPrototypeOf: hook})],
    ['revoked-proxy', false, value => {
      const proxy = Proxy.revocable(value, {}); proxy.revoke(); return proxy.proxy;
    }],
    ['uint16', false, value => new Uint16Array(value)],
    ['clamped', false, value => new Uint8ClampedArray(value)],
    ['fake-prototype', false, () => Object.create(Uint8Array.prototype)],
    ['detached', false, value => {
      structuredClone(value.buffer, {transfer: [value.buffer]}); return value;
    }],
    ['out-of-bounds', false, () => {
      const buffer = new ArrayBuffer(8, {maxByteLength: 16});
      const input = new Uint8Array(buffer, 4, 4); buffer.resize(2); return input;
    }],
    ...extraCases,
  ];
  for (const [name, accepted, make] of cases) {
    const owners = [], own = owner => { owners.push(owner); return owner; };
    let operationFailure, getterReads = 0;
    const hook = () => { getterReads++; throw new Error('input property hook executed'); };
    try {
      const runtime = own(new sdk.QPeriaptRuntime(policy, signature, root, new Uint8Array(), 2, 1));
      const key = own(runtime.generate_key()), input = make(context.slice(), hook);
      let encapsulation, rejected;
      try { encapsulation = own(runtime.encapsulate(key.public_key(), input)); }
      catch (error) { rejected = error; }
      if (accepted) {
        check(rejected === undefined && encapsulation !== undefined, `${name}: genuine bytes rejected`);
        const wire = encapsulation.ciphertext();
        Object.defineProperty(wire, 'length', {get: hook});
        const left = own(encapsulation.take_secret());
        const right = own(key.decapsulate(wire, context));
        const a = own(left.derive_key(sdk.QPeriaptKeyPurpose.Exporter, label, input));
        const b = own(right.derive_key(sdk.QPeriaptKeyPurpose.Exporter, label, context));
        const x = a.export_for_protocol(), y = b.export_for_protocol();
        check(x.length === 32 && x.every((value, i) => value === y[i]), `${name}: input copy changed bytes`);
        x.fill(0); y.fill(0);
        for (const action of [
          () => key.decapsulate(new Proxy(wire, {}), context),
          () => left.derive_key(sdk.QPeriaptKeyPurpose.Exporter, new Proxy(label, {}), context),
        ]) {
          let failure;
          try { action(); } catch (error) { failure = error; }
          check(failure instanceof Error, `${name}: invalid child-owner input accepted`);
        }
      } else {
        check(rejected instanceof Error && encapsulation === undefined, `${name}: invalid view accepted`);
        if (name === 'detached' || name === 'out-of-bounds') {
          check(rejected.cause instanceof TypeError, `${name}: original copy exception lost`);
        }
      }
      check(runtime.is_enabled() && key.public_key().length > 0, `${name}: input error poisoned owner`);
      check(getterReads === 0, `${name}: inspected caller property`);
    } catch (error) { operationFailure = error; }
    const cleanup = [];
    for (const owner of owners.reverse()) {
      try { owner.close(); } catch (error) { cleanup.push(error); }
      try { owner.free(); } catch (error) { cleanup.push(error); }
    }
    check(cleanup.length === 0, `${name}: owner cleanup failed: ${cleanup.map(error => error.message).join('; ')}`);
    if (operationFailure !== undefined) throw operationFailure;
  }
}
