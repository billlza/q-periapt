// SPDX-License-Identifier: Apache-2.0 OR MIT
import { QPeriaptPolicyStore } from './node_modules/q-periapt-sdk-wasm/web/storage.js';
const hex = bytes => [...bytes].map(value => value.toString(16).padStart(2, '0')).join('');
const decode = value => Uint8Array.from(value.match(/../g), value => parseInt(value, 16));
const require = (condition, message) => { if (!condition) throw Error(message); };
function gateEvent(object, property) {
  let release, observed;
  const wait = new Promise(resolve => { release = resolve; });
  const reached = new Promise(resolve => { observed = resolve; });
  let prototype = object, descriptor;
  while (prototype && !descriptor) {
    descriptor = Object.getOwnPropertyDescriptor(prototype, property);
    prototype = Object.getPrototypeOf(prototype);
  }
  require(typeof descriptor?.set === 'function', 'native event setter missing');
  Object.defineProperty(object, property, {
    configurable: true,
    set(callback) {
      descriptor.set.call(object, event => {
        observed();
        wait.then(() => callback.call(object, event));
      });
    },
  });
  return { reached, release };
}
async function fixture(name) {
  const response = await fetch(`/fixtures/${name}.json`);
  require(response.ok, 'fixture unavailable');
  const value = await response.json();
  return { root: decode(value.verification_key), policy: new TextEncoder().encode(value.policy_toml), signature: decode(value.signature) };
}
async function run() {
  const initial = await fixture('signed-policy-vectors');
  const disabled = await fixture('sdk-policy-revocation-vectors');
  const rows = [];
  for (const mode of ['transaction-complete', 'database-open']) {
    const name = `late-${mode}-${hex(crypto.getRandomValues(new Uint8Array(12)))}`;
    let owner = await QPeriaptPolicyStore.create({ name, ...initial });
    const before = hex(owner.trustedState());
    let gate, restore;
    if (mode === 'transaction-complete') {
      const original = IDBDatabase.prototype.transaction;
      IDBDatabase.prototype.transaction = function (...args) {
        const transaction = original.apply(this, args);
        IDBDatabase.prototype.transaction = original;
        gate = gateEvent(transaction, 'oncomplete');
        return transaction;
      };
      restore = () => { IDBDatabase.prototype.transaction = original; };
    } else {
      await owner.close(); owner = undefined;
      const original = IDBFactory.prototype.open;
      IDBFactory.prototype.open = function (...args) {
        const request = original.apply(this, args);
        IDBFactory.prototype.open = original;
        gate = gateEvent(request, 'onsuccess');
        return request;
      };
      restore = () => { IDBFactory.prototype.open = original; };
    }
    let error, early, earlyError, closedError;
    const started = performance.now();
    try {
      try {
        if (owner) await owner.replacePolicy(owner.trustedState(), disabled.policy, disabled.signature);
        else owner = await QPeriaptPolicyStore.open({ name, root: initial.root });
      } catch (failure) { error = failure; }
      require(error && gate, 'operation must reach its deadline');
      await gate.reached;
      const elapsed = performance.now() - started;
      if (owner) {
        try { owner.trustedState(); } catch (failure) { closedError = failure.code; }
        require(closedError === 'Closed', 'timed-out owner remained active');
      }
      try { early = await QPeriaptPolicyStore.open({ name, root: initial.root }); }
      catch (failure) { earlyError = failure.code; }
      rows.push({ mode, elapsed_ms: elapsed, error: error.code, message: String(error),
        cleanup: error.cause instanceof AggregateError ? error.cause.errors.map(item => item.code ?? item.name) : [],
        final_receipt_withheld: true, early_owner_admitted: Boolean(early), early_error: earlyError ?? null,
        closed_error: closedError ?? null, before });
    } finally {
      restore(); gate?.release();
      if (early) await early.close();
      if (owner) await owner.close();
    }
    // Wait for the actual browser callback and the root lease release receipt.
    let recovered, failures = [];
    const until = performance.now() + 3000;
    while (!recovered) {
      try { recovered = await QPeriaptPolicyStore.open({ name, root: initial.root }); }
      catch (failure) {
        require(failure.code === 'Busy' && performance.now() < until, 'reopen after receipt failed');
        failures.push(failure.code);
        await new Promise(resolve => setTimeout(resolve, 20));
      }
    }
    try {
      rows.at(-1).after = hex(recovered.trustedState());
      rows.at(-1).enabled = recovered.isEnabled();
      rows.at(-1).release_observations = failures;
      require(mode === 'database-open' ? rows.at(-1).after === before : !recovered.isEnabled(), 'original committed policy was lost');
    } finally { await recovered.close(); }
    postMessage({ progress: mode });
  }
  return { completed: true, held_until_receipt: rows.every(row => !row.early_owner_admitted && row.early_error === 'Busy'),
    cases: rows, browser: navigator.userAgent,
    scope: 'actual IndexedDB completion events delayed by the test scheduler; real policy runtime and original signed images' };
}
run().then(result => postMessage({ result }), error => postMessage({ result: { completed: false, error: String(error), stack: error.stack } }));
