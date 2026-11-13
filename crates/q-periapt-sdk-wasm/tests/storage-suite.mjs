// SPDX-License-Identifier: Apache-2.0 OR MIT
import { QPeriaptPolicyStore } from './node_modules/q-periapt-sdk-wasm/web/storage.js';
let owner;
const hex = value => [...value].map(b => b.toString(16).padStart(2, '0')).join('');
const decode = value => Uint8Array.from(value.match(/../g), b => parseInt(b, 16));
const fixtures = Promise.all(['signed-policy-vectors', 'sdk-policy-revocation-vectors', 'sdk-policy-update-vectors'].map(async name => {
  const response = await fetch(`/fixtures/${name}.json`);
  if (!response.ok) throw new Error('Fixture unavailable');
  const value = await response.json();
  return { root: decode(value.verification_key), policy: new TextEncoder().encode(value.policy_toml), signature: decode(value.signature) };
}));
function state() { return { enabled: owner.isEnabled(), state: hex(owner.trustedState()) }; }
function cryptography() {
  const values = [];
  const take = value => { values.push(value); return value; };
  try {
    const key = take(owner.generateKey());
    const encapsulated = take(owner.encapsulate(key.public_key(), new Uint8Array()));
    const left = take(encapsulated.take_secret()), right = take(key.decapsulate(encapsulated.ciphertext(), new Uint8Array()));
    const label = new TextEncoder().encode('browser-storage/v1');
    const a = take(left.derive_key(5, label, new Uint8Array()));
    const b = take(right.derive_key(5, label, new Uint8Array()));
    const x = a.export_for_protocol(), y = b.export_for_protocol();
    const same = hex(x) === hex(y); x.fill(0); y.fill(0);
    if (!same) throw new Error('Actual KEM roundtrip differs');
    return state();
  } finally { for (const value of values.reverse()) { value.close(); value.free(); } }
}
function cut(label) {
  if (typeof DedicatedWorkerGlobalScope !== 'function' || !(globalThis instanceof DedicatedWorkerGlobalScope)) throw new Error('Worker cut required');
  postMessage({ cut: label });
  // The controller terminates this dedicated test Worker at the observed boundary.
  // If termination fails, return a failed test instead of an apparent successful cut.
  const deadline = performance.now() + 3000;
  while (performance.now() < deadline) { /* bounded deliberate process-cut window */ }
  throw new Error('Controller did not terminate Worker');
}
export async function run(command, name, extra) {
  try {
    const [initial, disabled, enabled] = await fixtures;
    if (command === 'create' || command === 'open') {
      if (owner) throw new Error('Test owner already held');
      owner = command === 'create' ? await QPeriaptPolicyStore.create({ name, ...initial })
        : await QPeriaptPolicyStore.open({ name, root: initial.root });
      return { ok: true, ...state() };
    }
    if (command === 'close') { if (owner) await owner.close(); owner = undefined; return { ok: true }; }
    if (command === 'state') return { ok: true, ...state() };
    if (command === 'crypto') return { ok: true, ...cryptography() };
    if (command === 'corrupt') {
      const db = await new Promise((resolve, reject) => {
        const request = indexedDB.open(`qperiapt-sdk-policy/1/${name}`, 1);
        request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error);
      });
      try {
        await new Promise((resolve, reject) => {
          const tx = db.transaction('policy', 'readwrite', { durability: 'strict' });
          tx.oncomplete = resolve; tx.onabort = () => reject(tx.error);
          const store = tx.objectStore('policy'), read = store.get('current');
          read.onsuccess = () => { const value = read.result; value.signature[0] ^= 1; store.put(value, 'current'); };
        });
      } finally { db.close(); }
      return { ok: true };
    }
    const target = extra === 'enable' ? enabled : disabled;
    const expected = owner.trustedState(), signature = target.signature.slice();
    if (command === 'invalid') signature[0] ^= 1;
    if (command === 'stale') expected[0] ^= 1;
    const oldTransaction = IDBDatabase.prototype.transaction, oldPut = IDBObjectStore.prototype.put;
    if (command === 'abort' || command === 'cut-commit') {
      IDBDatabase.prototype.transaction = function (...args) {
        const tx = oldTransaction.apply(this, args);
        if (args[1] === 'readwrite') {
          if (command === 'abort') queueMicrotask(() => tx.abort());
          else tx.addEventListener('complete', () => cut('committed'));
        }
        return tx;
      };
    }
    if (command === 'cut-write') {
      IDBObjectStore.prototype.put = function (...args) {
        const request = oldPut.apply(this, args);
        request.addEventListener('success', () => cut('request-success'));
        return request;
      };
    }
    try {
      const key = owner.isEnabled() ? owner.generateKey() : undefined;
      try {
        const change = owner.replacePolicy(expected, target.policy, signature);
        const closing = command === 'close-update' ? owner.close() : undefined;
        try { await change; } finally { if (closing) await closing; }
        let revoked = !key;
        if (key) { try { key.public_key(); } catch (error) { revoked = /closed/.test(error.message); } }
        if (!revoked) throw new Error('Old key still admitted after replacement');
        return { ok: true, revoked, ...state() };
      } finally { if (key) { key.close(); key.free(); } }
    } finally {
      IDBDatabase.prototype.transaction = oldTransaction; IDBObjectStore.prototype.put = oldPut;
    }
  } catch (error) { return { ok: false, code: error.code ?? null, name: error.name, message: error.message }; }
}
