// SPDX-License-Identifier: Apache-2.0 OR MIT
import initialize, { QPeriaptRuntime } from './index.js';
import { QPeriaptStorageError, lease, openDatabase, imageTransaction, closeReceipt } from './policy-database.js';
export { QPeriaptStorageError } from './policy-database.js';
const fail = (code, cause) => new QPeriaptStorageError(code, cause);
async function afterCleanup(error, cleanup) {
  try { await closeReceipt(cleanup); }
  catch (cause) { throw fail(error.code ?? 'Storage', new AggregateError([error, cause])); }
  throw error;
}
const equal = (a, b) => a.length === b.length && a.every((value, i) => value === b[i]);
function bytes(value, min, max) {
  if (!(value instanceof Uint8Array) || value.length < min || value.length > max) throw new TypeError('Invalid policy bytes');
  return value.slice();
}
function inputs(options) {
  const { name, root, maxKeys = 16, maxInFlight = 4 } = options;
  if (typeof name !== 'string' || !/^[A-Za-z0-9._-]{1,128}$/.test(name)) throw new TypeError('Invalid store name');
  if (!Number.isInteger(maxKeys) || maxKeys < 1 || maxKeys > 1024
      || !Number.isInteger(maxInFlight) || maxInFlight < 1 || maxInFlight > 64) throw new TypeError('Invalid runtime limits');
  return { name: `qperiapt-sdk-policy/1/${name}`, root: bytes(root, 1952, 1952), maxKeys, maxInFlight };
}
function image(value) {
  if (!value || Object.keys(value).sort().join(',') !== 'policy,root,schema,signature,state' || value.schema !== 1) throw fail('Corrupt');
  try {
    return { schema: 1, root: bytes(value.root, 1952, 1952), policy: bytes(value.policy, 1, 65536),
      signature: bytes(value.signature, 3309, 3309), state: bytes(value.state, 36, 36) };
  } catch (cause) { throw new QPeriaptStorageError('Corrupt', cause); }
}
function same(a, b) { return ['root', 'policy', 'signature', 'state'].every(key => equal(a[key], b[key])); }
function destroy(runtime) { if (runtime) { runtime.close(); runtime.free(); } }
const owned = Symbol('policy-store-owner');

/** Exclusive origin-local policy owner. No runtime or update capability escapes. */
export class QPeriaptPolicyStore {
  #runtime; #image; #db; #release; #closed = false; #busy = false; #pending; #closing; #closeError;
  constructor(token, runtime, current, db, release) {
    if (token !== owned) throw new TypeError('Use create or open');
    this.#runtime = runtime; this.#image = current; this.#db = db; this.#release = release;
    const invalidate = () => { this.close().catch(error => { this.#closeError = error; }); };
    db.onversionchange = invalidate;
    db.onclose = invalidate;
  }
  static async create(options) {
    const selected = inputs(options), policy = bytes(options.policy, 1, 65536), signature = bytes(options.signature, 3309, 3309);
    await initialize();
    const runtime = new QPeriaptRuntime(policy, signature, selected.root, new Uint8Array(), selected.maxKeys, selected.maxInFlight);
    const initial = { schema: 1, root: selected.root, policy, signature, state: runtime.trusted_state() };
    return this.#acquire(selected, initial, runtime);
  }
  static async open(options) {
    const selected = inputs(options);
    await initialize();
    return this.#acquire(selected);
  }
  static async #acquire(selected, initial, runtime) {
    let release, db, pending;
    try {
      release = await lease(selected.name);
      const opening = openDatabase(selected.name, initial);
      pending = opening.settled;
      db = await opening.result;
      // Upgrade transactions have no selectable durability. Creation uses a second
      // strict transaction before exposing the already verified runtime.
      const reading = imageTransaction(db, initial, raw => {
        const value = image(raw);
        if (!equal(value.root, selected.root)) throw fail('RootMismatch');
        if (initial && !same(value, initial)) throw fail('Stale');
        runtime ??= new QPeriaptRuntime(value.policy, value.signature, selected.root, value.state, selected.maxKeys, selected.maxInFlight);
        if (!equal(runtime.trusted_state(), value.state)) throw fail('Corrupt');
        return value;
      });
      pending = reading.settled;
      const current = await reading.result;
      return new QPeriaptPolicyStore(owned, runtime, current, db, release);
    } catch (error) {
      destroy(runtime);
      const cleanup = (async () => {
        if (pending) await pending;
        if (db) db.close();
        if (release) await release();
      })();
      return afterCleanup(error, cleanup);
    }
  }
  #ready() { if (this.#closed) throw fail('Closed', this.#closeError); if (this.#busy) throw fail('Busy'); }
  trustedState() { this.#ready(); return this.#runtime.trusted_state(); }
  isEnabled() { this.#ready(); return this.#runtime.is_enabled(); }
  generateKey() { this.#ready(); return this.#runtime.generate_key(); }
  encapsulate(publicKey, context) { this.#ready(); return this.#runtime.encapsulate(publicKey, context); }
  async replacePolicy(expected, policy, signature) {
    this.#ready();
    expected = bytes(expected, 36, 36); policy = bytes(policy, 1, 65536); signature = bytes(signature, 3309, 3309);
    if (!equal(expected, this.#image.state)) throw fail('Stale');
    const update = this.#runtime.prepare_policy_update(policy, signature);
    this.#busy = true;
    try {
      const pair = update.states();
      if (!equal(pair.subarray(0, 36), expected)) throw fail('Stale');
      const next = { schema: 1, root: this.#image.root, policy, signature, state: pair.slice(36) };
      const writing = imageTransaction(this.#db, next, raw => {
        if (!same(image(raw), this.#image)) throw fail('Stale');
      });
      this.#pending = writing.settled;
      await writing.result;
      if (this.#closed) throw fail('Closed');
      const runtime = update.activate_after_persist();
      destroy(this.#runtime); this.#runtime = runtime; this.#image = next;
      return next.state.slice();
    } catch (error) {
      return afterCleanup(error, this.close());
    } finally {
      this.#busy = false; this.#pending = undefined; update.close(); update.free();
    }
  }
  /** Immediately revoke keys; release the cross-tab lease only after pending I/O settles. */
  close() {
    if (this.#closing) return closeReceipt(this.#closing);
    this.#closed = true; destroy(this.#runtime); this.#runtime = undefined;
    this.#closing = (async () => {
      // The result retains its error; only the actual I/O receipt permits release.
      if (this.#pending) await this.#pending;
      this.#db.close(); await this.#release();
    })();
    return closeReceipt(this.#closing);
  }
}
