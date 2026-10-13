// SPDX-License-Identifier: Apache-2.0 OR MIT
import { lease, pendingOperation, closeReceipt } from './storage-io.js';
import { fail, ioError, hex, identifier, prefix, scoped, describe, matches,
  metadata, validateState, sealState, unsealState, encryptSecret, secretAAD } from './storage-catalogue.js';
import { openDatabase, transaction, admitSnapshot } from './storage-database.js';
import { StorageOpening } from './storage-opening.js';
export { StorageOpening } from './storage-opening.js';

const owned = Symbol('browser-storage-owner');
const MAX_DB = 64 * 1024 * 1024;
function extent(offset, length) {
  if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(length) || offset < 0 || length < 0
      || offset + length > MAX_DB) throw fail('Capacity');
}
function inputs(name, id, binding) {
  if (!isSecureContext || typeof DedicatedWorkerGlobalScope !== 'function'
      || !(self instanceof DedicatedWorkerGlobalScope) || !crypto.subtle || !navigator.storage?.getDirectory) throw fail('Unavailable');
  if (typeof name !== 'string' || !/^[a-zA-Z0-9_-]{1,96}$/.test(name)
      || typeof id !== 'string' || !/^[a-f0-9]{64}$/.test(id) || /^0+$/.test(id)
      || !(binding instanceof Uint8Array) || binding.length < 1 || binding.length > 8192) throw new TypeError('Invalid original storage inputs');
  return binding.slice();
}
async function failedAfterClose(error, root) {
  try { await root.close(); }
  catch (cleanup) { throw fail(error.code ?? 'Storage', new AggregateError([error, cleanup])); }
  throw error;
}
export class SecretLease {
  #bytes; #release;
  constructor(token, bytes, release) {
    if (token !== owned) throw new TypeError('Owned secret lease');
    this.#bytes = new Uint8Array(bytes); this.#release = release;
  }
  bytes() { if (!this.#bytes) throw fail('Closed'); return this.#bytes; }
  close() {
    if (this.#bytes) { this.#bytes.fill(0); this.#bytes = undefined; this.#release(this); }
  }
}
export class DatabaseLease {
  #root; #handle; #path; #id; #published;
  constructor(token, root, handle, path, id, published) {
    if (token !== owned) throw new TypeError('Owned database lease');
    this.#root = root; this.#handle = handle; this.#path = path; this.#id = id; this.#published = published;
  }
  #check() { if (!this.#handle) throw fail('Closed'); this.#root.check(); }
  getSize() { this.#check(); const size = this.#handle.getSize(); extent(0, size); return size; }
  read(offset, out) {
    this.#check(); if (!(out instanceof Uint8Array)) throw new TypeError('Read buffer');
    extent(offset, out.length); return this.#handle.read(out, { at: offset });
  }
  write(offset, bytes) {
    this.#check(); if (!(bytes instanceof Uint8Array)) throw new TypeError('Write buffer');
    extent(offset, bytes.length); return this.#handle.write(bytes, { at: offset });
  }
  resize(size) { this.#check(); extent(0, size); this.#handle.truncate(size); }
  flush() { this.#check(); this.#handle.flush(); }
  publication(root, path) {
    this.#check(); if (root !== this.#root || path !== this.#path || this.#published) throw fail('Conflict');
    return this.#id;
  }
  markPublished() { this.#check(); this.#published = true; }
  retainedFile(root) {
    this.#check(); if (root !== this.#root) throw fail('Conflict');
    return 'db-' + this.#id;
  }
  close() {
    if (!this.#handle) return;
    const handle = this.#handle; this.#handle = undefined;
    try { handle.close(); } finally { this.#root.released(this, this.#path); }
  }
}
export class StorageRoot {
  #name; #id; #binding; #release; #db; #directory; #meta; #state;
  #signal = new AbortController(); #closed = false; #busy = false; #pending; #closing; #closeError;
  #receipts = new Set(); #children = new Set(); #paths = new Set();
  constructor(token, name, id, binding, release) {
    if (token !== owned) throw new TypeError('Use create, open or resume');
    this.#name = name; this.#id = id; this.#binding = binding; this.#release = release;
  }
  static beginCreate(name, id, binding, wrapping) {
    const original = inputs(name, id, binding);
    if (!(wrapping instanceof Uint8Array) || wrapping.length !== 40
        || new TextDecoder().decode(wrapping.subarray(0, 8)) !== 'QPVKEY01') throw new TypeError('Original wrapping key encoding');
    const copy = wrapping.slice();
    return new StorageOpening(async capture => {
      try { return await StorageRoot.#acquire(name, id, original, copy, false, capture); }
      finally { copy.fill(0); }
    });
  }
  static beginOpen(name, id, binding) {
    const original = inputs(name, id, binding);
    return new StorageOpening(capture => StorageRoot.#acquire(name, id, original, undefined, false, capture));
  }
  static beginResume(name, id, binding) {
    const original = inputs(name, id, binding);
    return new StorageOpening(capture => StorageRoot.#acquire(name, id, original, undefined, true, capture));
  }
  static async #finish(opening) {
    try { await opening.ready(); return opening.take(); }
    finally { opening.abandon(); }
  }
  static async create(name, id, binding, wrapping) {
    return StorageRoot.#finish(StorageRoot.beginCreate(name, id, binding, wrapping));
  }
  static async open(name, id, binding) { return StorageRoot.#finish(StorageRoot.beginOpen(name, id, binding)); }
  static async resume(name, id, binding) { return StorageRoot.#finish(StorageRoot.beginResume(name, id, binding)); }
  static async #acquire(name, id, binding, wrapping, resume, capture) {
    const release = await lease('qperiapt-continuity-storage/2/' + name);
    const root = new StorageRoot(owned, name, id, binding, release);
    try {
      capture(root);
      await root.#run(() => root.#initialize(wrapping, resume), 'OpenUnknown');
      return root;
    } catch (error) { return failedAfterClose(error, root); }
  }
  async #io(operation) {
    this.#receipts.add(operation.settled);
    operation.settled.then(() => this.#receipts.delete(operation.settled));
    return operation.result;
  }
  #transaction(operation, strict = true) {
    return this.#io(transaction(this.#db, this.#signal.signal, operation, strict));
  }
  async #initialize(wrapping, resume) {
    let initial;
    if (wrapping) {
      const parent = await navigator.storage.getDirectory(); this.check();
      let exists = false;
      try { await parent.getDirectoryHandle('qpc-v2-' + this.#name + '-' + this.#id); exists = true; }
      catch (error) { if (error.name !== 'NotFoundError') throw error; }
      this.check(); if (exists) throw fail('Exists');
      // Root key, exact original intent and wrapping ciphertext publish atomically.
      const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']); this.check();
      const path = this.prefix() + 'wrap.key';
      const sealed = await encryptSecret(key, this.#id, path, wrapping); this.check();
      const state = { binding: hex(this.#binding), files: [[path, describe(sealed)]], phase: 'creating', revision: 1 };
      const meta = await sealState(key, this.#name, this.#id, state); this.check();
      initial = { meta, path, wrapping: sealed };
    }
    this.#db = await this.#io(openDatabase('qperiapt-continuity-storage/2/' + this.#name, initial)); this.check();
    const invalidate = () => this.beginClose();
    this.#db.onversionchange = invalidate; this.#db.onclose = invalidate;
    const snapshot = await this.#transaction(({ root, paths, done }) => done({ root, paths }), false); this.check();
    this.#meta = metadata(snapshot.root, this.#id);
    this.#state = await unsealState(this.#meta, this.#name, this.#id, this.#binding); this.check();
    admitSnapshot(this.#meta, snapshot.paths, this.#meta, this.#state);
    if (!wrapping && !resume && this.#state.phase !== 'ready') throw fail('InitializationPending');
    // Only authenticated original creation can reconstruct an unpublished OPFS directory.
    const expected = new Set(this.#state.files.filter(pair => pair[1].kind === 'database').map(pair => 'db-' + pair[1].id));
    const parent = await navigator.storage.getDirectory(); this.check();
    try {
      this.#directory = await parent.getDirectoryHandle('qpc-v2-' + this.#name + '-' + this.#id,
        { create: this.#state.phase === 'creating' && expected.size === 0 });
    } catch (cause) { throw fail(cause.name === 'NotFoundError' ? 'Absent' : 'Storage', cause); }
    this.check();
    if (this.#state.phase === 'creating' || resume) await this.#removeUnpublished();
    await this.#transaction(({ root, paths, roots, done }) => {
      admitSnapshot(root, paths, this.#meta, this.#state); roots.put(this.#meta, 'current'); done();
    });
  }
  prefix() { this.check(); return prefix(this.#name, this.#id); }
  check() { if (this.#closed) throw fail('Closed', this.#closeError); }
  async #removeUnpublished() {
    // The authenticated catalogue is append-only: every published database is
    // retained there. Preserve live staging handles as well as committed files.
    const retained = new Set(this.#state.files.filter(pair => pair[1].kind === 'database').map(pair => 'db-' + pair[1].id));
    for (const child of this.#children) if (child instanceof DatabaseLease) retained.add(child.retainedFile(this));
    const present = new Set();
    for await (const [name, entry] of this.#directory.entries()) {
      this.check();
      if (present.size >= 256) throw fail('Capacity');
      if (entry.kind !== 'file' || !/^db-[a-f0-9]{64}$/.test(name)) throw fail('Corrupt');
      present.add(name);
    }
    // Validate the entire inventory before deleting any uncommitted staging.
    if ([...retained].some(name => !present.has(name))) throw fail('Absent');
    for (const name of present) if (!retained.has(name)) {
      await this.#directory.removeEntry(name); this.check();
    }
    return retained.size;
  }
  #path(path) { this.check(); return scoped(path, this.#name, this.#id); }
  #run(operation, code = 'CommitUnknown') {
    this.check(); if (this.#busy) throw fail('Busy'); this.#busy = true;
    const pending = pendingOperation(() => {
      this.#closed = true; this.#signal.abort(); pending.deliver(fail(code)); this.beginClose();
    });
    this.#pending = pending.settled;
    const task = (async () => { const value = await operation(); this.check(); return value; })();
    const finish = (error, value) => {
      // An awaiting caller may start the next operation as soon as it receives
      // the result. Clear only this operation's state before delivering it.
      this.#busy = false; this.#pending = undefined;
      pending.finish(error, value);
      if (error) this.beginClose();
    };
    task.then(value => finish(undefined, value), error => finish(ioError(error)));
    return pending.result;
  }
  async #lookup(path) {
    return this.#transaction(({ root, paths, roots, files, checked, done }) => {
      admitSnapshot(root, paths, this.#meta, this.#state);
      const request = files.get(path);
      request.onsuccess = checked(() => {
        const value = matches(request.result, new Map(this.#state.files).get(path));
        roots.put(this.#meta, 'current'); done(value);
      });
    });
  }
  async #publish(path, record) {
    if (this.#state.files.length >= 256 || this.#state.revision >= Number.MAX_SAFE_INTEGER) throw fail('Capacity');
    const state = { ...this.#state, files: [...this.#state.files, [path, describe(record)]].sort((a, b) => a[0] < b[0] ? -1 : 1), revision: this.#state.revision + 1 };
    validateState(state, this.#name, this.#id, this.#binding);
    const meta = await sealState(this.#meta.key, this.#name, this.#id, state); this.check();
    await this.#transaction(({ root, paths, roots, files, done }) => {
      admitSnapshot(root, paths, this.#meta, this.#state);
      files.add(record, path); roots.put(meta, 'current'); done();
    });
    this.#meta = meta; this.#state = state;
  }
  missing(path) { path = this.#path(path); return this.#run(async () => await this.#lookup(path) === null); }
  creationReady() { this.check(); return this.#state.phase === 'ready'; }
  finishCreation() {
    return this.#run(async () => {
      if (this.#state.phase === 'ready') return;
      if (this.#state.revision >= Number.MAX_SAFE_INTEGER) throw fail('Capacity');
      const state = { ...this.#state, phase: 'ready', revision: this.#state.revision + 1 };
      validateState(state, this.#name, this.#id, this.#binding);
      const meta = await sealState(this.#meta.key, this.#name, this.#id, state); this.check();
      await this.#transaction(({ root, paths, roots, done }) => {
        admitSnapshot(root, paths, this.#meta, this.#state); roots.put(meta, 'current'); done();
      });
      this.#meta = meta; this.#state = state;
    });
  }
  async publishSecret(path, bytes) {
    path = this.#path(path);
    if (!(bytes instanceof Uint8Array) || bytes.length < 1 || bytes.length > 65536) throw new TypeError('Secret width');
    const copy = bytes.slice();
    try { return this.#run(async () => {
      try {
        if (await this.#lookup(path) !== null) throw fail('Exists');
        const value = await encryptSecret(this.#meta.key, this.#id, path, copy); this.check();
        await this.#publish(path, value);
      } finally { copy.fill(0); }
    }); } catch (error) { copy.fill(0); throw error; }
  }
  readSecret(path) {
    path = this.#path(path);
    return this.#run(async () => {
      if (this.#children.size >= 64) throw fail('Capacity');
      const value = await this.#lookup(path);
      if (value === null) throw fail('Absent'); if (value.kind !== 'bytes') throw fail('Corrupt');
      let plain;
      try { plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: value.iv,
        additionalData: secretAAD(this.#id, path, value) }, this.#meta.key, value.data); }
      catch (cause) { throw fail('Authentication', cause); }
      if (this.#closed) { new Uint8Array(plain).fill(0); throw fail('Closed'); }
      const result = new SecretLease(owned, plain, child => this.#children.delete(child));
      this.#children.add(result); return result;
    });
  }
  released(child, path) { this.#children.delete(child); if (path) this.#paths.delete(path); }
  async #openHandle(file, path, id, published) {
    const handle = await file.createSyncAccessHandle();
    const result = new DatabaseLease(owned, this, handle, path, id, published);
    this.#children.add(result); this.#paths.add(path);
    try {
      const size = result.getSize();
      if (published ? size < 16 : size !== 0) throw fail('Corrupt'); return result;
    } catch (error) { result.close(); throw error; }
  }
  stageDatabase(path) {
    path = this.#path(path);
    return this.#run(async () => {
      if (await this.#lookup(path) !== null) throw fail('Exists');
      if (this.#paths.has(path)) throw fail('Busy'); if (this.#children.size >= 64) throw fail('Capacity');
      if (await this.#removeUnpublished() >= 256 || this.#state.files.length >= 256) throw fail('Capacity');
      for (let attempt = 0; attempt < 4; attempt++) {
        const id = identifier(); let missing = false;
        try { await this.#directory.getFileHandle('db-' + id); }
        catch (error) { if (error.name !== 'NotFoundError') throw error; missing = true; }
        this.check();
        if (missing) {
          const file = await this.#directory.getFileHandle('db-' + id, { create: true }); this.check();
          return this.#openHandle(file, path, id, false);
        }
      }
      throw fail('Capacity');
    });
  }
  openDatabase(path) {
    path = this.#path(path);
    return this.#run(async () => {
      if (this.#paths.has(path)) throw fail('Busy'); if (this.#children.size >= 64) throw fail('Capacity');
      const value = await this.#lookup(path);
      if (value === null) throw fail('Absent'); if (value.kind !== 'database') throw fail('Corrupt');
      let file;
      try { file = await this.#directory.getFileHandle('db-' + value.id); }
      catch (error) { throw fail(error.name === 'NotFoundError' ? 'Absent' : 'Storage', error); }
      this.check(); return this.#openHandle(file, path, value.id, true);
    });
  }
  publishDatabase(path, file) {
    path = this.#path(path);
    return this.#run(async () => {
      if (!(file instanceof DatabaseLease) || !this.#children.has(file)) throw fail('Conflict');
      const id = file.publication(this, path); if (file.getSize() < 16) throw fail('Corrupt'); file.flush();
      await this.#publish(path, { kind: 'database', id, revision: 1 }); file.markPublished();
    });
  }
  close() {
    this.#closed = true; this.#signal.abort();
    if (!this.#closing) this.#closing = (async () => {
      if (this.#pending) await this.#pending;
      await Promise.all([...this.#receipts]);
      const failures = [];
      for (const child of [...this.#children]) { try { child.close(); } catch (error) { failures.push(error); } }
      this.#meta = undefined; this.#state = undefined; this.#binding.fill(0);
      this.#db?.close(); await this.#release();
      if (failures.length) throw fail('Storage', new AggregateError(failures));
    })();
    return closeReceipt(this.#closing);
  }
  beginClose() { this.close().catch(error => { this.#closeError = error; }); }
}

// Preserve both primary failure and cleanup status across the WASM error boundary.
export function combineFailures(primary, cleanup) {
  return fail(primary.code ?? 'NativeFailure', new AggregateError([primary, cleanup]));
}

// Machine-readable classification supplements, rather than replaces, the original
// error and its cleanup/receipt chain. Closed says nothing about commit outcome.
export function continuityFailure(code, original, ownerClosed) {
  const value = new Error(typeof original?.message === 'string' ? original.message : String(original), { cause: original });
  value.name = typeof original?.name === 'string' ? original.name : 'Error';
  Object.defineProperty(value, 'code', { value: typeof original?.code === 'string' ? original.code : code, enumerable: true });
  if (ownerClosed !== undefined) Object.defineProperty(value, 'ownerClosed', { value: ownerClosed, enumerable: true });
  return value;
}

// Host input/callback values can have throwing getters or coercion hooks. Keep
// the original cause without inspecting it while a Rust owner is borrowed.
export function continuityInputFailure(code, original) {
  const value = new Error(code, { cause: original });
  Object.defineProperty(value, 'code', { value: code, enumerable: true });
  return value;
}
