// SPDX-License-Identifier: Apache-2.0 OR MIT
import init, { BrowserEnrollmentProbe } from '../pkg/q_periapt_continuity_identity_candidate.js';
import { lease } from '../pkg/storage-io.js';
await init();
const hex = bytes => [...bytes].map(value => value.toString(16).padStart(2, '0')).join('');
const sha = async bytes => hex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));
const required = (condition, text) => { if (!condition) throw Error(text); };
const observed = async operation => { try { return { ok: true, value: await operation }; } catch (error) { return { ok: false, error: String(error) }; } };
async function input(name) {
  const response = await fetch('/inputs/' + name); required(response.ok, 'public input fetch');
  return new Uint8Array(await response.arrayBuffer());
}
const root = await input('root.bin'), description = await input('description.bin');
function cut(boundary) {
  postMessage({ cut: boundary });
  const until = performance.now() + 3000;
  while (performance.now() < until) { /* Controller must terminate this real Worker. */ }
  throw Error('Worker cut was not executed');
}
function instrument(boundary) {
  const restores = [];
  if (boundary === 'root-published') {
    const original = IDBFactory.prototype.open;
    IDBFactory.prototype.open = function (...args) {
      const request = original.apply(this, args);
      request.addEventListener('success', () => cut(boundary), { once: true }); return request;
    };
    restores.push(() => { IDBFactory.prototype.open = original; });
  } else if (boundary === 'staged-flush') {
    const original = FileSystemSyncAccessHandle.prototype.flush;
    FileSystemSyncAccessHandle.prototype.flush = function (...args) {
      const result = original.apply(this, args); cut(boundary); return result;
    };
    restores.push(() => { FileSystemSyncAccessHandle.prototype.flush = original; });
  } else if (boundary === 'directory-created') {
    const original = FileSystemDirectoryHandle.prototype.getDirectoryHandle;
    FileSystemDirectoryHandle.prototype.getDirectoryHandle = async function (name, options) {
      const result = await original.call(this, name, options);
      if (options?.create && name.startsWith('qpc-v2-')) cut(boundary); return result;
    };
    restores.push(() => { FileSystemDirectoryHandle.prototype.getDirectoryHandle = original; });
  } else if (boundary) {
    const add = IDBObjectStore.prototype.add, put = IDBObjectStore.prototype.put;
    IDBObjectStore.prototype.add = function (value, key) {
      const result = add.call(this, value, key);
      if (boundary === 'root-before-commit' && this.name === 'files' && value.kind === 'bytes') {
        result.addEventListener('success', () => cut(boundary));
      }
      if (boundary === 'enrollment-published' && this.name === 'files' && value.kind === 'database') {
        this.transaction.addEventListener('complete', () => cut(boundary));
      }
      return result;
    };
    IDBObjectStore.prototype.put = function (value, key) {
      const result = put.call(this, value, key);
      // The ready marker's encrypted catalogue is captured at its creation below.
      if (this.name === 'root' && value.sealed && hex(value.sealed.data) === readyCipher) {
        if (boundary === 'ready-before-commit') result.addEventListener('success', () => cut(boundary));
        if (boundary === 'ready-published') this.transaction.addEventListener('complete', () => cut(boundary));
      }
      return result;
    };
    let readyCipher;
    const encrypt = SubtleCrypto.prototype.encrypt;
    SubtleCrypto.prototype.encrypt = async function (algorithm, key, bytes) {
      const result = await encrypt.call(this, algorithm, key, bytes);
      if (algorithm.additionalData && new TextDecoder().decode(algorithm.additionalData).includes('QPC-BROWSER-CATALOGUE/v2')) {
        const state = JSON.parse(new TextDecoder().decode(bytes));
        if (state.phase === 'ready') readyCipher = hex(new Uint8Array(result));
      }
      return result;
    };
    restores.push(() => { IDBObjectStore.prototype.add = add; IDBObjectStore.prototype.put = put; SubtleCrypto.prototype.encrypt = encrypt; });
  }
  return () => { for (const restore of restores.reverse()) restore(); };
}
async function openFixture(name) {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('qperiapt-continuity-storage/2/' + name, 2);
    request.onupgradeneeded = () => request.transaction.abort();
    request.onerror = () => reject(Error('Absent'));
    request.onsuccess = () => resolve(request.result);
  });
}
async function snapshot(db, mutate) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(['root', 'files'], 'readwrite', { durability: 'strict' });
    let value, rows, paths;
    tx.oncomplete = () => resolve({ value, rows, paths }); tx.onabort = () => reject(tx.error ?? Error('fixture abort'));
    const a = tx.objectStore('root').get('current'), b = tx.objectStore('files').getAll(), c = tx.objectStore('files').getAllKeys();
    let remaining = 3;
    for (const request of [a, b, c]) request.onsuccess = () => {
      if (--remaining) return; value = a.result; rows = b.result; paths = c.result;
      if (mutate) mutate(tx, value, rows, paths);
    };
  });
}
async function inspect(name, id, mutation) {
  const release = await lease('qperiapt-continuity-storage/2/' + name); let db;
  try {
    db = await openFixture(name); const before = await snapshot(db);
    const wrap = before.rows.find((_, i) => before.paths[i].endsWith('/wrap.key'));
    const enrollment = before.rows.find(row => row.kind === 'database');
    const result = { files: before.paths, wrap_sha256: wrap ? await sha(wrap.data) : null, catalogue_sha256: await sha(before.value.sealed.data),
      database_id: enrollment?.id ?? null, vault_extractable: before.value.key.extractable };
    const parent = await navigator.storage.getDirectory();
    const directory = await observed(parent.getDirectoryHandle('qpc-v2-' + name + '-' + id));
    result.opfs_files = [];
    if (directory.ok) for await (const [filename] of directory.value.entries()) result.opfs_files.push(filename);
    result.opfs_files.sort();
    if (mutation) await snapshot(db, (tx, meta, rows, paths) => {
      if (mutation === 'delete-enrollment') {
        const index = rows.findIndex(row => row.kind === 'database'); required(index >= 0, 'published db expected');
        tx.objectStore('files').delete(paths[index]);
      } else if (mutation === 'delete-wrap') {
        const path = paths.find(path => path.endsWith('/wrap.key')); tx.objectStore('files').delete(path);
      } else if (mutation === 'damage-catalogue') {
        const data = meta.sealed.data.slice(); data[0] ^= 1;
        tx.objectStore('root').put({ ...meta, sealed: { ...meta.sealed, data } }, 'current');
      } else throw Error('unknown mutation');
    });
    return result;
  } finally { db?.close(); await release(); }
}
self.onmessage = async ({ data }) => {
  let owner, result, restore = () => {};
  try {
    const { name, id, operation, boundary } = data;
    if (operation === 'inspect') { result = { value: await inspect(name, id, data.mutation) }; return; }
    restore = instrument(boundary);
    const inputDescription = description.slice(); if (data.wrongIntent) inputDescription[0] ^= 1;
    owner = await BrowserEnrollmentProbe[operation](name, id, root, inputDescription);
    if (data.noRequest) { result = { value: { opened: true } }; return; }
    const wire = await owner.request(BigInt(Math.floor(Date.now() / 1000)));
    required(wire.length === 5506, 'request length');
    const digest = await sha(wire);
    if (data.killRequest) { postMessage({ requestDigest: digest }); cut('request-committed'); }
    const again = await owner.request(BigInt(Math.floor(Date.now() / 1000)));
    required(await sha(again) === digest, 'request changed');
    result = { value: { request: [...wire], sha256: digest } };
  } catch (error) { result = { error: String(error) }; }
  finally {
    restore();
    if (owner) {
      try { await owner.close(); owner.free(); }
      catch (error) { result = { error: (result?.error ?? 'operation completed') + '; cleanup: ' + error }; }
    }
    if (result) postMessage({ done: true, ...result });
  }
};
postMessage({ ready: true });
