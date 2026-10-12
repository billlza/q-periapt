// SPDX-License-Identifier: Apache-2.0 OR MIT
// Browser persistence only. This module performs no policy or protocol decisions.
export class QPeriaptStorageError extends Error {
  constructor(code, cause) {
    super(`Q-Periapt browser storage: ${code}`, { cause });
    this.name = 'QPeriaptStorageError';
    this.code = code;
  }
}
const fail = (code, cause) => new QPeriaptStorageError(code, cause);
const storageFailure = cause => fail(cause?.name === 'QuotaExceededError' ? 'QuotaExceeded'
  : cause?.name === 'AbortError' ? 'Aborted' : 'Storage', cause);
const DEADLINE = 10000;
export function capabilities() {
  if (!globalThis.isSecureContext || !globalThis.indexedDB
      || typeof globalThis.navigator?.locks?.request !== 'function') throw fail('Unavailable');
}
export async function lease(name) {
  capabilities();
  let admit, deny, release;
  const ready = new Promise((resolve, reject) => { admit = resolve; deny = reject; });
  const held = navigator.locks.request(name, { mode: 'exclusive', ifAvailable: true }, async lock => {
    if (!lock) throw fail('Busy');
    await new Promise(resolve => { release = resolve; admit(); });
  });
  // Admission failures go to ready. Once admitted, held remains the release receipt.
  held.catch(deny);
  await ready;
  return async () => { release(); await held; };
}
export function openDatabase(name, initial) {
  return new Promise((resolve, reject) => {
    let settled = false, created = false, failure;
    const request = indexedDB.open(name, 1);
    const timer = setTimeout(() => finish(fail('OpenUnknown')), DEADLINE);
    function finish(error, db) {
      if (settled) { if (db) db.close(); return; }
      settled = true; clearTimeout(timer);
      if (error) { if (db) db.close(); reject(error); } else resolve(db);
    }
    request.onblocked = () => finish(fail('Busy'));
    request.onupgradeneeded = event => {
      if (settled || !initial || event.oldVersion !== 0) {
        failure = fail(initial ? 'Exists' : 'Absent'); request.transaction.abort(); return;
      }
      created = true;
      const transaction = request.transaction;
      transaction.onerror = event => { failure ??= storageFailure(event.target.error ?? transaction.error); };
      transaction.onabort = () => { if (transaction.error) failure ??= storageFailure(transaction.error); };
      try { request.result.createObjectStore('policy').add(initial, 'current'); }
      catch (error) { failure = storageFailure(error); transaction.abort(); }
    };
    request.onerror = () => finish(failure ?? storageFailure(request.error));
    request.onsuccess = () => {
      const db = request.result;
      if (initial && !created) { finish(fail('Exists'), db); return; }
      if (db.version !== 1 || db.objectStoreNames.length !== 1 || !db.objectStoreNames.contains('policy')) {
        finish(fail('Corrupt'), db); return;
      }
      finish(undefined, db);
    };
  });
}
/** Resolve only on transaction completion, never on a request's success event. */
export function imageTransaction(db, replacement, check) {
  return new Promise((resolve, reject) => {
    let tx, result, failure, settled = false;
    const finish = (error) => {
      if (settled) return;
      settled = true; clearTimeout(timer);
      if (error) reject(error); else resolve(result);
    };
    const timer = setTimeout(() => {
      failure = fail('CommitUnknown');
      try { tx?.abort(); } catch (error) { failure = fail('CommitUnknown', error); }
      finish(failure);
    }, DEADLINE);
    try {
      // Reopening also seals the original image: a prior creation may have
      // committed its upgrade transaction but lost the strict completion barrier.
      tx = db.transaction('policy', 'readwrite', { durability: 'strict' });
      tx.oncomplete = () => finish(failure);
      tx.onabort = () => finish(failure ?? fail(tx.error?.name === 'QuotaExceededError' ? 'QuotaExceeded' : 'Aborted', tx.error));
      tx.onerror = event => {
        const cause = event.target.error ?? tx.error;
        failure ??= storageFailure(cause);
      };
      if (tx.durability !== 'strict') { failure = fail('Unavailable'); tx.abort(); return; }
      const store = tx.objectStore('policy');
      if (store.keyPath !== null || store.autoIncrement) { failure = fail('Corrupt'); tx.abort(); return; }
      const request = store.getAllKeys(undefined, 2);
      request.onsuccess = () => {
        if (request.result.length !== 1 || request.result[0] !== 'current') { failure = fail('Corrupt'); tx.abort(); return; }
        const read = store.get('current');
        read.onsuccess = () => {
          try {
            result = check(read.result);
            store.put(replacement ?? result, 'current');
          } catch (error) { failure = error; tx.abort(); }
        };
      };
    } catch (error) {
      failure = error instanceof QPeriaptStorageError ? error : fail('Storage', error);
      if (tx) tx.abort(); else finish(failure);
    }
  });
}
