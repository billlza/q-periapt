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

// A timeout cannot cancel an IndexedDB open, and abort() is not an abort receipt.
// Keep the bounded caller result separate from actual native I/O settlement.
function pendingOperation(onTimeout) {
  let resolve, reject, acknowledge, delivered = false, finished = false;
  const result = new Promise((yes, no) => { resolve = yes; reject = no; });
  const settled = new Promise(yes => { acknowledge = yes; });
  const timer = setTimeout(onTimeout, DEADLINE);
  const deliver = (error, value) => {
    if (delivered) return;
    delivered = true; clearTimeout(timer);
    if (error) reject(error); else resolve(value);
  };
  return {
    result, settled, deliver,
    get delivered() { return delivered; },
    finish(error, value) {
      if (finished) return;
      finished = true; deliver(error, value); acknowledge();
    }
  };
}
/** Bound the caller's wait while the underlying cleanup and lease remain owned. */
export function closeReceipt(promise) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(fail('ClosePending')), DEADLINE);
    promise.then(value => { clearTimeout(timer); resolve(value); },
      error => { clearTimeout(timer); reject(error); });
  });
}
export function openDatabase(name, initial) {
  let created = false, failure, request;
  const pending = pendingOperation(() => {
    failure = fail('OpenUnknown');
    try { request?.transaction?.abort(); }
    catch (cause) { failure = fail('OpenUnknown', cause); }
    pending.deliver(failure);
  });
  try {
    request = indexedDB.open(name, 1);
    request.onblocked = () => { failure = fail('Busy'); pending.deliver(failure); };
    request.onupgradeneeded = event => {
      if (pending.delivered || !initial || event.oldVersion !== 0) {
        failure ??= fail(initial ? 'Exists' : 'Absent'); request.transaction.abort(); return;
      }
      created = true;
      const transaction = request.transaction;
      transaction.onerror = event => { failure ??= storageFailure(event.target.error ?? transaction.error); };
      transaction.onabort = () => { if (transaction.error) failure ??= storageFailure(transaction.error); };
      try { request.result.createObjectStore('policy').add(initial, 'current'); }
      catch (error) { failure = storageFailure(error); transaction.abort(); }
    };
    request.onerror = () => pending.finish(failure ?? storageFailure(request.error));
    request.onsuccess = () => {
      const db = request.result;
      if (pending.delivered || (initial && !created)) {
        db.close(); pending.finish(failure ?? fail('Exists')); return;
      }
      if (db.version !== 1 || db.objectStoreNames.length !== 1 || !db.objectStoreNames.contains('policy')) {
        db.close(); pending.finish(fail('Corrupt')); return;
      }
      pending.finish(undefined, db);
    };
  } catch (error) { pending.finish(storageFailure(error)); }
  return pending;
}
/** Result has a deadline; settled resolves only on the native terminal event. */
export function imageTransaction(db, replacement, check) {
  let tx, result, failure;
  const pending = pendingOperation(() => {
    failure = fail('CommitUnknown');
    try { tx?.abort(); } catch (error) { failure = fail('CommitUnknown', error); }
    pending.deliver(failure);
  });
  const abort = error => {
    failure = error;
    if (!tx) { pending.finish(failure); return; }
    try { tx.abort(); }
    catch (cause) {
      failure = fail('CommitUnknown', new AggregateError([error, cause]));
      pending.deliver(failure);
    }
  };
  try {
    // Reopening also seals the original image: creation may have committed its
    // upgrade transaction but lost the strict completion barrier.
    tx = db.transaction('policy', 'readwrite', { durability: 'strict' });
    tx.oncomplete = () => pending.finish(failure, result);
    tx.onabort = () => pending.finish(failure ?? storageFailure(tx.error ?? new DOMException('transaction aborted', 'AbortError')));
    tx.onerror = event => { failure ??= storageFailure(event.target.error ?? tx.error); };
    if (tx.durability !== 'strict') { abort(fail('Unavailable')); return pending; }
    const store = tx.objectStore('policy');
    if (store.keyPath !== null || store.autoIncrement) { abort(fail('Corrupt')); return pending; }
    const request = store.getAllKeys(undefined, 2);
    request.onsuccess = () => {
      if (pending.delivered) return;
      if (request.result.length !== 1 || request.result[0] !== 'current') { abort(fail('Corrupt')); return; }
      const read = store.get('current');
      read.onsuccess = () => {
        if (pending.delivered) return;
        try {
          result = check(read.result);
          store.put(replacement ?? result, 'current');
        } catch (error) { abort(error); }
      };
    };
  } catch (error) {
    abort(error instanceof QPeriaptStorageError ? error : fail('Storage', error));
  }
  return pending;
}
