// SPDX-License-Identifier: Apache-2.0 OR MIT
// IndexedDB policy image operations; caller results and native receipts stay distinct.
import { QPeriaptStorageError, pendingOperation } from './storage-io.js';
export { QPeriaptStorageError, capabilities, lease, closeReceipt } from './storage-io.js';
const fail = (code, cause) => new QPeriaptStorageError(code, cause);
const storageFailure = cause => fail(cause?.name === 'QuotaExceededError' ? 'QuotaExceeded'
  : cause?.name === 'AbortError' ? 'Aborted' : 'Storage', cause);
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
