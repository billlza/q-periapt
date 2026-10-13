// SPDX-License-Identifier: Apache-2.0 OR MIT
import { pendingOperation } from './storage-io.js';
import { fail, ioError, metadata, equal } from './storage-catalogue.js';

export function openDatabase(name, initial) {
  let request, created = false, failure;
  const pending = pendingOperation(() => {
    failure = fail('OpenUnknown');
    try { request?.transaction?.abort(); } catch (cause) { failure = fail('OpenUnknown', cause); }
    pending.deliver(failure);
  });
  try {
    request = indexedDB.open(name, 2);
    request.onblocked = () => { failure = fail('Busy'); pending.deliver(failure); };
    request.onupgradeneeded = event => {
      if (pending.delivered || !initial || event.oldVersion !== 0) {
        failure ??= fail(event.oldVersion ? 'Corrupt' : initial ? 'Exists' : 'Absent');
        request.transaction.abort(); return;
      }
      created = true;
      request.transaction.onerror = event => { failure ??= ioError(event.target.error ?? request.transaction.error); };
      try {
        const db = request.result;
        db.createObjectStore('root').add(initial.meta, 'current');
        db.createObjectStore('files').add(initial.wrapping, initial.path);
      } catch (error) { failure = ioError(error); request.transaction.abort(); }
    };
    request.onerror = () => pending.finish(failure ?? ioError(request.error));
    request.onsuccess = () => {
      const db = request.result;
      if (pending.delivered || (initial && !created)) { db.close(); pending.finish(failure ?? fail('Exists')); return; }
      if (db.version !== 2 || [...db.objectStoreNames].sort().join(',') !== 'files,root') {
        db.close(); pending.finish(fail('Corrupt')); return;
      }
      pending.finish(undefined, db);
    };
  } catch (error) { pending.finish(ioError(error)); }
  return pending;
}

// A result timeout and the actual transaction terminal event have separate receipts.
// Callback work stays synchronous; WebCrypto is completed before entering a transaction.
export function transaction(db, signal, operation, strict = true) {
  let tx, result, ready = false, failure;
  const abort = error => {
    failure ??= error;
    if (!tx) { pending.finish(failure); return; }
    try { tx.abort(); }
    catch (cause) { failure = fail('CommitUnknown', new AggregateError([failure, cause])); }
    pending.deliver(failure);
  };
  const pending = pendingOperation(() => abort(fail('CommitUnknown')));
  const cancel = () => abort(fail('CommitUnknown'));
  pending.settled.then(() => signal.removeEventListener('abort', cancel));
  if (signal.aborted) { pending.finish(fail('Closed')); return pending; }
  signal.addEventListener('abort', cancel, { once: true });
  const checked = callback => event => {
    if (pending.delivered) return;
    try { callback(event); } catch (error) { abort(ioError(error)); }
  };
  try {
    tx = strict ? db.transaction(['root', 'files'], 'readwrite', { durability: 'strict' })
      : db.transaction(['root', 'files'], 'readonly');
    tx.oncomplete = () => pending.finish(failure ?? (ready ? undefined : fail('Corrupt')), result);
    tx.onabort = () => pending.finish(failure ?? ioError(tx.error ?? new DOMException('aborted', 'AbortError')));
    tx.onerror = event => { failure ??= ioError(event.target.error ?? tx.error); };
    if (strict && tx.durability !== 'strict') { abort(fail('Unavailable')); return pending; }
    const roots = tx.objectStore('root'), files = tx.objectStore('files');
    if (roots.keyPath !== null || files.keyPath !== null || roots.autoIncrement || files.autoIncrement) throw fail('Corrupt');
    const keys = roots.getAllKeys(undefined, 2);
    keys.onsuccess = checked(() => {
      if (keys.result.length !== 1 || keys.result[0] !== 'current') throw fail('Corrupt');
      const root = roots.get('current'), paths = files.getAllKeys(undefined, 257);
      let remaining = 2;
      const obtained = checked(() => {
        if (--remaining) return;
        if (paths.result.length > 256) throw fail('Capacity');
        operation({ roots, files, root: root.result, paths: paths.result, checked,
          done: value => { result = value; ready = true; } });
      });
      root.onsuccess = obtained; paths.onsuccess = obtained;
    });
  } catch (error) { abort(ioError(error)); }
  return pending;
}
export function admitSnapshot(root, paths, expected, state) {
  metadata(root, expected.id);
  if (!equal(root.sealed.iv, expected.sealed.iv) || !equal(root.sealed.data, expected.sealed.data)) throw fail('Conflict');
  const named = state.files.map(pair => pair[0]);
  if (paths.length !== named.length || paths.some((path, index) => path !== named[index])) throw fail('Corrupt');
}
