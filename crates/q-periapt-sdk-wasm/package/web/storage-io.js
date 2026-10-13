// SPDX-License-Identifier: Apache-2.0 OR MIT
// Shared browser I/O ownership; no policy or protocol decisions.
export class QPeriaptStorageError extends Error {
  constructor(code, cause) {
    super(`Q-Periapt browser storage: ${code}`, { cause });
    this.name = 'QPeriaptStorageError';
    this.code = code;
  }
}
const fail = (code, cause) => new QPeriaptStorageError(code, cause);
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
export function pendingOperation(onTimeout) {
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
