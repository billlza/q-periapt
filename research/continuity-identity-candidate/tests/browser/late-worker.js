// SPDX-License-Identifier: Apache-2.0 OR MIT
import init, { BrowserEnrollmentProbe } from '../pkg/q_periapt_continuity_identity_candidate.js';
await init();
const required = (condition, text) => { if (!condition) throw Error(text); };
const hex = bytes => [...bytes].map(value => value.toString(16).padStart(2, '0')).join('');
const identity = () => hex(crypto.getRandomValues(new Uint8Array(32)));
const sha = async bytes => hex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));
function causes(error, depth = 0) {
  if (!error || depth > 4) return [];
  return [error.code ?? error.name, ...causes(error.cause, depth + 1),
    ...(error instanceof AggregateError ? error.errors.flatMap(value => causes(value, depth + 1)) : [])];
}
const observed = async promise => { try { return { ok: true, value: await promise }; }
  catch (error) { return { ok: false, error: String(error), code: error.code, causes: causes(error) }; } };
const read = async name => {
  const response = await fetch('/inputs/' + name); required(response.ok, 'public input fetch');
  return new Uint8Array(await response.arrayBuffer());
};
const root = await read('root.bin'), description = await read('description.bin'), rows = [];
function gateEvent(object, property, gate, entered) {
  let prototype = object, descriptor;
  while (prototype && !descriptor) { descriptor = Object.getOwnPropertyDescriptor(prototype, property); prototype = Object.getPrototypeOf(prototype); }
  required(typeof descriptor?.set === 'function', 'native event setter absent');
  Object.defineProperty(object, property, { configurable: true, set(callback) {
    descriptor.set.call(object, event => { entered(); gate.then(() => callback.call(object, event)); });
  } });
}
async function releaseReceipt(name) {
  const until = performance.now() + 5000, observations = [];
  for (;;) {
    const locks = await navigator.locks.query();
    const held = [...locks.held, ...locks.pending].filter(row => row.name === 'qperiapt-continuity-storage/2/' + name).length;
    observations.push(held); if (!held) return observations;
    required(performance.now() < until, 'lease did not release after native receipt');
    await new Promise(resolve => setTimeout(resolve, 20));
  }
}
async function test(mode) {
  const name = 'late-' + mode + '-' + identity().slice(0, 10), id = identity(), now = () => BigInt(Math.floor(Date.now() / 1000));
  let owner = await BrowserEnrollmentProbe.create(name, id, root, description);
  const original = await sha(await owner.request(now())); await owner.close(); owner.free(); owner = undefined;
  let release, entered = false;
  const gate = new Promise(resolve => { release = resolve; });
  let restore;
  if (mode === 'decrypt' || mode === 'handle') {
    const prototype = mode === 'decrypt' ? SubtleCrypto.prototype : FileSystemFileHandle.prototype;
    const method = mode === 'decrypt' ? 'decrypt' : 'createSyncAccessHandle';
    const descriptor = Object.getOwnPropertyDescriptor(prototype, method), original = descriptor.value;
    Object.defineProperty(prototype, method, { ...descriptor, value: async function (...args) {
      const result = original.apply(this, args); if (entered) return result;
      entered = true; const value = await result; await gate; return value;
    } });
    restore = () => Object.defineProperty(prototype, method, descriptor);
  } else {
    const prototype = mode === 'open' ? IDBFactory.prototype : IDBDatabase.prototype;
    const method = mode === 'open' ? 'open' : 'transaction', original = prototype[method];
    prototype[method] = function (...args) {
      const value = original.apply(this, args); prototype[method] = original;
      gateEvent(value, mode === 'open' ? 'onsuccess' : 'oncomplete', gate, () => { entered = true; });
      return value;
    };
    restore = () => { prototype[method] = original; };
  }
  let row;
  try {
    const started = performance.now(), attempt = await observed(BrowserEnrollmentProbe.open(name, id, root, description));
    const elapsed = performance.now() - started;
    const code = mode === 'handle' ? 'CommitUnknown' : 'OpenUnknown';
    required(entered && !attempt.ok && attempt.code === code && attempt.causes.includes('ClosePending'), 'missing timeout/cleanup distinction: ' + JSON.stringify(attempt));
    required(elapsed >= 19000 && elapsed < 35000, 'deadline bounds not observed');
    const concurrent = await observed(BrowserEnrollmentProbe.resume(name, id, root, description));
    required(!concurrent.ok && concurrent.error.includes('Busy'), 'resource lease released early');
    row = { mode, elapsed_ms: elapsed, code, error: attempt.error, causes: attempt.causes, concurrent: concurrent.error };
  } finally { restore(); release(); }
  row.release_observations = await releaseReceipt(name);
  owner = await BrowserEnrollmentProbe.resume(name, id, root, description);
  try { const digest = await sha(await owner.request(now())); required(digest === original, 'original request changed'); row.request_sha256 = digest; }
  finally { await owner.close(); owner.free(); }
  return row;
}
try {
  for (const mode of ['decrypt', 'handle', 'open', 'transaction']) {
    postMessage({ progress: mode }); rows.push(await test(mode));
  }
  // A pre-existing directory is not owned merely because an explicit create names it.
  const name = 'foreign-' + identity().slice(0, 10), id = identity();
  const parent = await navigator.storage.getDirectory();
  const directory = await parent.getDirectoryHandle('qpc-v2-' + name + '-' + id, { create: true });
  const file = await directory.getFileHandle('preserve.txt', { create: true });
  const handle = await file.createSyncAccessHandle();
  try { handle.write(new Uint8Array([2, 7, 1, 8])); handle.flush(); } finally { handle.close(); }
  const create = await observed(BrowserEnrollmentProbe.create(name, id, root, description));
  required(!create.ok && create.error.includes('Exists'), 'pre-existing directory was adopted');
  const saved = new Uint8Array(await (await file.getFile()).arrayBuffer());
  required(hex(saved) === '02070108', 'foreign directory was modified');
  const resume = await observed(BrowserEnrollmentProbe.resume(name, id, root, description));
  required(!resume.ok && resume.error.includes('Absent'), 'failed create published a root');
  rows.push({ mode: 'foreign-directory', create: create.error, resume: resume.error, preserved_sha256: await sha(saved) });
  postMessage({ completed: true, cases: rows, browser: navigator.userAgent,
    scope: 'scheduler-delayed real WebCrypto, OPFS and IndexedDB completion; unchanged ten-second bounds; foreign-directory preservation' });
} catch (error) { postMessage({ completed: false, error: String(error), cases: rows }); }
