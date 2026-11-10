// SPDX-License-Identifier: Apache-2.0 OR MIT
const results = [], captures = [];
const required = (condition, message) => { if (!condition) throw Error(message); };
const hex = bytes => [...bytes].map(value => value.toString(16).padStart(2, '0')).join('');
const identity = () => hex(crypto.getRandomValues(new Uint8Array(32)));
let sequence = 0;
async function invoke(args) {
  const value = await new Promise((resolve, reject) => {
    const worker = new Worker('./worker.js', { type: 'module' }); let requestDigest;
    const timer = setTimeout(() => { worker.terminate(); reject(Error('Worker deadline: ' + JSON.stringify(args))); }, 30000);
    const done = result => { clearTimeout(timer); worker.terminate(); resolve(result); };
    worker.onmessage = ({ data }) => {
      if (data.ready) worker.postMessage(args);
      else if (data.requestDigest) requestDigest = data.requestDigest;
      else if (data.cut) done({ cut: data.cut, requestDigest });
      else if (data.done) done(data);
    };
    worker.onerror = event => { clearTimeout(timer); worker.terminate(); reject(Error(event.message)); };
  });
  if (value.cut) {
    const observations = [], start = performance.now();
    for (;;) {
      const locks = await navigator.locks.query();
      const count = [...locks.held, ...locks.pending].filter(row => row.name === 'qperiapt-continuity-storage/2/' + args.name).length;
      observations.push({ elapsed_ms: performance.now() - start, count });
      if (!count) break;
      required(performance.now() - start < 15000, 'Terminated Worker retained lease');
      await new Promise(resolve => setTimeout(resolve, 20));
    }
    value.lease_observations = observations;
  }
  if (value.value?.request) {
    const bytes = new Uint8Array(value.value.request);
    const name = `${String(++sequence).padStart(2, '0')}-${args.name}-${args.operation}.bin`;
    const response = await fetch('./capture/' + name, { method: 'POST', body: bytes });
    required(response.ok, 'request capture failed'); captures.push({ name, sha256: value.value.sha256 });
    delete value.value.request;
  }
  return value;
}
async function success(args) {
  const result = await invoke(args); required(result.value, JSON.stringify({ args, result })); return result.value;
}
async function refusal(args, code) {
  const result = await invoke(args); required(result.error?.includes(code), JSON.stringify({ args, result, expected: code })); return result.error;
}
async function run() {
  const session = identity().slice(0, 10);
  const absent = { name: `absent-${session}`, id: identity() };
  results.push({ case: 'missing-root', error: await refusal({ ...absent, operation: 'resume' }, 'Absent') });
  for (const boundary of ['root-before-commit', 'root-published', 'directory-created', 'staged-flush',
    'enrollment-published', 'ready-before-commit', 'ready-published']) {
    document.querySelector('#result').textContent = boundary;
    const scope = { name: `${boundary}-${session}`, id: identity() };
    const cut = await invoke({ ...scope, operation: 'create', boundary }); required(cut.cut === boundary, JSON.stringify(cut));
    if (boundary === 'root-before-commit') {
      const error = await refusal({ ...scope, operation: 'resume' }, 'Absent');
      results.push({ case: boundary, cut, error, result: 'original root absent; no inferred first use' }); continue;
    }
    const before = await success({ ...scope, operation: 'inspect' });
    required(!before.vault_extractable && before.wrap_sha256, 'original wrapping record absent');
    const wrong = await refusal({ ...scope, operation: 'resume', wrongIntent: true }, 'Conflict');
    const afterWrong = await success({ ...scope, operation: 'inspect' });
    required(JSON.stringify(before) === JSON.stringify(afterWrong), 'wrong intent mutated original state');
    if (boundary !== 'ready-published') await refusal({ ...scope, operation: 'open' }, 'InitializationPending');
    const resumed = await success({ ...scope, operation: 'resume' });
    const after = await success({ ...scope, operation: 'inspect' });
    required(after.wrap_sha256 === before.wrap_sha256 && after.files.length === 3, 'resume replaced wrapping key or omitted signer');
    if (before.database_id) required(after.database_id === before.database_id, 'published database replaced');
    required(after.opfs_files.length === 1 && after.opfs_files[0] === 'db-' + after.database_id, 'unpublished staged file not reconciled');
    const reopened = await success({ ...scope, operation: 'open' });
    const repeated = await success({ ...scope, operation: 'resume' });
    required(resumed.sha256 === reopened.sha256 && resumed.sha256 === repeated.sha256, 'original request not stable');
    await refusal({ ...scope, operation: 'create' }, 'Exists');
    results.push({ case: boundary, cut, before, wrong, resumed, after, reopened, repeated });
  }
  for (const [mutation, code] of [['delete-enrollment', 'Corrupt'], ['delete-wrap', 'Corrupt'], ['damage-catalogue', 'Authentication']]) {
    const scope = { name: `${mutation}-${session}`, id: identity() };
    await success({ ...scope, operation: 'create', noRequest: true });
    await success({ ...scope, operation: 'inspect', mutation });
    const before = await success({ ...scope, operation: 'inspect' });
    const error = await refusal({ ...scope, operation: 'resume' }, code);
    const again = await refusal({ ...scope, operation: 'open' }, code);
    const after = await success({ ...scope, operation: 'inspect' });
    required(JSON.stringify(before) === JSON.stringify(after), 'corrupt original repaired or replaced');
    results.push({ case: mutation, error, again, unchanged: true });
  }
  const scope = { name: `request-cut-${session}`, id: identity() };
  const cut = await invoke({ ...scope, operation: 'create', killRequest: true });
  required(cut.cut === 'request-committed' && cut.requestDigest, 'request cut missing');
  const request = await success({ ...scope, operation: 'resume' });
  required(request.sha256 === cut.requestDigest, 'committed request changed after kill');
  results.push({ case: 'request-committed', cut, request });
  return { completed: true, cases: results, captures, browser: navigator.userAgent,
    scope: 'isolated authenticated first-creation catalogue; actual Worker termination; original Rust enrollment engine; no full browser lifecycle or independent implementation claim' };
}
run().then(async result => {
  globalThis.result = result; document.querySelector('#result').textContent = JSON.stringify(result, null, 2);
  const response = await fetch('./capture/RESULT.json', { method: 'POST', body: JSON.stringify(result, null, 2) });
  required(response.ok, 'result capture failed'); globalThis.captureComplete = true;
}, async error => {
  const result = { completed: false, error: String(error), stack: error.stack, cases: results, captures };
  globalThis.result = result; document.querySelector('#result').textContent = JSON.stringify(result, null, 2);
  await fetch('./capture/FAILED.json', { method: 'POST', body: JSON.stringify(result, null, 2) }); globalThis.captureComplete = true;
});
