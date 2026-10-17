// SPDX-License-Identifier: Apache-2.0 OR MIT
// Delayed real IndexedDB events, with the installed runtime and signed policy fixtures.
async (page) => {
  const origin = new URL(page.url()).origin;
  if (new URL(origin).hostname !== '127.0.0.1') throw Error('Controlled loopback origin required');
  const tab = await page.context().newPage(), diagnostics = [];
  tab.on('pageerror', error => diagnostics.push(String(error)));
  tab.on('console', message => { if (['error', 'warning'].includes(message.type())) diagnostics.push(message.text()); });
  try {
    await tab.goto(`${origin}/storage-browser.html`);
    const result = await tab.evaluate(() => new Promise((resolve, reject) => {
      const worker = new Worker('./storage-deadline-worker.mjs', { type: 'module' });
      const timer = setTimeout(() => { worker.terminate(); reject(Error('Deadline regression timed out')); }, 65000);
      worker.onmessage = ({ data }) => {
        if (data.progress) return;
        clearTimeout(timer); worker.terminate(); resolve(data.result);
      };
      worker.onerror = event => { clearTimeout(timer); worker.terminate(); reject(Error(event.message)); };
    }));
    if (!result.completed || !result.held_until_receipt || result.cases.length !== 2 || diagnostics.length) {
      throw Error(JSON.stringify({ result, diagnostics }));
    }
    for (const row of result.cases) {
      const expected = row.mode === 'transaction-complete' ? 'CommitUnknown' : 'OpenUnknown';
      if (row.error !== expected || row.elapsed_ms < 20000 || !row.cleanup.includes('ClosePending')
          || row.early_owner_admitted || row.early_error !== 'Busy' || !row.final_receipt_withheld
          || (row.mode === 'transaction-complete' ? row.closed_error !== 'Closed' || row.enabled
            : row.after !== row.before)) throw Error(JSON.stringify(row));
    }
    return { ...result, status: 'BROWSER_POLICY_DEADLINE_PASS', diagnostics };
  } finally { await tab.close(); }
}
