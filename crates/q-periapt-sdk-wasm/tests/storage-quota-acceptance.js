// SPDX-License-Identifier: Apache-2.0 OR MIT
// Independent Chromium quota scenarios with actual IndexedDB failures.
async (page) => {
  const origin = new URL(page.url()).origin, browser = page.context().browser();
  if (new URL(origin).hostname !== '127.0.0.1') throw new Error('Controlled origin required');
  const diagnostics = [], results = [], contexts = [], pressureBytes = 64 * 1024 * 1024;
  const quotaHeadroom = 8 * 1024 * 1024;
  const require = (condition, label) => { if (!condition) throw new Error(JSON.stringify({ label, results, diagnostics })); };
  for (const scenario of ['creation-reopen', 'replacement']) {
    // A fresh storage partition keeps an earlier scenario's temporary blob files
    // and quota grants out of this experiment. Never delete an SDK installation.
    const context = await browser.newContext(), tab = await context.newPage();
    tab.on('pageerror', error => diagnostics.push(String(error)));
    tab.on('console', message => { if (['error', 'warning'].includes(message.type())) diagnostics.push(message.text()); });
    const client = await context.newCDPSession(tab), name = `quota-${scenario}-${Date.now()}`;
    const call = async command => {
      const value = await tab.evaluate(args => storage.run(...args), [command, name]);
      results.push({ scenario, command, ...value }); return value;
    };
    async function pressure(enabled) {
      await tab.evaluate(({ enabled, bytes }) => {
        if (enabled) {
          const add = IDBObjectStore.prototype.add, put = IDBObjectStore.prototype.put;
          globalThis.restoreQuotaProbe = () => { IDBObjectStore.prototype.put = put; };
          IDBObjectStore.prototype.put = function (value, key) {
            const request = put.call(this, value, key);
            if (this.name === 'policy' && key === 'current' && this.transaction.mode === 'readwrite') {
              const body = new Uint8Array(bytes);
              for (let i = 0; i < bytes; i += 65536) crypto.getRandomValues(body.subarray(i, i + 65536));
              // This extra test write shares the real strict transaction. The
              // browser must abort it for quota; no error is synthesized.
              add.call(this, body, 'quota-pressure');
            }
            return request;
          };
        } else { globalThis.restoreQuotaProbe(); delete globalThis.restoreQuotaProbe; }
      }, { enabled, bytes: pressureBytes });
    }
    try {
      await tab.goto(`${origin}/storage-browser.html`);
      await tab.waitForFunction(() => globalThis.storage !== undefined);
      const initialUsage = await client.send('Storage.getUsageAndQuota', { origin });
      require(initialUsage.usage === 0, 'Quota scenario did not start with empty storage');
      await client.send('Storage.overrideQuotaForOrigin', { origin, quotaSize: quotaHeadroom });
      const constrained = await client.send('Storage.getUsageAndQuota', { origin });
      require(constrained.overrideActive && constrained.quota === quotaHeadroom, 'Quota override absent');
      contexts.push({ scenario, initialUsage, constrained });
      let initial;
      if (scenario === 'creation-reopen') {
        await pressure(true);
        require((await call('create')).code === 'QuotaExceeded', 'Create quota error lost');
        require((await call('open')).code === 'QuotaExceeded', 'Reopen bypassed the failed strict durability barrier');
        await pressure(false);
        await client.send('Storage.overrideQuotaForOrigin', { origin });
        require((await call('create')).code === 'Exists', 'Unknown creation overwrote the original image');
        initial = await call('open'); require(initial.ok && initial.enabled, 'Original signed image could not recover');
      } else {
        initial = await call('create'); require(initial.ok && initial.enabled, 'Initial owner failed');
        await pressure(true);
        require((await call('update')).code === 'QuotaExceeded', 'Update quota error lost');
        require((await call('state')).code === 'Closed', 'Quota failure left runtime active');
        await pressure(false);
        await client.send('Storage.overrideQuotaForOrigin', { origin });
        await call('close');
        const recovered = await call('open');
        require(recovered.ok && recovered.state === initial.state, 'Aborted quota write changed original policy');
      }
      require((await call('close')).ok, 'Recovered owner close failed');
    } finally {
      await client.send('Storage.overrideQuotaForOrigin', { origin });
      await client.detach(); await context.close();
    }
  }
  require(diagnostics.length === 0, 'Uncaught quota diagnostic');
  return { status: 'BROWSER_POLICY_QUOTA_PASS', browser: browser.version(), pressureBytes,
    pressurePattern: 'webcrypto-random', quotaHeadroom, contexts, results, diagnostics };
}
