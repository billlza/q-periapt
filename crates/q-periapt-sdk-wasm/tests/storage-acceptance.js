// SPDX-License-Identifier: Apache-2.0 OR MIT
// playwright-cli run-code --filename against the installed loopback consumer.
async (page) => {
  const origin = new URL(page.url()).origin;
  if (new URL(origin).hostname !== '127.0.0.1') throw new Error('Controlled loopback origin required');
  const context = page.context(), prefix = `policy-${Date.now()}`, cases = [], diagnostics = [];
  let checks = 0;
  function check(value, label) { if (!value) throw new Error(JSON.stringify({ label, cases, diagnostics })); checks++; }
  const errors = error => diagnostics.push(String(error));
  async function open(realm) {
    const tab = await context.newPage();
    tab.on('pageerror', errors);
    tab.on('console', message => { if (['error', 'warning'].includes(message.type())) diagnostics.push(message.text()); });
    await tab.goto(`${origin}/storage-browser.html?realm=${realm}`);
    await tab.waitForFunction(() => globalThis.storage !== undefined);
    return tab;
  }
  async function call(tab, command, name, extra) {
    const result = await tab.evaluate(async args => {
      let timer;
      try { return await Promise.race([storage.run(...args), new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error('Storage command deadline')), 15000);
      })]); } finally { clearTimeout(timer); }
    }, [command, name, extra]);
    cases.push({ command, store: name, ...result });
    return result;
  }
  const tabs = [];
  try {
    for (const realm of ['window', 'worker']) {
      const tab = await open(realm), competitor = await open(realm === 'window' ? 'worker' : 'window');
      tabs.push(tab, competitor);
      const name = `${prefix}-${realm}`;
      check((await call(tab, 'open', name)).code === 'Absent', 'Missing store became first use');
      const initial = await call(tab, 'create', name); check(initial.ok && initial.enabled, 'Create did not activate after storage');
      check((await call(competitor, 'open', name)).code === 'Busy', 'Cross-realm lease failed');
      check((await call(tab, 'crypto', name)).ok, 'Stored owner actual KEM failed');
      check(!(await call(tab, 'invalid', name)).ok, 'Invalid policy admitted');
      check((await call(tab, 'crypto', name)).state === initial.state, 'Invalid policy revoked current state');
      check((await call(tab, 'stale', name)).code === 'Stale', 'Stale caller admitted');
      check((await call(tab, 'state', name)).state === initial.state, 'Stale caller changed state');
      const revoked = await call(tab, 'update', name); check(revoked.ok && !revoked.enabled && revoked.revoked, 'Revocation not committed');
      check((await call(tab, 'close', name)).ok, 'Close failed');
      check((await call(competitor, 'open', name)).state === revoked.state, 'Restart forgot revocation');
      check((await call(competitor, 'update', name, 'enable')).enabled, 'Signed reenable failed');
      check((await call(competitor, 'close', name)).ok, 'Second owner close failed');
      check((await call(tab, 'create', name)).code === 'Exists', 'Create overwrote original');
      const reopened = await call(tab, 'open', name); check(reopened.ok && reopened.enabled, 'Original cannot reopen');
      check((await call(tab, 'crypto', name)).ok, 'Reopened owner KEM failed');
      check((await call(tab, 'close', name)).ok, 'Reopened close failed');
      await tab.reload(); await tab.waitForFunction(() => globalThis.storage !== undefined);
      check((await call(tab, 'open', name)).state === reopened.state, 'Realm restart changed state');
      await call(tab, 'close', name);
    }
    const tab = await open('window'); tabs.push(tab);
    for (const fault of ['abort', 'close-update']) {
      const name = `${prefix}-${fault}`, initial = await call(tab, 'create', name);
      const outcome = await call(tab, fault, name);
      check(!outcome.ok && outcome.code === (fault === 'abort' ? 'Aborted' : 'Closed'), 'Mutation failure hidden');
      check((await call(tab, 'state', name)).code === 'Closed', 'Failed owner still active');
      await call(tab, 'close', name);
      const reopened = await call(tab, 'open', name);
      check(reopened.ok && (fault === 'abort' ? reopened.state === initial.state : !reopened.enabled), 'Atomic failure recovery differs');
      await call(tab, 'close', name);
    }
    for (const boundary of ['write', 'commit']) {
      const worker = await open('worker'); tabs.push(worker);
      const name = `${prefix}-cut-${boundary}`, initial = await call(worker, 'create', name);
      await worker.evaluate(args => { storage.run(...args).then(result => { globalThis.cutReturned = result; }); }, [`cut-${boundary}`, name]);
      await worker.waitForFunction(() => globalThis.cutEvent !== undefined, undefined, { timeout: 15000 });
      const cut = await worker.evaluate(() => ({ boundary: cutEvent, returned: globalThis.cutReturned }));
      check(cut.returned === undefined, 'Cut happened after SDK returned');
      await worker.evaluate(() => storage.terminate());
      const started = Date.now(), leaseObservations = [];
      // query() is asynchronous: explicitly await each snapshot and inspect its
      // boolean result, rather than treating a Promise as a truthy predicate.
      for (;;) {
        const locks = await tab.evaluate(() => navigator.locks.query());
        const remaining = [...locks.held, ...locks.pending].filter(lock => lock.name === `qperiapt-sdk-policy/1/${name}`).length;
        leaseObservations.push({ elapsed: Date.now() - started, remaining });
        if (!remaining) break;
        check(Date.now() - started < 15000, 'Terminated Worker retained its lease');
        await tab.waitForTimeout(50);
      }
      const reopened = await call(tab, 'open', name);
      check(reopened.ok && (boundary === 'commit' ? !reopened.enabled : reopened.state === initial.state), 'Worker cut did not retain atomic state');
      cases.push({ command: 'Worker-termination', store: name, boundary: cut.boundary, recovered: reopened.state, leaseObservations });
      await call(tab, 'close', name);
    }
    const corruptName = `${prefix}-corrupt`;
    await call(tab, 'create', corruptName); await call(tab, 'close', corruptName); await call(tab, 'corrupt', corruptName);
    check(!(await call(tab, 'open', corruptName)).ok, 'Corrupt signature admitted');
    check((await call(tab, 'create', corruptName)).code === 'Exists', 'Corrupt original silently reset');
    check(diagnostics.length === 0, JSON.stringify(diagnostics));
    return { status: 'BROWSER_POLICY_STORAGE_PASS', checks, browser: context.browser().version(), cases, diagnostics };
  } finally {
    for (const tab of tabs) if (!tab.isClosed()) await tab.close();
  }
}
