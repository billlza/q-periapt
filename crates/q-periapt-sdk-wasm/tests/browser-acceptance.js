// SPDX-License-Identifier: Apache-2.0 OR MIT
// Run with playwright-cli run-code --filename after opening the fixture URL.
async (page) => {
  const base = await page.evaluate(() => {
    const url = new URL(location.href);
    return { hostname: url.hostname, pathname: url.pathname, origin: url.origin };
  });
  if (base.hostname !== '127.0.0.1' || base.pathname !== '/browser.html') {
    throw new Error('Expected the installed SDK loopback fixture URL');
  }
  const context = page.context();
  if (context.pages().length !== 1) throw new Error('Expected one isolated automation tab');
  const expectedAssertions = { roundtrip: 82, 'no-entropy': 15, 'throwing-entropy': 15,
    'init-fail': 6, 'no-wasm': 6 };
  const scenarios = ['window', 'worker'].flatMap(realm =>
    Object.keys(expectedAssertions).map(mode => ({ mode, realm })));
  const cases = [];
  for (const { mode, realm } of scenarios) {
    const pageErrors = [], diagnostics = [], requests = [], responses = [], workers = [];
    const onError = error => pageErrors.push(String(error));
    const onConsole = message => {
      if (['error', 'warning'].includes(message.type())) {
        diagnostics.push({ type: message.type(), text: message.text() });
      }
    };
    const onRequest = request => { if (request.url().endsWith('_bg.wasm')) requests.push(request.url()); };
    const onResponse = response => {
      if (response.url().endsWith('_bg.wasm')) responses.push({ url: response.url(), status: response.status() });
    };
    const onWorker = worker => workers.push(worker.url());
    page.on('pageerror', onError); page.on('console', onConsole); page.on('worker', onWorker);
    context.on('request', onRequest); context.on('response', onResponse);
    try {
      await page.goto(`${base.origin}/browser.html?mode=${mode}&realm=${realm}`, { waitUntil: 'load', timeout: 15000 });
      await page.waitForFunction(() => globalThis.__QPERIAPT_TEST_RESULT !== undefined, undefined, { timeout: 20000 });
      const result = await page.evaluate(() => globalThis.__QPERIAPT_TEST_RESULT);
      if (result.status !== 'pass' || result.mode !== mode || result.realm !== realm
          || result.assertions !== expectedAssertions[mode] || result.errors.length || pageErrors.length) {
        throw new Error(JSON.stringify({ result, pageErrors, diagnostics }));
      }
      if (diagnostics.length && !(mode === 'init-fail' && diagnostics.length === 1
          && diagnostics[0].type === 'error' && diagnostics[0].text.includes('404'))) {
        throw new Error(JSON.stringify(diagnostics));
      }
      const expectedWasm = `${base.origin}${mode === 'init-fail' ? '/broken' : ''}/node_modules/q-periapt-sdk-wasm/web/q_periapt_sdk_wasm_bg.wasm`;
      if (requests.length !== 1 || requests[0] !== expectedWasm || responses.length !== 1
          || responses[0].url !== expectedWasm || responses[0].status !== (mode === 'init-fail' ? 404 : 200)) {
        throw new Error(`Unexpected WASM load identity: ${JSON.stringify({ mode, realm, requests, responses })}`);
      }
      if (realm === 'worker' ? workers.length !== 1
          || workers[0] !== `${base.origin}/browser-worker.mjs?mode=${mode}` : workers.length !== 0) {
        throw new Error(`Unexpected worker identity: ${JSON.stringify(workers)}`);
      }
      cases.push({ ...result, pageErrors, diagnostics, requests, responses, workers });
    } finally {
      page.off('pageerror', onError); page.off('console', onConsole); page.off('worker', onWorker);
      context.off('request', onRequest); context.off('response', onResponse);
    }
  }
  return { status: 'WASM_INSTALLED_BROWSER_PASS', browser: context.browser().version(), cases };
}
