// SPDX-License-Identifier: Apache-2.0 OR MIT
async page => {
  const origin = new URL(page.url()).origin;
  if (new URL(origin).hostname !== '127.0.0.1') throw Error('Controlled loopback origin required');
  const diagnostics = [], results = {};
  page.on('pageerror', error => diagnostics.push(String(error)));
  page.on('console', message => { if (['error', 'warning'].includes(message.type())) diagnostics.push(message.text()); });
  for (const phase of ['creation', 'late']) {
    await page.goto(`${origin}/${phase}/index.html`);
    await page.waitForFunction(() => globalThis.captureComplete === true, undefined, { timeout: 140000 });
    const result = await page.evaluate(() => globalThis.result);
    if (!result?.completed) throw Error(JSON.stringify({ phase, result }));
    results[phase] = result;
  }
  if (diagnostics.length) throw Error(JSON.stringify(diagnostics));
  return { status: 'CONTINUITY_BROWSER_CREATION_PASS', results, diagnostics };
}
