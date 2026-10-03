// SPDX-License-Identifier: Apache-2.0 OR MIT
// Loopback-only fixture server. /broken/ serves real JS but a failing WASM response.
const { createServer } = require('node:http');
const { readFileSync } = require('node:fs');
const path = require('node:path');
const files = new Map([
  ['/browser.html', 'text/html'],
  ...['browser-suite.mjs', 'browser-worker.mjs'].map(name => [`/${name}`, 'application/javascript']),
  ...['signed-policy-vectors', 'sdk-policy-revocation-vectors', 'sdk-policy-update-vectors']
    .map(name => [`/fixtures/${name}.json`, 'application/json']),
  ...['index.js', 'expert.js', 'q_periapt_sdk_wasm.js', 'q_periapt_sdk_wasm_bg.wasm']
    .map(name => [`/node_modules/q-periapt-sdk-wasm/web/${name}`, name.endsWith('.wasm')
      ? 'application/wasm' : 'application/javascript'])
]);
const server = createServer((request, response) => {
  const url = new URL(request.url, 'http://localhost');
  const broken = url.pathname.startsWith('/broken/');
  const route = broken ? url.pathname.slice('/broken'.length) : url.pathname;
  const type = files.get(route);
  if (request.method !== 'GET' || !type || (broken && route.endsWith('.wasm'))) {
    response.writeHead(404, { 'Content-Type': type || 'text/plain', 'Cache-Control': 'no-store' });
    response.end('not found'); return;
  }
  try {
    const bytes = readFileSync(path.join(__dirname, route));
    response.writeHead(200, { 'Content-Type': type, 'Cache-Control': 'no-store' });
    response.end(bytes);
  } catch (error) {
    response.writeHead(500, { 'Content-Type': 'text/plain' });
    response.end('fixture read failed');
    console.error(error);
  }
});
server.listen(0, '127.0.0.1', () => console.log(JSON.stringify({ url:
  `http://127.0.0.1:${server.address().port}/browser.html`, pid: process.pid })));
