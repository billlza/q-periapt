// SPDX-License-Identifier: Apache-2.0 OR MIT
// Real loopback HTTP framing checks. This does not claim browser or signature qualification.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { once } from 'node:events';
import test from 'node:test';

const source = await readFile(new URL('../research/continuity-identity-candidate/src/browser/bounded-fetch.js', import.meta.url));
const { HttpExchange } = await import(`data:text/javascript;base64,${source.toString('base64')}`);

async function endpoint(t, replyLength, declared = true) {
  const requests = [];
  const server = createServer((request, response) => {
    const chunks = [];
    request.on('data', bytes => chunks.push(bytes));
    request.on('end', () => {
      requests.push(Buffer.concat(chunks));
      response.setHeader('Content-Type', 'application/octet-stream');
      if (declared) response.setHeader('Content-Length', replyLength);
      response.write(Buffer.alloc(Math.floor(replyLength / 2), 17));
      response.end(Buffer.alloc(replyLength - Math.floor(replyLength / 2), 17));
    });
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(async () => {
    server.closeAllConnections();
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  });
  return { url: `http://127.0.0.1:${server.address().port}/witness`, requests };
}
for (const [requestLength, replyLength] of [[3674, 3659], [3802, 3787]]) {
  test(`witness Fetch ${requestLength} selects exact ${replyLength} response`, { timeout: 5000 }, async t => {
    const server = await endpoint(t, replyLength);
    const request = new Uint8Array(requestLength).fill(23);
    const attempt = HttpExchange.start(server.url, request, 3000, () => false, 1);
    const reply = await attempt.reply();
    assert.equal(reply.length, replyLength);
    assert.ok(reply.every(byte => byte === 17));
    assert.deepEqual(server.requests, [Buffer.from(request)]);
  });
}
for (const [requestLength, wrongReply] of [[3674, 3787], [3802, 3659]]) {
  test(`witness Fetch ${requestLength} rejects cross-format response ${wrongReply}`, { timeout: 5000 }, async t => {
    const server = await endpoint(t, wrongReply);
    const attempt = HttpExchange.start(server.url, new Uint8Array(requestLength), 3000, () => false, 1);
    await assert.rejects(attempt.reply(), error => error.code === 'InvalidResponse');
    assert.equal(server.requests.length, 1);
  });
}
for (const wrongReply of [3786, 3788]) {
  test(`transferred witness Fetch rejects streamed response width ${wrongReply}`, { timeout: 5000 }, async t => {
    const server = await endpoint(t, wrongReply, false);
    const attempt = HttpExchange.start(server.url, new Uint8Array(3802), 3000, () => false, 1);
    await assert.rejects(attempt.reply(), error => error.code === 'InvalidResponse');
  });
}
test('witness Fetch refuses noncanonical request widths before dispatch', { timeout: 5000 }, async t => {
  const server = await endpoint(t, 3787);
  for (const length of [0, 3673, 3675, 3801, 3803]) {
    assert.throws(() => HttpExchange.start(server.url, new Uint8Array(length), 3000, () => false, 1), error => error.code === 'InvalidResponse');
  }
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(server.requests.length, 0);
});
