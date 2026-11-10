// SPDX-License-Identifier: Apache-2.0 OR MIT
// Unit HTTP response substitutes; actual TCP auth/enrollment is tested in Rust.
import test from 'node:test';
import assert from 'node:assert/strict';
import {request, HttpError, base64, unbase64} from '../../web/transport.mjs';

test('204 approval/cancellation is an explicit successful empty response', async t => {
  t.mock.method(globalThis, 'fetch', async (_path, options) => {
    assert.equal(options.credentials, 'same-origin');
    assert.equal(options.method, 'POST');
    assert.equal(options.cache, 'no-store');
    return new Response(null, {status: 204});
  });
  assert.deepEqual(await request('/api/enrollment/approve', {}), {value: null, text: '', status: 204});
});

test('plain-text body rejection remains a failure with its actual status', async t => {
  t.mock.method(globalThis, 'fetch', async () => new Response('Missing required field predecessor', {status: 422, headers: {'content-type': 'text/plain'}}));
  await assert.rejects(request('/api/enrollment/reapprove', {}), error => error instanceof HttpError && error.status === 422 && error.message.includes('predecessor'));
});

test('transport retains exact response text and sends u64 values without rounding', async t => {
  const original = '{ "version" : 18446744073709551615 }';
  t.mock.method(globalThis, 'fetch', async (_path, options) => {
    assert.equal(options.body, '{"version":9007199254740993}');
    return new Response(original, {headers: {'content-type': 'application/json; charset=utf-8'}});
  });
  const response = await request('/api/enrollment/issue', {version: 9007199254740993n});
  assert.equal(response.text, original);
  assert.equal(response.value.version, 18446744073709551615n);
});

test('malformed successful responses and oversized bodies do not become success', async t => {
  const fetch = t.mock.method(globalThis, 'fetch', async () => new Response('not JSON', {headers: {'content-type': 'application/json'}}));
  await assert.rejects(request('/api/enrollment/root'));
  fetch.mock.mockImplementation(async () => new Response('{}', {headers: {'content-type': 'text/plain'}}));
  await assert.rejects(request('/api/enrollment/root'), /Expected a JSON/);
  fetch.mock.mockImplementation(async () => new Response('x'.repeat(256 * 1024 + 1)));
  await assert.rejects(request('/api/enrollment/root'), /may have committed/);
});

test('request encodings reject noncanonical padding, trailing bits and oversized data', () => {
  assert.deepEqual(unbase64(base64(new Uint8Array([1, 2, 3])), 3), new Uint8Array([1, 2, 3]));
  for (const invalid of ['AQ==', 'AR', 'A', 'AA+', '', 'AAAA']) assert.throws(() => unbase64(invalid, 1));
});
