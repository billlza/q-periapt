// Fixture-only observations of the real transport result; SDK package bytes stay unchanged.
import {HttpExchange} from '/pkg/bounded-fetch.js';

const attempts = new WeakMap(), pending = new Set(), rows = [], failures = [];
const hash = async bytes => [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))]
  .map(value => value.toString(16).padStart(2, '0')).join('');
const start = HttpExchange.start, reply = HttpExchange.prototype.reply;
HttpExchange.start = function(endpoint, request, milliseconds, cancelled, profile) {
  const exchange = start.apply(this, arguments);
  if (profile === 1 || profile === 2) {
    if (!(request instanceof Uint8Array) || request.length > (profile === 1 ? 3802 : 32768)) {
      failures.push(Error('transport request observation bound'));
    } else attempts.set(exchange, {
      url: endpoint, request: request.slice(), maximum: profile === 1 ? 3787 : 32768});
  }
  return exchange;
};
HttpExchange.prototype.reply = function() {
  const original = reply.apply(this, arguments), attempt = attempts.get(this);
  if (!attempt) return original;
  const observe = original.then(async bytes => {
    if (!(bytes instanceof Uint8Array) || bytes.length > attempt.maximum) throw Error('transport response observation bound');
    const captured = bytes.slice();
    return {url: attempt.url, request_sha256: await hash(attempt.request),
      request_bytes: attempt.request.length, result: 'fulfilled',
      response_sha256: await hash(captured), response_bytes: captured.length};
  }, async error => ({url: attempt.url, request_sha256: await hash(attempt.request),
    request_bytes: attempt.request.length, result: 'rejected', error_code: String(error.code)}));
  const retained = observe.then(row => {
    if (rows.length >= 1024) throw Error('transport observation capacity exceeded');
    rows.push(row);
  }).catch(error => { failures.push(error); });
  pending.add(retained);
  retained.then(() => pending.delete(retained));
  // Preserve the exact Promise, values, rejection and cancellation behavior.
  return original;
};
export async function takeTransportReceipts() {
  await Promise.all([...pending]);
  if (failures.length) throw new AggregateError(failures, 'transport observation failed');
  return rows.splice(0);
}
