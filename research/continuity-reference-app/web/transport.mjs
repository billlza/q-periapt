// SPDX-License-Identifier: Apache-2.0 OR MIT
export function losslessSupport() {
  return typeof JSON.rawJSON === 'function' && JSON.parse('9007199254740993', (_key, _value, context) => context?.source) === '9007199254740993';
}
export function parse(text) {
  if (!losslessSupport()) throw new Error('This browser lacks lossless JSON support required for enrollment versions');
  return JSON.parse(text, (_key, value, context) => {
    if (typeof value !== 'number') return value;
    if (!/^-?(0|[1-9][0-9]*)$/.test(context.source)) throw new Error('Expected integer JSON fields');
    return Number.isSafeInteger(value) ? value : BigInt(context.source);
  });
}
export function encode(value) {
  if (!losslessSupport()) throw new Error('Lossless JSON support is required');
  return JSON.stringify(value, (_key, field) => {
    if (typeof field === 'bigint') return JSON.rawJSON(field.toString());
    if (typeof field === 'number' && !Number.isSafeInteger(field)) throw new Error('Refusing an inexact numeric field');
    return field;
  });
}
export function equal(a, b) {
  if (a === b) return true;
  if (a === null || b === null || typeof a !== 'object' || typeof b !== 'object') return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  const keys = Object.keys(a).sort(), other = Object.keys(b).sort();
  return keys.length === other.length && keys.every((key, i) => key === other[i] && equal(a[key], b[key]));
}
export function base64(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}
export function unbase64(value, limit) {
  if (typeof value !== 'string' || value.length > Math.ceil(limit / 3) * 4 || !/^[A-Za-z0-9_-]+$/.test(value)) throw new Error('Invalid bounded base64url field');
  const bytes = Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/')), c => c.charCodeAt(0));
  if (bytes.length > limit || base64(bytes) !== value) throw new Error('Noncanonical or oversized byte field');
  return bytes;
}
export class HttpError extends Error {
  constructor(message, status) { super(message); this.status = status; }
}
export async function request(path, body) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 35000);
  try {
    const response = await fetch(path, {method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin', cache: 'no-store', signal: controller.signal,
      headers: body === undefined ? {} : {'Content-Type': 'application/json'}, body: body === undefined ? undefined : encode(body)});
    const reader = response.body?.getReader();
    const parts = []; let length = 0;
    if (reader) {
      try {
        for (;;) {
          const {done, value} = await reader.read(); if (done) break;
          length += value.length;
          if (length > 256 * 1024) { controller.abort(); throw new Error('Host response exceeds the browser bound'); }
          parts.push(value);
        }
      } finally { reader.releaseLock(); }
    }
    const bytes = new Uint8Array(length); let offset = 0;
    for (const part of parts) { bytes.set(part, offset); offset += part.length; }
    const text = new TextDecoder('utf-8', {fatal: true}).decode(bytes);
    const json = response.headers.get('content-type')?.split(';')[0].trim() === 'application/json';
    if (!response.ok) {
      const message = json ? parse(text).error : text;
      throw new HttpError(typeof message === 'string' && message ? message.slice(0, 500) : `HTTP ${response.status}`, response.status);
    }
    if (response.status === 204 && text === '') return {value: null, text, status: 204};
    if (!json) throw new Error('Expected a JSON response from the host');
    return {value: parse(text), text, status: response.status};
  } catch (error) {
    if (controller.signal.aborted) throw new Error('Response unavailable; the host operation may have committed. Recover the original operation');
    throw error;
  } finally { clearTimeout(timeout); }
}
export async function json(path, body) { return (await request(path, body)).value; }
export async function hostLock(work) {
  if (!globalThis.navigator?.locks) throw new Error('Browser locks are required to coordinate account and device operations across tabs');
  return navigator.locks.request('qpc-reference-host-operation', {ifAvailable: true}, lock => {
    if (!lock) throw new Error('Another tab is performing a host operation; retry after it finishes');
    return work();
  });
}
