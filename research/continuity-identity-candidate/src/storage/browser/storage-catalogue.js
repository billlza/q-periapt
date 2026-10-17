// SPDX-License-Identifier: Apache-2.0 OR MIT
import { QPeriaptStorageError } from './storage-io.js';
export const fail = (code, cause) => new QPeriaptStorageError(code, cause);
export const ioError = error => error instanceof QPeriaptStorageError ? error
  : fail(error?.name === 'QuotaExceededError' ? 'QuotaExceeded'
    : error?.name === 'ConstraintError' ? 'Exists' : 'Storage', error);
export const hex = bytes => [...bytes].map(value => value.toString(16).padStart(2, '0')).join('');
export const identifier = () => hex(crypto.getRandomValues(new Uint8Array(32)));
export const equal = (a, b) => a instanceof Uint8Array && b instanceof Uint8Array
  && a.length === b.length && a.every((value, index) => value === b[index]);
const fields = (value, keys) => value && Object.keys(value).sort().join(',') === keys;
const id = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value) && !/^0+$/.test(value);
const encoder = new TextEncoder();
export const prefix = (name, identity) => `/qpc/${name}/${identity}/`;
export function scoped(path, name, identity) {
  const base = prefix(name, identity);
  if (typeof path !== 'string' || !path.startsWith(base) || path.length > 4096) throw fail('Corrupt');
  const leaf = path.slice(base.length);
  if (!/^[a-zA-Z0-9_./-]{1,1024}$/.test(leaf) || leaf.split('/').some(part => !part || part === '.' || part === '..')) throw fail('Corrupt');
  return path;
}
export function descriptor(value) {
  if (!value || !id(value.id)) throw fail('Corrupt');
  if (value.kind === 'database' && value.revision === 1 && fields(value, 'id,kind,revision')) return value;
  if (value.kind === 'bytes' && fields(value, 'id,kind,length,revision')
      && (value.revision === 1 || (value.revision === 2 && value.length === 8))
      && Number.isSafeInteger(value.length) && value.length > 0 && value.length <= 65536) return value;
  throw fail('Corrupt');
}
export function record(value) {
  if (value?.kind === 'database') return descriptor(value);
  if (!fields(value, 'data,id,iv,kind,length,revision') || value.kind !== 'bytes'
      || !(value.iv instanceof Uint8Array) || value.iv.length !== 12
      || !(value.data instanceof Uint8Array) || value.data.length !== value.length + 16) throw fail('Corrupt');
  descriptor({ kind: value.kind, id: value.id, revision: value.revision, length: value.length });
  return value;
}
export function describe(value) {
  record(value);
  return value.kind === 'database' ? value
    : { kind: value.kind, id: value.id, revision: value.revision, length: value.length };
}
export function matches(value, expected) {
  if (expected === undefined) { if (value !== undefined) throw fail('Corrupt'); return null; }
  const actual = describe(value);
  if (actual.id !== expected.id || actual.kind !== expected.kind || actual.revision !== expected.revision
      || actual.length !== expected.length) throw fail('Corrupt');
  return value;
}
export function metadata(value, identity) {
  if (!fields(value, 'id,key,schema,sealed') || value.schema !== 2 || value.id !== identity
      || !(value.key instanceof CryptoKey) || value.key.type !== 'secret' || value.key.extractable
      || value.key.algorithm.name !== 'AES-GCM' || value.key.algorithm.length !== 256
      || [...value.key.usages].sort().join(',') !== 'decrypt,encrypt'
      || !fields(value.sealed, 'data,iv') || !(value.sealed.iv instanceof Uint8Array) || value.sealed.iv.length !== 12
      || !(value.sealed.data instanceof Uint8Array) || value.sealed.data.length < 17 || value.sealed.data.length > 65552) throw fail('Corrupt');
  return value;
}
export function validateState(value, name, identity, binding) {
  if (!fields(value, 'binding,files,phase,revision') || !['creating', 'ready'].includes(value.phase)
      || !Number.isSafeInteger(value.revision) || value.revision < 1 || !Array.isArray(value.files)
      || value.files.length < 1 || value.files.length > 256) throw fail('Corrupt');
  if (value.binding !== hex(binding)) throw fail('Conflict');
  let previous;
  for (const pair of value.files) {
    if (!Array.isArray(pair) || pair.length !== 2) throw fail('Corrupt');
    const path = scoped(pair[0], name, identity); descriptor(pair[1]);
    if (previous !== undefined && previous >= path) throw fail('Corrupt'); previous = path;
  }
  const files = new Map(value.files), base = prefix(name, identity);
  if (files.get(base + 'wrap.key')?.kind !== 'bytes' || files.get(base + 'wrap.key')?.length !== 40) throw fail('Corrupt');
  if (files.has(base + 'enrollment.redb') && files.get(base + 'enrollment.redb').kind !== 'database') throw fail('Corrupt');
  if (value.phase === 'creating' && [...files.keys()].some(path => path !== base + 'wrap.key' && path !== base + 'enrollment.redb')) throw fail('Corrupt');
  if (value.phase === 'ready' && files.get(base + 'enrollment.redb')?.kind !== 'database') throw fail('Corrupt');
  return value;
}
const catalogueAAD = (name, identity) => encoder.encode(JSON.stringify(['QPC-BROWSER-CATALOGUE/v2', name, identity]));
export const secretAAD = (identity, path, value) => encoder.encode(JSON.stringify([
  'QPC-BROWSER-PRIVATE-BYTES/v1', identity, path, value.id, value.revision, value.length]));
export async function sealState(key, name, identity, value) {
  const body = encoder.encode(JSON.stringify(value));
  if (body.length > 65536) throw fail('Capacity');
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: catalogueAAD(name, identity) }, key, body));
  return { schema: 2, id: identity, key, sealed: { iv, data } };
}
export async function unsealState(value, name, identity, binding) {
  metadata(value, identity);
  let body;
  try { body = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: value.sealed.iv,
    additionalData: catalogueAAD(name, identity) }, value.key, value.sealed.data)); }
  catch (error) { throw fail('Authentication', error); }
  try { return validateState(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body)), name, identity, binding); }
  catch (error) { throw error instanceof QPeriaptStorageError ? error : fail('Corrupt', error); }
  finally { body.fill(0); }
}
export async function encryptSecret(key, identity, path, bytes) {
  const value = { kind: 'bytes', id: identifier(), revision: 1, length: bytes.length, iv: crypto.getRandomValues(new Uint8Array(12)) };
  return sealSecret(key, identity, path, bytes, value);
}
// The sole mutation of an existing secret retains its object identity. Revision
// two contains only the fixed signer retirement marker; it cannot store new keys.
export async function encryptRetiredSigner(key, identity, path, originalId) {
  if (!id(originalId)) throw fail('Corrupt');
  const bytes = encoder.encode('QPSRET01');
  const value = { kind: 'bytes', id: originalId, revision: 2, length: 8, iv: crypto.getRandomValues(new Uint8Array(12)) };
  return sealSecret(key, identity, path, bytes, value);
}
async function sealSecret(key, identity, path, bytes, value) {
  const data = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: value.iv,
    additionalData: secretAAD(identity, path, value) }, key, bytes));
  return { ...value, data };
}
