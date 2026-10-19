// SPDX-License-Identifier: Apache-2.0 OR MIT
import {parse, encode, equal, base64, unbase64} from './transport.mjs';
export const MAX_RECORD_BYTES = 4 * 1024 * 1024;
const MAX_RECORDS = 512;
function require(value, message) { if (!value) throw new Error(message); }
function fields(value, expected) {
  require(value && !Array.isArray(value) && typeof value === 'object' && equal(Object.keys(value).sort(), expected.split(' ').sort()), 'Unexpected recovery record fields');
}
export function id(value, size = 32) {
  require(Array.isArray(value) && value.length === size && value.every(b => Number.isInteger(b) && b >= 0 && b <= 255) && value.some(b => b !== 0), 'Invalid operation or device identity');
  return value;
}
function integer(value, positive = false) {
  require(typeof value === 'bigint' || Number.isSafeInteger(value), 'Invalid exact integer');
  require(BigInt(value) >= (positive ? 1n : 0n) && BigInt(value) <= 18446744073709551615n, 'Integer outside u64 range');
}
export function checkpoint(value) {
  if (value === null) return;
  fields(value, 'version digest'); integer(value.version, true); id(value.digest);
}
export function invitation(value, application, correlation) {
  fields(value, 'operation request_id application root_revision root family device generation valid_from valid_until deadline predecessor');
  id(value.operation); id(value.request_id); id(value.application); id(value.family); id(value.device, 16);
  require(base64(value.application) === application && equal(value.request_id, correlation), 'Invitation belongs to another account or correlation');
  require(unbase64(value.root, 1985).length === 1985, 'Invalid account root length');
  for (const key of ['root_revision', 'generation']) integer(value[key], true);
  for (const key of ['valid_from', 'valid_until', 'deadline']) integer(value[key]);
  require(value.valid_from < value.valid_until && value.deadline <= value.valid_until, 'Invalid invitation interval');
  checkpoint(value.predecessor);
  return value;
}
export function root(value) {
  fields(value, 'revision account public_key family suspended roster');
  integer(value.revision, true); id(value.account); id(value.family);
  require(unbase64(value.public_key, 1985).length === 1985 && typeof value.suspended === 'boolean', 'Invalid root observation');
  if (value.roster !== null) {
    fields(value.roster, 'checkpoint bytes'); checkpoint(value.roster.checkpoint);
    require(value.roster.checkpoint !== null, 'A roster must have a checkpoint');
    unbase64(value.roster.bytes, 65536);
  }
  return value;
}
function row(value, application) {
  fields(value, 'kind request_id previous predecessor request invitation'); id(value.request_id);
  require(value.kind === 'invite' || value.kind === 'reapprove', 'Unknown recovery operation');
  if (value.kind === 'invite') require(value.previous === null && value.predecessor === null, 'Invitation has unexpected predecessor');
  else { id(value.previous); checkpoint(value.predecessor); }
  if (value.request !== null) unbase64(value.request, 8192);
  if (value.invitation !== null) invitation(value.invitation, application, value.request_id);
  if (value.kind === 'reapprove' && value.invitation === null) require(value.request !== null, 'Pending reapproval has no original proof');
}
export class Records {
  constructor(storage, origin, application) {
    require(unbase64(application, 32).length === 32, 'Invalid application identity');
    this.storage = storage; this.origin = origin; this.application = application;
    this.key = `qpc-reference-enrollment/1/${application}`;
  }
  validate(value) {
    fields(value, 'schema origin application operations');
    require(value.schema === 1 && value.origin === this.origin && value.application === this.application, 'Recovery file belongs to another origin, account or schema');
    require(Array.isArray(value.operations) && value.operations.length <= MAX_RECORDS, 'Recovery record capacity');
    const seen = new Set();
    for (const operation of value.operations) {
      row(operation, this.application); const key = base64(operation.request_id);
      require(!seen.has(key), 'Duplicate recovery identity'); seen.add(key);
    }
    return value;
  }
  decode(text) {
    require(typeof text === 'string' && new TextEncoder().encode(text).length <= MAX_RECORD_BYTES, 'Recovery file exceeds bound');
    return this.validate(parse(text));
  }
  read() {
    const text = this.storage.getItem(this.key);
    // A never-used browser has no cache. Reading it never creates an invitation.
    return text === null ? {schema: 1, origin: this.origin, application: this.application, operations: []} : this.decode(text);
  }
  save(value) {
    const text = encode(this.validate(value));
    require(new TextEncoder().encode(text).length <= MAX_RECORD_BYTES, 'Recovery record capacity');
    this.storage.setItem(this.key, text);
    require(this.storage.getItem(this.key) === text, 'Browser recovery write outcome unknown; reopen the original records');
  }
  find(requestId) {
    const value = this.read().operations.find(r => base64(r.request_id) === requestId);
    require(value, 'Select an existing operation'); return value;
  }
  add(operation) {
    const value = this.read(); require(!value.operations.some(r => equal(r.request_id, operation.request_id)), 'Correlation already retained');
    value.operations.push(operation); this.save(value); return operation;
  }
  update(operation) {
    const value = this.read(), at = value.operations.findIndex(r => equal(r.request_id, operation.request_id));
    require(at >= 0, 'Original recovery record missing'); value.operations[at] = operation; this.save(value); return operation;
  }
  merge(text) {
    const imported = this.decode(text), value = this.read();
    for (const operation of imported.operations) {
      const original = value.operations.find(r => equal(r.request_id, operation.request_id));
      if (original) require(equal(original, operation), 'Imported record conflicts with original retained state');
      else value.operations.push(operation);
    }
    this.save(value);
  }
  export() { return encode(this.read()); }
}
