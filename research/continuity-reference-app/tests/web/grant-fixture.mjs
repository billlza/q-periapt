// SPDX-License-Identifier: Apache-2.0 OR MIT
// Structural browser fixtures only; these bytes are not cryptographic evidence.
import {base64, encode} from '../../web/transport.mjs';
import {Records} from '../../web/enrollment-records.mjs';
import {Enrollment} from '../../web/enrollment-model.mjs';
import {Grants} from '../../web/grant-model.mjs';
export const bytes = (n, size = 32) => Array(size).fill(n);
export class Storage {
  data = new Map(); fail = false;
  getItem(key) { return this.data.has(key) ? this.data.get(key) : null; }
  setItem(key, value) { if (this.fail) throw new Error('quota failure'); this.data.set(key, value); }
}
export function fixture(api = async () => { throw new Error('unexpected HTTP'); }) {
  const storage = new Storage(), records = new Records(storage, 'http://localhost:8087', base64(bytes(1)));
  const invitation = {operation: bytes(20), request_id: bytes(10), application: bytes(1), root_revision: 1,
    root: base64(bytes(2, 1985)), family: bytes(3), device: bytes(4, 16), generation: 1,
    valid_from: 100, valid_until: 1000, deadline: 400, predecessor: null};
  records.add({kind: 'invite', request_id: bytes(10), previous: null, predecessor: null, request: 'AQ', invitation});
  const schema1 = records.export(), previous = {version: 9007199254740993n, digest: bytes(6)};
  const issued = encode({operation: invitation.operation, root_revision: 1, certificate: 'AQ', roster: 'Ag', checkpoint: previous});
  const extension = {request: {request_id: bytes(30), enrollment: invitation.operation, previous_extension: null, predecessor: previous, valid_until: 3000}, root_revision: 1, response: null};
  const target = {version: 9007199254740994n, digest: bytes(7)};
  extension.response = encode({request: extension.request, root_revision: 1, certificate: 'Aw', roster: 'BA', checkpoint: target});
  records.addExtension(extension);
  const root = {revision: 1, account: bytes(5), public_key: invitation.root, family: invitation.family, suspended: false, roster: {checkpoint: target, bytes: 'BA'}};
  const report = {schema: 'qperiapt-retained-credential-request/1', application: invitation.application, enrollment: invitation.operation,
    root_revision: 1, operation: bytes(40), journal: bytes(41), original_owner: bytes(42), original_policy: {version: 1, digest: bytes(43)},
    current_policy: {version: 1, digest: bytes(43)}, current_policy_authorization: null, previous_checkpoint: previous,
    original_certificate: 'AQ', previous_certificate: 'AQ', original_roster: 'Ag', previous_roster: 'Ag'};
  const enrollment = new Enrollment(records, api), model = new Grants(enrollment), key = base64(invitation.request_id);
  const selections = {original: null, previous: null, successor: base64(extension.request.request_id)};
  return {storage, records, enrollment, model, key, root, invitation, report, selections, issued, schema1,
    prepare: () => model.prepare(key, root, report, selections, issued)};
}
export function response(request, changes = {}) {
  return ' \n' + encode({enrollment: request.retained.enrollment, operation: request.retained.operation, journal: request.retained.journal,
    root_revision: request.retained.root_revision, statement: bytes(50), checkpoint: request.target_checkpoint, grant: 'BQ', ...changes}) + '\n';
}
