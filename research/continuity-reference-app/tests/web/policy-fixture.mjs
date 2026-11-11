// SPDX-License-Identifier: Apache-2.0 OR MIT
// Structural browser inputs only; Rust boundary tests verify real signatures.
import {fixture as enrollment, bytes} from './grant-fixture.mjs';
import {base64, encode} from '../../web/transport.mjs';
import {PolicyApprovals} from '../../web/policy-model.mjs';
export function fixture(api) {
  const c = enrollment(api), checkpoint = {version: 1, digest: bytes(43)};
  const input = (version, digest) => ({
    pins: {schema: 'qperiapt-policy-pins/1', sdk_root: base64(bytes(2, 1952)), sdk_state: base64(bytes(3, 36)),
      policy_root: c.invitation.root, policy_version: version, policy_digest: bytes(digest), witness: null},
    materials: {schema: 'qperiapt-policy-materials/1', sdk_document: 'AQ', sdk_signature: base64(bytes(4, 3309)), policy: 'Ag'},
  });
  const report = {schema: 'qperiapt-retained-policy-request/1', application: c.invitation.application, enrollment: c.invitation.operation,
    root_revision: 1, scope: {operation: bytes(60), journal: bytes(41), original_owner: bytes(42), original_credential: bytes(44),
      current_credential: bytes(45), current_roster: c.root.roster.checkpoint, original_policy: checkpoint, previous_policy: checkpoint, previous_authorization: null},
    original_checkpoint: {version: 9007199254740993n, digest: bytes(6)},
    original_certificate: 'AQ', original_roster: 'Ag', current_certificate: 'Aw', current_roster: 'BA'};
  const inputs = {schema: 'qperiapt-policy-approval-inputs/1', family: c.invitation.family, original: input(1, 43), previous: input(1, 43), target: input(2, 61)};
  const review = {statement: bytes(62), target: {version: 2, digest: bytes(61)}, valid_from: 100, valid_until: 3000, send_budget: 8, witness_required: false};
  const selections = {original: null, current: base64(bytes(30))}, model = new PolicyApprovals(c.enrollment);
  const result = {...c, model, report, inputs, review, selections};
  result.prepare = () => model.prepare(c.key, report, inputs, selections, c.issued);
  return result;
}
export function response(request, review, changes = {}) {
  const r = request.retained;
  return ' \n' + encode({enrollment: r.enrollment, operation: r.scope.operation, journal: r.scope.journal, root_revision: r.root_revision,
    statement: review.statement, target: review.target, approval: 'BQY', ...changes}) + '\n';
}
