// SPDX-License-Identifier: Apache-2.0 OR MIT
// Browser bounds and original-history checks; cryptographic review is server-side.
import {base64, unbase64, encode, parse, equal} from './transport.mjs';
import {require, fields, id, integer, checkpoint} from './record-validation.mjs';
import {credentialHistory} from './credential-history.mjs';
export const POLICY_REPORT_BYTES = 64 * 1024;
export const POLICY_INPUT_BYTES = 448 * 1024;
export const POLICY_REQUEST_BYTES = 512 * 1024;
function bounded(value, limit) {
  require(new TextEncoder().encode(encode(value)).length <= limit, 'Policy input exceeds bound');
}
function head(value) { checkpoint(value); require(value !== null, 'A policy checkpoint is required'); }
export function policyHead(input) { return {version: input.pins.policy_version, digest: input.pins.policy_digest}; }
export function policyReport(r) {
  fields(r, 'schema application enrollment root_revision scope original_checkpoint original_certificate original_roster current_certificate current_roster');
  require(r.schema === 'qperiapt-retained-policy-request/1', 'Unknown retained policy request schema');
  id(r.application); id(r.enrollment); integer(r.root_revision, true); head(r.original_checkpoint);
  const s = r.scope;
  fields(s, 'operation journal original_owner original_credential current_credential current_roster original_policy previous_policy previous_authorization');
  for (const key of ['operation', 'journal', 'original_owner', 'original_credential', 'current_credential']) id(s[key]);
  for (const key of ['current_roster', 'original_policy', 'previous_policy']) head(s[key]);
  if (s.previous_authorization === null) require(equal(s.original_policy, s.previous_policy), 'Original policy predecessor differs');
  else { id(s.previous_authorization); require(BigInt(s.previous_policy.version) > BigInt(s.original_policy.version), 'Policy predecessor did not advance'); }
  for (const key of ['original_certificate', 'original_roster', 'current_certificate', 'current_roster']) unbase64(r[key], 16384);
  bounded(r, POLICY_REPORT_BYTES); return r;
}
function input(value) {
  fields(value, 'pins materials');
  const p = value.pins, m = value.materials;
  fields(p, 'schema sdk_root sdk_state policy_root policy_version policy_digest witness');
  fields(m, 'schema sdk_document sdk_signature policy');
  require(p.schema === 'qperiapt-policy-pins/1' && m.schema === 'qperiapt-policy-materials/1', 'Unknown policy input schema');
  for (const [name, size] of [['sdk_root', 1952], ['sdk_state', 36], ['policy_root', 1985]]) require(unbase64(p[name], size).length === size, 'Policy pin byte length');
  integer(p.policy_version, true); id(p.policy_digest);
  if (p.witness !== null) {
    fields(p.witness, 'identity key'); id(p.witness.identity);
    require(unbase64(p.witness.key, 1985).length === 1985, 'Witness key length');
  }
  unbase64(m.sdk_document, 65536);
  require(unbase64(m.sdk_signature, 3309).length === 3309, 'SDK signature length');
  unbase64(m.policy, 16384);
  bounded(p, 16384); bounded(m, 128 * 1024);
}
function samePins(value) {
  for (const name of ['original', 'previous', 'target']) input(value[name]);
  for (const p of [value.previous.pins, value.target.pins]) {
    for (const field of ['sdk_root', 'sdk_state', 'policy_root', 'witness']) require(equal(p[field], value.original.pins[field]), 'Policy renewal changes pinned authority or witness');
  }
}
export function policyInputs(value) {
  fields(value, 'schema family original previous target');
  require(value.schema === 'qperiapt-policy-approval-inputs/1', 'Unknown policy review bundle');
  id(value.family); samePins(value); bounded(value, POLICY_INPUT_BYTES); return value;
}
export function policyRequest(value) {
  fields(value, 'retained original_extension current_extension original previous target');
  policyReport(value.retained);
  for (const key of ['original_extension', 'current_extension']) if (value[key] !== null) id(value[key]);
  samePins(value);
  require(equal(value.retained.scope.original_policy, policyHead(value.original))
    && equal(value.retained.scope.previous_policy, policyHead(value.previous))
    && BigInt(value.target.pins.policy_version) > BigInt(value.previous.pins.policy_version), 'Selected policies differ from original scope');
  bounded(value, POLICY_REQUEST_BYTES); return value;
}
export function policyReview(value, request) {
  fields(value, 'statement target valid_from valid_until send_budget witness_required');
  id(value.statement); head(value.target); integer(value.valid_from); integer(value.valid_until, true);
  require(equal(value.target, policyHead(request.target)) && BigInt(value.valid_until) > BigInt(value.valid_from), 'Policy review target or interval differs');
  require(Number.isSafeInteger(value.send_budget) && value.send_budget > 0 && value.send_budget <= 65535
    && typeof value.witness_required === 'boolean' && value.witness_required === (request.target.pins.witness !== null), 'Policy review profile differs');
  return value;
}
export function policyResponse(text, request, review) {
  require(typeof text === 'string' && new TextEncoder().encode(text).length <= 128 * 1024, 'Policy response exceeds bound');
  require(review !== null, 'Original verified policy review is absent'); policyReview(review, request);
  const v = parse(text), r = request.retained;
  fields(v, 'enrollment operation journal root_revision statement target approval');
  for (const key of ['enrollment', 'operation', 'journal', 'statement']) id(v[key]);
  integer(v.root_revision, true); head(v.target); unbase64(v.approval, 128 * 1024);
  require(equal(v.enrollment, r.enrollment) && equal(v.operation, r.scope.operation) && equal(v.journal, r.scope.journal)
    && v.root_revision === r.root_revision && equal(v.statement, review.statement) && equal(v.target, review.target), 'Policy result changed the reviewed decision');
  return text;
}
export function policyContext(request, enrollmentResponse, operations, extensions, application) {
  policyRequest(request);
  const r = request.retained, original = operations.find(o => o.invitation && equal(o.invitation.operation, r.enrollment))?.invitation;
  require(original && base64(r.application) === application && original.root_revision === r.root_revision, 'Policy approval has no original account enrollment');
  const history = credentialHistory(enrollmentResponse, original, extensions);
  history.descends(request.current_extension, request.original_extension);
  require(history.issued(request.original_extension).certificate === r.original_certificate
    && history.issued(request.current_extension).certificate === r.current_certificate, 'Policy credentials differ from selected host issuance');
  const selected = history.issued(request.current_extension).checkpoint, current = r.scope.current_roster;
  require(BigInt(current.version) >= BigInt(selected.version)
    && (BigInt(current.version) !== BigInt(selected.version) || equal(current, selected)), 'Policy roster predates or forks selected credential');
  return original;
}
export function policyRecord(row, operations, extensions, application) {
  fields(row, 'request enrollment_response review state response');
  policyContext(row.request, row.enrollment_response, operations, extensions, application);
  require(['Prepared', 'Submitted', 'CancelRequested', 'Issued', 'Closed'].includes(row.state), 'Unknown policy recovery state');
  if (row.review === null) require(row.state === 'Closed', 'Unclosed policy decision requires a verified review');
  else policyReview(row.review, row.request);
  if (row.state === 'Issued') policyResponse(row.response, row.request, row.review);
  else require(row.response === null, 'Unissued policy decision has an unexpected result');
  return row;
}
