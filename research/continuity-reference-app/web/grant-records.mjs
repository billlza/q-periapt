// SPDX-License-Identifier: Apache-2.0 OR MIT
// Browser shape/history checks. Cryptographic authority remains with host and SDK.
import {base64, unbase64, encode, parse, equal} from './transport.mjs';
import {require, fields, id, integer, checkpoint} from './record-validation.mjs';
export const GRANT_REQUEST_BYTES = 64 * 1024;
function bounded(text, maximum) {
  require(typeof text === 'string' && new TextEncoder().encode(text).length <= maximum, 'Recovery input exceeds bound');
  return parse(text);
}
function selectedHead(value) { checkpoint(value); require(value !== null, 'A checkpoint is required'); }
export function retainedRequest(value) {
  fields(value, 'schema application enrollment root_revision operation journal original_owner original_policy current_policy current_policy_authorization previous_checkpoint original_certificate previous_certificate original_roster previous_roster');
  require(value.schema === 'qperiapt-retained-credential-request/1', 'Unknown retained request schema');
  for (const name of ['application', 'enrollment', 'operation', 'journal', 'original_owner']) id(value[name]);
  integer(value.root_revision, true);
  for (const name of ['original_policy', 'current_policy', 'previous_checkpoint']) selectedHead(value[name]);
  if (value.current_policy_authorization !== null) id(value.current_policy_authorization);
  require(BigInt(value.current_policy.version) >= BigInt(value.original_policy.version)
    && (BigInt(value.current_policy.version) !== BigInt(value.original_policy.version) || equal(value.current_policy, value.original_policy)), 'Reported policy history conflicts');
  for (const name of ['original_certificate', 'previous_certificate', 'original_roster', 'previous_roster']) unbase64(value[name], 16384);
  bounded(encode(value), GRANT_REQUEST_BYTES); return value;
}
export function grantRequest(value) {
  fields(value, 'retained original_extension previous_extension successor_extension target_checkpoint');
  retainedRequest(value.retained); id(value.successor_extension); selectedHead(value.target_checkpoint);
  for (const key of ['original_extension', 'previous_extension']) if (value[key] !== null) id(value[key]);
  require(BigInt(value.target_checkpoint.version) > BigInt(value.retained.previous_checkpoint.version), 'Grant target must follow the reported predecessor');
  bounded(encode(value), GRANT_REQUEST_BYTES); return value;
}
function issuance(text, original) {
  const value = bounded(text, 128 * 1024);
  fields(value, 'operation root_revision certificate roster checkpoint');
  id(value.operation); integer(value.root_revision, true); selectedHead(value.checkpoint);
  require(equal(value.operation, original.operation) && value.root_revision === original.root_revision, 'Historical issuance belongs to another enrollment');
  unbase64(value.certificate, 65536); unbase64(value.roster, 65536); return value;
}
export function grantResponse(text, request) {
  const value = bounded(text, 128 * 1024), r = request.retained;
  fields(value, 'enrollment operation journal root_revision statement checkpoint grant');
  for (const key of ['enrollment', 'operation', 'journal', 'statement']) id(value[key]);
  integer(value.root_revision, true); selectedHead(value.checkpoint); unbase64(value.grant, 128 * 1024);
  require(equal(value.enrollment, r.enrollment) && equal(value.operation, r.operation) && equal(value.journal, r.journal)
    && value.root_revision === r.root_revision && equal(value.checkpoint, request.target_checkpoint), 'Grant result changed the original decision');
  return text;
}
export function grantRecord(row, operations, extensions, application) {
  fields(row, 'request enrollment_response state response'); grantRequest(row.request);
  require(['Prepared', 'Submitted', 'CancelRequested', 'Issued', 'Closed'].includes(row.state), 'Unknown grant recovery state');
  const request = row.request, r = request.retained;
  const original = operations.find(o => o.invitation && equal(o.invitation.operation, r.enrollment))?.invitation;
  require(original && base64(r.application) === application && original.root_revision === r.root_revision, 'Retained grant has no original account enrollment');
  const first = issuance(row.enrollment_response, original);
  function extension(selection) {
    const item = extensions.find(e => equal(e.request.request_id, selection));
    require(item && item.response !== null && equal(item.request.enrollment, r.enrollment)
      && item.root_revision === r.root_revision, 'Select an issued extension of the original enrollment');
    return item;
  }
  function certificate(selection) { return selection === null ? first.certificate : parse(extension(selection).response).certificate; }
  function descends(child, ancestor) {
    for (let steps = 0; steps <= extensions.length; ++steps) {
      if (equal(child, ancestor)) return;
      require(child !== null, 'Selected extension is outside the original chain');
      child = extension(child).request.previous_extension;
    }
    throw new Error('Cyclic extension history');
  }
  descends(request.previous_extension, request.original_extension);
  descends(request.successor_extension, request.previous_extension);
  require(certificate(request.original_extension) === r.original_certificate && certificate(request.previous_extension) === r.previous_certificate, 'Reported credentials differ from selected host issuance');
  const target = parse(extension(request.successor_extension).response).checkpoint;
  require(BigInt(request.target_checkpoint.version) >= BigInt(target.version)
    && (BigInt(request.target_checkpoint.version) !== BigInt(target.version) || equal(request.target_checkpoint, target)), 'Selected target predates or forks the extension');
  if (row.state === 'Issued') grantResponse(row.response, request);
  else require(row.response === null, 'Unissued decision has an unexpected result');
  return row;
}
