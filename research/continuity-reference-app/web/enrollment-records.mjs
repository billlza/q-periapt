// SPDX-License-Identifier: Apache-2.0 OR MIT
import {parse, encode, equal, base64, unbase64} from './transport.mjs';
import {require, fields, id, integer, checkpoint} from './record-validation.mjs';
import {grantRecord, grantResponse} from './grant-records.mjs';
import {policyRecord, policyResponse} from './policy-records.mjs';
export {id, checkpoint} from './record-validation.mjs';
export const MAX_RECORD_BYTES = 4 * 1024 * 1024;
const MAX_RECORDS = 512;
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
export function extensionRequest(value) {
  fields(value, 'request_id enrollment previous_extension predecessor valid_until');
  id(value.request_id); id(value.enrollment); integer(value.valid_until, true);
  require(BigInt(value.valid_until) < 18446744073709551615n, 'Extension expiry must be finite');
  if (value.previous_extension !== null) {
    id(value.previous_extension); require(!equal(value.previous_extension, value.request_id), 'Extension cannot precede itself');
  }
  checkpoint(value.predecessor); require(value.predecessor !== null, 'Extension requires a selected roster');
  require(BigInt(value.predecessor.version) < 18446744073709551615n, 'Roster version exhausted');
}
export function extensionResponse(text, request, revision) {
  require(typeof text === 'string' && new TextEncoder().encode(text).length <= 128 * 1024, 'Extension response exceeds bound');
  const value = parse(text); fields(value, 'request root_revision certificate roster checkpoint');
  extensionRequest(value.request); integer(value.root_revision, true);
  require(equal(value.request, request) && value.root_revision === revision, 'Extension response changed the original request or root');
  unbase64(value.certificate, 65536); unbase64(value.roster, 65536); checkpoint(value.checkpoint);
  require(value.checkpoint !== null && BigInt(value.checkpoint.version) === BigInt(request.predecessor.version) + 1n, 'Extension successor checkpoint differs');
  return text;
}
function extension(value, operations) {
  fields(value, 'request root_revision response'); extensionRequest(value.request); integer(value.root_revision, true);
  const source = operations.find(r => r.invitation && equal(r.invitation.operation, value.request.enrollment));
  require(source && source.invitation.root_revision === value.root_revision, 'Extension has no original enrollment/root');
  if (value.response !== null) extensionResponse(value.response, value.request, value.root_revision);
}
export class Records {
  constructor(storage, origin, application) {
    require(unbase64(application, 32).length === 32, 'Invalid application identity');
    this.storage = storage; this.origin = origin; this.application = application;
    this.key = `qpc-reference-enrollment/1/${application}`;
  }
  validate(value) {
    const shape = {1: 'schema origin application operations', 2: 'schema origin application operations extensions', 3: 'schema origin application operations extensions grants', 4: 'schema origin application operations extensions grants policy_approvals'}[value?.schema];
    require([1, 2, 3, 4].includes(value?.schema), 'Unknown browser recovery schema'); fields(value, shape);
    require(value.origin === this.origin && value.application === this.application, 'Recovery file belongs to another origin, account or schema');
    require(Array.isArray(value.operations) && value.operations.length <= MAX_RECORDS, 'Recovery record capacity');
    const extensions = value.schema >= 2 ? value.extensions : [], grants = value.schema >= 3 ? value.grants : [];
    const policies = value.schema >= 4 ? value.policy_approvals : [];
    require([extensions, grants, policies].every(Array.isArray) && value.operations.length + extensions.length + grants.length + policies.length <= MAX_RECORDS, 'Recovery record capacity');
    const seen = new Set();
    for (const operation of value.operations) {
      row(operation, this.application); const key = base64(operation.request_id);
      require(!seen.has(key), 'Duplicate recovery identity'); seen.add(key);
    }
    for (const item of extensions) {
      extension(item, value.operations); const key = base64(item.request.request_id);
      require(!seen.has(key), 'Duplicate recovery identity'); seen.add(key);
      const previous = item.request.previous_extension;
      if (previous !== null) {
        const source = extensions.find(r => equal(r.request.request_id, previous));
        require(source && source.response !== null && equal(source.request.enrollment, item.request.enrollment)
          && source.root_revision === item.root_revision && BigInt(item.request.valid_until) > BigInt(source.request.valid_until), 'Extension predecessor is absent or conflicts');
      } else {
        const source = value.operations.find(r => r.invitation && equal(r.invitation.operation, item.request.enrollment));
        require(BigInt(item.request.valid_until) > BigInt(source.invitation.valid_until), 'Extension must increase original validity');
      }
    }
    for (const item of grants) {
      grantRecord(item, value.operations, extensions, this.application);
      const key = base64(item.request.retained.operation);
      require(!seen.has(key), 'Duplicate recovery identity'); seen.add(key);
    }
    for (const item of policies) {
      policyRecord(item, value.operations, extensions, this.application);
      const key = base64(item.request.retained.scope.operation);
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
  extensions() { const value = this.read(); return value.schema >= 2 ? value.extensions : []; }
  findExtension(key) {
    const value = this.extensions().find(r => base64(r.request.request_id) === key);
    require(value, 'Select an existing extension request'); return value;
  }
  addExtension(item) {
    const value = this.read();
    // Only this explicit preparation/import upgrades the payload. Reads leave
    // schema-1 bytes untouched, and the cache key stays bound to the same account.
    this.save({...value, schema: Math.max(value.schema, 2), extensions: [...(value.schema >= 2 ? value.extensions : []), item]});
  }
  completeExtension(key, response) {
    const value = this.read(); require(value.schema >= 2, 'Original extension records absent');
    const row = value.extensions.find(r => base64(r.request.request_id) === key);
    require(row, 'Original extension request missing'); extensionResponse(response, row.request, row.root_revision);
    require(row.response === null || row.response === response, 'Host changed the original extension result');
    row.response = response; this.save(value);
  }
  grants() { const value = this.read(); return value.schema >= 3 ? value.grants : []; }
  findGrant(key) {
    const value = this.grants().find(r => base64(r.request.retained.operation) === key);
    require(value, 'Select an existing recovery authorization'); return value;
  }
  addGrant(item) {
    const value = this.read();
    this.save({...value, schema: Math.max(value.schema, 3), extensions: value.schema >= 2 ? value.extensions : [], grants: [...(value.schema >= 3 ? value.grants : []), item]});
  }
  transitionGrant(key, state, response = null) {
    const value = this.read(); require(value.schema >= 3, 'Original grant records absent');
    const row = value.grants.find(r => base64(r.request.retained.operation) === key);
    require(row, 'Original grant request missing');
    transition(row, state, response, () => grantResponse(response, row.request)); this.save(value);
  }
  policyApprovals() { const value = this.read(); return value.schema >= 4 ? value.policy_approvals : []; }
  findPolicyApproval(key) {
    const value = this.policyApprovals().find(r => base64(r.request.retained.scope.operation) === key);
    require(value, 'Select an existing policy decision'); return value;
  }
  addPolicyApproval(item) {
    const value = this.read();
    this.save({...value, schema: 4, extensions: value.schema >= 2 ? value.extensions : [], grants: value.schema >= 3 ? value.grants : [],
      policy_approvals: [...(value.schema >= 4 ? value.policy_approvals : []), item]});
  }
  transitionPolicyApproval(key, state, response = null) {
    const value = this.read(); require(value.schema >= 4, 'Original policy records absent');
    const row = value.policy_approvals.find(r => base64(r.request.retained.scope.operation) === key);
    require(row, 'Original policy request missing');
    transition(row, state, response, () => policyResponse(response, row.request, row.review)); this.save(value);
  }
  merge(text) {
    const imported = this.decode(text), value = this.read();
    for (const operation of imported.operations) {
      const original = value.operations.find(r => equal(r.request_id, operation.request_id));
      if (original) require(equal(original, operation), 'Imported record conflicts with original retained state');
      else value.operations.push(operation);
    }
    if (imported.schema >= 2) {
      if (value.schema === 1) { value.schema = 2; value.extensions = []; }
      for (const item of imported.extensions) {
        const original = value.extensions.find(r => equal(r.request.request_id, item.request.request_id));
        if (original) require(equal(original, item), 'Imported extension conflicts with original retained state');
        else value.extensions.push(item);
      }
    }
    if (imported.schema >= 3) {
      if (value.schema < 3) { value.schema = 3; value.grants = []; }
      for (const item of imported.grants) {
        const original = value.grants.find(r => equal(r.request.retained.operation, item.request.retained.operation));
        if (original) require(equal(original, item), 'Imported grant conflicts with original retained state');
        else value.grants.push(item);
      }
    }
    if (imported.schema >= 4) {
      if (value.schema < 4) { value.schema = 4; value.policy_approvals = []; }
      for (const item of imported.policy_approvals) {
        const original = value.policy_approvals.find(r => equal(r.request.retained.scope.operation, item.request.retained.scope.operation));
        if (original) require(equal(original, item), 'Imported policy decision conflicts with original retained state');
        else value.policy_approvals.push(item);
      }
    }
    this.save(value);
  }
  export() { return encode(this.read()); }
}

function transition(row, state, response, verifyResponse) {
  const allowed = {Prepared: ['Prepared', 'Submitted', 'CancelRequested', 'Issued', 'Closed'], Submitted: ['Submitted', 'CancelRequested', 'Issued', 'Closed'],
    CancelRequested: ['CancelRequested', 'Issued', 'Closed'], Issued: ['Issued'], Closed: ['Closed']};
  require(allowed[row.state].includes(state), 'Host status contradicts original retained outcome');
  if (state === 'Issued') {
    verifyResponse();
    require(row.response === null || row.response === response, 'Host changed the original signed result');
  }
  row.state = state; row.response = response;
}
