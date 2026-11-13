// SPDX-License-Identifier: Apache-2.0 OR MIT
import {base64, unbase64, equal, parse} from './transport.mjs';
import {invitation, root, id, checkpoint, replacementInvitation} from './enrollment-records.mjs';
const sameIntent = (a, b) => ['application', 'root_revision', 'root', 'family', 'device', 'generation', 'valid_from', 'valid_until'].every(key => equal(a[key], b[key]));
function require(value, message) { if (!value) throw new Error(message); }
function proof(bytes) {
  require(bytes instanceof Uint8Array && bytes.length > 0 && bytes.length <= 8192, 'Device request must contain 1–8192 bytes');
  return base64(bytes);
}
export class Enrollment {
  constructor(records, api, random = () => Array.from(crypto.getRandomValues(new Uint8Array(32)))) {
    this.records = records; this.api = api; this.random = random;
  }
  pending(kind, previous = null, predecessor = null, request = null) {
    if (kind === 'invite') require(this.records.read().operations.every(row => row.kind !== 'invite' || row.invitation !== null), 'Recover the unresolved initial invitation before creating another device');
    const row = {kind, request_id: id(this.random()), previous, predecessor, request, invitation: null};
    // A storage exception prevents the HTTP request. A later response/storage
    // failure leaves this same correlation available for explicit recovery.
    this.records.add(row); return base64(row.request_id);
  }
  newInvitation() { return this.pending('invite'); }
  async recover(key) {
    const row = this.records.find(key);
    if (row.invitation !== null) return row;
    const body = row.kind === 'invite' ? {request_id: row.request_id} : row.kind === 'replace' ? {
      request_id: row.request_id, enrollment: row.previous, predecessor: row.predecessor,
    } : {
      previous: row.previous, request_id: row.request_id, predecessor: row.predecessor, request: row.request,
    };
    const value = (await this.api(`/api/enrollment/${row.kind === 'replace' ? 'replace-device' : row.kind}`, body)).value;
    invitation(value, this.records.application, row.request_id);
    if (row.kind === 'reapprove') {
      const previous = this.records.read().operations.find(r => r.invitation && equal(r.invitation.operation, row.previous));
      require(previous && sameIntent(previous.invitation, value) && equal(row.predecessor, value.predecessor), 'Host changed the original reapproval intent');
    }
    if (row.kind === 'replace') {
      const previous = this.records.read().operations.find(r => r.invitation && equal(r.invitation.operation, row.previous));
      replacementInvitation(value, previous?.invitation, row.predecessor);
    }
    return this.records.update({...row, invitation: value});
  }
  retainProof(key, bytes) {
    const row = this.records.find(key); require(row.invitation !== null, 'Recover the invitation first');
    const request = proof(bytes);
    require(row.request === null || row.request === request, 'This operation already retains a different request; preserve its original device state');
    return this.records.update({...row, request});
  }
  operation(key, proof = false) {
    const row = this.records.find(key);
    require(row.invitation !== null && (!proof || row.request !== null), 'Recover the invitation and load its original device request first');
    return row;
  }
  async prepareRoot() { return root((await this.api('/api/enrollment/root/prepare', {})).value); }
  async readRoot() { return root((await this.api('/api/enrollment/root')).value); }
  authorityProfile(observation) {
    root(observation);
    return {schema: 'qperiapt-host-authority/1', application: Array.from(unbase64(this.records.application, 32)),
      root_revision: observation.revision, root: observation.public_key, family: observation.family};
  }
  async status(key) {
    const row = this.operation(key), value = (await this.api('/api/enrollment/status', {operation: row.invitation.operation})).value;
    require(value && ['Invited', 'Approved', 'Issued', 'Closed', 'Reapproved'].includes(value.state), 'Unknown enrollment status');
    if (value.state === 'Invited' || value.state === 'Approved') require(equal(value.invitation, row.invitation), 'Host returned a different invitation');
    if (value.state === 'Issued') { root(value.current); this.issuedText(key, value.response); }
    if (value.state === 'Reapproved') {
      invitation(value.successor, this.records.application, value.successor.request_id);
      require(sameIntent(row.invitation, value.successor), 'Historical successor changed the original device intent');
    }
    return value;
  }
  async approve(key) {
    const row = this.operation(key, true);
    const result = await this.api('/api/enrollment/approve', {operation: row.invitation.operation, request: row.request});
    require(result.status === 204, 'Unexpected approval response');
  }
  validateIssuance(key, text) {
    const row = this.operation(key), value = parse(text);
    require(equal(value.operation, row.invitation.operation) && value.root_revision === row.invitation.root_revision, 'Issuance does not belong to the original operation');
    unbase64(value.certificate, 65536); unbase64(value.roster, 65536); checkpoint(value.checkpoint);
    require(value.checkpoint !== null, 'Issuance checkpoint absent'); return text;
  }
  issuedText(key, encoded) {
    return this.validateIssuance(key, new TextDecoder('utf-8', {fatal: true}).decode(unbase64(encoded, 128 * 1024)));
  }
  async issue(key) {
    const row = this.operation(key);
    const result = await this.api('/api/enrollment/issue', {operation: row.invitation.operation});
    return this.validateIssuance(key, result.text);
  }
  async cancel(key) {
    const row = this.operation(key);
    const result = await this.api('/api/enrollment/cancel', {operation: row.invitation.operation});
    require(result.status === 204, 'Unexpected cancellation response');
  }
  reapproval(key, observation, selectedRequest) {
    const row = this.operation(key); root(observation);
    require(row.kind !== 'replace', 'Prepare a fresh replacement decision from its issued predecessor');
    const request = selectedRequest === undefined ? row.request : proof(selectedRequest);
    require(request !== null, 'Select the original device request before approving');
    require(!observation.suspended && observation.public_key === row.invitation.root && observation.revision === row.invitation.root_revision && equal(observation.family, row.invitation.family), 'Displayed root does not authorize the original device intent');
    // This is a new explicit decision under the same original device intent.
    // Keep every earlier attempt. The host atomically allows at most one source
    // successor, and an Approved source still requires byte-identical proof.
    return this.pending('reapprove', row.invitation.operation, observation.roster === null ? null : observation.roster.checkpoint, request);
  }
  replacement(key, observation, status) {
    const row = this.operation(key); root(observation);
    require(status?.state === 'Issued', 'Recover the original issued operation before replacement');
    this.issuedText(key, status.response);
    require(!observation.suspended && observation.roster !== null && observation.public_key === row.invitation.root
      && observation.revision === row.invitation.root_revision && equal(observation.family, row.invitation.family), 'Displayed root does not authorize replacement');
    require(BigInt(row.invitation.generation) + 1n < 18446744073709551615n, 'Device generation exhausted');
    require(this.records.read().operations.every(r => r.kind !== 'replace' || !equal(r.previous, row.invitation.operation) || r.invitation !== null), 'Recover the unresolved replacement invitation first');
    return this.pending('replace', row.invitation.operation, observation.roster.checkpoint);
  }
  selectSuccessor(key, status) {
    const row = this.operation(key);
    require(status.state === 'Reapproved', 'No recorded successor');
    const value = invitation(status.successor, this.records.application, status.successor.request_id);
    require(sameIntent(row.invitation, value), 'Successor changed the device intent');
    const retained = this.records.read().operations.find(r => equal(r.request_id, value.request_id));
    if (retained) require(retained.invitation === null || equal(retained.invitation, value), 'Retained successor conflicts with host history');
    else this.records.add({kind: 'reapprove', request_id: value.request_id, previous: row.invitation.operation, predecessor: value.predecessor, request: row.request, invitation: value});
    return base64(value.request_id);
  }
}
