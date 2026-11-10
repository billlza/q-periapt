// SPDX-License-Identifier: Apache-2.0 OR MIT
import {base64, unbase64, equal, parse} from './transport.mjs';
import {root} from './enrollment-records.mjs';
import {grantRecord, grantResponse, retainedRequest} from './grant-records.mjs';
import {require, fields} from './record-validation.mjs';
const endpoint = '/api/enrollment/credential-grant';
export class Grants {
  constructor(enrollment) { this.enrollment = enrollment; this.records = enrollment.records; }
  prepare(key, observation, report, selections, enrollmentResponse) {
    const original = this.enrollment.operation(key).invitation; root(observation); retainedRequest(report);
    require(!observation.suspended && observation.roster !== null && observation.public_key === original.root
      && observation.revision === original.root_revision && equal(observation.family, original.family), 'Displayed root cannot issue this recovery authorization');
    fields(selections, 'original previous successor');
    const select = key => key === null ? null : this.records.findExtension(key).request.request_id;
    require(selections.successor !== null, 'Select an already-issued target extension');
    const request = {retained: report, original_extension: select(selections.original), previous_extension: select(selections.previous),
      successor_extension: select(selections.successor), target_checkpoint: observation.roster.checkpoint};
    require(equal(report.enrollment, original.operation), 'Retained request belongs to another selected device');
    const row = {request, enrollment_response: enrollmentResponse, state: 'Prepared', response: null};
    const records = this.records.read(); grantRecord(row, records.operations, this.records.extensions(), this.records.application);
    const existing = this.records.grants().find(g => equal(g.request.retained.operation, report.operation));
    if (existing) require(equal(existing.request, request) && existing.enrollment_response === enrollmentResponse, 'Original recovery decision differs; retain it and prepare a new operation explicitly');
    else this.records.addGrant(row);
    return base64(report.operation);
  }
  async submit(key) {
    const row = this.records.findGrant(key);
    require(['Prepared', 'Submitted'].includes(row.state), 'Only the original approved decision may be issued or resumed');
    this.records.transitionGrant(key, 'Submitted'); // Retain approval before any dispatch.
    const result = await this.enrollment.api(endpoint, row.request);
    grantResponse(result.text, row.request); this.records.transitionGrant(key, 'Issued', result.text);
    return result.text;
  }
  async refresh(key) {
    const row = this.records.findGrant(key), result = (await this.enrollment.api(endpoint + '/status', row.request)).value;
    require(result && ['Absent', 'Pending', 'Issued', 'Closed'].includes(result.state), 'Unknown host grant status');
    fields(result, result.state === 'Issued' ? 'state response' : 'state');
    if (result.state === 'Issued') {
      const text = new TextDecoder('utf-8', {fatal: true}).decode(unbase64(result.response, 128 * 1024));
      grantResponse(text, row.request); this.records.transitionGrant(key, 'Issued', text);
    } else if (result.state === 'Closed') this.records.transitionGrant(key, 'Closed');
    else {
      require(!['Issued', 'Closed'].includes(row.state), 'Host lost an original terminal grant outcome');
      if (result.state === 'Pending' && row.state === 'Prepared') this.records.transitionGrant(key, 'Submitted');
    }
    return result.state;
  }
  async cancel(key) {
    const row = this.records.findGrant(key);
    require(['Prepared', 'Submitted', 'CancelRequested', 'Closed'].includes(row.state), 'An issued authorization cannot be cancelled');
    if (row.state !== 'Closed') this.records.transitionGrant(key, 'CancelRequested');
    const result = await this.enrollment.api(endpoint + '/cancel', row.request);
    require(result.status === 204, 'Unexpected grant cancellation response');
    this.records.transitionGrant(key, 'Closed');
  }
}
