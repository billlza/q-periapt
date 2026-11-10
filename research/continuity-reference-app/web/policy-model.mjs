// SPDX-License-Identifier: Apache-2.0 OR MIT
import {base64, unbase64, equal} from './transport.mjs';
import {require, fields} from './record-validation.mjs';
import {policyInputs, policyReport, policyContext, policyReview, policyResponse} from './policy-records.mjs';
const endpoint = '/api/enrollment/policy-approval';
export class PolicyApprovals {
  constructor(enrollment) { this.enrollment = enrollment; this.records = enrollment.records; }
  async prepare(key, report, inputs, selections, enrollmentResponse) {
    const original = this.enrollment.operation(key).invitation;
    policyReport(report); policyInputs(inputs); fields(selections, 'original current');
    require(equal(inputs.family, original.family) && equal(report.enrollment, original.operation), 'Policy input belongs to another selected installation');
    const select = key => key === null ? null : this.records.findExtension(key).request.request_id;
    const request = {retained: report, original_extension: select(selections.original), current_extension: select(selections.current),
      original: inputs.original, previous: inputs.previous, target: inputs.target};
    const records = this.records.read();
    policyContext(request, enrollmentResponse, records.operations, this.records.extensions(), this.records.application);
    const identity = base64(report.scope.operation), existing = this.records.policyApprovals().find(r => equal(r.request.retained.scope.operation, report.scope.operation));
    if (existing) {
      require(equal(existing.request, request) && existing.enrollment_response === enrollmentResponse, 'Original policy decision differs; retain it and prepare a new operation explicitly');
      await this.review(identity);
      return identity;
    }
    const preview = (await this.enrollment.api(endpoint + '/preview', request)).value;
    require(preview && ['Absent', 'Pending', 'Issued', 'Closed'].includes(preview.state), 'Unknown policy preview state');
    fields(preview, preview.state === 'Closed' ? 'state' : 'state review');
    const review = preview.state === 'Closed' ? null : policyReview(preview.review, request);
    this.records.addPolicyApproval({request, enrollment_response: enrollmentResponse, review,
      state: preview.state === 'Closed' ? 'Closed' : preview.state === 'Absent' ? 'Prepared' : 'Submitted', response: null});
    if (preview.state === 'Issued') await this.refresh(identity); // Observe only; never re-sign.
    return identity;
  }
  async review(key) {
    const row = this.records.findPolicyApproval(key), preview = (await this.enrollment.api(endpoint + '/preview', row.request)).value;
    require(preview && ['Absent', 'Pending', 'Issued', 'Closed'].includes(preview.state), 'Unknown policy preview state');
    fields(preview, preview.state === 'Closed' ? 'state' : 'state review');
    if (preview.state === 'Closed') this.records.transitionPolicyApproval(key, 'Closed');
    else {
      policyReview(preview.review, row.request);
      require(equal(preview.review, row.review), 'Host review differs from the original retained review');
      require(row.state !== 'Closed' && (row.state !== 'Issued' || preview.state === 'Issued'), 'Host lost an original terminal policy outcome');
      if (preview.state === 'Issued') await this.refresh(key);
    }
    return preview.state;
  }
  async submit(key) {
    const row = this.records.findPolicyApproval(key);
    require(['Prepared', 'Submitted'].includes(row.state), 'Only the original reviewed policy decision may be issued or resumed');
    // Imported metadata is not a signature. Recheck every displayed review
    // field with the authenticated host before dispatching a signing request.
    const state = await this.review(key);
    if (state === 'Issued') return this.records.findPolicyApproval(key).response;
    require(state !== 'Closed', 'Original policy decision is closed');
    this.records.transitionPolicyApproval(key, 'Submitted');
    const result = await this.enrollment.api(endpoint, row.request);
    policyResponse(result.text, row.request, row.review);
    this.records.transitionPolicyApproval(key, 'Issued', result.text);
    return result.text;
  }
  async refresh(key) {
    const row = this.records.findPolicyApproval(key), result = (await this.enrollment.api(endpoint + '/status', row.request)).value;
    require(result && ['Absent', 'Pending', 'Issued', 'Closed'].includes(result.state), 'Unknown host policy status');
    fields(result, result.state === 'Issued' ? 'state response' : result.state === 'Pending' ? 'state statement' : 'state');
    if (result.state === 'Issued') {
      const text = new TextDecoder('utf-8', {fatal: true}).decode(unbase64(result.response, 128 * 1024));
      policyResponse(text, row.request, row.review); this.records.transitionPolicyApproval(key, 'Issued', text);
    } else if (result.state === 'Closed') this.records.transitionPolicyApproval(key, 'Closed');
    else {
      require(!['Issued', 'Closed'].includes(row.state), 'Host lost an original terminal policy outcome');
      if (result.state === 'Pending') {
        require(equal(result.statement, row.review.statement), 'Host changed the reviewed policy statement');
        if (row.state === 'Prepared') this.records.transitionPolicyApproval(key, 'Submitted');
      }
    }
    return result.state;
  }
  async cancel(key) {
    const row = this.records.findPolicyApproval(key);
    require(['Prepared', 'Submitted', 'CancelRequested', 'Closed'].includes(row.state), 'An issued policy approval cannot be cancelled');
    if (row.state !== 'Closed') this.records.transitionPolicyApproval(key, 'CancelRequested');
    const result = await this.enrollment.api(endpoint + '/cancel', row.request);
    require(result.status === 204, 'Unexpected policy cancellation response');
    this.records.transitionPolicyApproval(key, 'Closed');
  }
}
