// SPDX-License-Identifier: Apache-2.0 OR MIT
import {base64, equal} from './transport.mjs';
import {root, id, extensionRequest, extensionResponse} from './enrollment-records.mjs';
function require(value, message) { if (!value) throw new Error(message); }

// This input is explicitly UTC, independent of browser locale and DST offsets.
export function expiryUTC(text) {
  require(typeof text === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?$/.test(text), 'Choose an exact UTC date and time');
  const canonical = text.length === 16 ? text + ':00' : text, millis = Date.parse(canonical + 'Z');
  require(Number.isSafeInteger(millis) && millis > 0 && new Date(millis).toISOString() === canonical + '.000Z', 'Invalid UTC expiry');
  return millis / 1000;
}

export class Extensions {
  constructor(enrollment, clock = () => Math.floor(Date.now() / 1000)) {
    this.enrollment = enrollment; this.records = enrollment.records; this.clock = clock;
  }
  prepare(key, observation, previous, validUntil) {
    const original = this.enrollment.operation(key).invitation; root(observation);
    require(!observation.suspended && observation.roster !== null && observation.public_key === original.root
      && observation.revision === original.root_revision && equal(observation.family, original.family), 'Displayed root does not authorize original-device renewal');
    let validAfter = original.valid_until, predecessor = null;
    if (previous !== null) {
      const source = this.records.findExtension(previous);
      require(source.response !== null && equal(source.request.enrollment, original.operation)
        && source.root_revision === original.root_revision, 'Select a completed extension of this original device');
      validAfter = source.request.valid_until; predecessor = source.request.request_id;
    }
    const request = {request_id: id(this.enrollment.random()), enrollment: original.operation,
      previous_extension: predecessor, predecessor: observation.roster.checkpoint, valid_until: validUntil};
    extensionRequest(request);
    const now = this.clock(); require(Number.isSafeInteger(now) && now >= 0, 'Invalid host clock');
    require(BigInt(validUntil) > BigInt(validAfter) && BigInt(validUntil) > BigInt(now), 'Renewal expiry must extend the selected credential and be in the future');
    this.records.addExtension({request, root_revision: original.root_revision, response: null});
    return base64(request.request_id);
  }
  async submit(key) {
    const row = this.records.findExtension(key);
    // Even an expired or stale request is retried exactly: it may already have
    // committed. Current root and consumer admission remain separate operations.
    const result = await this.enrollment.api('/api/enrollment/extend-credential', row.request);
    extensionResponse(result.text, row.request, row.root_revision);
    this.records.completeExtension(key, result.text);
    return result.text;
  }
}
