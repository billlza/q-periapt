// SPDX-License-Identifier: Apache-2.0 OR MIT
// Shared structural issuance lineage. Host and SDK verify the signatures.
import {parse, unbase64, equal} from './transport.mjs';
import {require, fields, id, integer, checkpoint} from './record-validation.mjs';
export function credentialHistory(text, original, extensions) {
  require(typeof text === 'string' && new TextEncoder().encode(text).length <= 128 * 1024, 'Historical issuance exceeds bound');
  const first = parse(text);
  fields(first, 'operation root_revision certificate roster checkpoint');
  id(first.operation); integer(first.root_revision, true); checkpoint(first.checkpoint);
  require(first.checkpoint !== null && equal(first.operation, original.operation) && first.root_revision === original.root_revision, 'Historical issuance belongs to another enrollment');
  unbase64(first.certificate, 65536); unbase64(first.roster, 65536);
  function extension(selection) {
    const item = extensions.find(e => equal(e.request.request_id, selection));
    require(item && item.response !== null && equal(item.request.enrollment, original.operation)
      && item.root_revision === original.root_revision, 'Select an issued extension of the original enrollment');
    return item;
  }
  function issued(selection) { return selection === null ? first : parse(extension(selection).response); }
  function descends(child, ancestor) {
    for (let steps = 0; steps <= extensions.length; ++steps) {
      if (equal(child, ancestor)) return;
      require(child !== null, 'Selected extension is outside the original chain');
      child = extension(child).request.previous_extension;
    }
    throw new Error('Cyclic extension history');
  }
  return {issued, extension, descends};
}
