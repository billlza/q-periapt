// SPDX-License-Identifier: Apache-2.0 OR MIT
import {base64, equal, encode} from './transport.mjs';
import {Extensions, expiryUTC} from './extension-model.mjs';
const el = id => document.getElementById(id);
function expiry(value) {
  const seconds = BigInt(value);
  return seconds <= 8640000000000n ? new Date(Number(seconds) * 1000).toISOString() : `${value} Unix seconds (outside browser calendar range)`;
}

export function extensionUI({state, bind, change, download, fingerprint, refreshRoot}) {
  let context = '', selected = '';
  function source() {
    const s = state(), records = s.model ? s.model.records.read() : null;
    const original = s.selected && records ? records.operations.find(r => base64(r.request_id) === s.selected) : null;
    if (s.selected && !original) throw new Error('Selected original enrollment record is missing');
    return {...s, records, invitation: original ? original.invitation : null};
  }
  function controls() {
    const s = source(), next = s.model ? `${s.model.records.application}/${s.selected}` : '';
    if (context !== next) {
      context = next; selected = ''; el('renewal-until').value = '';
      el('renewal-base').replaceChildren(new Option('Original issued credential', ''));
      el('renewal-detail').textContent = 'Select an issued device, read its current roster, and prepare a renewal for review.';
    }
    const rows = s.invitation && s.records.schema === 2 ? s.records.extensions.filter(r => equal(r.request.enrollment, s.invitation.operation)) : [];
    const base = el('renewal-base').value;
    el('renewal-base').replaceChildren(new Option('Original issued credential', ''));
    el('renewals').replaceChildren(new Option('Select a retained renewal request', ''));
    for (const row of rows) {
      const key = base64(row.request.request_id);
      el('renewals').add(new Option(`${row.response === null ? 'Result unresolved' : 'Result retained'} · ${key.slice(0, 12)}…`, key));
      if (row.response !== null) el('renewal-base').add(new Option(`Renewal ${key.slice(0, 12)}… · until ${expiry(row.request.valid_until)}`, key));
    }
    el('renewal-base').value = base; el('renewals').value = selected;
    const row = rows.find(r => base64(r.request.request_id) === selected), issued = s.disposition?.state === 'Issued';
    el('renewal-base').disabled = !issued; el('renewal-until').disabled = !issued;
    el('prepare-renewal').disabled = !issued || !s.observation || s.observation.suspended || !s.observation.roster;
    el('renewals').disabled = rows.length === 0;
    el('submit-renewal').disabled = !issued || !row;
    el('save-renewal-request').disabled = !row;
    el('save-renewal').disabled = !row || row.response === null;
  }
  async function show() {
    controls();
    if (!selected) {
      el('renewal-detail').textContent = 'No renewal selected. Preparing a request saves its exact expiry and roster for review; it does not issue a credential.';
      return;
    }
    const s = source(), row = s.model.records.findExtension(selected), value = row.request;
    el('renewal-detail').textContent = [
      `Device: ${base64(s.invitation.device)} · generation ${s.invitation.generation}`,
      `Original enrollment: ${base64(value.enrollment)}`, `Renewal correlation: ${selected}`,
      `Selected predecessor: version ${value.predecessor.version} · ${base64(value.predecessor.digest)}`,
      value.previous_extension === null ? 'Extends: original issued credential' : `Extends renewal: ${base64(value.previous_extension)}`,
      `Requested expiry (UTC): ${expiry(value.valid_until)}`, `Expiry (Unix seconds): ${value.valid_until}`,
      `Request SHA-256: ${await fingerprint(new TextEncoder().encode(encode(value)))}`,
      row.response === null ? 'Result unresolved. Submit only after approving these exact details; an interrupted request may already have committed.' : 'Exact historical result retained. Consumer admission still needs current trust, roster and signed policy.',
      'This keeps the original device keys. It does not renew protocol policy or authorize retained-session recovery.',
    ].join('\n');
  }
  bind('prepare-renewal', async () => {
    const s = source();
    if (s.disposition?.state !== 'Issued') throw new Error('Refresh the original issued enrollment first');
    selected = new Extensions(s.model).prepare(s.selected, s.observation, el('renewal-base').value || null, expiryUTC(el('renewal-until').value));
    await show();
  });
  bind('submit-renewal', async () => {
    await new Extensions(source().model).submit(selected); await show();
    await refreshRoot(); controls();
  });
  bind('save-renewal', async () => {
    const row = source().model.records.findExtension(selected);
    if (row.response === null) throw new Error('Recover the exact renewal result first');
    download('credential-extension.json', row.response);
  });
  bind('save-renewal-request', async () => {
    download('credential-extension-request.json', encode(source().model.records.findExtension(selected).request));
  });
  change('renewals', async () => { selected = el('renewals').value; await show(); });
  return {controls};
}
