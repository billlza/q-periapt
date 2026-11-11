// SPDX-License-Identifier: Apache-2.0 OR MIT
import {base64, encode, parse, equal} from './transport.mjs';
import {Grants} from './grant-model.mjs';
import {GRANT_REQUEST_BYTES, retainedRequest} from './grant-records.mjs';
import {displayExpiry} from './extension-model.mjs';
const el = id => document.getElementById(id);
export function grantUI({state, bind, change, download, fingerprint}) {
  let context = '', selected = '', draft = null, observed = '';
  function source() {
    const s = state(), records = s.model ? s.model.records.read() : null;
    const original = records && s.selected ? records.operations.find(r => base64(r.request_id) === s.selected) : null;
    if (s.selected && !original) throw new Error('Selected original enrollment is missing');
    return {...s, records, invitation: original?.invitation};
  }
  function controls() {
    const s = source(), next = s.model ? `${s.model.records.application}/${s.selected}` : '';
    if (next !== context) {
      context = next; selected = ''; draft = null; observed = '';
      el('grant-detail').textContent = 'Load this device’s original retained-state request, then select the issued credentials for review.';
      el('grant-file-detail').textContent = '';
      for (const key of ['grant-original', 'grant-previous', 'grant-target']) el(key).replaceChildren();
    }
    const extensions = s.invitation && s.records.schema >= 2 ? s.records.extensions.filter(r => r.response !== null && equal(r.request.enrollment, s.invitation.operation)) : [];
    for (const key of ['grant-original', 'grant-previous', 'grant-target']) {
      const previous = el(key).value;
      el(key).replaceChildren(new Option(key === 'grant-target' ? 'Select an issued target renewal' : 'Original issued credential', ''));
      for (const row of extensions) {
        const id = base64(row.request.request_id);
        el(key).add(new Option(`Renewal ${id.slice(0, 12)}… · until ${displayExpiry(row.request.valid_until)}`, id));
      }
      el(key).value = previous; el(key).disabled = s.disposition?.state !== 'Issued';
    }
    const rows = s.invitation && s.records.schema >= 3 ? s.records.grants.filter(r => equal(r.request.retained.enrollment, s.invitation.operation)) : [];
    el('grants').replaceChildren(new Option('Select a retained recovery authorization', ''));
    for (const row of rows) {
      const key = base64(row.request.retained.operation);
      el('grants').add(new Option(`${row.state} · ${key.slice(0, 12)}…`, key));
    }
    el('grants').value = selected; el('grants').disabled = rows.length === 0;
    const row = rows.find(r => base64(r.request.retained.operation) === selected);
    el('grant-state').textContent = !row ? '' : `Browser recovery state: ${row.state}${observed ? ` · last host observation: ${observed}` : ''}. ` +
      (row.state === 'CancelRequested' ? 'Cancellation outcome unresolved. Query or repeat cancellation; do not issue another version.' :
        row.state === 'Issued' ? 'Historical result retained. The device still checks current membership, policy and time.' :
          row.state === 'Closed' ? 'This exact decision is closed. A new decision needs a new retained request operation.' :
            'Review the exact decision before approval. Query an uncertain result before resuming issuance.');
    el('grant-file').disabled = s.disposition?.state !== 'Issued'; el('grant-file').value = '';
    el('prepare-grant').disabled = !draft || s.disposition?.state !== 'Issued' || !s.observation?.roster || s.observation.suspended || !el('grant-target').value;
    el('submit-grant').disabled = !row || !['Prepared', 'Submitted'].includes(row.state);
    el('submit-grant').textContent = row?.state === 'Submitted' ? 'Finish the original approved issuance' : 'Approve and issue this recovery authorization';
    el('refresh-grant').disabled = !row;
    el('cancel-grant').disabled = !row || row.state === 'Issued';
    el('save-grant-request').disabled = !row;
    el('save-grant').disabled = !row || row.response === null;
  }
  async function show() {
    controls();
    if (!selected) {
      el('grant-detail').textContent = 'Preparing saves the exact decision for review. It does not sign a recovery authorization.';
      return;
    }
    const s = source(), row = s.model.records.findGrant(selected), request = row.request, r = request.retained;
    const target = s.model.records.findExtension(base64(request.successor_extension));
    const selection = value => value === null ? 'original enrollment issuance' : base64(value);
    el('grant-detail').textContent = [
      `Device: ${base64(s.invitation.device)} · generation ${s.invitation.generation}`,
      `Original enrollment: ${base64(r.enrollment)}`, `Recovery operation: ${selected}`,
      `Original credential source: ${selection(request.original_extension)}`, `Previous credential source: ${selection(request.previous_extension)}`,
      `Target renewal: ${base64(request.successor_extension)}`, `Target credential expiry (UTC): ${displayExpiry(target.request.valid_until)}`,
      `Previous roster: ${r.previous_checkpoint.version} · ${base64(r.previous_checkpoint.digest)}`,
      `Approved target roster: ${request.target_checkpoint.version} · ${base64(request.target_checkpoint.digest)}`,
      `Original owner: ${base64(r.original_owner)}`, `Original policy scope: ${r.original_policy.version} · ${base64(r.original_policy.digest)}`,
      `Reported journal: ${base64(r.journal)}`, `Reported current policy: ${r.current_policy.version} · ${base64(r.current_policy.digest)}`,
      `Decision SHA-256: ${await fingerprint(new TextEncoder().encode(encode(request)))}`,
      'Approval authorizes the original retained owner under the selected original policy. Reported journal and current policy are context; they are not extra signed grant scope.',
    ].join('\n');
  }
  change('grant-file', async () => {
    const s = source(), file = el('grant-file').files[0];
    if (!file || file.size === 0 || file.size > GRANT_REQUEST_BYTES) throw new Error('Choose the original retained-state JSON request, at most 64 KiB');
    const bytes = new Uint8Array(await file.arrayBuffer());
    const value = retainedRequest(parse(new TextDecoder('utf-8', {fatal: true}).decode(bytes)));
    if (!s.invitation || !equal(value.enrollment, s.invitation.operation) || base64(value.application) !== s.model.records.application) throw new Error('Request belongs to another selected account or device');
    draft = value; selected = ''; observed = '';
    el('grant-file-detail').textContent = `Loaded request ${base64(value.operation)} · SHA-256 ${await fingerprint(bytes)}`;
    await show();
  });
  for (const key of ['grant-original', 'grant-previous', 'grant-target']) change(key, async () => controls());
  bind('prepare-grant', async () => {
    const s = source();
    if (!draft || s.disposition?.state !== 'Issued' || typeof s.issued !== 'string') throw new Error('Load the original request and refresh its issued enrollment first');
    selected = new Grants(s.model).prepare(s.selected, s.observation, draft, {
      original: el('grant-original').value || null, previous: el('grant-previous').value || null, successor: el('grant-target').value || null,
    }, s.issued); observed = ''; await show();
  });
  bind('submit-grant', async () => { await new Grants(source().model).submit(selected); observed = 'Issued'; await show(); });
  bind('refresh-grant', async () => { observed = await new Grants(source().model).refresh(selected); await show(); });
  bind('cancel-grant', async () => { await new Grants(source().model).cancel(selected); observed = 'Closed'; await show(); });
  bind('save-grant-request', async () => download('retained-grant-request.json', encode(source().model.records.findGrant(selected).request)));
  bind('save-grant', async () => {
    const row = source().model.records.findGrant(selected);
    if (row.response === null) throw new Error('Recover the exact signed result first');
    download('retained-grant.json', row.response);
  });
  change('grants', async () => { selected = el('grants').value; observed = ''; await show(); });
  return {controls};
}
