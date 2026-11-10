// SPDX-License-Identifier: Apache-2.0 OR MIT
import {base64, unbase64, encode, parse, equal} from './transport.mjs';
import {PolicyApprovals} from './policy-model.mjs';
import {POLICY_REPORT_BYTES, POLICY_INPUT_BYTES, policyReport, policyInputs} from './policy-records.mjs';
import {displayExpiry} from './extension-model.mjs';
const el = id => document.getElementById(id);
export function policyUI({state, bind, change, download, fingerprint}) {
  let context = '', selected = '', reviewed = '', report = null, inputs = null, observed = '';
  let selections = {original: '', current: ''};
  function source() {
    const s = state(), records = s.model?.records.read();
    const original = records && s.selected ? records.operations.find(r => base64(r.request_id) === s.selected) : null;
    if (s.selected && !original) throw new Error('Selected original enrollment is missing');
    return {...s, records, invitation: original?.invitation};
  }
  function controls() {
    const s = source(), next = s.model ? `${s.model.records.application}/${s.selected}` : '';
    if (next !== context) {
      context = next; selected = ''; reviewed = ''; report = null; inputs = null; observed = ''; selections = {original: '', current: ''};
      el('policy-detail').textContent = 'Load the original policy renewal request and the publisher’s public policy bundle for review.';
      el('policy-file-detail').textContent = ''; el('policy-inputs-detail').textContent = '';
    }
    const extensions = s.invitation && s.records.schema >= 2 ? s.records.extensions.filter(r => r.response !== null && equal(r.request.enrollment, s.invitation.operation)) : [];
    for (const name of ['original', 'current']) {
      const node = el(`policy-${name}`);
      node.replaceChildren(new Option('Original issued credential', ''));
      for (const row of extensions) {
        const key = base64(row.request.request_id);
        node.add(new Option(`Renewal ${key.slice(0, 12)}… · until ${displayExpiry(row.request.valid_until)}`, key));
      }
      node.value = selections[name]; node.disabled = s.disposition?.state !== 'Issued';
    }
    const rows = s.invitation && s.records.schema >= 4 ? s.records.policy_approvals.filter(r => equal(r.request.retained.enrollment, s.invitation.operation)) : [];
    el('policies').replaceChildren(new Option('Select a retained policy decision', ''));
    for (const row of rows) {
      const key = base64(row.request.retained.scope.operation);
      el('policies').add(new Option(`${row.state} · ${key.slice(0, 12)}…`, key));
    }
    el('policies').value = selected; el('policies').disabled = rows.length === 0;
    const row = rows.find(r => base64(r.request.retained.scope.operation) === selected);
    el('policy-state').textContent = !row ? '' : `Browser recovery state: ${row.state}${observed ? ` · last host observation: ${observed}` : ''}. ` +
      (row.state === 'CancelRequested' ? 'Cancellation outcome unresolved. Query or repeat cancellation.' :
        row.state === 'Issued' ? 'Original account approval retained. Policy approval and device admission remain required.' :
          row.state === 'Closed' ? 'This exact decision is closed. A new decision requires a new device operation.' :
            'Review the verified policy interval and exact request before issuing. Query an uncertain outcome before resuming.');
    for (const key of ['policy-file', 'policy-inputs']) {
      el(key).value = ''; el(key).disabled = s.disposition?.state !== 'Issued';
    }
    // Historical recovery must remain available after expiry or suspension.
    // The authenticated host distinguishes a new live decision from history.
    el('prepare-policy').disabled = !report || !inputs || s.disposition?.state !== 'Issued';
    el('submit-policy').disabled = !row || reviewed !== selected || !['Prepared', 'Submitted'].includes(row.state);
    el('submit-policy').textContent = row?.state === 'Submitted' ? 'Finish the original approved policy issuance' : 'Approve and issue this policy decision';
    el('refresh-policy').disabled = !row;
    el('cancel-policy').disabled = !row || row.state === 'Issued';
    el('save-policy-request').disabled = !row;
    el('save-policy').disabled = !row || row.response === null;
    el('save-policy-signature').disabled = !row || row.response === null;
  }
  async function show() {
    controls();
    if (!selected) {
      el('policy-detail').textContent = 'Review checks the signed policy inputs with the account host. It does not issue either approval.';
      return;
    }
    const s = source(), row = s.model.records.findPolicyApproval(selected), q = row.request, r = q.retained, v = row.review;
    const choice = value => value === null ? 'original enrollment issuance' : base64(value);
    el('policy-detail').textContent = [
      `Device: ${base64(s.invitation.device)} · generation ${s.invitation.generation}`,
      `Original enrollment: ${base64(r.enrollment)}`, `Policy operation: ${selected}`, `Reported journal: ${base64(r.scope.journal)}`,
      `Original credential source: ${choice(q.original_extension)}`, `Current credential source: ${choice(q.current_extension)}`,
      `Unchanged roster: ${r.scope.current_roster.version} · ${base64(r.scope.current_roster.digest)}`,
      ...['original', 'previous', 'target'].map(name => `${name} policy: ${q[name].pins.policy_version} · ${base64(q[name].pins.policy_digest)}`),
      ...(v ? [`${reviewed === selected ? 'Verified' : 'Retained, not yet reverified'} target interval (UTC): ${displayExpiry(v.valid_from)} – ${displayExpiry(v.valid_until)}`,
        `Unchanged send budget: ${v.send_budget} · witness required: ${v.witness_required ? 'yes' : 'no'}`,
        `Canonical statement: ${base64(v.statement)}`] : ['The host retained a closed decision; no signable review was returned.']),
      `Decision SHA-256: ${await fingerprint(new TextEncoder().encode(encode(q)))}`,
      'This account approval requires a separate policy-authority approval. The original device checks both before continuing retained state; it does not create a new installation.',
    ].join('\n');
  }
  for (const [key, limit, validate] of [['policy-file', POLICY_REPORT_BYTES, policyReport], ['policy-inputs', POLICY_INPUT_BYTES, policyInputs]]) {
    change(key, async () => {
      const s = source(), file = el(key).files[0];
      if (!file || file.size === 0 || file.size > limit) throw new Error(`Choose the original public JSON file, at most ${limit / 1024} KiB`);
      const bytes = new Uint8Array(await file.arrayBuffer());
      const value = validate(parse(new TextDecoder('utf-8', {fatal: true}).decode(bytes)));
      if (!s.invitation || (key === 'policy-file'
        ? !equal(value.enrollment, s.invitation.operation) || base64(value.application) !== s.model.records.application
        : !equal(value.family, s.invitation.family))) throw new Error('Policy input belongs to another selected account or device');
      if (key === 'policy-file') report = value; else inputs = value;
      selected = ''; reviewed = ''; observed = '';
      el(`${key}-detail`).textContent = `Loaded public input · SHA-256 ${await fingerprint(bytes)}`; await show();
    });
  }
  for (const name of ['original', 'current']) change(`policy-${name}`, async () => {
    selections[name] = el(`policy-${name}`).value; selected = ''; reviewed = ''; observed = ''; await show();
  });
  bind('prepare-policy', async () => {
    const s = source();
    if (!report || !inputs || s.disposition?.state !== 'Issued' || typeof s.issued !== 'string') throw new Error('Load both policy inputs and refresh the original issued enrollment first');
    selected = await new PolicyApprovals(s.model).prepare(s.selected, report, inputs,
      {original: selections.original || null, current: selections.current || null}, s.issued);
    reviewed = selected; observed = ''; await show();
  });
  bind('submit-policy', async () => { await new PolicyApprovals(source().model).submit(selected); observed = 'Issued'; await show(); });
  bind('refresh-policy', async () => { observed = await new PolicyApprovals(source().model).refresh(selected); await show(); });
  bind('cancel-policy', async () => { await new PolicyApprovals(source().model).cancel(selected); observed = 'Closed'; await show(); });
  bind('save-policy-request', async () => download('reviewed-policy-request.json', encode(source().model.records.findPolicyApproval(selected).request)));
  for (const raw of [false, true]) bind(raw ? 'save-policy-signature' : 'save-policy', async () => {
    const row = source().model.records.findPolicyApproval(selected);
    if (row.response === null) throw new Error('Recover the original policy result first');
    if (raw) download('account-policy-approval.bin', unbase64(parse(row.response).approval, 128 * 1024), 'application/octet-stream');
    else download('historical-policy-approval.json', row.response);
  });
  change('policies', async () => {
    selected = el('policies').value; reviewed = ''; observed = ''; await show();
    if (selected) { observed = await new PolicyApprovals(source().model).review(selected); reviewed = selected; await show(); }
  });
  return {controls};
}
