// SPDX-License-Identifier: Apache-2.0 OR MIT
import {base64, unbase64, encode, json, request} from './transport.mjs';
import {Records, MAX_RECORD_BYTES} from './enrollment-records.mjs';
import {Enrollment} from './enrollment-model.mjs';
import {extensionUI} from './extension.mjs';
import {grantUI} from './grant.mjs';
const el = id => document.getElementById(id);
function download(name, text) {
  const url = URL.createObjectURL(new Blob([text], {type: 'application/json'}));
  const anchor = document.createElement('a'); anchor.href = url; anchor.download = name;
  document.body.append(anchor); anchor.click(); anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
async function fingerprint(bytes) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  return Array.from(digest, byte => byte.toString(16).padStart(2, '0')).join('');
}
export function enrollmentUI(action, identity) {
  let model = null, selected = '', disposition = null, observation = null, issued = null, draft = null, hasProof = false, directProof = false;
  const extensions = extensionUI({state: () => ({model, selected, disposition, observation}), bind, download, fingerprint,
    change: (id, work) => el(id).addEventListener('change', () => action(async () => { await authenticated(); await work(); })),
    refreshRoot: async () => {
      observation = null; el('root-detail').textContent = 'Renewal may have changed the roster. Reading the current host observation…';
      await showRoot(await model.readRoot());
    }});
  const grants = grantUI({state: () => ({model, selected, disposition, observation, issued}), bind, download, fingerprint,
    change: (id, work) => el(id).addEventListener('change', () => action(async () => { await authenticated(); await work(); }))});
  function clearObservation() {
    disposition = null; observation = null; issued = null; draft = null; hasProof = false; directProof = false;
    el('root-detail').textContent = 'Read the current root and roster before selecting a new approval.';
    el('operation-detail').textContent = 'Select an original operation or explicitly create an invitation.';
  }
  function list() {
    const select = el('operations'); select.replaceChildren(new Option('Select an original operation', ''));
    if (!model) return;
    for (const row of model.records.read().operations) {
      const key = base64(row.request_id), label = row.invitation ? `Device ${base64(row.invitation.device)}` : 'Unresolved response';
      select.add(new Option(`${label} · ${key.slice(0, 12)}…`, key));
    }
    select.value = selected;
  }
  function controls() {
    const known = !!model && !!selected, phase = disposition?.state;
    // A native input change can precede a rejected cross-tab lock. Restore the
    // displayed selection to the operation actually held by this controller.
    el('operations').value = selected;
    el('request-file').value = ''; el('recovery-file').value = '';
    el('recover-operation').disabled = !known;
    el('request-file').disabled = !known;
    el('save-invitation').disabled = !known;
    el('approve-request').disabled = !known || !hasProof || !directProof || phase !== 'Invited';
    el('issue-device').disabled = !known || !['Approved', 'Issued'].includes(phase);
    el('cancel-operation').disabled = !known || !['Invited', 'Approved'].includes(phase);
    el('reapprove-request').disabled = !known || !hasProof || !observation || !['Invited', 'Approved'].includes(phase);
    el('select-successor').disabled = phase !== 'Reapproved';
    el('save-issued').disabled = issued === null;
    el('save-root').disabled = observation === null;
    el('save-authority').disabled = observation === null;
    extensions.controls();
    grants.controls();
  }
  async function authenticated() {
    if (!model || !identity()) throw new Error('Sign in as the original account first');
    const actual = await json('/api/me');
    if (actual.application_id !== model.records.application || actual.application_id !== identity().application_id) throw new Error('The browser account changed. Reload and sign in as the original account');
  }
  async function showRoot(value) {
    observation = value;
    el('root-detail').textContent = [
      `Root revision: ${value.revision}`, `Root SHA-256: ${await fingerprint(unbase64(value.public_key, 1985))}`,
      `Account: ${base64(value.account)}`, `Policy family: ${base64(value.family)}`,
      `Issuance suspended: ${value.suspended ? 'yes' : 'no'}`,
      value.roster === null ? 'Selected predecessor: empty roster' : `Selected predecessor: version ${value.roster.checkpoint.version}\nDigest: ${base64(value.roster.checkpoint.digest)}`,
      'This is a host observation. Client acceptance also requires independently authenticated trust and current signed policy.',
    ].join('\n');
  }
  async function showOperation() {
    list();
    if (!selected) { clearObservation(); controls(); return; }
    const row = model.records.find(selected), value = row.invitation;
    const lines = [`Correlation: ${selected}`, `Kind: ${row.kind}`];
    if (value) lines.push(`Operation: ${base64(value.operation)}`, `Device: ${base64(value.device)} · generation ${value.generation}`,
      `Root revision: ${value.root_revision}`, `Root SHA-256: ${await fingerprint(unbase64(value.root, 1985))}`,
      `Policy family: ${base64(value.family)}`, `Credential interval (Unix seconds): ${value.valid_from}–${value.valid_until}`,
      `Approval deadline (Unix seconds): ${value.deadline}`, `Host state: ${disposition?.state || 'Not refreshed'}`);
    else lines.push('Response unresolved. Recover this correlation; do not create another device.');
    if (!value && row.kind === 'reapprove') lines.push(`Source operation: ${base64(row.previous)}. If the host rejected this decision, select that original source and explicitly approve against a newly reviewed roster. This attempt remains retained.`);
    hasProof = row.request !== null || draft !== null;
    directProof = row.request === null || draft === null || row.request === base64(draft);
    if (row.request) lines.push(`Original retained request SHA-256: ${await fingerprint(unbase64(row.request, 8192))}`);
    else if (draft) lines.push(`Selected request SHA-256 (not submitted): ${await fingerprint(draft)}`);
    else lines.push('Load the original device request file before approving.');
    if (!directProof) lines.push(`Separately selected request SHA-256: ${await fingerprint(draft)}. This can only be submitted as a new explicit reapproval while the source is still unapproved; the original request will remain retained.`);
    if (disposition?.state === 'Reapproved') lines.push(`Recorded successor: ${base64(disposition.successor.operation)}. Select it explicitly to continue.`);
    if (disposition?.state === 'Issued') lines.push('Issued is a historical result, not current permission to communicate.');
    el('operation-detail').textContent = lines.join('\n'); controls();
  }
  async function refresh() {
    disposition = await model.status(selected); issued = null;
    if (disposition.state === 'Issued') { issued = model.issuedText(selected, disposition.response); await showRoot(disposition.current); }
    await showOperation();
  }
  function bind(id, work) {
    el(id).addEventListener('click', () => action(async () => { await authenticated(); await work(); }));
  }
  bind('prepare-root', async () => { await showRoot(await model.prepareRoot()); controls(); });
  bind('read-root', async () => { await showRoot(await model.readRoot()); controls(); });
  bind('new-invitation', async () => {
    selected = model.newInvitation(); clearObservation(); await showOperation();
    await model.recover(selected); await refresh();
  });
  bind('recover-operation', async () => { await model.recover(selected); await refresh(); });
  bind('approve-request', async () => {
    if (draft) model.retainProof(selected, draft);
    await model.approve(selected); draft = null; await refresh();
  });
  bind('issue-device', async () => { issued = await model.issue(selected); await refresh(); });
  bind('cancel-operation', async () => { await model.cancel(selected); await refresh(); });
  bind('reapprove-request', async () => {
    if (!observation) throw new Error('Read and review the current root and roster first');
    selected = model.reapproval(selected, observation, draft === null ? undefined : draft); clearObservation(); await showOperation();
    await model.recover(selected); await refresh();
  });
  bind('select-successor', async () => {
    selected = model.selectSuccessor(selected, disposition); clearObservation(); await showOperation();
    await model.recover(selected); await refresh();
  });
  bind('save-invitation', async () => download('enrollment-invitation.json', encode(model.operation(selected).invitation)));
  bind('save-records', async () => download('enrollment-recovery.json', model.records.export()));
  bind('save-issued', async () => {
    if (issued === null) throw new Error('Recover the original issued response first');
    download('historical-enrollment-result.json', issued);
  });
  bind('save-root', async () => {
    if (!observation) throw new Error('Read the root and roster first');
    download('observed-root-and-roster.json', encode(observation));
  });
  bind('save-authority', async () => {
    if (!observation) throw new Error('Read and review the account root first');
    download('client-host-authority.json', encode(model.authorityProfile(observation)));
  });
  el('operations').addEventListener('change', () => action(async () => {
    await authenticated(); selected = el('operations').value; clearObservation(); await showOperation();
    if (selected && model.records.find(selected).invitation) await refresh();
  }));
  el('request-file').addEventListener('change', () => action(async () => {
    await authenticated(); const file = el('request-file').files[0];
    if (!file || file.size === 0 || file.size > 8192) throw new Error('Choose the original binary device request, at most 8192 bytes');
    const bytes = new Uint8Array(await file.arrayBuffer()), retained = model.operation(selected).request;
    if (retained !== null && retained !== base64(bytes) && disposition?.state !== 'Invited') throw new Error('An already approved or unknown source cannot select another device request');
    draft = bytes;
    el('request-file').value = ''; await showOperation();
  }));
  el('recovery-file').addEventListener('change', () => action(async () => {
    await authenticated(); const file = el('recovery-file').files[0];
    if (!file || file.size > MAX_RECORD_BYTES) throw new Error('Recovery file exceeds the 4 MiB bound');
    model.records.merge(await file.text()); el('recovery-file').value = ''; list(); controls();
  }));
  return {
    controls,
    render(account) {
      el('enrollment').hidden = !account;
      if (!account || model?.records.application !== account.application_id) {
        model = account ? new Enrollment(new Records(localStorage, location.origin, account.application_id), request) : null;
        selected = ''; clearObservation(); list();
      }
      controls();
    },
  };
}
