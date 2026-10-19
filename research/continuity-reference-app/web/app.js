'use strict';
import {json as request, hostLock, losslessSupport, HttpError} from './transport.mjs';
import {enrollmentUI} from './enrollment.mjs';
const el = id => document.getElementById(id);
let current = null;
let statusRevision = 0;
function showStatus(message) {
  statusRevision += 1;
  el('status').textContent = message;
  return statusRevision;
}
const enrollment = enrollmentUI(action, () => current);
function render(value) {
  current = value;
  el('identity').hidden = !value;
  el('account-form').hidden = !!value;
  el('account-detail').textContent = value ? `${value.account} · ${value.passkeys} passkey(s)` : '';
  enrollment.render(value);
}
async function action(work) {
  document.querySelectorAll('button, input, select').forEach(b => { b.disabled = true; });
  const pendingRevision = showStatus('Working…');
  try { await hostLock(work); if (statusRevision === pendingRevision) showStatus('Operation completed. Review its displayed state.'); }
  catch (error) {
    if (error instanceof HttpError && error.status === 401 && current) render(null);
    showStatus(`Not completed: ${error.message}. Original account and device state is retained. Recover or retry the original operation; do not replace it with a new device.`);
  }
  finally { document.querySelectorAll('button, input, select').forEach(b => { b.disabled = false; }); enrollment.controls(); }
}
async function register(name) {
  showStatus('Confirm passkey creation on your device.');
  const options = await request('/api/register/start', {name});
  const credential = await navigator.credentials.create({publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options.publicKey)});
  if (!credential) throw new Error('Passkey creation was cancelled');
  const account = await request('/api/register/finish', credential.toJSON());
  if (current) { render(account); showStatus('Another passkey is saved for this account.'); }
  else { showStatus('Account created. Sign in with your passkey to authenticate.'); }
}
el('account-form').addEventListener('submit', event => {
  event.preventDefault();
  action(async () => {
    showStatus('Confirm sign-in on your device.');
    const options = await request('/api/login/start', {name: el('name').value});
    const credential = await navigator.credentials.get({publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options.publicKey)});
    if (!credential) throw new Error('Sign-in was cancelled');
    render(await request('/api/login/finish', credential.toJSON()));
    showStatus('Signed in. Device registration still requires a separate approval.');
  });
});
el('create').addEventListener('click', () => { if (el('account-form').reportValidity()) action(() => register(el('name').value)); });
el('add').addEventListener('click', () => action(() => register(current.account)));
el('sign-out').addEventListener('click', () => action(async () => { await request('/api/logout', {}); render(null); showStatus('Signed out.'); }));
(async () => {
  if (!window.PublicKeyCredential || !PublicKeyCredential.parseCreationOptionsFromJSON || !PublicKeyCredential.parseRequestOptionsFromJSON || !losslessSupport() || !navigator.locks) {
    showStatus('This example requires WebAuthn JSON, lossless JSON and browser lock support. No account or device operation has started.');
    document.querySelectorAll('button').forEach(b => { b.disabled = true; });
    return;
  }
  try {
    render(await request('/api/me')); showStatus('Your current session is active.');
  } catch (error) {
    if (error instanceof HttpError && error.status === 401) { render(null); return; } // No login session is an ordinary state.
    showStatus(`Could not read account or recovery state: ${error.message}`);
  }
})();
