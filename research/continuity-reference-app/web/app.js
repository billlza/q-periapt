'use strict';
const el = id => document.getElementById(id);
let current = null;
async function request(path, body) {
  const response = await fetch(path, {method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin', cache: 'no-store',
    headers: body === undefined ? {} : {'Content-Type': 'application/json'}, body: body === undefined ? undefined : JSON.stringify(body)});
  const value = await response.json();
  if (!response.ok) throw new Error(value.error || `Request failed (${response.status})`);
  return value;
}
function render(value) {
  current = value;
  el('identity').hidden = !value;
  el('account-form').hidden = !!value;
  el('account-detail').textContent = value ? `${value.account} · ${value.passkeys} passkey(s)` : '';
}
async function action(work) {
  document.querySelectorAll('button').forEach(b => { b.disabled = true; });
  try { await work(); }
  catch (error) { el('status').textContent = `Not completed: ${error.message}. Start a new ceremony to retry; existing account state is retained.`; }
  finally { document.querySelectorAll('button').forEach(b => { b.disabled = false; }); }
}
async function register(name) {
  el('status').textContent = 'Confirm passkey creation on your device.';
  const options = await request('/api/register/start', {name});
  const credential = await navigator.credentials.create({publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options.publicKey)});
  if (!credential) throw new Error('Passkey creation was cancelled');
  const account = await request('/api/register/finish', credential.toJSON());
  if (current) { render(account); el('status').textContent = 'Another passkey is saved for this account.'; }
  else { el('status').textContent = 'Account created. Sign in with your passkey to authenticate.'; }
}
el('account-form').addEventListener('submit', event => {
  event.preventDefault();
  action(async () => {
    el('status').textContent = 'Confirm sign-in on your device.';
    const options = await request('/api/login/start', {name: el('name').value});
    const credential = await navigator.credentials.get({publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options.publicKey)});
    if (!credential) throw new Error('Sign-in was cancelled');
    render(await request('/api/login/finish', credential.toJSON()));
    el('status').textContent = 'Signed in. Device registration still requires a separate approval.';
  });
});
el('create').addEventListener('click', () => { if (el('account-form').reportValidity()) action(() => register(el('name').value)); });
el('add').addEventListener('click', () => action(() => register(current.account)));
el('sign-out').addEventListener('click', () => action(async () => { await request('/api/logout', {}); render(null); el('status').textContent = 'Signed out.'; }));
(async () => {
  if (!window.PublicKeyCredential || !PublicKeyCredential.parseCreationOptionsFromJSON || !PublicKeyCredential.parseRequestOptionsFromJSON) {
    el('status').textContent = 'This browser needs WebAuthn JSON support. Use a current Safari, Chrome, Edge or Firefox.';
    document.querySelectorAll('button').forEach(b => { b.disabled = true; });
    return;
  }
  try {
    const response = await fetch('/api/me', {credentials: 'same-origin', cache: 'no-store'});
    if (response.status === 401) { render(null); return; } // Absence of a login session is an ordinary state.
    const value = await response.json();
    if (!response.ok) throw new Error(value.error || 'Account state unavailable');
    render(value); el('status').textContent = 'Your current session is active.';
  } catch (error) { el('status').textContent = `Could not read account state: ${error.message}`; }
})();
