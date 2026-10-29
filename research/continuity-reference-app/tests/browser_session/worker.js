import initialize, * as sdk from '/pkg/index.js';
await initialize();
const bytes = value => Uint8Array.from(value);
const b64 = value => Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/')), c => c.charCodeAt(0));
const now = () => BigInt(Math.floor(Date.now() / 1000));
const required = (value, message) => { if (!value) throw Error(message); };
const initial = await (await fetch('/initial.json')).json();
const own = [];
const keep = value => { own.push(value); return value; };
const runtime = keep(new sdk.QPeriaptRuntime(b64(initial.materials.sdk_document), b64(initial.materials.sdk_signature),
  b64(initial.pins.sdk_root), new Uint8Array(), 256, 64));
const policy = keep(new sdk.QPeriaptContinuityPolicy(runtime, b64(initial.pins.policy_root), bytes(initial.invitation.family),
  BigInt(initial.pins.policy_version), bytes(initial.pins.policy_digest), b64(initial.materials.policy), now()));
const invitation = initial.invitation;
const intent = keep(new sdk.QPeriaptContinuityEnrollment(b64(invitation.root), bytes(invitation.device),
  BigInt(invitation.generation), bytes(invitation.family), BigInt(invitation.valid_from), BigInt(invitation.valid_until)));
let device, peer, trust, session, grant, stage = 'initialized';
async function loadPeer() {
  stage = 'fetch-grant';
  grant = await (await fetch('/grant.json')).json();
  stage = 'account-trust';
  const account = keep(new sdk.QPeriaptContinuityAccountTrust(bytes(grant.current.account), b64(grant.current.public_key),
    BigInt(grant.current.roster.checkpoint.version), bytes(grant.current.roster.checkpoint.digest), bytes(invitation.family)));
  const initiator = keep(new sdk.QPeriaptContinuityParticipant(account, bytes(invitation.device), 1n));
  const responder = keep(new sdk.QPeriaptContinuityParticipant(account, bytes(grant.native_device), 1n));
  stage = 'peer-trust';
  trust = keep(new sdk.QPeriaptContinuityPeerTrust(initiator, responder, sdk.QPeriaptContinuityQuality.ReusableBoth, bytes(grant.directory)));
  return account;
}
async function message(id, text, path = '/exchange') {
  const input = new sdk.QPeriaptContinuityMessage(bytes(id), new TextEncoder().encode(text), new TextEncoder().encode('installed browser/native'));
  const endpoint = sdk.QPeriaptContinuityEndpoint.for_loopback(location.origin + path);
  try { return await device.deliver_session_message(session, input, endpoint, 10000, now); }
  finally { input.close(); input.free(); endpoint.free(); }
}
async function action(data) {
  if (data.op === 'create') {
    device = await sdk.QPeriaptContinuityDevice.create(data.scope.name, bytes(data.scope.id), intent);
    return {request: [...await device.request(now())], secure: isSecureContext,
      realm: globalThis instanceof DedicatedWorkerGlobalScope};
  }
  if (data.op === 'activate') {
    const account = await loadPeer();
    stage = 'accept';
    const journal = await device.accept(b64(grant.certificate), b64(grant.current.roster.bytes), account, policy, now());
    stage = 'prepare'; const prepared = await device.prepare(policy, now());
    try { required(!prepared.requires_witness(), 'fixture explicitly selects the local policy profile'); }
    finally { prepared.free(); }
    stage = 'activate-local';
    required(JSON.stringify([...await device.activate_local(policy, now())]) === JSON.stringify([...journal]), 'activation replaced journal');
    stage = 'admit-peer';
    peer = keep(await device.admit_peer(bytes(grant.bundle), policy, trust, sdk.QPeriaptContinuityRole.Initiator, now()));
    stage = 'endpoint'; const endpoint = sdk.QPeriaptContinuityEndpoint.for_loopback(location.origin + '/exchange');
    stage = 'establish';
    try { session = keep(await device.establish_session(peer, bytes(data.request), endpoint, 10000, now)); }
    finally { endpoint.free(); }
    stage = 'first-message-id'; const first = [...await device.next_session_message_id(session, now())];
    stage = 'first-delivery';
    required(await message(first, 'installed browser epoch zero') === sdk.QPeriaptContinuityConsumption.Confirmed, 'first delivery not confirmed');
    stage = 'rekey'; const control = sdk.QPeriaptContinuityEndpoint.for_loopback(location.origin + '/exchange');
    let progress;
    try {
      progress = await device.drive_session_rekey(session, 1n, 4, control, 10000, now);
      required(progress.epoch() === 1n, 'wrong rekey epoch');
    } finally { progress?.free(); control.free(); }
    const lost = [...await device.next_session_message_id(session, now())];
    let failure;
    try { await message(lost, 'original browser delivery with lost ACK', '/exchange/drop-once'); }
    catch (error) { failure = {code: error.code, message: String(error), ownerClosed: error.ownerClosed, closed: device.is_closed()}; }
    required(failure?.code === 'PeerTransport' && failure.closed && failure.ownerClosed === true,
      'transport loss did not close the owner with the original error');
    return {journal:[...journal], session:[...session.id()], first, lost, failure};
  }
  if (data.op === 'resume') {
    device = await sdk.QPeriaptContinuityDevice.open(data.scope.name, bytes(data.scope.id), intent);
    await loadPeer();
    const journal = await device.activate_local(policy, now());
    required(JSON.stringify([...journal]) === JSON.stringify(data.original.journal), 'reopen replaced journal');
    session = keep(await device.reopen_session(bytes(grant.bundle), policy, trust, sdk.QPeriaptContinuityRole.Initiator,
      bytes(data.original.session), now()));
    const before = await device.session_message_status(session, bytes(data.original.lost));
    required(before === sdk.QPeriaptContinuityMessageStatus.Committed, 'lost ACK inferred completion');
    required(await message(data.original.lost, 'original browser delivery with lost ACK') === sdk.QPeriaptContinuityConsumption.Confirmed,
      'original replay not confirmed');
    const after = await device.session_message_status(session, bytes(data.original.lost));
    required(after === sdk.QPeriaptContinuityMessageStatus.Acknowledged, 'replay not acknowledged');
    const last = [...await device.next_session_message_id(session, now())];
    required(await message(last, 'installed browser after full peer restart') === sdk.QPeriaptContinuityConsumption.Confirmed,
      'post-restart delivery not confirmed');
    const progress = await device.session_rekey_progress(session);
    required(progress.confirmed_epoch() === 1n && progress.sending_epoch() === 1n
      && progress.receiving_epoch() === 1n && progress.pending_epoch() === undefined, 'reopened rekey state differs');
    const result = {journal:[...journal], session:[...session.id()], before, after, last,
      confirmed_epoch:progress.confirmed_epoch().toString(), sending_epoch:progress.sending_epoch().toString(),
      receiving_epoch:progress.receiving_epoch().toString()};
    progress.free();
    await device.close(); device.free(); device = undefined;
    for (const item of own.reverse()) item.free();
    return result;
  }
  throw Error('unknown operation');
}
self.onmessage = async ({data}) => {
  try { postMessage({result:await action(data)}); }
  catch (error) {
    const causes=[];let cause=error;
    for(let i=0;i<8 && cause;i++,cause=cause.cause) causes.push({message:String(cause),code:cause.code});
    postMessage({error:{stage,message:String(error),stack:error.stack,code:error.code,ownerClosed:error.ownerClosed,causes}});
  }
};
postMessage({ready:true});
