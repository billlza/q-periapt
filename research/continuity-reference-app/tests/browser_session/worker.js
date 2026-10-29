import initialize, * as sdk from '/pkg/index.js';
import {openEffects} from '/effects.js';
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
const witness = initial.pins.witness === null ? undefined : keep(sdk.QPeriaptContinuityWitness.for_loopback(
  bytes(initial.pins.witness.identity), b64(initial.pins.witness.key), location.origin + '/witness', 10000));
const invitation = initial.invitation;
const intent = keep(new sdk.QPeriaptContinuityEnrollment(b64(invitation.root), bytes(invitation.device),
  BigInt(invitation.generation), bytes(invitation.family), BigInt(invitation.valid_from), BigInt(invitation.valid_until)));
let device, peer, trust, session, grant, stage = 'initialized';
let effects, preparedOriginal, activationResume;
const stageTimes = [];
function atStage(value) {
  stage = value;
  stageTimes.push({stage, unix_ms: Date.now(), monotonic_ms: performance.now()});
}
async function activateSelected() {
  return witness ? device.activate(policy, witness, now()) : device.activate_local(policy, now());
}
async function prepareOriginal(data) {
  if (preparedOriginal) return preparedOriginal;
  if (!device) device = await sdk.QPeriaptContinuityDevice.open(data.scope.name, bytes(data.scope.id), intent);
  const account = await loadPeer();
  if (data.prepared) {
    atStage('resume-original-activation-status');
    const status = await device.status();
    try {
      activationResume = {phase: status.phase(), journal: [...status.journal()]};
      required(activationResume.phase === sdk.QPeriaptContinuityPhase.Activating
        && JSON.stringify(activationResume.journal) === JSON.stringify(data.prepared.journal), 'original activation state changed');
    } finally { status.free(); }
    preparedOriginal = data.prepared; // Retained approval input; never recreate selected children.
    return preparedOriginal;
  }
  atStage('accept-original-grant');
  const journal = await device.accept(b64(grant.certificate), b64(grant.current.roster.bytes), account, policy, now());
  atStage('prepare-original-children');
  const prepared = await device.prepare(policy, now());
  try {
    required(prepared.requires_witness() === Boolean(witness), 'signed policy and pinned witness differ');
    preparedOriginal = {journal: [...journal], requires_witness: prepared.requires_witness()};
    if (witness) Object.assign(preparedOriginal, {subject: [...prepared.subject()], head: [...prepared.image_digest()]});
    return preparedOriginal;
  } finally { prepared.free(); }
}
async function reopenOriginal(scope, original) {
  device = await sdk.QPeriaptContinuityDevice.open(scope.name, bytes(scope.id), intent);
  await loadPeer();
  const journal = await activateSelected();
  required(JSON.stringify([...journal]) === JSON.stringify(original.journal), 'reopen replaced journal');
  session = keep(await device.reopen_session(bytes(grant.bundle), policy, trust, sdk.QPeriaptContinuityRole.Initiator,
    bytes(original.session), now()));
  return journal;
}
async function closeOwner() {
  effects?.close(); effects = undefined;
  await device.close(); device.free(); device = undefined;
  for (const item of own.reverse()) item.free();
}
async function loadPeer() {
  atStage('fetch-grant');
  grant = await (await fetch('/grant.json')).json();
  atStage('account-trust');
  const account = keep(new sdk.QPeriaptContinuityAccountTrust(bytes(grant.current.account), b64(grant.current.public_key),
    BigInt(grant.current.roster.checkpoint.version), bytes(grant.current.roster.checkpoint.digest), bytes(invitation.family)));
  const initiator = keep(new sdk.QPeriaptContinuityParticipant(account, bytes(invitation.device), 1n));
  const responder = keep(new sdk.QPeriaptContinuityParticipant(account, bytes(grant.native_device), 1n));
  atStage('peer-trust');
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
  if (data.op === 'witness-prepare') {
    required(witness !== undefined, 'required witness profile missing');
    return prepareOriginal(data);
  }
  if (data.op === 'witness-refusal') {
    required(witness !== undefined, 'required witness profile missing');
    if (data.kind === 'offline') {
      device = await sdk.QPeriaptContinuityDevice.open(data.scope.name, bytes(data.scope.id), intent);
      await loadPeer();
    } else await prepareOriginal(data);
    const status = await device.status();
    let startingStatus;
    try { startingStatus = {phase: status.phase(), journal: [...status.journal()]}; }
    finally { status.free(); }
    atStage('witness-refusal-' + data.kind);
    let failure;
    try {
      if (data.kind === 'missing') await device.activate_local(policy, now());
      else await activateSelected();
    } catch (error) {
      failure = {code: error.code, message: String(error), ownerClosed: error.ownerClosed, closed: device.is_closed()};
    }
    const expected = {missing: 'AnchorRequired', unenrolled: 'WitnessTransport', offline: 'WitnessTransport'}[data.kind];
    required(expected && failure?.code === expected && failure.ownerClosed === true && failure.closed,
      'required witness refusal or closed owner differs: ' + JSON.stringify(failure));
    return {kind: data.kind, starting_status: startingStatus, failure};
  }
  if (data.op === 'activate') {
    atStage('prepare-original'); const prepared = await prepareOriginal(data);
    const journal = bytes(prepared.journal);
    atStage('activate-original');
    required(JSON.stringify([...await activateSelected()]) === JSON.stringify([...journal]), 'activation replaced journal');
    atStage('admit-peer');
    peer = keep(await device.admit_peer(bytes(grant.bundle), policy, trust, sdk.QPeriaptContinuityRole.Initiator, now()));
    atStage('endpoint'); const endpoint = sdk.QPeriaptContinuityEndpoint.for_loopback(location.origin + '/exchange');
    atStage('establish');
    try { session = keep(await device.establish_session(peer, bytes(data.request), endpoint, 10000, now)); }
    finally { endpoint.free(); }
    atStage('first-message-id'); const first = [...await device.next_session_message_id(session, now())];
    atStage('first-delivery');
    required(await message(first, 'installed browser epoch zero') === sdk.QPeriaptContinuityConsumption.Confirmed, 'first delivery not confirmed');
    atStage('rekey'); const control = sdk.QPeriaptContinuityEndpoint.for_loopback(location.origin + '/exchange');
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
    return {journal:[...journal], session:[...session.id()], first, lost, failure, activation_resume:activationResume};
  }
  if (data.op === 'resume') {
    const journal = await reopenOriginal(data.scope, data.original);
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
    await closeOwner();
    return result;
  }
  if (data.op === 'receive') {
    if (!device) await reopenOriginal(data.scope, data.original);
    effects ??= await openEffects(data.scope.name);
    atStage('receive-original-frame');
    const incoming = await fetch('/incoming'); required(incoming.ok, 'incoming HTTP request failed');
    const wire = new Uint8Array(await incoming.arrayBuffer());
    let callback;
    const consume = async (receivedSession, messageId, plaintext) => {
      required(JSON.stringify([...receivedSession]) === JSON.stringify(data.original.session)
        && JSON.stringify([...messageId]) === JSON.stringify(data.message), 'application identity differs');
      callback = await effects.commit(receivedSession, messageId, plaintext);
      if (data.cut) {
        postMessage({cut: {stage: 'host-effect-committed-before-consumer-return', effect: callback,
          effects: await effects.snapshot(), session: [...session.id()]}});
        await new Promise(() => {}); // Parent terminates this actual Worker at the observed cut.
      }
    };
    atStage('serve-session-message');
    const reply = await device.serve_session_message(session, wire, consume, 10000, now);
    required(callback !== undefined, 'application consumer was not invoked');
    atStage('send-actual-reply');
    const sent = await fetch('/incoming/response', {method: 'POST', body: reply});
    required(sent.ok, 'actual reply delivery failed');
    const result = {session: [...session.id()], effect: callback, effects: await effects.snapshot()};
    if (data.finish) await closeOwner();
    return result;
  }
  throw Error('unknown operation');
}
self.onmessage = async ({data}) => {
  try { postMessage({result:await action(data)}); }
  catch (error) {
    const causes=[];let cause=error;
    for(let i=0;i<8 && cause;i++,cause=cause.cause) causes.push({message:String(cause),code:cause.code});
    postMessage({error:{stage,message:String(error),stack:error.stack,code:error.code,ownerClosed:error.ownerClosed,causes,stageTimes}});
  }
};
postMessage({ready:true});
