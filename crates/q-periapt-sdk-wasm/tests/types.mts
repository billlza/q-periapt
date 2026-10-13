import { QPeriaptRuntime, QPeriaptKeyPurpose } from 'q-periapt-sdk-wasm';
import { QPeriaptExpert } from 'q-periapt-sdk-wasm/expert';
import initialize, { QPeriaptRuntime as WebRuntime } from 'q-periapt-sdk-wasm/web';
import { QPeriaptExpert as WebExpert } from 'q-periapt-sdk-wasm/web/expert';
import { QPeriaptPolicyStore } from 'q-periapt-sdk-wasm/web/storage';
const data = new Uint8Array();
const runtime: QPeriaptRuntime = new QPeriaptRuntime(data, data, data, data, 32, 4);
const key = runtime.generate_key();
const secret = key.decapsulate(data, data);
const application = secret.derive_key(QPeriaptKeyPurpose.Exporter, data, data);
const bytes: Uint8Array = application.export_for_protocol();
QPeriaptExpert.import_expanded(runtime, bytes);
const ready: Promise<void> = initialize();
const web = new WebRuntime(data, data, data, data, 32, 4);
WebExpert.import_expanded(web, bytes);
void ready;
async function durablePolicy() {
  const store = await QPeriaptPolicyStore.open({ name: 'installation', root: data });
  const original: Uint8Array = store.trustedState();
  const next: Uint8Array = await store.replacePolicy(original, data, data);
  store.generateKey().close();
  await store.close();
  return next;
}
void durablePolicy;

import { QPeriaptContinuityDevice, QPeriaptContinuityEnrollment,
  QPeriaptContinuityPolicy, QPeriaptContinuityAccountTrust,
  QPeriaptContinuityWitness, QPeriaptContinuityPrekeyKind, QPeriaptContinuityPhase,
  QPeriaptContinuityPublicationPlan, QPeriaptContinuityPublicationPhase,
  QPeriaptContinuityPrekeyStatus,
  type QPeriaptContinuityError } from 'q-periapt-sdk-wasm/web';
async function continuityDevice() {
  const intent = new QPeriaptContinuityEnrollment(data, data, 1n, data, 1n, 100n);
  const policy = new QPeriaptContinuityPolicy(web, data, data, 1n, data, data, 1n);
  const trust = new QPeriaptContinuityAccountTrust(data, data, 1n, data, data);
  const witness = new QPeriaptContinuityWitness(data, data, 'https://example.test/witness', 5000);
  const device = await QPeriaptContinuityDevice.create('installation', data, intent);
  const closed: boolean = device.is_closed();
  const status = await device.status();
  const phase: QPeriaptContinuityPhase = status.phase();
  const originalJournal: Uint8Array | undefined = status.journal();
  const refresh = status.roster_refresh();
  if (refresh) {
    const previous = refresh.previous(), target = refresh.target(), observed = refresh.observed();
    const time: bigint | undefined = refresh.observed_at();
    const outcome = refresh.outcome();
    previous.free(); target.free(); observed?.free(); refresh.free(); void time; void outcome;
  }
  status.free(); void closed; void phase; void originalJournal;
  const describeFailure = (error: QPeriaptContinuityError): [string, boolean | undefined, unknown] =>
    [error.code, error.ownerClosed, error.cause];
  void describeFailure;

  try {
    const request: Uint8Array = await device.request(1n);
    const journal: Uint8Array = await device.accept(data, data, trust, policy, 1n);
    const preparation = await device.prepare(policy, 1n);
    if (preparation.requires_witness()) {
      const subject: Uint8Array = preparation.subject();
      const digest: Uint8Array = preparation.image_digest();
      void subject; void digest;
    }
    preparation.free();
    await device.activate(policy, witness, 1n);
    const prekey: Uint8Array = await device.generate_prekey(policy, data,
      QPeriaptContinuityPrekeyKind.OneTimePq, 1n, 100n, 1n);
    const plan = new QPeriaptContinuityPublicationPlan(data, 1n, 100n);
    plan.generate(QPeriaptContinuityPrekeyKind.SignedClassical, 1n, 100n);
    plan.generate(QPeriaptContinuityPrekeyKind.LastResortPq, 1n, 100n);
    plan.reuse(data, QPeriaptContinuityPrekeyKind.OneTimePq, 1n, 100n);
    const capacity: number = plan.artifact_size_bound();
    const id: Uint8Array = await device.next_publication_id();
    const observation = await device.publication_status(id);
    const publicationPhase: QPeriaptContinuityPublicationPhase = observation.phase();
    const originalIntent: Uint8Array | undefined = observation.intent_digest();
    const originalArtifact: Uint8Array | undefined = observation.artifact_digest();
    const originalManifest: Uint8Array | undefined = observation.manifest_digest();
    observation.free();
    const publication = await device.prepare_publication(id, plan, policy, 5000, () => 1n);
    const publicBytes: Uint8Array = publication.bytes();
    const members: Uint8Array[] = publication.inventory_requests();
    const originalId: Uint8Array = publication.id();
    const intentDigest: Uint8Array = publication.intent_digest();
    const artifactDigest: Uint8Array = publication.artifact_digest();
    (await device.retire_publication(id, artifactDigest)).free();
    const inventory: QPeriaptContinuityPrekeyStatus = await device.prekey_status(policy, members[0]!);
    const retired: QPeriaptContinuityPrekeyStatus = await device.retire_prekey(policy, members[0]!);
    void inventory; void retired;
    publication.free(); plan.free();
    void capacity; void publicationPhase; void originalIntent; void originalArtifact;
    void originalManifest; void publicBytes; void members; void originalId; void intentDigest;
    void request; void journal; void prekey;
  } finally {
    await device.close(); device.free();
    policy.close(); policy.free(); trust.free(); witness.free(); intent.free();
  }
}
void continuityDevice;

import { QPeriaptContinuityParticipant, QPeriaptContinuityPeerTrust,
  QPeriaptContinuityQuality, QPeriaptContinuityRole, QPeriaptContinuityPeer,
  QPeriaptContinuityEndpoint, QPeriaptContinuityMessage,
  QPeriaptContinuityConsumption, QPeriaptContinuityMessageStatus,
  type QPeriaptContinuityRekeyCompletion, type QPeriaptContinuityRekeyProgress,
  type QPeriaptContinuitySession } from 'q-periapt-sdk-wasm/web';
async function sessionExchange(device: QPeriaptContinuityDevice, policy: QPeriaptContinuityPolicy,
    account: QPeriaptContinuityAccountTrust) {
  const a = new QPeriaptContinuityParticipant(account, data, 1n);
  const b = new QPeriaptContinuityParticipant(account, data, 1n);
  const trust = new QPeriaptContinuityPeerTrust(a, b, QPeriaptContinuityQuality.OneTimeBoth, data);
  const peer = await device.admit_peer(data, policy, trust, QPeriaptContinuityRole.Initiator, 1n);
  const request: Uint8Array = QPeriaptContinuityPeer.new_request_id();
  const endpoint = new QPeriaptContinuityEndpoint('https://example.test/session');
  const session: QPeriaptContinuitySession = await device.establish_session(peer, request, endpoint, 5000, () => 1n);
  const id: Uint8Array = await device.next_session_message_id(session, 1n);
  const input = new QPeriaptContinuityMessage(id, data, data);
  const consumption: QPeriaptContinuityConsumption = await device.deliver_session_message(session, input, endpoint, 5000, () => 1n);
  const status: QPeriaptContinuityMessageStatus = await device.session_message_status(session, id);
  const reopened = await device.reopen_session(data, policy, trust, QPeriaptContinuityRole.Initiator, session.id(), 1n);
  const consume = async (_session: Uint8Array, _message: Uint8Array, _plaintext: Uint8Array): Promise<void> => {};
  const reply: Uint8Array = await device.serve_session_exchange(peer, data, consume, 5000, () => 1n);
  const resumedReply: Uint8Array = await device.serve_session_message(reopened, data, consume, 5000, () => 1n);
  const progress: QPeriaptContinuityRekeyProgress = await device.session_rekey_progress(session);
  const completed: QPeriaptContinuityRekeyCompletion = await device.drive_session_rekey(session, 1n, 4, endpoint, 10000, () => 1n);
  const target: bigint = completed.epoch();
  const pending: bigint | undefined = progress.pending_epoch();
  const controlReply: Uint8Array = await device.serve_session_control(session, data, 10000, () => 1n);
  completed.free(); progress.free(); void target; void pending; void controlReply;
  input.close(); input.free(); session.free(); reopened.free(); endpoint.free(); peer.free(); trust.free(); a.free(); b.free();
  void consumption; void status; void reply; void resumedReply;
}
void sessionExchange;

import {QPeriaptContinuityHistoricalPolicy, QPeriaptContinuityRosterTarget,
  QPeriaptContinuityRosterProposal, QPeriaptContinuityCheckpoint,
  QPeriaptContinuityWitnessRosterStage, QPeriaptContinuityWitnessRosterState}
  from 'q-periapt-sdk-wasm/web';
async function rosterMaintenance(device: QPeriaptContinuityDevice,
    account: QPeriaptContinuityAccountTrust, policy: QPeriaptContinuityPolicy,
    witness: QPeriaptContinuityWitness) {
  const history = new QPeriaptContinuityHistoricalPolicy(data, data, 1n, data, data);
  const previous = new QPeriaptContinuityCheckpoint(1n, data);
  const target = new QPeriaptContinuityRosterTarget(account, data, data, 1n);
  const operation = QPeriaptContinuityRosterProposal.new_operation_id();
  const proposal = await device.prepare_witnessed_roster_refresh(operation, history, policy, target, witness, 1n);
  const restored = new QPeriaptContinuityRosterProposal(proposal.bytes());
  const recovered = await device.recover_witnessed_roster_refresh_preparation(history);
  const status = await device.witnessed_roster_refresh_progress();
  const stage: QPeriaptContinuityWitnessRosterStage | undefined = status?.stage();
  const applied: QPeriaptContinuityWitnessRosterState = await device.commit_witnessed_roster_refresh(restored, history, policy, witness, 1n);
  const reconciled = await device.reconcile_witnessed_roster_refresh(restored, history, witness);
  const closed = await device.close_witnessed_roster_refresh(restored, history, witness);
  const abandoned = await device.abandon_unprepared_roster_refresh(operation, history);
  const local = await device.refresh_local_roster(previous, data, account, policy, 1n);
  const targetCheckpoint = target.checkpoint();
  const resolution = await device.resolve_local_roster_refresh(previous, targetCheckpoint, history, 1n);
  resolution.free(); targetCheckpoint.free(); local.free(); abandoned.free(); status?.free(); recovered?.free();
  restored.free(); proposal.free(); target.free(); previous.free(); history.free();
  void stage; void applied; void reconciled; void closed;
}
void rosterMaintenance;
