import { QPeriaptRuntime, QPeriaptKeyPurpose } from 'q-periapt-sdk-wasm';
import { QPeriaptExpert } from 'q-periapt-sdk-wasm/expert';
import initialize, { QPeriaptRuntime as WebRuntime,
  QPeriaptContinuityPolicyRequest } from 'q-periapt-sdk-wasm/web';
import { QPeriaptExpert as WebExpert } from 'q-periapt-sdk-wasm/web/expert';
import { QPeriaptPolicyStore } from 'q-periapt-sdk-wasm/web/storage';
const data = new Uint8Array();
const policyOperation: Uint8Array = QPeriaptContinuityPolicyRequest.new_operation_id();
void policyOperation;
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
  const remoteHead: QPeriaptContinuityCheckpoint = await device.admit_peer_roster(data, account, policy, 1n);
  remoteHead.free();
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

import {QPeriaptContinuityCredentialRequest} from 'q-periapt-sdk-wasm/web';
async function credentialRequest(device: QPeriaptContinuityDevice,
    original: QPeriaptContinuityHistoricalPolicy, witness: QPeriaptContinuityWitness) {
  const id = QPeriaptContinuityCredentialRequest.new_operation_id();
  const request = await device.witnessed_credential_renewal_request(id, original, witness);
  const operation: Uint8Array = request.operation_id();
  const version: bigint = request.previous_roster_version();
  const authorization: Uint8Array | undefined = request.current_policy_authorization();
  request.original_credential(); request.original_roster(); request.previous_credential(); request.previous_roster();
  request.original_owner(); request.journal(); request.original_policy_digest();
  request.original_roster_version(); request.original_roster_digest(); request.previous_roster_digest();
  request.previous_valid_from(); request.previous_valid_until(); request.current_policy_version(); request.current_policy_digest();
  request.free();
  const local = await device.credential_renewal_request(id, original); local.free();
  void operation; void version; void authorization;
}
void credentialRequest;

import {QPeriaptContinuityCredentialGrant, QPeriaptContinuityCredentialProposal,
  QPeriaptContinuityCredentialPhase} from 'q-periapt-sdk-wasm/web';
async function credentialMaintenance(device: QPeriaptContinuityDevice,
    account: QPeriaptContinuityAccountTrust, policy: QPeriaptContinuityPolicy,
    original: QPeriaptContinuityHistoricalPolicy, witness: QPeriaptContinuityWitness) {
  const grant = new QPeriaptContinuityCredentialGrant(data, account, original, 1n);
  const id: Uint8Array = grant.operation_id();
  const statement: Uint8Array = grant.statement();
  grant.target().free();
  (await device.admit_peer_credential_renewal(grant, id, policy, 1n)).free();
  (await device.stage_credential_renewal(grant, id, policy, 1n)).free();
  const proposal = await device.prepare_witnessed_credential_renewal(original, policy, witness, 1n);
  const restored = new QPeriaptContinuityCredentialProposal(proposal.bytes());
  restored.binding(); restored.statement(); restored.operation_id();
  (await device.commit_witnessed_credential_renewal(restored, original, policy, witness, 1n)).free();
  (await device.reconcile_witnessed_credential_renewal(id, statement, original, witness, 1n)).free();
  (await device.close_witnessed_credential_renewal(id, statement, original, witness, 1n)).free();
  (await device.recover_witnessed_credential_renewal_preparation(original, 1n))?.free();
  const cancellation = await device.prepare_witnessed_credential_cancellation(original, 1n);
  cancellation.bytes(); cancellation.free();
  (await device.reconcile_expired_credential_renewal(id, statement, policy, 1n)).free();
  const status = await device.credential_renewal_status();
  const phase: QPeriaptContinuityCredentialPhase = status.phase();
  status.operation_id(); status.statement(); status.target()?.free();
  status.observed_head()?.free(); status.observed_at(); status.free();
  restored.free(); proposal.free(); grant.free(); void phase;
}
void credentialMaintenance;

import {QPeriaptContinuityPolicyContinuation} from 'q-periapt-sdk-wasm/web';
async function jointPolicyMaintenance(device: QPeriaptContinuityDevice,
    request: QPeriaptContinuityCredentialRequest, grant: QPeriaptContinuityCredentialGrant,
    original: QPeriaptContinuityHistoricalPolicy, previous: QPeriaptContinuityHistoricalPolicy,
    target: QPeriaptContinuityPolicy, targetHistory: QPeriaptContinuityHistoricalPolicy,
    witness: QPeriaptContinuityWitness) {
  const proof = new QPeriaptContinuityPolicyContinuation(data, request, grant, original, previous, target, 1n);
  const id: Uint8Array = proof.operation_id(), statement: Uint8Array = proof.statement();
  const predecessor: Uint8Array | undefined = proof.previous_statement();
  const targetVersion: bigint = proof.target_version();
  proof.bytes(); proof.credential_statement(); proof.target_digest();
  (await device.stage_policy_continuation(grant, proof, id, target, 1n)).free();
  (await device.reconcile_policy_continuation(original, target, 1n)).free();
  (await device.recover_historical_policy_continuation(id, statement, original, targetHistory, 1n)).free();
  const localJournal: Uint8Array = await device.activate_local_policy_continuation(original, target, 1n);
  const witnessedJournal: Uint8Array = await device.activate_witnessed_policy_continuation(original, target, witness, 1n);
  const proposal = await device.prepare_witnessed_credential_renewal(original, target, witness, 1n);
  proposal.credential_statement(); proposal.policy_continuation_statement();
  proposal.independent_policy_statement(); proposal.adopts_policy();
  proposal.free(); proof.free(); void predecessor; void targetVersion; void localJournal; void witnessedJournal;
}
void jointPolicyMaintenance;

import { QPeriaptContinuityAccountTargets, QPeriaptContinuityAccountMessage,
  QPeriaptContinuityAccountPhase, QPeriaptContinuityAccountOutcome,
  QPeriaptContinuityAccountMemberPhase } from 'q-periapt-sdk-wasm/web';
async function accountDelivery(device: QPeriaptContinuityDevice,
    session: QPeriaptContinuitySession, endpoint: QPeriaptContinuityEndpoint) {
  const targets = new QPeriaptContinuityAccountTargets();
  targets.add(session);
  const count: number = targets.len(), empty: boolean = targets.is_empty();
  const id: Uint8Array = await device.next_account_message_id();
  const input = new QPeriaptContinuityAccountMessage(id, data, data, data);
  const state = await device.account_message_status(id);
  const phase: QPeriaptContinuityAccountPhase = state.phase();
  const abandoned: Uint8Array | undefined = state.abandonment_id();
  state.operation_id(); state.free();
  const result = await device.deliver_account_member(targets, input, 0, endpoint, 5000, () => 1n);
  const outcome: QPeriaptContinuityAccountOutcome = result.outcome();
  result.device(); result.session(); result.message(); result.exchanges(); result.free();
  const members = await device.reconcile_account_message(id, targets);
  members.operation_id(); members.len(); members.is_empty();
  const member = members.member(0);
  const memberPhase: QPeriaptContinuityAccountMemberPhase = member.phase();
  member.device(); member.session(); member.message(); member.free(); members.free();
  await device.retire_account_message(id, targets);
  input.operation_id(); input.close(); input.is_closed(); input.free(); targets.free();
  void count; void empty; void phase; void abandoned; void outcome; void memberPhase;
}
void accountDelivery;

import { QPeriaptContinuityClosurePhase } from 'q-periapt-sdk-wasm/web';
// Compile-only coverage of distinct original-account/session lifecycle phases.
async function restrictedAccounting(accountOwner: QPeriaptContinuityDevice,
    sessionOwner: QPeriaptContinuityDevice, original: QPeriaptContinuityHistoricalPolicy,
    witness: QPeriaptContinuityWitness, required: boolean) {
  if (required) {
    await accountOwner.recover_account(data, original, witness);
    await sessionOwner.recover_session(data, original, witness);
  } else {
    await accountOwner.recover_account_local(data, original);
    await sessionOwner.recover_session_local(data, original);
  }
  const aggregate = await accountOwner.recovered_account_status();
  aggregate.operation_id(); aggregate.phase(); aggregate.abandonment_id(); aggregate.free();
  const members = await accountOwner.recovered_account_members(); members.free();
  const batch = await accountOwner.begin_account_abandonment();
  const batchJson: string = batch.to_json(), count: number = batch.member_count();
  batch.operation_id(); const batchReport: Uint8Array = batch.report_id(); batch.free();
  await accountOwner.acknowledge_account_abandonment(batchReport);
  await accountOwner.retire_recovered_account();
  const status = await sessionOwner.recovered_session_status();
  const phase: QPeriaptContinuityClosurePhase = status.phase();
  const saved: Uint8Array | undefined = status.report_id(); status.free();
  const closure = await sessionOwner.begin_session_closure();
  const closureJson: string = closure.to_json(); closure.session_id();
  const report: Uint8Array = closure.report_id(); closure.free();
  await sessionOwner.acknowledge_session_closure(report);
  void batchJson; void closureJson; void count; void phase; void saved;
}
void restrictedAccounting;

import { QPeriaptContinuityRetirement, QPeriaptContinuityErasureState } from 'q-periapt-sdk-wasm/web';
// Compile-only coverage: each receipt comes from its independent control-plane step.
async function permanentRetirement(intent: QPeriaptContinuityEnrollment,
    witness: QPeriaptContinuityWitness, approved: Uint8Array, subject: Uint8Array,
    retirementReceipt: Uint8Array, inventoryReceipt: Uint8Array,
    reportReceipt: Uint8Array, recordedReport: Uint8Array, acknowledgement: Uint8Array) {
  const retirement = new QPeriaptContinuityRetirement(witness, approved, subject, retirementReceipt);
  const owner = await QPeriaptContinuityDevice.open_retired('original', data, intent, retirement);
  const inventory = await owner.retirement_inventory();
  inventory.to_bytes(); inventory.binding(); inventory.stored_image_digest(); inventory.pending_intent_digest(); inventory.free();
  const request = await owner.prepare_retired_report(inventoryReceipt);
  request.to_bytes(); request.report_id(); request.inventory_binding(); request.free();
  (await owner.retired_report_request())?.free();
  const report = await owner.retired_report(inventoryReceipt, reportReceipt);
  const canonical: Uint8Array = report.to_bytes(), inspection: string = report.to_json();
  report.report_id(); report.free();
  (await owner.prepare_retired_host_acknowledgement(recordedReport, inventoryReceipt, reportReceipt)).free();
  (await owner.retired_host_acknowledgement_request())?.free();
  const journal: QPeriaptContinuityErasureState = await owner.retired_journal_erasure_status();
  await owner.erase_retired_journal(acknowledgement);
  await owner.prepare_retired_signer_erasure(acknowledgement);
  const signer: QPeriaptContinuityErasureState = await owner.retired_signer_erasure_status();
  await owner.erase_retired_signer(); owner.is_closed(); owner.free(); retirement.free();
  void canonical; void inspection; void journal; void signer;
}
void permanentRetirement;

import { QPeriaptContinuityPendingWriteRequest } from 'q-periapt-sdk-wasm/web';
// Compile-only: approval and recorded metadata must come from independent retention.
async function exactPendingWrite(owner: QPeriaptContinuityDevice,
    original: QPeriaptContinuityHistoricalPolicy, witness: QPeriaptContinuityWitness,
    approved: Uint8Array, recordedMetadata: Uint8Array) {
  const request: QPeriaptContinuityPendingWriteRequest = await owner.pending_write_recovery_request(original, witness);
  const proposal: Uint8Array = request.proposal(), metadata: Uint8Array = request.metadata();
  const signature: Uint8Array = request.signed_request(), inspection: string = request.to_json();
  request.binding(); request.free();
  await owner.confirm_pending_write_recovery(approved, recordedMetadata, original, witness);
  void proposal; void metadata; void signature; void inspection;
}
void exactPendingWrite;
