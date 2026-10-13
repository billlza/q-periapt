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
