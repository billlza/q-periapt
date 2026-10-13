// SPDX-License-Identifier: Apache-2.0 OR MIT
import init from './q_periapt_sdk_wasm.js';
export { QPeriaptDerivedKey, QPeriaptEncapsulation, QPeriaptKey,
  QPeriaptKeyPurpose, QPeriaptPolicyUpdate, QPeriaptRuntime,
  QPeriaptSecret } from './q_periapt_sdk_wasm.js';

let initialization;
/** Load the adjacent WASM once. A failed initialization stays failed in this module. */
export default function initialize() {
  initialization ??= init().then(() => undefined);
  return initialization;
}

export { QPeriaptContinuityEnrollment, QPeriaptContinuityDevice, QPeriaptContinuityPolicy,
  QPeriaptContinuityAccountTrust, QPeriaptContinuityWitness,
  QPeriaptContinuityPreparation, QPeriaptContinuityPrekeyKind,
  QPeriaptContinuityPrekeyStatus } from './q_periapt_sdk_wasm.js';

export { QPeriaptContinuityPhase, QPeriaptContinuityStatus, QPeriaptContinuityCheckpoint,
  QPeriaptContinuityRosterRefresh, QPeriaptContinuityRosterOutcome } from './q_periapt_sdk_wasm.js';

export { QPeriaptContinuityPublicationPlan, QPeriaptContinuityPublicationPhase,
  QPeriaptContinuityPublicationStatus, QPeriaptContinuityPreparedPublication } from './q_periapt_sdk_wasm.js';

export { QPeriaptContinuityParticipant,
  QPeriaptContinuityPeerTrust,
  QPeriaptContinuityQuality,
  QPeriaptContinuityRole,
  QPeriaptContinuityPeer,
  QPeriaptContinuityEndpoint,
  QPeriaptContinuitySession,
  QPeriaptContinuitySessionReopenRequest,
  QPeriaptContinuityMessage,
  QPeriaptContinuityConsumption,
  QPeriaptContinuityMessageStatus } from './q_periapt_sdk_wasm.js';

export { QPeriaptContinuityRekeyProgress, QPeriaptContinuityRekeyCompletion } from './q_periapt_sdk_wasm.js';

export { QPeriaptContinuityHistoricalPolicy,
  QPeriaptContinuityPolicyRequest,
  QPeriaptContinuityCredentialRequest,
  QPeriaptContinuityRosterTarget,
  QPeriaptContinuityRosterProposal,
  QPeriaptContinuityWitnessRosterStage,
  QPeriaptContinuityWitnessRosterState,
  QPeriaptContinuityWitnessRosterProgress } from './q_periapt_sdk_wasm.js';

export { QPeriaptContinuityCredentialGrant, QPeriaptContinuityCredentialProposal, QPeriaptContinuityCredentialCancellation, QPeriaptContinuityCredentialPhase, QPeriaptContinuityCredentialStatus } from './q_periapt_sdk_wasm.js';

export { QPeriaptContinuityPolicyGrant, QPeriaptContinuityPolicyProposal,
  QPeriaptContinuityPolicyPhase, QPeriaptContinuityPolicyAbandonment, QPeriaptContinuityPolicyStatus,
  QPeriaptContinuityWitnessPolicyState, QPeriaptContinuityWitnessPolicyStage,
  QPeriaptContinuityWitnessPolicyProgress } from './q_periapt_sdk_wasm.js';
