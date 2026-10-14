export { QPeriaptDerivedKey, QPeriaptEncapsulation, QPeriaptKey,
  QPeriaptKeyPurpose, QPeriaptPolicyUpdate, QPeriaptRuntime,
  QPeriaptSecret } from './q_periapt_sdk_wasm.js';
/** Load the adjacent WASM once; rejects on loading/compilation/initialization failure. */
export default function initialize(): Promise<void>;

export { QPeriaptContinuityEnrollment, QPeriaptContinuityDevice, QPeriaptContinuityPolicy,
  QPeriaptContinuityAccountTrust, QPeriaptContinuityWitness,
  QPeriaptContinuityPreparation, QPeriaptContinuityPrekeyKind,
  QPeriaptContinuityPrekeyStatus } from './q_periapt_sdk_wasm.js';

export { QPeriaptContinuityPhase, QPeriaptContinuityStatus, QPeriaptContinuityCheckpoint,
  QPeriaptContinuityRosterRefresh, QPeriaptContinuityRosterOutcome } from './q_periapt_sdk_wasm.js';

export { QPeriaptContinuityPublicationPlan, QPeriaptContinuityPublicationPhase,
  QPeriaptContinuityPublicationStatus, QPeriaptContinuityPreparedPublication } from './q_periapt_sdk_wasm.js';

/** Shared-engine failure classification. Never proves that a mutation did not commit. */
export interface QPeriaptContinuityError extends Error {
  readonly code: string;
  /** Present on device-operation failures; true does not mean native cleanup finished. */
  readonly ownerClosed?: boolean;
  /** Original failure, including any nested primary/cleanup receipt errors. */
  readonly cause: unknown;
}

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
  QPeriaptContinuityCredentialRequest,
  QPeriaptContinuityRosterTarget,
  QPeriaptContinuityRosterProposal,
  QPeriaptContinuityWitnessRosterStage,
  QPeriaptContinuityWitnessRosterState,
  QPeriaptContinuityWitnessRosterProgress } from './q_periapt_sdk_wasm.js';

export { QPeriaptContinuityCredentialGrant, QPeriaptContinuityCredentialProposal, QPeriaptContinuityCredentialCancellation, QPeriaptContinuityCredentialPhase, QPeriaptContinuityCredentialStatus } from './q_periapt_sdk_wasm.js';
export { QPeriaptContinuityPolicyContinuation } from './q_periapt_sdk_wasm.js';

export { QPeriaptContinuityPolicyGrant, QPeriaptContinuityPolicyProposal,
  QPeriaptContinuityPolicyPhase, QPeriaptContinuityPolicyAbandonment, QPeriaptContinuityPolicyStatus,
  QPeriaptContinuityWitnessPolicyState, QPeriaptContinuityWitnessPolicyStage,
  QPeriaptContinuityWitnessPolicyProgress } from './q_periapt_sdk_wasm.js';

export {
  QPeriaptContinuityAccountTargets,
  QPeriaptContinuityAccountMessage,
  QPeriaptContinuityAccountPhase,
  QPeriaptContinuityAccountStatus,
  QPeriaptContinuityAccountOutcome,
  QPeriaptContinuityAccountDelivery,
  QPeriaptContinuityAccountMemberPhase,
  QPeriaptContinuityAccountMember,
  QPeriaptContinuityAccountMembers
} from './q_periapt_sdk_wasm.js';

export {
  QPeriaptContinuityClosurePhase,
  QPeriaptContinuityClosureStatus,
  QPeriaptContinuityAccountAbandonment,
  QPeriaptContinuitySessionClosure
} from './q_periapt_sdk_wasm.js';

export {
  QPeriaptContinuityRetirement,
  QPeriaptContinuityRetiredInventory,
  QPeriaptContinuityRetiredReportRequest,
  QPeriaptContinuityRetiredReport,
  QPeriaptContinuityErasureState
} from './q_periapt_sdk_wasm.js';
