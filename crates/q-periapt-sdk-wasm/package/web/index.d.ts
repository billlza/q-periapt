export { QPeriaptDerivedKey, QPeriaptEncapsulation, QPeriaptKey,
  QPeriaptKeyPurpose, QPeriaptPolicyUpdate, QPeriaptRuntime,
  QPeriaptSecret } from './q_periapt_sdk_wasm.js';
/** Load the adjacent WASM once; rejects on loading/compilation/initialization failure. */
export default function initialize(): Promise<void>;

export { QPeriaptContinuityEnrollment, QPeriaptContinuityDevice, QPeriaptContinuityPolicy,
  QPeriaptContinuityAccountTrust, QPeriaptContinuityWitness,
  QPeriaptContinuityPreparation, QPeriaptContinuityPrekeyKind } from './q_periapt_sdk_wasm.js';

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
