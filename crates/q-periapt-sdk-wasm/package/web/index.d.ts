export { QPeriaptDerivedKey, QPeriaptEncapsulation, QPeriaptKey,
  QPeriaptKeyPurpose, QPeriaptPolicyUpdate, QPeriaptRuntime,
  QPeriaptSecret } from './q_periapt_sdk_wasm.js';
/** Load the adjacent WASM once; rejects on loading/compilation/initialization failure. */
export default function initialize(): Promise<void>;
