import type { QPeriaptRuntime } from './q_periapt_sdk_wasm.js';
export class QPeriaptStorageError extends Error { readonly code: string; }
export interface PolicyStoreOptions {
  /** Stable origin-local name. Missing storage is never treated as first use. */
  name: string;
  /** Independently retained ML-DSA policy root. */
  root: Uint8Array;
  maxKeys?: number;
  maxInFlight?: number;
}
export class QPeriaptPolicyStore {
  private constructor();
  static create(options: PolicyStoreOptions & { policy: Uint8Array; signature: Uint8Array }): Promise<QPeriaptPolicyStore>;
  static open(options: PolicyStoreOptions): Promise<QPeriaptPolicyStore>;
  trustedState(): Uint8Array;
  isEnabled(): boolean;
  generateKey(): ReturnType<QPeriaptRuntime['generate_key']>;
  encapsulate(publicKey: Uint8Array, context: Uint8Array): ReturnType<QPeriaptRuntime['encapsulate']>;
  replacePolicy(expected: Uint8Array, policy: Uint8Array, signature: Uint8Array): Promise<Uint8Array>;
  /** Revoke immediately. ClosePending means cleanup still owns the cross-tab lease;
   * call close again to await its eventual receipt. Never treat it as released. */
  close(): Promise<void>;
}
