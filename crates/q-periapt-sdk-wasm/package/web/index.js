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
