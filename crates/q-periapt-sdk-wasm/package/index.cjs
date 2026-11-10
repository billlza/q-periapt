// SPDX-License-Identifier: Apache-2.0 OR MIT
// Explicit assignments also give Node ESM consumers named exports. Both loading
// modes share this module and the same WebAssembly instance and owner classes.
const sdk = require('./node/q_periapt_sdk_wasm.js');
exports.QPeriaptDerivedKey = sdk.QPeriaptDerivedKey;
exports.QPeriaptEncapsulation = sdk.QPeriaptEncapsulation;
exports.QPeriaptKey = sdk.QPeriaptKey;
exports.QPeriaptKeyPurpose = sdk.QPeriaptKeyPurpose;
exports.QPeriaptPolicyUpdate = sdk.QPeriaptPolicyUpdate;
exports.QPeriaptRuntime = sdk.QPeriaptRuntime;
exports.QPeriaptSecret = sdk.QPeriaptSecret;
