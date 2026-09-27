// SPDX-License-Identifier: Apache-2.0 OR MIT
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import * as esm from 'q-periapt-sdk-wasm';
import { QPeriaptExpert } from 'q-periapt-sdk-wasm/expert';
const require = createRequire(import.meta.url);
const cjs = require('q-periapt-sdk-wasm');
assert.equal(esm.QPeriaptRuntime, cjs.QPeriaptRuntime);
assert.equal(QPeriaptExpert, require('q-periapt-sdk-wasm/expert').QPeriaptExpert);
assert.equal('QPeriaptExpert' in esm, false);
assert.equal('QPeriaptExpert' in esm.default, false);
for (const name of ['node/q_periapt_sdk_wasm.js', 'web/q_periapt_sdk_wasm.js', 'package.json']) {
  assert.throws(() => require(`q-periapt-sdk-wasm/${name}`), { code: 'ERR_PACKAGE_PATH_NOT_EXPORTED' });
}
const f = JSON.parse(readFileSync(new URL('./fixtures/signed-policy-vectors.json', import.meta.url)));
const hex = text => new Uint8Array(Buffer.from(text, 'hex'));
const runtime = new esm.QPeriaptRuntime(new TextEncoder().encode(f.policy_toml), hex(f.signature),
  hex(f.verification_key), new Uint8Array(), 2, 1);
const key = runtime.generate_key();
const serialized = QPeriaptExpert.export_expanded(key);
const imported = QPeriaptExpert.import_expanded(runtime, serialized);
serialized.fill(0);
assert.deepEqual(imported.public_key(), key.public_key());
for (const owner of [key, imported, runtime]) { owner.close(); owner.free(); }
console.log('WASM_INSTALLED_CJS_ESM_SINGLE_INSTANCE_PASS');
