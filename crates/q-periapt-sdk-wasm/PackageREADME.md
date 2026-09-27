# Q-Periapt WASM SDK — 0.2.0-alpha.1 candidate

The product entry verifies ML-DSA-65 signed policy, obtains fresh platform
cryptographic randomness and keeps hybrid private keys in explicit owners.
This is a local prerelease candidate, not a published npm release.

Install the supplied archive with `npm install ./q-periapt-sdk-wasm-0.2.0-alpha.1.tgz`.
It has no npm dependencies, install scripts or native compilation step.
The Node entry requires Node 24 or newer. CommonJS and ESM share one WASM
instance; both support the named exports shown here:

```js
import { QPeriaptRuntime, QPeriaptKeyPurpose } from 'q-periapt-sdk-wasm';
// CommonJS: const { QPeriaptRuntime } = require('q-periapt-sdk-wasm');

// These four Uint8Arrays come from your authenticated policy configuration and
// protected storage. Empty previousState is only for first provisioning.
const runtime = new QPeriaptRuntime(policyBytes, signature, pinnedRoot, previousState, 32, 4);
let key;
try {
  await persistTrustedStateAtomically(runtime.trusted_state());
  key = runtime.generate_key();
  const publicKey = key.public_key();
  // Send publicKey through your authenticated application protocol.
} finally {
  if (key) { key.close(); key.free(); }
  runtime.close(); runtime.free();
}
```

For browser ESM, import from `q-periapt-sdk-wasm/web` and `await initialize()`
before constructing an owner. Bundlers using the standard package exports map
also select this web entry for the root import. For unbundled deployments,
serve the package's `web/` directory with JavaScript and `application/wasm`
MIME types, then import its `index.js` by URL:

```js
import initialize, { QPeriaptRuntime } from '/q-periapt/web/index.js';
await initialize(); // loads q_periapt_sdk_wasm_bg.wasm next to the JS module
```

Concurrent initialization calls share one promise and one instance. A loading,
compilation or initialization failure rejects that promise and stays failed
until the module is loaded in a fresh realm. No automatic retry is performed.
Deploy on HTTPS (localhost is suitable for development) with WebCrypto
`globalThis.crypto.getRandomValues`. Missing or failing entropy rejects key
generation, import and encapsulation; no deterministic or weak fallback exists.

The default exports have no private-key getter, caller coins or raw combiner.
For deliberate plaintext key transfer, separately import `QPeriaptExpert`
from `q-periapt-sdk-wasm/expert` (Node) or `q-periapt-sdk-wasm/web/expert`
(browser). The legacy deterministic/KAT package is separate. These are API
boundaries for ownership and misuse prevention, not isolation from malicious
JavaScript executing in the same realm.

Limits are JS number integers: 1–1024 live keys and 1–64 synchronous operations.
Strings, booleans, fractions and wrapped integers fail. Close owners explicitly,
then call `free()` once to release their wrappers; never use a freed wrapper.
Runtime close revokes its key/secret/derived owners. An exported JS byte array
cannot be revoked or erased by the runtime; protect and erase it yourself.
Use `secret.derive_key(QPeriaptKeyPurpose.Exporter, label, context)` for an owned
HKDF-SHA-256 application key, then explicitly export only when your cipher needs
bytes. Labels are 1–255 printable ASCII bytes; context is at most 65536 bytes.

Policy update is prepare → persist the signed policy and trusted state atomically
→ `activate_after_persist()`. Activation revokes the old epoch. The application
owns durable storage and recovery; this package supplies no persistent service,
worker cancellation, transport authentication or session protocol.

`PACKAGE_CONTENTS.json` records candidate bytes and source/tool identities. It is
not a signature or external review. `THIRD_PARTY/rust/INVENTORY.json` records
the target-filtered production dependency license closure. Current platform,
security and release gates are documented in the repository's
[release readiness ledger](https://github.com/billlza/q-periapt/blob/main/docs/SDK_0_2_RELEASE_READINESS.md).
