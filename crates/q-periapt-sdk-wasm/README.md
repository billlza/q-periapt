# Q-Periapt product WASM SDK 0.2.0

Install the [official npm tarball](https://github.com/billlza/q-periapt/releases/download/abi2-platforms-v0.2.0/q-periapt-sdk-wasm-0.2.0.tgz) in a Node 24+ project.

```sh
npm install https://github.com/billlza/q-periapt/releases/download/abi2-platforms-v0.2.0/q-periapt-sdk-wasm-0.2.0.tgz
```

This separate entry point uses the owned Rust SDK. Its default build verifies
ML-DSA-65 policy signatures and uses platform cryptographic randomness. The
existing `q-periapt-wasm` package remains the explicit expert/KAT interface.

Build the installable product package and run its outside-checkout consumers:

```sh
npm exec --yes --ignore-scripts --package typescript@5.9.3 -- tsc --version
CC_wasm32_unknown_unknown=/absolute/path/to/upstream/clang \
  sh artifact/python-run.sh artifact/wasm_sdk_package.py --output target/sdk-wasm-package
```

The output directory must be new. The producer uses the locked Rust dependencies,
wasm-pack 0.15.0, Node >=24, and the cached TypeScript 5.9.3 tool offline. The npm
archive has no installation scripts or npm runtime dependencies. It exposes
owned APIs by default; deliberate plaintext transfer uses the `/expert` subpath.
See the self-contained [package quickstart](https://github.com/billlza/q-periapt/blob/main/crates/q-periapt-sdk-wasm/PackageREADME.md) and
[packaging/validation guide](https://github.com/billlza/q-periapt/blob/v0.2.0-verified-cohort/docs/SDK_WASM_PACKAGE.md). Generated `pkg-node`
is a development artifact and is not the recommended installation entry.

For direct binding development:

```sh
CC_wasm32_unknown_unknown=/absolute/path/to/upstream/clang \
  wasm-pack build crates/q-periapt-sdk-wasm --target nodejs --out-dir pkg-node -- --locked
cp crates/q-periapt-sdk-wasm/src/input.mjs crates/q-periapt-sdk-wasm/pkg-node/input.mjs
node crates/q-periapt-sdk-wasm/tests/product.cjs
```

For browsers build with `--target web` and copy the same `src/input.mjs` beside
the generated module. The installed package stages this helper automatically. A compatible `globalThis.crypto` is
required when generating keys, importing private keys or encapsulating; failure is reported, without
deterministic coins or a weak RNG fallback. Browser runtime verification is a
separate gate from the Node integration test.

```javascript
// policyBytes, signature, pinnedRoot and previouslyPersistedState are Uint8Array.
const runtime = new QPeriaptRuntime(
  policyBytes, signature, pinnedRoot, previouslyPersistedState, 32, 4);
await persistTrustedStateAtomically(runtime.trusted_state());
let key;
try {
  if (!runtime.is_enabled()) throw new Error('Policy disables this SDK suite');
  key = runtime.generate_key();
  const publicKey = key.public_key(); // send through your authenticated protocol
  // const result = runtime.encapsulate(peerPublicKey, applicationContext);
  // const secret = result.take_secret(); // transfers once; no byte getter
  // const derived = secret.derive_key(QPeriaptKeyPurpose.InitiatorTraffic,
  //   new TextEncoder().encode('my-protocol/v1/aes256'), transcript);
  // const bytes = derived.export_for_protocol(); // only the application key leaves
  // Erase bytes yourself; close/free derived, secret and result objects after use.
} finally {
  if (key) { key.close(); key.free(); }
  runtime.close(); runtime.free();
}
```

Keep the runtime alive while using its keys. Explicit close rejects subsequent
calls. `.free()` releases the wasm-bindgen object; do not use a freed wrapper.
Public-key and ciphertext encodings are 1216 and 1120 bytes, respectively.
Context is at most 65536 bytes; empty application context is permitted because
the signed-policy wrapper supplies the nonempty protocol context. JS types and
lengths are checked before copying inputs into WASM. WASM-side context copies
are erased after each call. JS-owned inputs and explicit secret exports remain
the application's erasure responsibility.

The basic runtime supplies synchronous ownership and misuse protection.
`export_for_protocol()` copies a secret; use the purpose-key API below for key
derivation. The browser policy store and Continuity lifecycle have separate
owning APIs in the package quickstart. Explicit
[prepare/persist/activate transitions](https://github.com/billlza/q-periapt/blob/v0.2.0-verified-cohort/docs/SDK_POLICY_UPDATES.md) are available;
the application supplies durable storage and coordinates recovery.

`QPeriaptExpert.import_expanded(runtime, bytes)` and `export_expanded(key)` provide
[explicit plaintext transfer](https://github.com/billlza/q-periapt/blob/v0.2.0-verified-cohort/docs/SDK_KEY_TRANSFER.md). Imported WASM
temporaries are wiped; callers must protect and erase JS copies. No seeds,
caller coins or new default private-key getter are exposed.

Use `derive_key` for the specified [HKDF-SHA-256 purpose-key schedule](https://github.com/billlza/q-periapt/blob/v0.2.0-verified-cohort/docs/SDK_KEY_DERIVATION.md).
It binds the protocol direction, label, context, policy state and trust root, and
returns a separate owner. Closing the source secret keeps that derived owner
valid; closing the runtime revokes it. Labels are 1..255 printable ASCII bytes.
The five named purposes are exported as `QPeriaptKeyPurpose`. Purposes and runtime
limits validate the original JS value: non-numbers, fractions and out-of-range
numbers fail without invoking coercion hooks. Runtime limits are integers in
1..1024 (live keys) and 1..64 (operations).

See the [release and evidence index](https://github.com/billlza/q-periapt/blob/main/docs/EVIDENCE_INDEX.md)
for the selected package, platform scope and reproduction entry points.

The `browser-continuity` build feature adds the shared browser device lifecycle
through the existing npm web entry. The Node build retains its original exports.
`QPeriaptContinuityDevice` owns first-use enrollment through witnessed activation
and original prekey recovery; it accepts typed independent trust inputs and the
existing signed-policy `QPeriaptRuntime`. The [package quickstart](https://github.com/billlza/q-periapt/blob/main/crates/q-periapt-sdk-wasm/PackageREADME.md)
documents creation/reopen, sessions, publication, root/roster maintenance and
the specific authorization and resource-release contract of each entry.
