# Q-Periapt WASM SDK — 0.2.0 candidate

The product entry verifies ML-DSA-65 signed policy, obtains fresh platform
cryptographic randomness and keeps hybrid private keys in explicit owners.
This is a local prerelease candidate, not a published npm release.

Install the supplied archive with `npm install ./q-periapt-sdk-wasm-0.2.0.tgz`.
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
→ `activate_after_persist()`. Activation revokes the old epoch. The raw runtime does not supply a persistent session service. The browser
policy store and Continuity lifecycle owner below provide separate persistence
contracts; complete Continuity session bindings remain under development.

`PACKAGE_CONTENTS.json` records candidate bytes and source/tool identities;
distribution signatures are verified separately. `THIRD_PARTY/rust/INVENTORY.json` records
the target-filtered production dependency license closure. Current platform,
security and release gates are documented in the repository's
[release readiness ledger](https://github.com/billlza/q-periapt/blob/main/docs/SDK_0_2_RELEASE_READINESS.md).
# Browser policy storage candidate

`q-periapt-sdk-wasm/web/storage` provides `QPeriaptPolicyStore.create` and `open`.
Supply a stable origin-local `name` and an independently retained policy `root`;
creation also takes the signed `policy` and `signature`. Opening never creates a
missing installation, and creation never replaces an existing one. This browser
entry requires a secure context, IndexedDB with strict transaction durability and
Web Locks. It returns `Unavailable` when a required capability is absent.

The owner supplies `trustedState`, `isEnabled`, `generateKey` and `encapsulate`.
It keeps the raw runtime and update authority private. Use
`replacePolicy(expectedState, policy, signature)` to verify a strictly newer
policy and atomically persist the complete signed image and trusted state before
activation. An invalid signature or caller state leaves the current owner usable.
An I/O, quota, commit or activation failure closes it. Reopen the same name and
root to reconcile actual stored state; a rejected promise does not establish that
a write was absent. No automatic reset, weaker persistence mode or signature
fallback exists.
Opening verifies and reasserts the original signed image in a strict transaction
before exposing a runtime. This also recovers creation interrupted between its
schema/image transaction and strict completion barrier.

Call and await `close()` explicitly. It immediately revokes retained key/secret
owners and releases its origin-wide lease after pending I/O settles. Closing
during replacement prevents returning a new runtime; the signed policy may still
have committed. Other tabs and Workers receive `Busy` while the lease is held.
An operation timeout reports `OpenUnknown` or `CommitUnknown`; it does not count
as an I/O completion receipt. Cleanup waits another ten seconds, then reports
`ClosePending` while retaining the lease until the browser actually settles.
When both operation and cleanup fail, the operation code is preserved and
`error.cause.errors` contains both errors. A rejected `close()` can be called
again to await cleanup; it never grants permission to replace stored state.
Garbage collection is not an owner-lifecycle API.

This is origin-local policy storage, not a Continuity session journal or witness
implementation. Web Locks coordinate cooperating SDK users; they do not isolate
malicious same-origin code. Browser storage can be cleared or evicted, and there
is no rollback guarantee against restoration of a complete old browser profile.
Missing state must be recovered through the application's independently retained
trust/history rather than silently recreated. IndexedDB `strict` requests the
browser's strongest standard transaction durability; it is not a demonstrated
native-filesystem or power-loss equivalence. The schema is explicitly versioned;
unknown or malformed records are refused, not migrated by guesswork.

# Browser Continuity lifecycle

The same web entry exposes `QPeriaptContinuityEnrollment`,
`QPeriaptContinuityDevice`, `QPeriaptContinuityPolicy`,
`QPeriaptContinuityAccountTrust` and `QPeriaptContinuityWitness`.
They reuse the shared native protocol engine and the real `QPeriaptRuntime`;
there is no private fixture-key import or policy-digest-only admission.
The Node entry keeps its existing API and does not load browser storage modules.

Run persistent device operations in a dedicated Worker on a secure origin with
IndexedDB, Web Locks and OPFS synchronous access handles. Use one stable name
(1–96 ASCII letters, digits, underscores or hyphens), an independently retained
32-byte storage ID, and the exact same enrollment intent on reopen. The intent
constructor takes the pinned account root, 16-byte device ID, generation,
32-byte policy family and validity interval. Timestamps and versions are BigInt;
buffer inputs are Uint8Array and are bounded before copying into WASM.

The lifecycle is `create` (or explicit original `resume`) → `request` → authority
registration → `accept` → `prepare` → any required independent witness enrollment
→ `activate`. `open` never creates or replaces missing original state. It returns
an enrollment owner even for an already active installation; call `activate`
with current verified policy and witness configuration to reopen that service.
`activate_local` is available only when the signed policy admits local protection.
Preparation exposes the public witness subject and genesis digest when required;
these are expectations to enroll, not evidence that enrollment already happened.

The owner can generate/recover an original public prekey. This does not advertise
it or imply a remote publication receipt. Signed prekey publication, connections,
root/roster lifecycle and migration still require final browser API integration.
The protocol and package remain prerelease candidates.

Await `close()` before releasing the wrapper with `free()`. Close cancels pending
witness traffic and waits for actual storage-release receipts. Concurrent device
operations are refused. An operational failure closes the owner; reopen the same
identity to reconcile the original state. Timeout/cancellation may follow a remote
commit and never authorize reset. Independently pin witness identity and public
key; normal witness configuration requires HTTPS, while `for_loopback` is an
explicit local diagnostic entry. Cross-origin endpoints must permit your origin
and `application/octet-stream` POST through CORS. No automatic retry, redirect,
ambient credential or unanchored fallback is used.
