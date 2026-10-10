# Product WASM package candidate

`artifact/wasm_sdk_package.py` builds a single `q-periapt-sdk-wasm` npm archive
for 0.2.0. C remains ABI 2; WASM package entry points do not change the
native ABI, its symbol identities or its existing status codes.

The default Node CommonJS and ESM imports share the same instance and classes.
The default browser entry and explicit `/web` entry use generated browser ESM,
await one initialization promise and do not return raw WASM exports. The
deliberate plaintext-transfer API is available only through `/expert` or
`/web/expert`. The old deterministic/KAT crate remains separate. The exports map
is an integration boundary, not a same-realm adversarial isolation mechanism.

Build from the repository root with pinned Rust 1.98.1, wasm-pack 0.15.0, npm 12.1.0,
a WASM-capable C compiler and Node >=24:

```sh
npm exec --yes --ignore-scripts --package typescript@7.0.2 -- tsc --version
CC_wasm32_unknown_unknown=/absolute/path/to/clang \
  sh artifact/python-run.sh artifact/wasm_sdk_package.py --output target/sdk-wasm-package
```

No global npm installation or publication is performed. The output must be a
fresh directory; failed attempts and the external consumer directory are kept.
The producer builds release Node/web modules, includes target-filtered license
texts and pinned Rust standard-library notices, checks npm's packlist, writes
the existing canonical tar.gz format with the npm `package/` root, extracts it
with a pinned archive digest, then installs it offline in a fresh directory
outside the checkout. The package has no npm runtime dependencies or scripts.
Its original manifest digest and every installed file are checked before and
after the actual lifecycle/policy/entropy and CJS/ESM consumer executions. Strict
TypeScript 7.0.2 NodeNext compilation checks both module modes without skipping
declaration checking. Source inputs must remain unchanged through the run.

The producer and standalone archive consumer share the same installation and
execution path. To qualify an exact runtime using an already produced archive:

```sh
sh artifact/python-run.sh artifact/wasm_sdk_package.py \
  --archive "$archive" --archive-sha256 "$archive_sha256" \
  --manifest-sha256 "$manifest_sha256" \
  --node /absolute/path/to/node --npm-cli /absolute/path/to/npm-cli.js \
  --expected-node-version v24.0.0 --output target/sdk-wasm-node24-minimum
```

Use the digests from the trusted producer receipt. The consumer requires the
matching source checkout, records the actual Node executable/version and tool
hashes, installs offline outside the checkout, and checks package, source and
tool bytes again after execution. A newer Node binary cannot satisfy an exact
24.0.0 qualification. SDK tests must emit their expected completion records
without diagnostics; the entropy-failure child must also finish without warnings.

The current macOS ARM64 candidate was consumed successfully by both Node
**24.0.0 / npm 11.3.0** and **26.3.0 / npm 11.16.0**, including strict TypeScript
5.9.3 checks. Both runs used archive SHA-256
`6a75adb49acec798816be5731e9d4a98368ccd4942b444de13e658f5dba84b5c`
and manifest SHA-256
`f39fea44ce7d0bbf09352049815a6a37abc4e296e527843e3c183a60e8808c2d`.
This candidate was rebuilt after removing the redundant prepared public-key
cache; the [current checkpoint](../research/sdk-alpha1/evidence/20260927-sdk-public-key-view/manifest.json)
retains both installed Node executions. The subsequent
[browser checkpoint](../research/sdk-alpha1/evidence/20260927-wasm-public-view-browsers/manifest.json)
executes this same archive in Chrome and Firefox windows and dedicated Workers.
Earlier browser archives retain their separate historical identities.
The minimum runtime came from the
[official Node 24.0.0 distribution](https://nodejs.org/en/blog/release/v24.0.0),
with its archive checked against the published checksum and installed only in
the task's tool directory. Hosted Linux execution remains pending. CI now
switches to exact 24.0.0 after production and consumes that same archive.

`INSTALLED_CONSUMER.json` records the exact archive, installed path and Node/type
results. Its browser field remains `not-run`: browser validation is a separate
real execution with its own record. Candidate hashes establish byte identity;
they are not signed publication, security review or a stable release claim.
The package quickstart is copied from
[`PackageREADME.md`](../crates/q-periapt-sdk-wasm/PackageREADME.md).

For browser validation, read `consumer-location.json` and run `node serve.cjs`
in that external consumer. The loopback-only fixture server prints a URL and
serves only the installed web entry, fixtures and test page. Visit that URL
with each mode: `roundtrip`, `no-entropy`, `throwing-entropy`, `init-fail`, and
`no-wasm`. The page returns `__QPERIAPT_TEST_RESULT` after explicit owner cleanup;
any failed assertion or cleanup changes its status to `fail`. Success paths use
the real platform entropy and crypto. Failure modes deliberately remove/throw
the entropy provider, serve an actual HTTP 404 for the WASM file, or remove the
WebAssembly capability. No crypto is mocked into success. A browser runner must
also reject page errors and enforce a deadline; reading an initial page or a
missing result is not a pass.

Run every mode with both `realm=window` and `realm=worker`; for example,
`/browser.html?mode=roundtrip&realm=worker`. Both use the same acceptance module,
and the Worker case verifies its actual dedicated-worker global. The copied
`browser-acceptance.js` runner checks all ten scenarios, exact WASM loads and
Worker script identity. Worker startup/result errors and a 15-second deadline
are failures, with termination of the owned Worker on every outcome.

The numeric boundary regression has a concrete old/new witness: the old WASM
converted `1.5`, `4294967297`, strings, booleans and coercible objects into valid
resource limits. Purposes also accepted non-number coercions. Rust now receives
the original JS value, requires a number, checks integer/range constraints before
conversion, and preserves strict generated TypeScript declarations. Existing
signed-policy, transcript and rejection semantics remain unchanged.
The WASM trusted-state getter also now rejects a closed or revoked runtime,
matching the owned C surface; the previous getter returned 36 bytes after close.

The macOS build logs retain wasm-pack 0.15.0's existing warning that its prebuilt
wasm-bindgen platform is unrecognized before it uses the cargo-installed tool.
The same warning is present in the earlier sealed 2026-09-25 WASM logs. It is an
external tool installer warning, not a Rust compiler diagnostic; it has not been
hidden or treated as proof of a new toolchain installation. Current compiler
Clippy checks use `-D warnings`.

The [current browser execution record](SDK_BROWSER_RUNTIME.md) covers five cases
in both window and dedicated module Worker in Chrome 153 and stock Firefox 156
on macOS ARM64, with Firefox host diagnostics
retained separately. Safari's automation setting is disabled; Safari/mobile and
minimum browser versions, bundlers and other Worker types remain open. The browser path is
synchronous after initialization; applications own durable policy storage,
authenticated protocols and erasure of any explicitly exported JS bytes.

Package resolution follows the primary
[Node package exports contract](https://nodejs.org/api/packages.html#conditional-exports)
and the distinct Node/web outputs documented by
[wasm-bindgen](https://wasm-bindgen.github.io/wasm-bindgen/reference/deployment.html).
