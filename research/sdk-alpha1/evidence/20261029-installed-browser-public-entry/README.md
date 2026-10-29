# Installed browser public entry qualification

The same locally built and npm-installed SDK now runs the existing browser API,
storage and original-enrollment tests through its public entry. This is local
macOS arm64 evidence, not hosted CI or complete Continuity lifecycle acceptance.

Two gaps were observed before repair. The existing Window/Worker acceptance
script was not called by the CI browser driver; when executed, its exact export
whitelist rejected twenty account-delivery, closure, retirement and recovery
exports already present in the product JavaScript and Rust definitions. The
TypeScript web entry also omitted `QPeriaptContinuityPolicyRequest`, despite the
runtime export and its documented policy-renewal use. A real TypeScript consumer
of the old installed package fails with TS2724. The identical probe compiles
against the corrected package. The strict export whitelist is updated explicitly;
Expert remains absent from the default entry.

The package was rebuilt and installed outside the checkout with Rust 1.98.1,
wasm-pack 0.15.0, private wasm-bindgen 0.2.129, Node 26.3.0 and npm 12.1.0.
The old and corrected product payloads differ only in `web/index.d.ts`; compiled
WASM, JavaScript and all other package members remain byte-identical. Their
source manifests and external consumer test inputs also differ as recorded.
Strict TypeScript 7.0.2 NodeNext checks and the real Node consumer tests pass.

The final npm archive SHA-256 is
`06b13752dd172c6629e62c2251b99ff6174043713a2d8966014686d5f1169ed3`;
its manifest SHA-256 is
`362ee17ac36fe8515a41febb7504d590289e130ca0b2ae6c077fa517830c37d1`.
Chrome 156.0.8078.48 executes:

- Ten Window/Worker cases, with 563 assertions: roundtrip, absent entropy,
  throwing entropy, an actual 404 WASM load and absent WebAssembly. Every case
  checks the exact installed WASM request, response and Worker identity.
- The unchanged real storage, quota and delayed-completion controls: crypto
  operations, actual Worker termination, abort/close races, QuotaExceeded,
  CommitUnknown/OpenUnknown, ClosePending and retained leases until native
  completion receipts. No timeout is increased.
- Twelve original-enrollment creation/recovery cases and five late-completion
  cases. The fixture converts public arguments and returns actual
  `QPeriaptContinuityDevice` owners. All eighteen served package web members are
  byte-identical to the installation. No research WASM is compiled for this lane.
- Nineteen captured original requests are verified and granted by the fresh
  native issuer, covering seven distinct signing identities and public keys.
  Wrong intent, damaged published state and premature resource reuse remain
  rejected; original requests and storage are preserved.

The existing research-source lane remains explicit when no installation receipt
is supplied. CI now supplies the exact producer receipt and runs the installed
public entry. The npm producer's own `browser_runtime: not-run` remains intact;
the separate browser receipts establish the actual browser executions.

The initial local build failure is retained: the existing global wasm-bindgen
0.2.125 did not match 0.2.129, and wasm-pack could not obtain a matching prebuilt
binary for this platform. A task-private installation repaired the tool setup;
the global installation was unchanged. The first full browser run's stale-export
failure and the TypeScript rejection remain preserved. A second local reader
incorrectly required a console message for the Worker's expected 404; its failure
is also retained. The final reader matches the original JavaScript contract:
zero console events, or exactly one 404 only for the failing-load case. Actual
404 responses, initialization rejection, assertion counts and zero unrelated
errors remain mandatory. Every successful browser CLI command must exit zero.

`CAPTURE.zip` contains the final npm archive, public execution records, relevant
source inputs and failure controls. Its 249 members were read back byte-for-byte;
49 zero-exit command records and 98 paired streams were checked. The archive is
2,592,177 bytes with SHA-256
`06343d9c58f0891f0ab8ef52630080afd58d2f07e2764183d5741c536ab9c5e3`.
The private issuer state is not archived. Its native binary hash was checked
locally; that binary is not included. The issuer and browser use the shared
engine, so this is not independent-implementation evidence.

The frozen Chrome user-agent contains an Intel Mac string; the recorded native
Node host architecture is arm64. This does not add Intel Mac support. Full
browser communication and multi-device lifecycle, mobile-device regressions,
Witness migration, power-loss behavior, multi-epoch security, formal ABI freeze
and final release acceptance remain separate obligations.
