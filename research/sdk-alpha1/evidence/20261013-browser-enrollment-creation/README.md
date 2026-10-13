# Browser enrollment creation and original recovery

The candidate now stores its exact original enrollment inputs, vault and wrapping
key atomically. An authenticated catalogue records which files were published.
Explicit `resume` can finish unpublished first-use work or reopen its original
database; it cannot regenerate a missing published key or database. Ordinary
`open` requires completed initialization. Native callers use the same enrollment
state machine with synchronous storage calls.

The final real Chrome cohort passed 12 scenarios, including eight actual Worker
terminations. Nineteen captured requests were verified by the separate native
issuer using the same Rust protocol engine. Seven browser-generated signing
identities were observed. Published database IDs and wrapping ciphertext stayed
unchanged through recovery, and repeated requests were byte-identical. Wrong
inputs, deleted published rows and damaged catalogue authentication were refused
without repair. This is cross-runtime evidence, not independent-implementation
interoperability.

Four scheduler-controlled delays covered real WebCrypto, OPFS handle acquisition,
IndexedDB opening and transaction completion. Each retained the root lease until
the underlying completion receipt, returned the original operation error with
`ClosePending`, rejected a second owner as `Busy`, and later recovered the original
request. The first attempt exposed a WASM error-wrapper defect that discarded
structured cleanup causes; that failed result is retained. A pre-existing foreign
directory was refused and its file contents remained unchanged.

The shared `storage-io.js` is also used by the product policy store. Its fresh
installed package passed the existing quota and lifecycle groups plus the delayed
completion group. The current native C adapter and its test targets compiled with
strict Clippy on Rust 1.98.1 and with Rust 1.90. Those source checks do not complete
the separate Rust/C/Swift installed runtime qualification. The preceding storage
adapter cohort's 959-test run remains historical evidence rather than a full run
of this final integrated source.

`CHECKS.json` records hashes and scope; `CAPTURE.zip` retains the served sources,
public requests and credentials, build and runtime receipts, failed attempts and
integrated source. Private issuer keys, browser profiles and private journals are
excluded. The archive was reread member-by-member before sealing.

Operational browser activation, sessions, root/roster lifecycle, transport,
unified product packaging and schema migration remain open. Authenticated local
metadata provides no whole-profile rollback guarantee. Non-extractable keys do
not isolate hostile same-origin code or a compromised profile. Staging cleanup is
logical deletion, and these browser tests establish no native power-loss or
cryptographic-erasure equivalence.
