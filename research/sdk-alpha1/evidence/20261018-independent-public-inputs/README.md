# Independent portable inputs and original-context reconstruction

The independent Python/OpenSSL reference now accepts the existing QPBNDL01 public
container through a byte-oriented API, with roots, exact devices/generations,
checkpoints, SDK policy state, directory, required quality, witness pin and trusted
time supplied separately. It does not load trust from a bundle or depend on test
issuer filenames. See the [host contract](../../../continuity-openssl-peer/PUBLIC_INPUTS.md).

Current verification reuses the unchanged signed-input verifier. Explicit original
verification additionally requires the host's retained original context digest.
Bounded, untrusted interval hints select a possible common instant no later than
the actual current time; the ordinary verifier then checks every signature, pin,
membership, signed interval intersection and manifest containment at that instant.
The exact digest must match. This reconstructs a public snapshot, not a current
operational grant or a native live SDK policy/runtime owner.

The common session worker now takes each operation's trusted time and the original
scope digest through this path. It no longer uses a fixed historical time of 150
for every reopen. The old test's separation of historical parsing and current
operation checks was intentional; this change makes that separation an explicit
caller interface. It does not weaken ordinary expiry checks or claim that the
previous test driver exposed a new authentication vulnerability.

Two fresh profiles cover local and required-witness policies. Each independently
encoded 22,980-byte bundle is consumed by the unchanged real Rust
`import_bootstrap_bundle` executable, producing exactly the same context as the
Python verifier. Twenty actual importer calls yield two successes and eighteen
typed exit-1 refusals. Forty-nine independent negative controls cover field
mutations, quality mismatch, unsupported qualities, framing/bounds, future
snapshots, wrong original commitments and expired creation. All 45,960 possible
truncations across the two bundles are rejected. The absent active local journal
is not recreated, and expired historical snapshots cannot create/provision local
or witnessed session state.

All eighteen final runtime entrypoints pass with an exact 88-file source closure;
ten public readers verify their source/binary bindings, signed outputs, original
message/rekey identities, history, process cuts and native importer receipts.
Existing explicit expiry, revocation, credential renewal, unknown delivery and
privileged pending-write controls still pass through the updated common worker.
No final-cohort invocation failed or needed a weakened assertion.

The implementation adds a 75-line input module and 32-line interval-hint module.
The separate 142-line public-input qualification driver is not product-path code.
All 79 Python files parse, actionlint and diff checks pass. The tracked Rust census
remains 725, and all Rust source hashes plus the original native counterpart are
byte-identical to the committed `ace757f4` qualification. Its native ARM64 digest
remains `2806fae5faad22c4412a87167cd0030367fb5a5013508b700c9b8c32e9dd301f`.
That unchanged counterpart was not rebuilt or re-linted. The existing native
importer was built and checked with release/offline/locked and Clippy `-D warnings`;
its ARM64 digest is
`268ee6d7a719b7565077ebbedf971a71600d02893c4d7cdbc7971505bee70a54`.

`CAPTURE.zip` is 47,081,862 bytes with 14,409 members, SHA-256
`8d28229469fdf4e133b942e1b8368392dec76a6046e8f0a16417df539568a300`. It retains the complete final public transcripts,
frozen sources, both executables, native source inventory, readers and verified
manifest. Private image and key material remain outside the capture.

Public readback does not decrypt private images or rederive their MACs. Store
nonmutation, cancellation and no-output checks remain runtime observations.
Fixture trust remains explicit in qualification. This interface does not supply
account authentication, protected registration ownership or a standalone installed
network service. Same-account coordination, complete policy/witness/device/root
replacement, deployed independent lifecycle, resource/energy measurements, full
retained-state PCS/refinement, final ABI/integration and user-owned external review
remain required. This is not complete 0.2.0 release admission.
