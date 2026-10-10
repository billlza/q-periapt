# Independently authorized SDK policy-root recovery

Source `8d835c634a20a8d45e5f2a2ff62a74ec43e8d963`, macOS Apple Silicon.
This implements the opt-in Rust host-store v2 path; it does not close the complete
0.2.0 identity-lifecycle/release objective. The current contract and wire format
are in [SDK_HOST_STORE.md](../../../../docs/SDK_HOST_STORE.md).

The new store pins an independent recovery root before an incident, verifies its
enrollment proof, and requires recovery authorization plus incoming-key possession
over the exact transition. A policy at u32::MAX can move to a different root's
version1 without rolling back/reinitializing the old store. Original operations,
predecessor state, history and both roots remain bound. Ordinary updates stay
strictly monotonic. Previously used roots/operations cannot return; recovery
history has an explicit lifetime bound of 4,096 transitions. V1 files do not acquire
this authority merely because an open call supplies a different key/configuration.

Observed verification:

- Host-store: 42 Debug, 42 Release, 42 Rust 1.90 tests passed; strict Clippy passed.
  Cases include actual signatures, exhausted enabled policy to new-root disable,
  later normal reenable, rejected roles/domains/root reuse, stale requests,
  original receipt replay after later policy/root changes, corrupted metadata,
  and mutation of a prior history entry caught by the signed history commitment.
- Real-file commit failure and post-sync concurrent runtime close leave the owner
  closed. Original authorization reconciles old/new outcomes. Child exits 71/72
  exercise preparation loss and committed-before-activation process loss.
- A further caught-unwind test initially failed: the draft retained an active old
  owner after actual commit. Moving Active onto the mutation's stack fixed it;
  child 73 now verifies both old aliases and the store are closed. Ordinary policy
  updates use the same ownership pattern and child 43 verifies their unwind path.
  The panic is still propagated. These are process/I/O traces, not physical
  power-loss or hardware rollback/erasure tests.
- SDK 27 tests plus 4 compile-fail docs and FFI 43 tests passed. Final host/library
  source fingerprints are retained; later extra historical-corruption assertions
  did not change the tested SDK/FFI production source. Rustfmt/diff checks passed.
- All 60 affected CodeQL inventory, Rust package-profile and ABI tests passed in a
  clean standalone checkout. The earlier linked-worktree attempt correctly failed
  its two provenance-sensitive cases; no provenance check was weakened. Tracked
  Rust inventory is 419 after adding the actual recovery module.
- Twelve exact Cargo archives were rebuilt in a clean checkout. The four public
  external-consumer groups passed with Rust 1.98.1 and1.90, including fresh OS-random
  policy issuers and root recovery. Workspace/fuzz/consumer audits used one fresh
  RustSec database and retained all warning classes; no findings/warnings occurred.
  The test's three issuers live in one process: role verification is not proof of
  operational offline key isolation. No package was published.

OpenSSL 3.6.4 generated independent recovery/incoming key pairs and signed the
actual enrollment, target policy and both transition messages. The driver consumed
eight archive-extracted packages outside the checkout. Python independently
reconstructed every 2,168-byte request field, trust/history commitment and policy
state digest. The installed Rust store rejected swapped roles, accepted the
correct authorization, persisted a disabled new-root runtime and reopened the
same original operation as AlreadyApplied. Extracted package files/report were
rechecked unchanged. This is an independent signer/encoding check, not independent
implementation of the entire session protocol. The Pure ML-DSA context/CLI contract
is documented by [OpenSSL](https://docs.openssl.org/3.6/man7/EVP_SIGNATURE-ML-DSA/)
and [pkeyutl](https://docs.openssl.org/3.6/man1/openssl-pkeyutl/).

The first standalone probe had an unused rustls patch warning. The corrected
probe supplies only its eight actual archive dependencies, rejects warnings, and
passed again. The initial warning/result are retained separately.

Only public messages, public keys, signatures, source and logs are retained for
the OpenSSL experiment. Fresh OpenSSL private-key files were confined to its
removed temporary directory; no physical erasure is claimed. The Rust genesis is
the deliberately public deterministic seed 91 fixture, not a production secret.

`raw-records.json` losslessly preserves commands, full source fingerprints and
logs as gzip+base64. Decode and check each original length/SHA256 before reading.
The failing draft module is `unwind-red-source.rs.txt`: it was reconstructed by
reversing only the ownership fix and matches the exact recorded red-run hash
`4b0fbb92793e41b3b18795ac94d48c5c0190db2cc30a47ec0419bd841aa5c485`.
It is evidence, not product source. A disposable 8d835c63 checkout with that module
can exercise the named root-recovery process-cut regression; never replace the
product checkout for this diagnostic. Earlier compile/Clippy failures are retained
as development failures, not presented as security counterexamples.

Remaining scope includes foreign-language recovery APIs, explicit v1 trust
migration, recovery-key rotation/threshold governance where required, complete
Continuity credential/family/witness/session migration, independent security review,
current remote CI/platform/device evidence and full matched performance/release
qualification. A successful root transition does not prove restored message
confidentiality, remove exported secrets, or defend an old whole-disk snapshot.
