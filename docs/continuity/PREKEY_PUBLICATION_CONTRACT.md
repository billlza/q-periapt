# Owned prekey publication contract — implementation work in progress

This is the required contract for the next lifecycle component. It is not an
implemented API, a frozen storage format, or evidence that directory publication
already exists. Existing `generate_prekey` and `issue_manifest` remain lower-level
operations with their documented responsibilities.

## Observed boundary

`durable/prekeys.rs` reserves key-generation randomness, commits the public leaf,
and recovers the same inventory request after reopen. The request cannot change
its kind, validity or SDK binding. Available, consumed, abandoned and retired
keys remain distinct; generating another manifest does not reset these states.

`manifest.rs` signs a caller-supplied epoch/context and public leaf set. It does
not allocate or durably reserve that epoch. `VerifiedManifest::digest` commits to
the canonical body, independently of signature randomness. This is intentional:
signature verification does not establish publication history or current
directory consistency. `DirectoryExpectation` is independently trusted input,
not a consistency proof obtained from the incoming manifest.

Two native regressions in `durable/prekeys/tests.rs` exercise the boundary using
real persisted prekeys, the actual SDK runtime and hybrid signatures:

- `publication_boundary_inventory_reopen_does_not_retain_manifest_signature_bytes`
  reopens the inventory and reconstructs the same body, manifest digest and every
  membership proof without changing the journal revision. It records whether the
  two signed envelopes match. The observed run produced different envelopes;
  envelope inequality is not required of every future valid signature backend.
- `publication_boundary_signer_does_not_allocate_a_durable_manifest_epoch`
  signs two different real prekey sets at the same caller-selected epoch. Both
  signatures and all proofs verify, while their manifest digests differ.

These are composition obligations, not findings that the existing signature or
inventory primitives violate their contracts. A foreign signer wrapper alone
would leave these obligations with the application.

The stable body digest is correct protocol behavior. Different valid signature
bytes can still represent the same logical manifest when a distributor deduplicates
by that verified digest. The observations do not justify changing the manifest
digest to include signing randomness or forcing deterministic signatures. The
operation below deliberately retains the committed envelope to offer byte-identical
artifact retries and avoid signing during recovery; that is an SDK integration
contract, not a cryptographic necessity established by envelope inequality alone.

## Required owned operation

An operational enrolled-device owner must coordinate one publication intent,
its inventory work and its original public artifact. Private keys, recovery
tokens and a general signing capability must remain inside the native owner.
The operation must use the existing journal transaction, write-intent, witness,
authority and cancellation machinery rather than a second persistence layer.

The retained intent binds the journal/device generation, signing identity,
credential and roster checkpoint, protocol and SDK policy bindings, fixed suite,
independently supplied directory expectation, validity interval, publication
epoch, and complete bounded leaf plan. Retrying that operation cannot change any
of those inputs. Freshly generated keys must have stable original inventory IDs;
explicit reuse of an existing key must retain its original role, policy binding
and validity and pass the inventory's current availability checks.

The publication epoch must be allocated by the owner. A client must not be able
to exhaust it by submitting an arbitrary maximum integer. Reuse the existing
`FanoutId` allocation pattern: a deterministic domain-separated journal/ordinal
binding, the exact next ordinal, and an atomic reservation of that ordinal and
the full intent. Reject a competing intent or a future ordinal. A race is a
conflict, not permission to create a replacement operation automatically. A
separate random nonce or a second allocation protocol is unnecessary. The final
publication-specific domain, epoch mapping and state format require implementation
and codec validation before admission.

Reserve the complete intent before generating any member. Partial generation
must resume those same inventory requests. Commit the exact signed manifest and
the complete canonical public member/proof set before releasing output. A crash
before that commit may redo unexposed signing work; an uncertain commit must
reconcile the retained target and must not re-sign an already committed artifact.
Current policy, credential, roster, witness and leaf availability must be checked
again at public release. Error and late cancellation must preserve the original
recovery path without releasing a partial advertisement.

## Status, distribution and retirement

Local preparation is not remote publication. The local result must identify its
original operation, body digest and exact artifact bytes. It must not return a
`Published` or remote-success state without an independently authenticated
distribution protocol and receipt. A lost external reply remains unknown;
re-signing does not resolve it. Public artifact retrieval must not imply that a
one-time key is still available, that an expired grant is current, or that a
directory has served a fresh consistent view.

History retention needs a bounded policy and a persistent monotonic floor.
Compacted history must produce an explicit history-unavailable result, not
authenticated absence or invented success. An old operation cannot become a new
reservation after compaction. Retiring a publication must not automatically erase
keys referenced by another advertisement, erase consumption tombstones, or bypass
pending-response protections. Capacity handling must leave ordinary traffic,
roster/credential maintenance, revocation and cleanup available. Do not choose an
arbitrary lifetime publication quota without testing it against the existing
prekey and aggregate-image budgets.

## Storage and verification obligations

The present authenticated image is `QPVLT021`. A new durable record must have
explicit format/version admission, bounded counts, validation and resource
accounting. Existing images must remain readable; older implementations must
refuse an unsupported new format without rebuilding state. Whole-device retired
reports must include publication metadata, including unfinished original intent
and retained-artifact identity, before cleanup can acknowledge the complete
image. No journal or report variant may be silently omitted.

Required validation includes process cuts before/after intent reservation, each
member commit and signed-artifact commit; uncertain witness commits; exact-byte
reopen; same-ID/context substitution and same-epoch competition; authority changes
and expiry during work; cancellation; concurrent owner/lease admission; claimed
or retired members; capacity without maintenance starvation; compaction replay;
old-image upgrade; and complete retired-device reporting. Then the installed
C/Swift/Kotlin successor scenario must obtain its advertisement through this
owner instead of native fixture prekey/manifest setup.

Cross-language API and ABI work follows the native recoverable operation. The
overall 0.2.0 gate still includes real distribution packages, independent
implementations, platform/device coverage and security analysis.
