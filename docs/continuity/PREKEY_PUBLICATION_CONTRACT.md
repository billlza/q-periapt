# Owned prekey publication contract — implementation work in progress

The native journal now implements the local recoverable operation below through
`next_prekey_publication_id`, `prepare_prekey_publication`, status, abandon and
retire. The registered Rust owner and C device-parent entry points now compose
that operation without exposing a signer. Swift/Kotlin publication entry points
and the installed successor's use of them remain open. This is neither a frozen storage/ABI contract
nor evidence of remote directory publication. Existing `generate_prekey` and
`issue_manifest` remain lower-level operations with their documented responsibilities.

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

Images without a publication registry retain `QPVLT021`/`QPVIMG21`. The first
atomic reservation writes `QPVLT022`/`QPVIMG22`; the registry survives even after
all artifacts retire, preserving the next ordinal. The v21 decoder cannot admit
the new record, and v22 requires exactly one validated registry. The database
container/table is unchanged. New code reads both image formats; the older v21
parser rejects the new outer tag. Actual old-binary rejection qualification remains
a separate gate, rather than being inferred from a new-code round trip. Whole-device retired
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

## Native implementation checkpoint

`PrekeyPublicationPlan` binds the ordered key roles, intervals and explicit reuse
IDs before work. A complete permitted bootstrap mode must be present. All fresh
inventory reservations and zero-filled space for the complete final artifact are
committed together. Subsequent generation and final serialization fit that
reservation; current authority, clock, leaf availability and cancellation are
rechecked before returning output. A retry of a committed artifact rebuilds
canonical membership proofs from its retained public leaves without re-signing.
`Prepared` is historical local state, and can remain readable after release is
refused because a key was claimed or authority expired.

There are at most 16 live publication entries, with a 512 KiB total public-registry
budget. A new reservation may use at most 1.5 MiB of the 2 MiB aggregate image,
leaving at least 512 KiB for subsequent ordinary work. The byte limit and live-entry
limit are separate from the 128 session-operation slots and 1024 inventory records.
Retirement reclaims public-registry capacity, never inventory claim tombstones.
This gives maintenance headroom; it does not promise unlimited traffic or bypass
the existing overall image/record limits. New inventory still has its existing
lifetime identity budget.

A prepared artifact retires only after acknowledgement of its exact artifact
digest. Abandoning a reserved intent retires fresh unshared members atomically,
while reused members and references from another publication remain intact.
Neither operation asserts remote revocation or physical erasure.

Complete device-retirement metadata uses `QPRDMD02` when any view includes the
registry, including its ordinal floor and all pending/prepared public records.
Otherwise the original `QPRDMD01` encoding remains. Native report authentication
still covers every byte; Swift/Kotlin framing accepts only these two versions.
The complete report contains linkable host metadata even though it contains no
private generation tokens.

Native regressions cover exact envelope/proof reopen, original-intent conflicts,
future-ordinal refusal, partial generation, 15 observed cancellation boundaries,
15 corresponding killed-process boundaries, 25 observed sync points with 50
before/after-sync typed failures, and 14 real witness request/reply-loss cases.
They also cover expired/closed authority, missing reused inventory, oversized
plans without mutation, reclaimed publication capacity, malformed authenticated
inventory bindings, and actual witness-retired reporting of prepared plus unfinished
publications. These are implementation regressions on the macOS arm64 host; they
do not establish independent implementation, cross-platform storage behavior,
current/minimum physical-device support or post-compromise recovery security.

## Registered owner and C boundary

`EnrolledDevice` exposes next/status/prepare/retire/abandon while retaining its
original enrollment, signer and installation leases. The C device parent uses
those owned methods for registered devices and the same journal contract for
legacy installed devices; it retains the verified local identity and its current
policy. Parent close, cancellation, nonblocking exclusivity and witness deadlines
use the existing parent invocation machinery.

`QPPUBA01` is a bounded public-artifact wrapper, not another authenticated network
protocol. It contains the original ID/intent/artifact commitments, signed manifest,
original inventory IDs in plan order and proofs in canonical leaf order. Native
encoding finishes before final release checks, including **each member's own
validity interval**, which may end before the manifest/policy interval. A regression
first reproduced an expired member escaping the last check, then passed after the
member intervals were added to final admission. A committed historical artifact
may remain Prepared while current public release is refused.

C callers provide the complete plan, retain the next ID before dispatch, calculate
the size bound, then prepare into a sufficiently sized output region. A short
buffer fails before owner lookup/reservation and copies no partial bytes. The
u32 struct-size prefix is read before the full options structure. Status distinguishes
Absent, Reserved, Prepared and Retired; neither parsing the wrapper nor seeing
Prepared proves remote publication. Current C qualification exercises independent
process retries followed by normal application connection/consumption. It remains
a component/native-ABI workload; whole installed-package and other-language
publication qualification are separate gates.
