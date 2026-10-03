# Continuity identity, prekey selection and bootstrap candidate

The [installed Rust package gate](PACKAGE_CONSUMER.md) packages this unchanged
shared engine and exercises the public connection/recovery trace through exact
crate archives outside the checkout. It retains the unpublished candidate boundary;
foreign bindings and the product protocol freeze remain separate release work.

The consolidated [wire contract](../../docs/continuity/WIRE_V1.md) covers the exact
current public record/carrier grammars, domains and verification boundaries.
`contract` exposes the resource constants consumed by the real codecs and journal;
the compiled `contract_report` example is checked against
[BUDGETS_V1.json](../../docs/continuity/BUDGETS_V1.json). This metadata is not an
authorization object or a claim that the product protocol is frozen.

This unpublished, isolated implementation exercises the accountable identity
chain proposed for [Continuity in 0.2.0](../../docs/continuity/RELEASE_0_2_SCOPE.md).
An independently pinned account root verifies a device credential and an exact
signed roster; the verified device then authenticates a signed prekey manifest
and individual Merkle membership proofs. Both ML-DSA-65 and ECDSA P-256/SHA-256
must verify. This crate is outside the SDK workspace and publication graph.
The existing ABI major remains **2**.

The candidate supplies actual signatures and byte validation. The lifecycle model
remains a separate test artifact, and supplies no authority to this implementation.
The candidate also verifies a signed session policy and performs a three-flight
bootstrap with two fresh hybrid KEM contributions and mutual key confirmation.
Product admission still needs the complete protocol, capability schema,
ratchet and durable transaction contracts. Candidate
identifiers and encodings are not frozen product wire formats.

## Authority and ownership

`RootSigningKey`, `PolicySigningKey` and `DeviceSigningKey` have distinct public issuance APIs, no raw
secret export, no clone, and explicit idempotent close. Closing drops zeroizing
secret owners. ML-DSA expanded material returned by the low-level provider is
explicitly cleared after transfer to the heap owner. This owner-level guarantee
does not cover compiler/provider copies, registers, paging or process abort.

`AccountPin` requires the expected self-certifying account identifier, root public
keys, exact roster version **and** body digest, and policy family. Enrollment must
obtain those expectations independently of the messages being authenticated.
The host supplies trusted time, durable checkpoint advancement and revocation.
Constructing a pin from an incoming bundle does not authenticate its claimed peer.

`VerifiedDevice` binds the credential, account, generation and exact roster.
`VerifiedManifest` additionally binds a bundle epoch, policy/suite/directory
digests, expiry, count and root. These signed context digests require separate
semantic authorization. `AuthenticatedLeaf` authenticates public bytes and their
role; it is not a primitive-validated KEM key, a lease or a consumption receipt.
Retained objects do not discover later revocation. The journal's installed
[account roster heads](ROSTER_AUTHORITY.md) recheck current membership before
private work and output release. Updates preserve observed generation history
and fence old contexts after restart. The host must explicitly supply independently
authenticated updates; these snapshots do not establish global newest-head agreement.

Exact public-byte fingerprints exclude role, epoch and expiry, allowing the
issuer to reject repeated public bytes within a manifest. They do not establish
mathematical equivalence of differently encoded keys. Cross-manifest uniqueness,
provider canonical admission, one-time use and durable tombstones remain storage
and bootstrap obligations.

`VerifiedManifest::select_prekeys` requires authenticated reusable classical and
last-resort PQ baseline proofs plus an explicit choice for each leg. Every proof
is checked against this same signed manifest and supplied trusted time. The method
derives an `AuthenticatedPrekeySelection`; callers cannot supply its IDs, quality
code, record or digest, and there is no public decoder that promotes network
bytes into this type. The one-time choice requires both a distinct leaf ID and
distinct exact public bytes relative to its reusable baseline, even if a malicious
signer constructed a tree that bypassed the honest issuer's duplicate check.

The selection retains the intersection of **all referenced** leaf intervals,
including reusable baselines when one-time keys are selected. `check_time` checks
only that interval. A service still needs current authority, mode-policy,
directory and primitive-key checks and atomic consumption. Explicitly selecting
a reusable role never grants policy permission or proves exhaustion.

`VerifiedSessionPolicy` binds a distinct hybrid-signature authority, exact
protocol-policy checkpoint, fixed candidate suite, actual verified SDK policy
binding, finite validity and an explicit four-mode permission set. It rejects
device reuse of either protocol-authority component or the SDK policy's ML-DSA
root. Empty permissions disable bootstrap. Closing this policy instance revokes
future admission through it; durable updates and other instances require host
coordination. The SDK's algorithm-only policy schema remains unchanged.

The [bootstrap specification](BOOTSTRAP.md) defines the role-ordered context,
three flights, separate confirmation keys and root derivation. Its responder
borrows the selected owned PQ and classical components through role-typed SDK
expert APIs. Both component owners must belong to the **specified runtime**;
equivalent signed policy bytes do not join independent runtime lifetimes. One
SDK operation slot covers a decapsulation, with the existing ContextBound
implementation and implicit rejection behavior. No private-key export or
re-import is needed. These additive Rust APIs change no C or JNI entry point.

The [encrypted device journal](DURABILITY.md) reserves before real computation,
pins the private result, commits one-time public-key claims with the exact response,
and commits final confirmation before reporting completion. It uses the existing
host-store private filesystem and bounded database backend. Independent expected
journal identity, authenticated whole-image encryption, exact input reconciliation,
real I/O faults and process-kill tests cover this local boundary. The initiator
seals key-generation, encapsulation and signing commands before execution and
recovers identical public outputs after pre-pin crashes. It also restores reply
state and pins replies before processing. The responder persists its admitted
initial contribution and exact KEM/signing reservations; after that boundary,
recovery no longer needs the original prekeys. Its local encrypted inventory now
restores those keys before initial authentication, publishes only committed public
leaves, and atomically consumes one-time tokens with the response outbox. Pending
references block key retirement. Both roles are exercised against a surviving
actual peer, including process loss before the first authentication. Account-root,
device and policy [signing owners](SIGNING_OWNERS.md) can now be provisioned into
encrypted immutable files before enrollment and restored for unfinished signing.
The journal's [write intents](WRITE_INTENTS.md) also preserve exact sealed target
bytes across interrupted state commits. Cryptographic erasure and the wider
identity lifecycle remain open.

The [durable message layer](MESSAGES.md) transfers each completed bootstrap root
into separate send/receive chains in the same journal. It reserves exact plaintext
input before encryption and commits chain/outbox or chain/inbox together before
release. It supports bounded reordered delivery, exact replay and owned plaintext
results. [Consumption acknowledgements](RETENTION.md) now reclaim inbox/outbox
records using authenticated monotonic floors and session-issued sequence IDs.
The initial epoch itself adds no new entropy. Signed hybrid rekeys now install
separate traffic/ACK epochs. Signed settled-prefix retirement bounds history;
explicit [closed-epoch outcome reports](EPOCH_RESOLUTION.md) account for unresolved
old deliveries without labelling them successful. A signed application-send
budget now bounds new reservations without locally completed rekey progress.
The [control-progress path](CONTROL_PROGRESS.md) adds a durable signed request
and one-target step driver for an otherwise idle proposer. Its optional native
[TLS carrier](CONTROL_TLS.md) now delivers those controls through the SDK's
standard mutually authenticated TLS engine with explicit deadlines, cancellation
and finite retries. Real separate-process loopback tests cover either initiating
role and restart after committed replies are lost. Installed language integration,
cross-host scheduling, device lifecycle and multi-device contracts remain required
within 0.2.0.

The [atomic account-send candidate](FANOUT.md) binds the complete installed
signed roster, reserves all required pairwise inputs together and commits every
chain/outbox before releasing any member. Its v18 journal prevents individual
release of a reserved batch member, preserves monotonic aggregate IDs, and
reconciles the existing required witness over the whole local image. This is
one sending device's transaction; remote application execution and transactions
across independently owned sender journals remain separate boundaries.

The [durable hybrid rekey path](REKEY_OFFERS.md) now commits four signed flights
and switches sending/receiving epochs at authenticated, crash-recoverable boundaries.
Message IDs and ACK authority are scoped to epochs, preserving old outboxes and
rejecting old-key influence on new traffic. Its v6 profile can advance beyond the
four-retained-epoch bound after each peer drains the displaced history or its
application acknowledges an immutable resolution report. Missing ACKs, unconsumed
plaintext and unacknowledged reports otherwise retain explicit backpressure.
Resolution preserves unknown delivery outcomes and does not repair past
authenticity. Product transport scheduling and complete lifecycle remain open.
`public_vectors --with-rekey` completes the real journals, restarts them, exercises
new traffic and exports public control/frame bytes for the independent oracle.

The optional [encrypted witness carrier](ANCHOR_TLS.md) uses standard mutual TLS,
an exact server certificate pin, and explicit client-certificate/subject bindings.
It reuses the signed witness protocol without requiring an active SDK runtime.
This native feature is under validation; installed C/other-language TLS witness
paths and deployed service lifecycle remain separate work. The reference signed
TCP path remains explicitly unencrypted, with no automatic transport fallback.

The [monotonic witness](ANCHOR_WITNESS.md) adds actual signed requests/replies,
trusted enrollment from journal genesis, durable full-head/fence comparison and
unknown-outcome recovery. Fresh challenges and one-result-per-attempt admission
reject stale or cancelled replies. The [required-anchor profile](REQUIRED_ANCHOR.md)
binds its identity into the signed policy and the encrypted journal, gates state
application and output, and reconciles exact saved commands after unknown outcomes.
Its independent storage trust and explicit
whole-witness rollback counterexample remain part of the acceptance boundary.

## Exact candidate encoding

All integers are unsigned, big-endian, with no implicit padding. No trailing
bytes, unknown leaf kinds or variable algorithm selection are accepted. Intervals
are half-open `[from:u64, until:u64)`, nonempty, with `until != u64::MAX`.
Generations, roster versions and bundle epochs are in `1..u64::MAX` (exclusive
upper bound). Device IDs and context digests must be nonzero.

The public key is `ML-DSA-65 public[1952] || compressed SEC1 P-256 public[33]`.
P-256 points are decoded and checked against their canonical compressed encoding.
The signature is `ML-DSA-65 signature[3309] || ECDSA r[32] || s[32]`.
ECDSA uses SHA-256 and fixed-width unsigned r/s; the verifier rejects high S.

Let `C = ASCII("Q-PERIAPT-CONTINUITY-IDENTITY-CANDIDATE/v1")`.
Both algorithms sign `C || purpose:u8 || body_length:u32 || body`.
ML-DSA additionally uses `C` as its external context, with the ordinary ML-DSA
message encoding. Purposes are credential=1, roster=2, manifest=3,
session policy=4, bootstrap initiator=5 and bootstrap responder=6.
The envelope is `body_length:u32 || body || signature[3373]` and admits at most
16,384 body bytes. ECDSA and ML-DSA are both required; neither is a fallback.

For every digest below, define
`D(name, bytes) = SHA3-256(u64(len(domain)) || domain || u64(len(bytes)) || bytes)`,
where `domain = ASCII("Q-PERIAPT-CONTINUITY-" + name + "-CANDIDATE/v1")`.
Body digests exclude randomized signatures.

| Record | Body, in field order |
| --- | --- |
| Credential (2,097 bytes) | `QPCERT01[8]`, account[32], device[16], generation:u64, interval[16], family[32], public key[1985] |
| Roster (66 + 56*n bytes) | `QPROST01[8]`, account[32], version:u64, interval[16], count:u16, entries `(device[16], generation:u64, credential_digest[32])` |
| Manifest (290 bytes) | `QPMANF01[8]`, scope[248], count:u16, Merkle root[32] |
| Leaf (57 or 1,209 bytes) | `QPLEAF01[8]`, kind:u8, interval[16], exact public key[32 or 1184] |
| Membership proof | index:u16, leaf_length:u16, leaf, depth:u8, siblings[depth*32] |
| Authenticated selection (492 bytes) | The unchanged sixteen LP8 fields in [PrekeySelectionV1](../../docs/continuity/PREKEY_SELECTION_V1.md), derived from this manifest and the referenced members |

Account ID is `D("ACCOUNT", root public key)`. Credential and roster digests are
`D("CREDENTIAL", credential body)` and `D("ROSTER", roster body)`.
The roster has at most 32 entries, strictly sorted by device ID, with no duplicate
device ID. An empty roster revokes all listed membership. The root rejects device
keys sharing either of its signing components.

Scope is the concatenation of account[32], device[16], generation:u64,
credential_digest[32], roster_version:u64, roster_digest[32], bundle_epoch:u64,
policy_digest[32], suite_digest[32], directory_checkpoint[32], interval[16].
The authority binding is `D("AUTHORITY", account || roster_version ||
roster_digest || family)`. The manifest digest is `D("MANIFEST", body)`.

Kinds 1 and 2 designate reusable signed and one-time X25519 keys; kinds 3 and 4
designate last-resort and one-time ML-KEM-768 keys. Leaf shape checks require the
exact public key length and reject all-zero bytes. They do not replace primitive
validation. Leaf ID is `D("PREKEY-LEAF", scope || leaf)`; exact-public-byte
fingerprint is `D("PREKEY-PUBLIC", algorithm:u8 || public)`, where algorithm=1
for X25519 and 2 for ML-KEM-768.

The issuer sorts 1..1024 leaves by leaf ID. A one-leaf tree root is its
leaf ID. Otherwise split at the largest power of two strictly smaller than the
count and compute `D("PREKEY-NODE", left_root || right_root)` recursively.
Proof siblings are ordered from leaf toward root; count and index determine all
left/right directions and the exact path length, at most 10. No padded leaves
are used. An individual proof establishes the selected leaf's membership, not
the uniqueness or ordering of undisclosed leaves chosen by a malicious signer.
Manifest intervals must be contained in both credential and roster
intervals; leaf intervals must be contained in the manifest interval. Time is
rechecked during device, manifest and leaf verification.

The selection reuses the existing model codec's record and digest domains without
adding a candidate suffix. Its digest is SHA3-256 over the existing 555-byte
`LP8(selection digest domain) || LP8(record)` preimage. Its four quality codes
retain both legs: 1=one-time/one-time, 2=signed-only/last-resort,
3=signed-only/one-time, 4=one-time/last-resort. Both baseline IDs are always bound.
The actual implementation has no dependency on the lifecycle model.

## Reproduce verification

Run from the repository root with the locked toolchain and the supported Unix
private-filesystem adapter for the durable rekey fixture. Each output directory
below must be new; evidence is never overwritten.
Keep build output in the repository's designated `target` tree (or outside the
checkout), so the source-provenance gate can distinguish generated build files
from untracked source. The subshell below keeps the target setting local.

```sh
(
export CARGO_TARGET_DIR="$PWD/target/continuity-identity-build"
cargo fmt --manifest-path research/continuity-identity-candidate/Cargo.toml --package q-periapt-continuity-identity-candidate -- --check
cargo clippy --manifest-path research/continuity-identity-candidate/Cargo.toml --locked --all-targets -- -D warnings
cargo test --manifest-path research/continuity-identity-candidate/Cargo.toml --locked
cargo test --manifest-path research/continuity-identity-candidate/Cargo.toml --locked --release
cargo audit --file research/continuity-identity-candidate/Cargo.lock --deny warnings
cargo run --manifest-path research/continuity-identity-candidate/Cargo.toml --locked --example public_vectors -- target/continuity-public-vectors --with-rekey --with-anchor
sh artifact/python-run.sh research/continuity-identity-candidate/scripts/verify_public_vectors.py --fixtures target/continuity-public-vectors --output target/continuity-public-verification --openssl /absolute/path/to/openssl --with-rekey
sh artifact/python-run.sh research/continuity-identity-candidate/scripts/verify_anchor_vectors.py --fixtures target/continuity-public-vectors --output target/continuity-anchor-verification --openssl /absolute/path/to/openssl
)
```

The verifier commands require OpenSSL with ML-DSA and external-context support
(OpenSSL 3.5 or later). It fails when the required provider is unavailable. The
example generates fresh signing and actual X25519/ML-KEM public keys, emits only
public records, and discards secret owners. Python independently reconstructs
canonical bodies, 19 body/signature bindings and 30 membership proofs across
tree sizes 1, 2, 3, 5 and 17. OpenSSL verifies both signature components and rejects
95 altered-body, purpose or ML-DSA-context controls. Both generator and verifier
require `--with-rekey` to include the four control flights and their new-epoch
message encodings. The anchor verifier separately checks 12 envelopes and 60
negative controls across six transitions. The independent existing
PrekeySelectionV1 codec also reconstructs nine authenticated selection records
(four role combinations for each of the 5- and 17-leaf trees, plus the two-leaf
bootstrap manifest), their digests and quality codes from the verified leaf set.
The bootstrap fixture additionally verifies the signed SDK and protocol policies,
role-ordered context, both signed flights and final transcript/session identity.
It exports no live shared secret; secret confirmation and root agreement are
covered by real peer tests, separately from this public oracle. The schema-3 report records fixture
hashes, OpenSSL identity, command arguments and return codes; separate bounded
stdout/stderr logs preserve failures. This is component verification, not a
network protocol or session-recovery test.

Hosted CI builds/tests the locked candidate on Linux with Rust 1.98.1 and the
declared 1.90.0 floor, and on macOS with Rust 1.98.1. The macOS lane uses its
installed OpenSSL provider for the independent fixture check. A separate
dependency fence prevents the candidate from entering SDK package manifests.

Explicit [fanout abandonment](FANOUT_ABANDONMENT.md) freezes a reserved batch's
whole sessions and requires durable metadata-only loss accounting before logical
key erasure. Its original v19 storage is superseded by the shared v20 lifecycle
format; pairwise v6 wire bytes remain unchanged.
This scoped lifecycle operation does not complete account-wide device replacement.

The optional [native connection carrier](CONNECTION_TLS.md) runs the original
bootstrap through the encrypted prekey inventory, delivers actual application
frames and confirms only authenticated consumption prefixes after durable host
accounting. It shares TLS I/O with the control carrier. This is a native candidate
execution path; installed bindings and account-directory integration remain open.

[Portable bootstrap materials](BOOTSTRAP_BUNDLE.md) provide a bounded byte-input
contract for subsequent language integration. Verification retains an existing
policy owner and independently pinned, exact device expectations; parsing the
container grants no authority. Native endpoint tests consume this file boundary,
and a separate Python producer exercises the compiled Rust importer.

[Permanent independent session closure](SESSION_CLOSURE.md) now freezes ordinary
sessions and incomplete rekeys for explicit host loss accounting, then replaces
private state with keyless tombstones. It cannot split a reserved fanout or turn
unknown delivery into acknowledgement. Journal v20 shares its terminal codec and
accounting projection with aggregate abandonment.

The same closure engine now accepts a wrapping-key-authenticated QPCSCA01 archive
through a restricted `SessionClosureJournal`. Persist that archive before message
activation; reopening verifies an existing exact session or its already sealed
activation transaction. It never rebuilds operational policy/device/context authority,
and all original witness requirements remain. See [archived admission](SESSION_CLOSURE.md#archived-admission-and-restart).

[The bounded native archive index](SESSION_ARCHIVE_STORE.md) is now mandatory in the
connection Actor. Both endpoints durably retain their archive before activation and
verify its original scope/MAC before application traffic. The reference connection
then closes both endpoints from the index in new processes without verified contexts.


## Permanent bootstrap cancellation

[Bootstrap cancellation](BOOTSTRAP_CANCELLATION.md) provides an explicit terminal
operation before application activation, including a cleanup-only reopening owner
that needs no live verified policy/context. The original operation and one-time
claims remain reserved; early selected one-time inventory becomes abandoned and
cannot be reused. Receipts describe local durable state, never peer delivery or
remote cancellation. Existing application sessions still require session closure.

The current candidate disk format is v21 with a preallocated cancellation metadata
slot. Earlier v19/v20 lifecycle checkpoints above retain their historical scope;
old candidate images are refused without implicit migration. Primitive, SDK ABI and
network wire contracts are unchanged. See the cancellation contract and release
ledger for exact source-bound verification and remaining integration requirements.


## Archived aggregate cleanup

[Whole-batch archived cleanup](FANOUT_ABANDONMENT.md#archived-whole-batch-cleanup)
loads every original session archive from the persisted index and checks the
complete authenticated batch before recovery or mutation. Its restricted owner
freezes the whole reserved set, requires full durable host loss accounting before
logical erasure, and can retire acknowledged abandoned-batch metadata while keeping
terminal sessions and monotonic IDs. No operational context is reconstructed, and
required witnesses still gate readback and advancement. Ordinary committed-history
retirement, catalogue restoration and installed-language service integration remain
separate lifecycle requirements.

## Journal creation recovery

The [journal creation contract](DURABILITY.md#creation-with-an-unknown-result)
requires a public identity retained before provisioning. A process exit after
commit can then reopen the exact original genesis. Required-witness creation can
recover only enrollment metadata before explicit enrollment and fresh witness
admission. Partial creation is refused without repair or replacement. This closes
a native journal prerequisite; installed SDK owner integration remains outstanding.

The [native installation owner](INSTALLATION.md) now durably binds that journal
identity to the original key, device, policy and configured paths before child
creation. It commits Active before releasing a service that retains all three
leases. Required-witness enrollment remains explicit, unknown activation outcomes
reconcile the original record, and missing active children are never recreated.
This supplies the native service initialization boundary; published binding and
complete device/root lifecycle integration remain required.
