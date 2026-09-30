# Continuity in the 0.2.0 release

The release scope changed on 2026-09-28: persistent sessions, fresh-PQ rekeying,
disconnect recovery, revocation, continuous PQ recovery and multi-device lifecycle
are required in **0.2.0**. Earlier scheduling that placed these capabilities in a
later release is superseded. The SDK ownership, ContextBound, native-backend,
standard-TLS, binding, installation, device and performance requirements remain.
ABI major remains **2**.

This is a requirements and implementation-boundary record. It does not promote
the existing public-commitment model into a working cryptographic protocol.

## Current implementation boundary

- `q-periapt-sdk` owns verified policy runtimes and coupled KEM keys, with explicit
  purpose derivation, policy transitions and bounded lifetimes. Its optional
  [sealed operation interface](../SDK_SEALED_OPERATIONS.md) reserves platform KEM
  randomness for exact policy/input-bound recovery. It has no message ratchet or
  session-secret persistence; its sealed operations now back the candidate's staged
  initiator/responder and encrypted prekey inventory. The candidate separately
  persists root/device/policy signing owners before enrollment.
- `q-periapt-rustls::connection` supplies the authenticated reference connection,
  policy confirmation, bounded request/response transport and revocation. A TLS
  connection or symmetric TLS key update does not establish continuous PQ recovery.
- `q-periapt-host-store` persists signed policy through protected files and redb,
  including uncertain commit and activation failure. It does not store encrypted
  ratchet state, inboxes, outboxes or device rosters.
- `q-periapt-continuity-model` is `publish = false` and represents public
  commitments and trusted adapter outcomes. It contains neither cryptographic
  payloads nor a real storage/provider adapter. Its lifecycle counterexamples and
  canonical-context tests are useful design inputs, not product execution.
- `research/continuity-spqr-reference` executes the fixed upstream SPQR component
  under seven loss/reorder/directionality schedules, retains exact public wire
  corpora and checks actual message-key agreement. Its one-way trace has no fresh
  PQ epoch progression. It remains a separate reference workspace; product ratchet
  selection still requires the matched alternatives and compromise analysis.
  Its passive snapshot experiment now reproduces exposed message keys, including
  a pending KEM key's next-epoch contribution, across 84 actual state disclosures.
  The finite experiment does not close the continuous-recovery proof obligation.
- `research/continuity-whole-kem-reference` supplies an isolated full ML-KEM-768
  periodic control with authenticated proposal/ciphertext/confirmation, immutable
  pending material, bounded skipped keys and actual message-key agreement. Three
  fixed intervals run the same traffic schedules and 252 passive snapshots. This
  is a comparison construction, without a product dependency, durable store or
  full hybrid security claim; profile selection remains open.
- `research/continuity-identity-candidate` implements an isolated actual-signature
  root/credential/roster/manifest chain, Merkle membership verification and a
  canonical selection derived from the actual authenticated members. It also
  supplies a signed session policy, three-flight confirmed bootstrap and an
  encrypted device journal with real initiator/responder reservation/result/outbox
  commits and restart from saved private state. Both roles seal KEM/signing commands
  before execution and recover exact results across pre-pin crashes. The responder
  stores its admitted first contribution. Its encrypted inventory restores selected
  prekeys before authentication, exposes committed public leaves and consumes
  one-time tokens with the response outbox; pending references block retirement.
  Its own lockfile and public-byte/OpenSSL verifier remain separate.
  Protected signing files restore unfinished operations, and local write intents
  preserve exact sealed target bytes across state-write retries. A separate witness
  provider now signs fresh, command-bound receipts after real state/fence commits;
  signed required-anchor policy and journal admission/application/release gates now
  reconcile the exact command derived from each durable write intent. Restored
  client snapshots fail against a newer witness head; witness storage remains an
  independent trust boundary. Its [initial-epoch message layer](../../research/continuity-identity-candidate/MESSAGES.md)
  now transfers confirmed roots into directional chains and atomically commits
  immutable ciphertext outboxes or authenticated plaintext inboxes before release.
  Exact input reservations, bounded skipped keys and retained receipts support
  restart, reordering and duplicate reconciliation. Authenticated contiguous
  consumption acknowledgements now bound outstanding records while monotonic
  sequence IDs prevent retired requests from becoming new sends. Its installed
  [account roster heads](../../research/continuity-identity-candidate/ROSTER_AUTHORITY.md)
  now fence bootstrap, prekey, message and cached-output authority across restarts,
  preserving observed device-generation history through exact write-intent recovery.
  Its [identity-signed hybrid rekey](../../research/continuity-identity-candidate/REKEY_OFFERS.md)
  now commits offer, response, final and receipt flights, installs fresh traffic
  and ACK epochs and preserves exact output across restart. The current v6 profile retires
  a settled prefix only after both peers' signed assertions, keeping at most four
  traffic epochs without resetting their identities. Unconsumed inboxes and
  unacknowledged outboxes cause backpressure unless the application explicitly
  records and acknowledges an immutable [closed-epoch resolution](../../research/continuity-identity-candidate/EPOCH_RESOLUTION.md).
  Such unresolved sends remain `DeliveryUnknown`; no successful delivery is
  invented. Its signed, nonzero [application-send budget](SEND_PROGRESS_V1.md)
  now bounds committed and reserved sends across the old/new epoch confirmation
  window. ACKs, restart and old-epoch resolution cannot refund that budget; exact
  previously admitted work remains recoverable. Continuous recovery analysis,
  matched comparisons and product control scheduling remain open. Its
  [independent control steps](../../research/continuity-identity-candidate/CONTROL_PROGRESS.md)
  now reserve signed requests for an idle proposer and resume one explicit target
  through the existing flight transactions. An optional
  [native TLS carrier](../../research/continuity-identity-candidate/CONTROL_TLS.md)
  now exchanges them over the standard SDK connection in separate same-host Rust
  processes, with finite retry/cancel/deadline semantics and restart after each
  committed reply is lost. This does not qualify installed bindings, bootstrap
  delivery or cross-host operation. A measured product budget, full device
  lifecycle, cryptographic erasure and product integration remain required work.
  Its [account-send candidate](../../research/continuity-identity-candidate/FANOUT.md)
  now derives the complete recipient set from the installed signed roster. One
  device journal reserves all required inputs and commits all pairwise chain/outbox
  changes before releasing any member. A required witness covers that same whole
  image. Its current v20 format preserves batch ownership and monotonic IDs across crashes;
  per-recipient ACK and unknown-delivery accounting remain distinct. This does not
  provide atomic remote application execution or a distributed transaction among
  independently owned sending-device journals.
  Its [reserved-session abandonment](../../research/continuity-identity-candidate/FANOUT_ABANDONMENT.md)
  now freezes all member sessions, requires durable loss accounting, and replaces
  private state with terminal source/session records without resetting IDs.
  Its optional [native connection carrier](../../research/continuity-identity-candidate/CONNECTION_TLS.md)
  now carries the inventory-backed bootstrap and real application traffic over the
  same standard TLS engine. A complete process trace performs three network rekeys
  and confirms application consumption with independent disk readback in both
  directions. Installed bindings, independent implementations/cross-host/device
  qualification and the remaining product protocol requirements stay open.
  A [portable bootstrap-material input](../../research/continuity-identity-candidate/BOOTSTRAP_BUNDLE.md)
  now reconstructs contexts through the existing public verifiers while keeping
  policy/runtime owners, account pins, exact intended devices and requested modes
  independent of received bytes. A Python producer exercises the actual Rust
  consumer, and native endpoint processes reverify saved bundles. This closes a
  serialization/admission prerequisite, not the installed binding requirement.

The native [independent-session lifecycle](../../research/continuity-identity-candidate/SESSION_CLOSURE.md)
now freezes ordinary sessions and incomplete rekeys, retains complete metadata for
host loss accounting, and commits keyless terminal state without refunding any
slot. Committed fanout members retain separate ACK/unknown outcomes; a reserved
aggregate cannot be split by this API. It shares journal v20 accounting/terminal
codecs with batch abandonment. This closes the local established-session terminal
path, not device replacement, initial bootstrap cancellation, whole-account
coordination or installed binding integration. A QPCSCA01 cleanup archive can now
be persisted before activation and reopened without an operational context through
the restricted SessionClosureJournal. Existing or sealed session admission, original
owner/context and required witness remain mandatory. Expired witness enrollment and installed-language service integration still need
explicit lifecycle integration; no fresh permission is reconstructed from stale data.

The native QPCNET01 [archive index](../../research/continuity-identity-candidate/SESSION_ARCHIVE_STORE.md)
now persists exact cleanup scope before both endpoint activations. Archive failure,
cancellation and deadline crossings cannot be relabeled as a completed connection;
data paths require the retained authenticated archive. Full native execution includes
both terminal cleanup processes after three network rekeys and bidirectional actual
consumption. This closes a native service-persistence prerequisite, while published
bindings, catalogue restoration and device/root lifecycle remain open.

Native [permanent bootstrap cancellation](../../research/continuity-identity-candidate/BOOTSTRAP_CANCELLATION.md)
now removes private pre-activation plans while retaining their original operation,
context and one-time claims. Its cleanup-only restart owner does not need live
verified policy/device/context objects. Cancellation cannot recall peer messages
or refund a claimed key, and established application sessions require session closure.

Native [archived whole-batch abandonment](../../research/continuity-identity-candidate/FANOUT_ABANDONMENT.md#archived-whole-batch-cleanup)
loads complete membership from the authenticated journal and verifies every original
session archive before recovery or mutation. After explicit host loss accounting,
it closes every reserved member and can retire that abandoned batch's metadata,
while all terminal sessions, sources/claims and the monotonic ID remain. It cannot
split the set, cancel a committed batch or bypass the original witness. Fresh
required-witness evidence also gates absence/retirement dispositions. This closes
native archival cleanup of reserved fanout; ordinary committed-history retirement,
index/restore UX, witness renewal and installed-language integration retain their
separate requirements. These native additions do not close the broader completion
table below; candidate storage is v21 with no implicit migration from old formats.

The native archive index now adds bounded discovery and exact restoration through
an existing `SessionClosureJournal`, without reconstructing expired operational
context objects. Explicit index retirement requires the original protected
`Closed(report)` state and independently retained host report ID. Fresh original
witness checks still precede every present or absent disposition; journal
tombstones, claims, budgets and capacity remain unchanged. This supplies a native
catalogue API, not an installed recovery flow or permission to initialize a new
device lineage. Aggregate history and service/device lifecycle integration remain
required within 0.2.0.

The native [installation owner](../../research/continuity-identity-candidate/INSTALLATION.md)
now retains the journal identity and exact original key/device/policy/path bindings
in separate trusted configuration before creating children. It distinguishes
Creating from Active, commits Active before releasing the existing journal/index
engines, and holds the configuration lease for their service lifetime. Missing
active files are refused, never interpreted as first install. Required-witness
preparation returns the original enrollment metadata; activation and restart keep
fresh witness admission/release. This implements a native initialization boundary,
not published bindings, policy/credential renewal, global lineage uniqueness or
rollback protection for the independent trusted configuration.

Native installation recovery now admits only the original Active configuration,
key/path binding and existing catalogue after operational policy or credentials
are unavailable. Selecting a session authenticates its original archive and opens
only the restricted closure journal under unchanged witness requirements. It
retains installation/index/journal ownership across explicit host loss accounting,
terminal acknowledgement and catalogue retirement. No operational context or
permission is reconstructed. This closes the native installed-state cleanup entry;
foreign adapters, witness/credential renewal and product packaging remain required.

The separate [installed Rust candidate gate](../../research/continuity-identity-candidate/PACKAGE_CONSUMER.md)
now builds a real Cargo archive and consumes it with nine exact SDK archives outside
the checkout. The existing public multi-process connection/recovery trace executes
in both Debug and Release, including unknown-delivery reconciliation, network
rekey, reverse application bytes and cleanup after durable revocation. Package
origins, locked external dependencies, executable identities and independent file
readback are checked. The candidate remains unpublished at 0.0.0; this closes a
Rust archive-consumption boundary, not the product protocol freeze or the foreign
language adapters. Same-run Linux CI and the remaining platform gates require
their own completed results.

## Required completion evidence

| Capability | Implementation obligation | Evidence required before completion |
| --- | --- | --- |
| Protocol and identity | Separate Continuity identifier, wire version, closed cryptographic profile, authenticated account/device identity and canonical context | Complete protocol/wire/state specifications, strict parsing and independent vectors; authentication, replay, cross-device and downgrade analysis |
| Persistent pairwise sessions | Owned secret state, one-use message keys, bounded skipped keys, atomic state/inbox/outbox transitions and exact-operation reconciliation | Real encrypted storage, crash injection at each durability/release boundary, restart/duplicate/race/cancellation tests and no plaintext release before commit |
| Fresh-PQ rekeying | Fresh post-quantum material introduced and confirmed according to the selected protocol, with a non-negotiable policy floor | Wire/state traces for both roles; update collisions, lost acknowledgements, old-epoch traffic, revoked peers, expiry, overflow and unknown outcomes |
| Disconnect and rollback recovery | Exact committed outbox replay, retained deduplication, suspended uncertain operations and an explicit trusted rollback-anchor contract | Real multi-process restart and restored-snapshot tests; an old snapshot cannot silently reset message-key or nonce state within the claimed anchor profile |
| Continuous PQ recovery | A construction-specific recovery condition under explicit compromise, authentication and delivery assumptions | Protocol analysis and adversarial compromise traces, implementation correspondence and matched reference comparisons; elapsed time or a symmetric key update cannot substitute |
| Multi-device lifecycle | Independent device identities/sessions, enrollment, fresh signed roster, revocation, device replacement and account-wide fanout transactions | Multi-device process tests covering roster races, partial external-anchor progress, duplicate delivery, stale devices, equivocation and required-recipient failures |
| Cross-language and package integration | Shared protocol implementation behind owned Rust/C/Swift/Kotlin/Android/WASM interfaces and actual package consumers | Canonical vectors, the same failure/close/cancel semantics, installed cross-language connections and current/minimum platform execution |
| Performance and final release | Measured session lifecycle, durable latency, recovery, bandwidth, memory, concurrency and energy under the same security contract | Source/binary-bound baselines and results, quality/maintainability review, final exact-source checks, signed distributions where required and the release transaction |

## Dependency and authority boundaries

The cryptographic composition crate remains dependency-free. Account, ratchet,
network and persistence logic belongs above its existing primitive contracts.
The research/reference lane remains separate from the product implementation;
production code cannot acquire authority by depending on a test-model receipt.

One repository transaction must cover each affected session revision, consumed
prekey/deduplication record, inbox release and immutable outbox. Unknown commit
results close the operation to new work until the exact operation is reconciled.
External anchors require their own durable intent and reconciliation; local
database atomicity alone cannot prove that a wholly restored snapshot is fresh.

Ordinary application sends must not release candidate ciphertext before commit.
Receives must not release candidate plaintext or advance an unrelated session on
failure. Multi-device fanout commits all required recipients together before any
item becomes dispatchable. Explicit exclusions must be observable to the caller.

The current ABI 2 functions retain their meanings and ownership contracts.
Continuity must not be smuggled into an existing protocol/group identifier or a
serialized policy-decision blob. Any additive binding surface requires a precise
versioned contract and matching export/registration checks before qualification.

## Implementation sequence within 0.2.0

1. Complete `PROTOCOL_V1.md`, `WIRE_V1.md`, `STATE_MACHINE_V1.md`,
   `STORAGE_RECOVERY_V1.md`, `METADATA_PRIVACY_V1.md`, `BUDGETS_V1.json` and
   `SPEC_LOCK.json`. Resolve authentication semantics, bootstrap/confirmation
   permissions, ratchet selection, rollback-anchor profile and resource bounds
   before presenting the protocol as frozen.
2. Implement and test authenticated pairwise establishment, message protection
   and real transactional persistence with owned secrets and explicit failures.
3. Implement fresh-PQ transitions, continuous recovery, disconnect reconciliation
   and revocation, keeping the protocol and storage models aligned with the code.
4. Add account/device lifecycle and atomic fanout, then integrate the shared
   service into every supported language and installed-package path.
5. Complete the reference comparisons, model-to-implementation checks, current
   device/network matrix, performance measurements and final release audit.

Every step belongs to 0.2.0; completing an intermediate component does not close
the full release goal. Research hypotheses about superiority remain hypotheses
until their specific proof or experiment supports the claim.
