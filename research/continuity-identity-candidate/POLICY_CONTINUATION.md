# Joint policy continuation candidate

Status: signatures, retained records, original-enrollment Pending, local-only
joint commit/reconciliation, retained-session P1 admission and continued enrolled
owner release are implemented in this isolated native candidate. It has not been promoted to the product or
qualified for release. The original release goal still includes policy-only
renewal, witness renewal, identity replacement and the complete recovery path.

`qperiapt-policy-continuation/1` uses signing purpose 16, separately from
credential renewal (15). Both the account root and the policy root approve the
same canonical `QPPCTN01` body. `QPPCTB01` contains the two exact signed envelopes.
Approvals cannot choose their verification roots, independent current pins,
original journal or expected predecessor. The verified inputs are supplied by
the host. Issuers must independently authenticate user approval and serialize
their current authority; producing a signature does not perform these duties.

The body binds the original credential operation, journal, immutable storage
owner, original and predecessor credential commitments, complete credential-grant
statement, target credential and account-authority binding, policy family,
predecessor roster, original P0 checkpoint, prior adopted policy checkpoint,
target policy checkpoint and exact prior policy authorization. Its only
permission byte is retained established sessions. A missing prior authorization
is canonical only when the predecessor is exactly original P0. Later transitions
must name a nonzero prior statement and a later predecessor policy version.

`PolicyContinuationStatement::new` verifies the input relationship before either
issuer signs. P0 and the predecessor can be expired historical metadata. The
target must have a real current runtime owner and current target credential and
roster. The original policy family/root, SDK binding, prekey modes, witness
requirement, application-send budget and interval start must remain identical;
the target version and interval end must increase. This construction currently
couples a credential validity extension to a policy validity extension. It does
not silently implement a policy-only update by changing a roster version.

`VerifiedPolicyContinuation` is a verified relation, not an operational owner or
a commit receipt. Its stable statement digest differs from the credential-only
grant. Two independently approved target policies for the same credential
operation have different joint statements; mixed issuer approvals are rejected.
Current verification rechecks target policy/runtime closure and time. Exact
original envelope bytes are retained even though signatures may be randomized.

`HistoricalPolicyContinuation` carries no runtime or current-time permission.
The roster record's new `QPRHST04` encoding preserves it separately from both
the latest credential grant and `LocalRenewalCommit`. It contains a checked
optional receipt plus the policy public key and original joint approval bytes.
On decoding, the authenticated roster supplies the account root and policy
family; the stored policy key must match that exact family, be independent of
the account key, and verify the second signature. This historical decode does
not verify a current P1 owner or authorize a new operation. Legacy roster
records decode with no policy continuation and cannot themselves imply one.
Whole-image validation and roster reads also bind T to the exact journal,
original storage owner and local account. Required-witness protection, any local
receipt and matching original-owner credential grants must agree on P0. A valid
same-root approval for another journal cannot be grafted into this one. A local
image header alone does not contain P0; installation admission must still check it.

The existing ordinary roster and credential update code preserves this field,
including after revocation and receipt removal. Encoding a retained T never
falls back to an earlier record tag merely because its receipt was cleared.
The original record-codec tests directly set T into fixtures. The enrollment
coordinator now also writes T through a real authorized local journal transaction;
the isolated required-witness follow-on below now also prepares the actual sealed target.

`DeviceEnrollment::stage_policy_continuation` reuses the original enrollment
lease, signer and credential intent path. Its new `QPENST06` configuration stores
the complete original T with G in the first Pending write; legacy tags keep their
original grammar. It checks original journal/owner/P0, target P1 and G, the policy
predecessor CAS, live successor admission and the existing time floor. Exact
historical retries preserve the bytes after expiry and return metadata only.
The Pending statement is T's digest. An already pending credential-only operation
cannot acquire T, and the same G/operation cannot replace T with another valid
target. Authenticated saved bytes must agree with the original Pending header.
Six focused tests exercise real configuration storage, expiry, exact retries,
grafting/substitution and all six sides of three synchronization barriers. The
73-test enrollment group, strict all-target Clippy and three doc tests pass.

`reconcile_policy_continuation` returns historical status only. It reuses the
credential-only activation coordinator's journal commit, configuration completion
readback and receipt ACK order. The original historical P0 authenticates the
same installation paths/key, owner, journal and protection; no old current policy
owner is reconstructed. P1 supplies current permission for a new mutation.
`LocalRenewalTarget` binds a joint receipt to T and G, and one journal transaction
commits the successor roster/credential, independent T and receipt after both
predecessor comparisons. An exact retained receipt additionally requires the
same full T bytes and can finish historical configuration recovery after expiry.
Without that receipt, expired/closed P1 cannot create a new commit.

Configuration completion retains adopted T atomically with the new credential
and receipt, then checks exact durable readback before journal ACK. Subsequent
credential-only commits preserve T in both stores. A later joint target must
name that T and its target policy, even if another credential grant intervened.
This local-only reconciliation entry explicitly refuses required-witness policy
continuation. The separate witness transaction below binds exact G/T adoption;
an ordinary head query cannot substitute for that protocol.

Targeted evidence includes six configuration completion synchronization cuts,
six initial intent cuts, sixteen journal commit/ACK cuts, three real process
kills at the shared commit boundaries, and two chained process kills with T1
completed but unacknowledged before T2 starts. The recovered state retains the
original approvals, signer, owner and journal. Tests distinguish P1 expiry from
a still-live C1. A read-only redb reopen can change file bookkeeping, so absence
of a protocol mutation is checked against the authenticated journal identity,
owner, revision and image digest, not whole database file byte equality.

`DeviceService::reopen_continued_peer` and
`DeviceInstallation::reopen_continued_session` admit an authenticated original
bundle only for its exact established live message session. They require an
independently verified current P1, the journal's exact completed T, no outstanding
local completion receipt, the original owner/session/role, the retained archive
and both current identities and rosters. Historical P0 authenticates the original
installation; it is never turned into a current policy runtime. Required-witness
continuation now has the separate carrier admission path below. Ordinary P0 and fresh-bootstrap
entry points still refuse an adopted T even at a previously valid P0 time.

The admitted context retains the original P0 transcript, storage owner and archive
commitments, and caches the exact T statement and actual P1 runtime separately.
Message, rekey and fanout admission compares that cache with the owning journal's
current T and current credential grants before releasing outputs. A new T2
invalidates cached T1 even while P1 is still live. Closing P1 also denies output.
Original message budgets, epochs, counters, reserved rekey material and operation
identities remain intact; reopening does not reserve replacement randomness.

New fanout selection uses the current credential identities. Committed fanout
replay separately authenticates every actual member record and current authority,
including terminal members, and keeps the complete current roster check. A
closing or closed member returns its existing terminal outcome while a live
member retains its exact original ciphertext. Metadata-only closure and archive
cleanup remain usable with the original historical credential after expiry and
revocation; they do not release ciphertext or revive a session. Their immutable
batch binding includes its originally selected credential, roster and message IDs.

The added component regressions cover both session roles after genuine P0/C0
expiry, exact cached ciphertext recovery and peer decryption, new traffic,
restart, wrong session/role/P1 rejection, unacknowledged receipt rejection,
T2 invalidation, preserved reserved rekey bytes, two-member fanout with each
possible stale member, terminal outcomes, runtime closure and metadata cleanup.
Their setup explicitly supplies the internal journal commit and ACK; it does not
claim to exercise public enrollment and signer release end to end.

`DeviceEnrollment::activate_continued_session` consumes the original enrollment
lease and reuses the same service returned by joint reconciliation. It returns
the existing `EnrolledDevice` together with a `ReopenedPeer` for the caller's
exact retained live session. The original P0 and C0 bind storage and signer
identity; configuration adopted T must match the journal, the current credential
must agree with the journal-resolved identity, and session/role/archive, both
current memberships and the actual P1 runtime are rechecked. The original signer
is opened with creation disabled and checked against that current credential
before ownership is returned. Ordinary `activate` still refuses adopted T.

This entry can finish the already authorized renewal before discovering that
the selected session or archive is unavailable. Such an error returns no owner
but can leave the exact renewal committed; callers reopen and query the original
enrollment status. No new identity or session is substituted. Metadata-only
`reconcile_policy_continuation` remains available after expiry, while owner release
requires current permission. A later credential-only G2 can keep T1: completion
and current credential are checked separately from the adopted policy statement.

A public-flow regression uses real enrollment on both ends, actual owned prekey
inventory, original bundle and session archives, public staging/reconciliation,
then closes and reopens the original owners after P0/C0 expiry. It recovers and
decrypts the old ciphertext, sends new traffic in both directions and completes
one rekey using the borrowed original signers. It also checks lease exclusion,
restart, wrong request/target, post-commit session refusal, P1 expiry/closure,
G2 with retained T1, authenticated old-configuration rollback and observed local
revocation. It calls no internal renewal commit or receipt-ACK helper. This is
native in-process evidence, not an installed foreign-language or independent
implementation result.

`DeviceEnrollment::activate_policy_continuation` also admits the original local
owner without first requiring current peer credentials. It checks the same
configuration completion, exact durable T, cleared receipt, current local G and
membership, and the independently supplied current P1. This breaks the restart
cycle when both endpoints' P0/C0 have expired and neither has received peer G.
The caller then uses `DeviceService::admit_peer_credential_renewal` and reopens
the original session. `activate_continued_session` composes these same operations.

The saved admission remains the exact G completion receipt. Its old signed
roster may expire after the journal accepts a newer roster. On restart, the
configuration authenticates the retained credential and original signer as
history; journal G/T and the current roster decide current authorization. The
returned device carries that current roster, checkpoint and authority binding.
An expired current roster or an observed local revocation still refuses owner
release without rewriting the configuration, signer or journal. A public-owner
regression reproduces the former `Validity` failure and checks both refusals.

Peer G remains bound to original P0; P1 supplies current permission. The service
retains only signed historical P0 metadata alongside its original authority and
local identity. Every peer mutation and exact retry rechecks journal T/G, receipt
completion, current local membership and current P1, without treating those
retained metadata as permission. Local identity selects the local grant even when
another device belongs to the same account. T2 rejects a still-live P1. Observed
peer revocation cannot be undone by retrying the old peer grant.

A valid same-account peer successor roster may also revoke the local device.
The SDK durably records that authenticated authority change, then withholds
success if local admission is gone. It does not silently discard the observed
revocation. Such a post-commit error is not evidence of NoCommit. Component
regressions cover the preserved T, exact peer retry, unacknowledged local receipt,
local and peer revocation, and all twelve before/after faults at six measured peer
journal sync barriers. The public-flow regression now also begins with both
expired peers and no installed peer grants, then completes communication/rekey.

After losing a cached view, the live-session reopen API cannot mint a new view
for an already closed fanout member; aggregate-specific recovery is still needed.
Complete exact-T required-witness qualification, policy-only transitions, remaining lifecycle
paths and installed foreign
consumers remain integration and verification work.

## Required-witness integration under development

The isolated follow-on connects witness storage to sealed journal transactions,
enrollment completion and operational owner/session admission. Complete
qualification remains open.
`QPCRNP01` credential-only proposals remain 296 bytes. `QPCRNP02`
proposals are 329 bytes and bind G, a separate T statement and an explicit
adopt/carry mode. Adoption completes the T statement; a later G-only transition
completes G while carrying the current T. Both modes participate in the full
proposal/command binding and cannot alias each other during recovery.

`QPANC006` retains current G and policy authority separately from the transaction
and ACK slot. Policy authority includes the exact T statement, P1 checkpoint
and independent P1 validity. A separate policy-version floor survives Closed
and ACK. Closing T2 preserves actual T1 but retires the attempted versions; a
distinct higher-version G can continue under T1, while a fresh G cannot reuse
the retired policy version. Earlier `QPANC001`–`004` state decodes with explicit
absence of T. The isolated experimental `QPANC005` format is not reinterpreted
as this format.

Fresh opcode 10 admission binds current account authority, G and T in the
existing 97-byte command width. Account-only admission refuses after T adoption.
Roster refresh requires the actually adopted P1 and preserves its validity;
using a still-live P0 cannot rewrite it. Ordinary G/P0 entry points cannot
prepare a proposal that claims unverified policy adoption.

Component tests use real enrolled witness storage, actual dual approvals and
fresh signed replies. Their target heads are explicit opaque expectations:
they do not prove that a sealed journal target contains the same G/T. They cover
G1/T1, later G2, ACK, restart, ordinary advance, closed T2, retained T1, separate
version floors and refusal after P1 expiry while the credential remains live.
These store tests remain distinct from the sealed-target tests described below.

`QPWINT04` binds G, T and adopt/carry mode in the authenticated write intent.
Its target is the original ciphertext containing the exact new credential,
independently retained T and typed completion receipt. Semantic decoding checks
the actual decrypted target against all three intent fields. Legacy
`QPWINT01` ordinary writes and `QPWINT02` G-only writes keep their grammar;
`QPWINT03` remains target-free cancellation. An old G-only intent cannot
silently carry a T-bearing target. Ordinary Advance/reconcile cannot apply any
credential-renewal intent, and direct local commit still refuses required T.

`prepare_witnessed_policy_continuation` uses historical original P0 only for
installation identity and independently current P1 for new target admission.
It returns metadata for independent witness approval. The new
`commit_witnessed_policy_continuation` entry requires the exact retained
proposal. Existing historical reconciliation/close use its
`transaction_statement()`: T for adoption, G for a later credential-only carry.
Neither operation releases an owner. Historical cancellation and independent
closure now use the separate paths described below.

`QPENST07` configuration identifies the 329-byte coordinated proposal, while
old configuration tags retain their original 296-byte proposal grammar.
Completion atomically retains the adopted T and full typed receipt before
independent durable readback and ACK. Closing an uncommitted T does not adopt it.
Historical recovery uses the original ciphertext, never a newly sealed target.
After expiry or runtime closure it can complete a previously Applied operation,
but cannot initiate a new Commit or infer NoCommit from Unavailable.

A reproduced counterexample substituted another genuinely signed T in a durable
Applied configuration after completion but before ACK. The previous recovery
branch returned Committed and sent ACK for the old proposal without detecting
the inconsistent adopted T. Recovery now rechecks the adopted T at independent
terminal readback, then compares the full configuration completion receipt and
adopted T against the actual journal before ACK. The same journal comparison
applies when Closed must retain the predecessor T, and when a prior retirement
already removed the pending intent. It does not compare Closed against its
rejected target T.

New regressions exercise G1/T1 followed by G2 retaining T1 through real sealed
targets and ACK; completion synchronization failures on both sides of a barrier,
then P1 expiry and lost ACK; lost Commit/Status/ACK replies; exact uncommitted
closure; authenticated alternate-T/mode/format substitution; and the reproduced
Applied-terminal substitution for both adoption and carry. They check original
ciphertext bytes, command traces and retained configuration, not only status.
These are native component tests. T-specific process kills, complete fault
sweeps, old-binary migration, foreign bindings and installed/platform/security
qualification remain open.

## Required-witness operational admission under qualification

`activate_witnessed_policy_continuation` restores the original enrolled signer
and owning service only when configuration has no Pending or unacknowledged
coordination, the complete configuration receipt/T matches the actual journal,
and a fresh opcode 10 reply admits its current G/T and current roster authority.
It never implicitly commits a staged renewal. P0 remains immutable signed
installation history; P1 must be independently current before and after the
network check. Local-only receipt pruning and required-witness retained
completion remain separate: an outstanding local receipt suspends local
continuation, whereas required protection verifies its exact retained typed
receipt and the witness rejects operational admission until ACK clears its slot.

The owning service can then admit peer grants under current P1 and reopen the
original archived sessions. Standalone installation reopen also accepts
the original required witness carrier. Original-policy and fresh-bootstrap
entry points retain their refusal of an adopted continuation.

`check_operational_release` derives current G/T from authenticated journal
authority, refreshes the current local credential against the installed roster,
and checks the fresh signed reply's head and outcome. Normal message and rekey
outputs use the shared session release check. Fanout has its own final check
because committed replay permits terminal members whose live ratchets may have
been retired. It checks the full batch and every member, obtains fresh G/T
admission, then rechecks all member authority after the network callback. Generic
head queries remain available for historical progress and metadata-only cleanup.

A controlled negative variant removed only the final fanout G/T check. With
the same head and a still-live credential, a stale-time client received one
cached member even though the witness's P1 had expired. Restoring that check
produces AuthorityDenied without releasing ciphertext. The integration test
uses two real enrollments sharing an independent witness, original owned
prekeys and an actual handshake/archive. It covers P0 expiry, both continued
owners, original ciphertext and peer decryption, bidirectional P1 traffic,
rekey through epoch 1, installation reopen, cached message/fanout refusal, and
P1 closure in the callback after a signed admission reply.

A separate required-witness test enrolls two real recipient devices under one
complete account roster and establishes both original sessions. The sender
completes G1/T1 and then G2/T2 through the actual enrollment coordinator and
independent witness. Its original two-member batch survives the transition with
identical ciphertext. Closing one session moves that member through
ResolutionPending to DeliveryUnknown while the other stays Committed. Two
owning-service reopen cycles preserve those exact results and obtain fresh
opcode 10 admission. The remaining recipient independently admits G1 and G2,
restores its original context with the current peer credential, and decrypts the
original retained ciphertext. The test does not change product paths. Mixed
stale/current member refusal and request-loss sweeps under required T2 remain
separate controls; the corresponding local-only tests do not cover that boundary.

## Historical G/T cancellation and independent close

A staged joint renewal can outlive P1 before any sealed proposal is prepared.
The original enrollment can now reserve its exact target-free cancellation
without generating ciphertext, admitting a runtime or sending a witness command.
`HistoricalPolicyContinuationMaterials` and
`HistoricalPolicyContinuation::from_bytes` authenticate the complete original
approval against independent historical P0/predecessor/target pins and G. They
verify the same profile and scope relationships and both signatures, but grant
no current permission. Live verification still independently checks the real
runtime and current policy/device validity.

`QPCRNC02` is 281 bytes: the original G cancellation metadata plus explicit
adopt/carry mode and T. Its complete binding is used by Status and ACK.
`QPWINT05` retains those bytes in a 353-byte authenticated target-free intent.
Legacy `QPCRNC01` and `QPWINT03` remain 248 and 320 bytes respectively and
cannot infer T from surrounding state. `QPENST08` identifies a coordinated
policy cancellation using tag 4; older configuration grammars cannot contain it.

The independent witness's `close_unprepared_policy_continuation` verifies
historical joint approvals and both exact predecessors, then atomically consumes
the credential and policy version floors while retaining the current G/T,
owner, authority, validity and head. Explicit G-only carry cancellation uses
`close_unprepared_continued_credential_renewal`; it consumes only the credential
version and preserves an already higher policy floor. New `QPANC007` tag 8
retains the policy cancellation and exact target metadata. After ACK the normal
006 encoding retains a nonzero policy floor even if no T has ever been adopted.
The original G-only entry and its legacy tag 4 refuse a current adopted T.
A controlled regression restoring the old behavior reproduced an implicit T1
carry returning Closed; the corrected path rejects it.

An existing sealed proposal cannot be replaced by a target-free cancellation.
If the proposal exists but independent preparation did not finish before
expiry, `close_policy_continuation` authenticates the original historical
materials and closes that exact sealed proposal. It also closes an existing
Prepared record; an Applied record remains Applied. The corresponding carry
entry retains the actual current T. Original target bytes are never resealed.

Closed configuration preserves the previous adopted T and complete completion
receipt. Independent terminal readback and journal comparison still precede
ACK. Unknown Status/ACK replies retain the original intent; Unavailable without
an existing durable terminal remains Pending. Native tests cover real expired
Pending, both sides of lost Status/ACK, witness restart, alternate T/mode and
legacy-format rejection, conflict with a sealed proposal, pre/post-Prepared and
Applied closure, and T2-close followed by carry-close without floor rewind.
Fourteen injected configuration faults span both sides of all three reservation
and four terminal/retirement synchronization barriers. New T-specific process
kills, journal/witness fault sweeps, migration and foreign installed exposure
remain separate qualification work.

## Local completion with historical target policy

`recover_historical_policy_continuation` takes the exact original operation and
transaction statement plus independently signature-verified historical P0/P1.
It reuses the original enrollment coordinator and can finish an existing exact
journal receipt after every current runtime has closed and P1 has expired. The
read-only receipt inspection validates the full G/T target before configuration
completion and original receipt ACK. It never creates a new target or releases
an operating service. A Pending target without its matching receipt returns
Suspended and remains unchanged; this is not an abandonment or NoCommit fact.
Required-witness protection retains its separate recovery protocol.

The private coordinator distinguishes current permission from historical
metadata in its input type. Existing current calls retain their live admission
before new journal writes. Native tests cover six real process interruptions
(journal, configuration completion and receipt acknowledgement, for both joint
G1/T1 and credential-only G2 carrying T1), followed by repeated history-only
recovery with closed runtimes. A separate original-Pending case stays unchanged
both before and after P1 expiry. Uncommitted local policy abandonment, foreign
runtime-expiry controls and the broader release gates remain separate work.
