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
the required-witness transaction has not yet been connected.

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
Required-witness policy continuation is explicitly refused: an ordinary head
query cannot substitute for independent exact-T adoption.

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
continuation is refused without a fallback. Ordinary P0 and fresh-bootstrap
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

After losing a cached view, the live-session reopen API cannot mint a new view
for an already closed fanout member; aggregate-specific recovery is still needed.
Peer credential renewal after P0 expiry, exact-T required-witness authority,
policy-only transitions, remaining lifecycle paths and installed foreign
consumers remain integration and verification work.
