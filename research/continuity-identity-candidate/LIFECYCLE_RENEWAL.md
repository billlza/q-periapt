# Joint credential and policy continuation: construction boundary

Status: **experimental authorization construction; no policy-renewal operation is
implemented**. This does not change the 0.2.0 release scope. Policy and witness
renewal, device replacement and independently authorized root replacement remain
required lifecycle work. The first construction below keeps the same account
root, policy root, complete device key/generation, journal and witness. It extends
validity only; later identity/key changes need their own explicit authorization.

## Why the existing two renewal operations cannot be composed sequentially

The account root can authenticate an expired predecessor credential C0 and a
currently valid successor C1 under an independently current roster pin. However,
credential-renewal admission and commit still require the original exact policy
P0 to be current. A newly signed P1 changes the policy digest even if only its
expiry differs. Enrollment, installation, journal and witness correctly refuse
substitution. If C0 and P0 both expire, requiring one to remain current while
renewing the other creates a cycle.

Historical verification authenticates the old identity; it cannot authorize new
traffic, a new commit, or revive membership removed by a current roster. The
solution must introduce a jointly authorized transition rather than extend P0's
validity in memory, change a checkpoint getter, or remove an exact-digest check.

Relevant implementation boundaries:

- `identity/renewal.rs`: current independently pinned account authorization can
  identify an expired predecessor without treating it as current membership.
- `enrollment/renewal.rs`, `installation.rs`, `durable/rosters/local_renewal.rs`:
  original policy, owner, operation and predecessor are durable scope checks.
- `anchor/store/renewal.rs`: independent witness preparation and exact joint
  head/credential commit, with separate historical cleanup.
- `bootstrap/retained.rs`: an established-session authority view preserves the
  original transcript and cannot be used as a fresh bootstrap context.

## Isolated authorization experiment

The experiment uses the candidate's actual ML-DSA-65 plus P-256 signatures and an
actual enabled SDK runtime. C0/P0 end at trusted time 160; C1/P1 are verified at
170. These are explicit synthetic clock inputs, not a real-time expiration test.

Both the account root and policy root sign **one identical canonical statement**:

```
experimental domain and retained-established permission
original operation and journal identity
original storage owner and original credential commitment
exact credential-renewal statement commitment
current account/roster authority commitment
exact predecessor P0 checkpoint and target P1 checkpoint
```

The credential statement transitively binds the full device key/generation,
original/predecessor/successor credentials, exact predecessor/target rosters and
original policy. Verification additionally matches the protected local expected
predecessor. Keys, pins, expected state and current time are independent inputs;
none is selected by incoming wire bytes. The target retains the SDK binding,
modes, witness binding and application-send budget. A higher policy version and
strict validity extension are required for this experiment.

The probe adds signature purpose 16 **only to an isolated source copy**. It is an
experimental domain, not an allocated product protocol or ABI change. Its result
is a statement digest with no conversion to an operational owner or policy.

Observed: two independently approved targets verify; 27 prohibited cases refuse,
including missing approval, A/B signature splicing, mismatched original scope,
current-pin revocation, invalid time, foreign roots, cross-protocol signatures,
malformed envelopes, signed budget/witness changes and a closed SDK runtime.
Verification leaves the original installation without a staged renewal.

This establishes an authorization construction to investigate. It does not
establish durable renewal, retained-session traffic, concurrent cutover,
cross-language behavior, or a computational security proof.

## Counterexample to treating an opaque head as semantic approval

A second experiment uses the existing real journal and persistent AnchorStore:

1. Root grants A and B have distinct operations/statements but the same C1/R1,
   original owner, complete device key and P0.
2. Honest journal code prepares and seals target B. Its exact encrypted bytes
   remain pending.
3. A proposal retains B's target head but substitutes A's operation and statement.
   The public proposal decoder accepts the structurally valid metadata.
4. A device-signed Commit before independent preparation is unavailable. After
   the trusted control plane explicitly approves A with that opaque target, A's
   Commit is Applied; B's Commit/Status are unavailable.
5. Fresh `AdmitAuthority(C1/R1)` reports Current and exactly B's target head. This
   remains true after A is acknowledged and its transaction slot is pruned.
6. **Full honest B recovery still returns Suspended** before and after ACK. It
   does not release an owner or change the pending image bytes.

No hash collision, forged authority signature, expired-policy admission or TLS
bypass is involved. A caller chooses `H(image_B)` from the outset. The witness
does not receive the image and cannot inspect its meaning. The device signer
cannot invoke independent Prepare; the experiment explicitly includes that
control-plane approval. It calls the real store directly and does not claim a
network/TLS test.

This is not an existing complete recovery bypass. Current pending-state decoding
checks the embedded operation, statement, receipt and root grant; recovery asks
for the exact proposal's status. The permanent regression
`opaque_witness_target_never_replaces_the_exact_renewal_receipt` preserves those
refusals. Signed Unavailable means missing exact evidence, never proof of
non-commit.

For a future policy transition, two distinct continuation grants may authorize
different policies while sharing C1/R1. A hypothetical reopen check limited to
`exact head + account authority` cannot distinguish them. Ordinary witness head
advancement also does not inspect policy semantics.

Distinguish attacker capabilities: possession of an opaque `JournalKey` Rust
owner provides no public arbitrary-image seal API. Exposure of wrapping-key
bytes plus malicious local-file writes is stronger. Device signing capability
does not supply independent account/policy approvals or TLS credentials. The
construction must explicitly state which of these capabilities it covers.

## Required durable construction before implementation admission

The next prototype must preserve the immutable P0 session transcript and original
storage/witness subject while keeping **current operational authorization**
separate. It must not reset epochs, nonce/prekey allocation, rekey state,
send-budget consumption, pending operations or outboxes.

An independent witness authorization binding must distinguish the exact approved
continuation, including after ACK. It must survive ordinary head advancement and
roster updates, and be checked by a fresh authenticated release observation.
An authenticated target image plus an account-only authority hash is not a
substitute. Whether to use a separate witness field/operation or a versioned
authority projection remains a wire/state design decision, not a proven choice.

The joint transaction must compare the exact durable predecessor, retain the
original operation and sealed target before dispatch, and atomically commit its
head and current authorization. Unknown outcomes recover the same target and
operation. Once target authority expires, historical recovery can reconcile
approved bytes and terminal state only; it cannot issue new Commit, re-sign or
re-seal a target, or release a current owner. Competing transitions need one
winner and durable retirement; ACK must not erase the current authorization or
turn absence into non-commit.

Before adoption, demonstrate actual established-session traffic and unchanged
pending/outbox/budget state, current revocation refusal, same-head/different-grant
refusal, competing updates, crash/unknown-commit recovery, double expiry,
old-config reopen, cleanup after target expiry, and installed foreign consumers.
Local-only success cannot qualify the independently witnessed profile. Existing
ordinary bootstrap and direct policy substitution must remain refused.

## Persistent exact-authority experiment

A follow-on isolated source copy implements a candidate persistence mechanism;
none of these runtime changes is yet admitted to the product source. It keeps
the ordinary account authority unchanged and adds an optional exact Applied
renewal statement to the independent witness entry. An experimental schema
`QPANC005` persists that field after ACK. A new experimental opcode 9 checks
account authority, statement and live validity together and signs the head from
that same store observation. An opcode or schema number in this experiment is
not an allocated compatibility promise.

The initial query-only variant passed 46 witness tests, including two new
mechanism/wire tests. Its native owner-release variant also derives the expected
statement from the authenticated journal's local credential grant. Once the
witness has adopted the exact mode, old account-only opcode 4 refuses instead of
providing a downgrade path. Original owners with no adopted renewal retain their
original admission path. The actual A/B sealed-target regression checks that A
is Current and B Denied at exactly the same head, both before and after ACK; full
B recovery remains Suspended with unchanged pending bytes.

The experiment observes these distinct properties:

- Discarding a Commit reply and reopening the original store preserves the
  Applied statement; it does not depend on a successful client return.
- ACK, later Closed/ACK, ordinary Advance/Fence and a same-credential roster
  refresh preserve that statement. Only another Applied transition replaces it.
- A roster change with an unchanged head denies the old account binding even
  when the statement still matches; a wrong statement under the new account is
  also denied.
- Second Apply replaces the old statement atomically; expiry refuses current
  use without erasing historical identity. The legacy authority-only mutation
  remains prohibited once the joint-renewal floor exists.
- Canonical command width is still 97 bytes. All 97 shorter prefixes, trailing
  bytes, nonzero padding and zero fields refuse; an old-opcode reply or a reply
  from a different fresh attempt cannot satisfy the new command.

The owner-release variant passed 46 witness tests, the 22 real native
enrollment/witness recovery and cancellation tests, and strict all-target Clippy.
These include the actual
sealed-target A/B case, repeated renewal, persistence faults, real child-process
loss and cleanup after expiry. They do not establish installed-package behavior
or complete policy continuation.

Two limitations prevent treating this mechanism as the final construction.
First, its statement is the **credential-renewal** statement: a future policy
continuation must preserve its own exact scope, predecessor and validity bound
across a credential-only renewal. Replacing it with whichever transaction last
ran would lose policy authorization. Second, legacy witness formats can lack
the exact statement after ACK. Decoding them as absent is explicit; neither
floor nor ACK can reconstruct the missing grant. Refusing a resumed owner whose
exact witness binding is unavailable is safe failure, not a completed upgrade
path. Independent renewed authorization and original-state recovery still need
an actual old-to-new execution test before admission.

The prototype does not renew P0, extend any policy lifetime, change a session
transcript, or migrate legacy stores. The next durable construction must carry
the jointly signed policy continuation itself, serialize its exact predecessor,
preserve separate account updates, and connect those semantics to the same
single-observation release boundary.

[Sealed prototype evidence](../sdk-alpha1/evidence/20261004-witness-authorization-prototype-af55fbf7/QUALIFICATION.json)
contains the exact patches, source hashes, commands and results for both variants.
