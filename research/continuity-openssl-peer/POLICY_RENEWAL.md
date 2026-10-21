# Original policy renewal

The independent reference now coordinates policy-only renewal through the same
protected registration and its original session journal. Local and required-witness
profiles use separate coordination paths, selected by the original registration.
The required profile needs its original witness transport; it cannot fall back to
local commits. This document does not change the candidate's release status.

The existing original device, journal, handshake transcript, session, outboxes and
reserved work remain in place. Renewal extends only the policy version and end
time. The policy family, signing root, SDK binding, prekey modes, witness profile,
send allowance and validity start must remain identical. The current credential
and roster must still authorize the original device. P cannot replace a device
key, revive a revoked generation, extend a credential, or start a new handshake.

Both the account root and the original policy root approve the exact request.
Account authentication and issuer authorization remain the embedding host's
responsibility. A device's possession proof is not a user login. Incoming approval
bytes cannot select the journal or predecessor: those come from the protected
original state while its directory lease is held.

## Borrow the registered coordinator

Retain one random nonzero 32-byte operation ID before requesting approval. Use
the same ID and installation after an interrupted call. The client exposes the
same lifetime-bound child as the lower-level `Registration` owner:

```python
with client.policy_renewal(operation, now) as renewal:
    request = renewal.request()

# The host authenticates the user and obtains the two issuer approvals.
# The target policy pins come through an independently trusted host channel.
with client.policy_renewal(operation, now) as renewal:
    renewal.stage(approval, policy_pins_json, policy_materials_json, now)
    outcome = renewal.commit(now)

with client.session(now) as session:
    original_ciphertext = session.resume(original_message_id, now=now)
```

`request()` returns public original/current credential and roster bytes, original
and predecessor signed policies, and a 313-byte scope. The scope contains the
operation, journal, original credential-derived owner, original/current
credential digests, current roster checkpoint, original/predecessor policy
checkpoints and the exact previous adoption digest. This metadata is not a
reservation or permission. The issuer statement and dual signature container are
the native `QPPRNW01` / `QPPRNB01` formats.

`stage` accepts the existing `qperiapt-policy-pins/1` and
`qperiapt-policy-materials/1` JSON byte contracts. It verifies the current target,
rechecks the actual predecessor, and reserves the final representation before
publishing Pending. A semantic retry preserves the first approval bytes. Another
operation cannot replace Pending. Ordinary session use and G/R mutation are
blocked while P remains pending. Closing the parent revokes the borrowed child
and withholds a result even if a write has already committed.

`commit(now)` rechecks current target/C/R validity and retained time floors, then
publishes the exact local transaction. An already observed commit is historical
metadata. Reopening a session still checks the current policy, credentials and
roster before work and again before releasing a result. Historical status never
releases plaintext, ciphertext, a signer or a new session.

## Recover the same operation

After an error, close and reopen the original registration and use
`policy_renewal(operation, now).status()`. The local journal reconciles its
authenticated original write intent; it does not generate a replacement target.

* `Pending`: the original approval is retained, and no policy adoption has been
  observed. Commit while its target and current identities remain valid.
* `Committed`: the exact adoption was observed. This status may remain readable
  after expiry; current traffic is still refused after its authority expires.
* `ExpiredUncommitted`: the exact still-pending target was observed to have
  expired. `reconcile_expired(now)` records this disposition and a durable time
  floor. The operation cannot be reused. Obtain a new independently authorized
  request that matches the still-retained predecessor.
* An unknown operation raises an explicit unavailable-outcome error. It is not
  an assertion that no commit happened and does not authorize resetting storage.

The record retains one current adoption, one Pending and one expiry disposition.
Older overwritten history is not an unbounded receipt service. The local-only
profile retains its existing rollback boundary; this work does not provide the
fresh external witness checks required for rollback-resistant adoption.

## Storage and current validation scope

`QPREFS11` wraps the unchanged original session/G/R representation with bounded
policy metadata and the original journal identity. Existing business and G/R
limits remain enforced inside that wrapper. A larger encoded file is not more
business capacity. Expired policy metadata remains parseable for original-state
recovery, while operational admission requires the actually committed live
policy. The original transcript's P0 fields are never replaced with a fresh
bootstrap context.

## Required-witness coordination

Pass the same original witness carrier to `client.policy_renewal`. `request()`
reads the actual retained predecessor. Obtain the two root approvals and target
trust inputs through the host's authorization path, then call
`prepare(approval, policy_pins_json, policy_materials_json, now)`. This returns the
296-byte `QPPWNP01` proposal. It commits to the original witness subject, operation,
statement, expected head and sealed target head. Preparation retains the first
exact sealed image; retries do not re-sign or reseal it.

The host submits the proposal, the approvals and their signed policy/identity
materials to the independently authorized witness service. Device possession or
the ordinary signed byte carrier cannot approve this step. Until preparation is
observed there, `status()` returns `Unavailable` and `commit(now)` refuses.
Unavailable is never evidence that the operation did not commit.

After independent preparation, `commit(now)` rechecks the current target and
identity validity before sending the typed P commit. `recover()` queries this
same operation after lost replies or process interruption. `close_proposal()`
requests a definitive `Closed` outcome when still Prepared; an already Applied
operation remains Applied. Closed retires the target's policy version even if its
predecessor remains installed. Reusing that version or operation does not revive
permission. The local `ExpiredUncommitted` disposition is not used in this path.

The coordinator retains the exact Applied/Closed result before ACK and intent
cleanup. It keeps one current policy authorization and the latest P disposition,
alongside existing G/R history. `Applied` and `Closed` remain historical outcomes,
not traffic leases. A session checks command 15, which binds current account
authority and the exact adopted policy statement, before work and before release.
An unavailable reply at either boundary withholds the output. Command 4 cannot
substitute for this policy check.

`QPRFPI01` authenticates the original sealed P intent; `QPRFLC04` wraps typed P
control around existing G/R control. Neither wrapper replaces the original
journal subject. Local G/R time floors and witness P version floors remain
different constraints. Independent G/R composition after P is not yet qualified.

## Validation drivers

`local_policy_checks.py` exercises original registered 3/32-member accounts,
sequential native approvals, real native continuation, original write recovery,
old and new traffic, and PQ rekey under explicit fixture clocks.
`local_policy_boundary_checks.py` covers full business capacity, expiry of a
pending target, simultaneous current and pending records, and parent-close
recovery. The installation runner requires both drivers using the selected wheel
outside the checkout and rechecks their source/native identities. A source run
alone does not qualify the installed package.
`witness_policy_checks.py` exercises required-witness P with real native peers,
lost commit/ACK replies, exact-head recovery, closed-version retirement and fresh
policy admission at both output boundaries, and PQ rekey followed by native
decryption in the new epoch. The rekey observation is not a PCS proof.
`witness_policy_boundary_checks.py`
retains the full 123-outbox, two-epoch business store through expired-target
closure, parent cancellation and a later applied policy. It also checks that
expiry sends no Commit and that policy metadata cannot fund more business data.
The installation runner requires both witness drivers as well. Installed-package
qualification and G/R composition after P still need their own evidence. None of
these drivers is a device or full release qualification.
