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

The record retains one current adoption, one Pending, one expiry disposition and,
when needed, the exact policy proof for the latest completed roster transaction.
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

`preparation()` exports the native-compatible
`qperiapt-policy-witness-preparation/1` object while the original intent remains
retained. It includes the proposal, binding and **first sealed approval bytes**;
a semantically identical re-signature on retry cannot replace them. After
intent retirement, this export fails explicitly. Query `status()` or `recover()`
for the retained terminal outcome instead.

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
different constraints.

## Credential and roster operations after adoption

G still authenticates its root-signed credential grant against the original P0
digest. The coordinator separately admits the actually adopted live policy; it
does not rewrite a grant's signed policy binding. Required-witness G uses the
329-byte `QPCRNP03` proposal with the retained P statement, and `QPRFLI02` retains
the exact target. `QPRFLC05` / `QPRFLC06` distinguish the corresponding single-device
and complete-account controls. A pending G or R cannot be bypassed by starting P.

A new R names the actual adopted policy checkpoint and its exact approval
statement. The completed R retains that proof across later P and G transitions.
`QPIPRC02` encodes an alias when the proof is still the active P, or one full
bounded historical grant after a later adoption. The reader authenticates this
proof before decoding the account and then checks the actual journal and identity.
Removing the wrapper, substituting the proof, or using that older proof for a new
R fails. This history adds no current permission and no business storage allowance.

This is sequential composition of separately authorized operations. It is not
the candidate's joint policy/credential transaction, root replacement, or a new
device-generation transition.

## Command-line policy maintenance

Use the installed `qperiapt_continuity_reference.policy_cli` module with the
same `--provider-root`, `--directory`, `--key-file` and `--client-id` as the original
session CLI. Its `--timeout` bounds one invocation (0 < seconds <= 120), including
witness exchanges. It uses actual OS time. Persist the operation ID before use;
IDs are nonzero 32-byte canonical unpadded base64url and may begin with `-`.

```text
... request --operation=<original-operation> --witness-address 127.0.0.1 9001 \
  --output /absolute/private/retained-request.json
... prepare --operation=<original-operation> --witness-address 127.0.0.1 9001 \
  --account-approval /absolute/account-approval.bin \
  --policy-approval /absolute/policy-approval.bin \
  --policy-pins /absolute/trusted/policy-pins.json \
  --policy-materials /absolute/policy-materials.json \
  --output /absolute/private/preparation.json
... recover-preparation --operation=<original-operation> \
  --witness-address 127.0.0.1 9001 --output /absolute/private/recovered.json
... status --operation=<original-operation> --witness-address 127.0.0.1 9001
... commit --operation=<original-operation> --witness-address 127.0.0.1 9001
... recover --operation=<original-operation> --witness-address 127.0.0.1 9001
```

`request` derives `qperiapt-retained-policy-request/1` from the protected original
enrollment and journal, including historical identity inputs and the actual
predecessor. The host API equivalent is `client.policy_renewal_request(...)`.
The two 3803-byte approval files come from the authenticated account and policy
issuer; the coordinator verifies both signatures. Independently authorize the
witness with the exported preparation before committing. A missing witness is
an explicit failure for a required-witness session. `close-proposal` requests the
same definitive closure described above; it does not undo an Applied result.

For a local-only profile, omit `--witness-address` and use `stage` with the same
four approval/input flags, followed by `commit`, `status` or `reconcile-expired`.
The original profile determines which commands are available. There is no
automatic switch between local and witnessed maintenance.

Public exports use exclusive creation in a private directory. Export failure,
broken stdout, timeout or cancellation may occur **after** preparation or commit.
Retain the original installation and operation; recover its preparation to a new
output filename, or query/recover its exact terminal result. Never recreate a
device or session to handle an unknown outcome. All commands close the owner
before exporting a successful result.

The actual-time authenticated `host_roster.py --credential-renewal
--credential-recovery-probe ... --independent-policy-renewal` workload exercises
this CLI against the native account, publisher and witness. It retains the
original unknown-ACK message through independent policy adoption, rekey and
bidirectional traffic. The installed host-exchange schema 15 requires the
schema-6 workload, including subsequent independent G through the
[credential CLI](CREDENTIAL_CLI.md), and public-output readback. The flow does
not wait for the independent peer's original credential to expire; it does not establish dual-endpoint expiry or full lifecycle
acceptance. The fixture-clock drivers below separately test expiry and cuts.

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
The installation runner requires both witness drivers as well.
`policy_composition_checks.py` runs P/G/P/G/R/P/G and removal of the real receiving
peer on the same 3/32-member registered sessions, for local and required-witness
profiles. It tests retained ciphertext, an outstanding send reservation, lost
commit/ACK replies, process cuts, new-epoch decryption, stale approvals and
same-generation resurrection rejection. Its explicit fixture time passes the
original policy and credential expiries. Receipt schema9 additionally requires
this workload from the installed wheel. Each source or package qualification
applies only to its captured inputs; none is device or full release qualification.

`policy_composition_capacity_checks.py` reuses the existing full-account storage
workload with four policy adoptions around G/G/R/G. The local Pending state holds
P3 for historical R, current P4 and Pending P5 together. The witness profile
retains the exact prepared P5 image with historical P3. Both keep the original
123 outboxes and two epoch records, recover original writes, and reject spending
policy history space on business traffic. The installed schema9 runner requires
these two full-store profiles in addition to the four traffic/removal profiles.
