# Independent credential renewal under an original local-only policy

`peer.local_credential.LocalCredentialRenewal` extends the local credential of
one established session whose original signed policy is explicitly local-only.
It requires the original context, private directory, scope, protection key and
operation ID. The host supplies a genuine original-root grant and an independently
trusted target roster checkpoint. The original full key, identity, policy,
predecessor credential and predecessor roster must match. This coordinator cannot
open a required-witness context; that mode uses [LocalRenewal](LOCAL_RENEWAL.md).

Close the normal session before opening the coordinator. The existing directory
lease allows one owner. The calls return metadata, never an active traffic owner:

| Call | Contract |
| --- | --- |
| `open(path, scope, key, context, operation, observer=None)` | Recover the original journal and identify one original operation. |
| `stage(grant, checkpoint, now)` | Verify current authorization and capacity for both Pending and completed images, then persist Pending. |
| `status()` | Return Pending, Committed or ExpiredUncommitted for a retained original operation. Unknown or discarded operations fail explicitly. |
| `commit(now)` | Adopt a Pending grant only while its target credential, target roster and policy are current and time is not below the retained floor. |
| `reconcile_expired(now)` | Preserve an existing terminal, or record ExpiredUncommitted only after a Pending target credential or roster expires while its exact predecessor remains current in the authenticated state. |
| `close()` | Release the lease; a reentrant close cancels result release without undoing a durable transition. |

Every result contains `status`, `operation`, `statement`, `target`, `time_floor`
and `expired_observation`. The latter is null except for ExpiredUncommitted,
where it identifies the observed journal revision, digest and supplied time.
The host must provide trustworthy time. A durable floor prevents later calls
from backdating below an accepted expiry observation; it is not a secure clock
and does not detect restoration of an entire older local store.

After interruption, reopen the same store with the same original inputs and
operation. Recovery installs the exact already sealed intent target. A semantic
re-signing of the same operation, statement and checkpoint preserves the first
grant. A different Pending grant is refused. Do not delete the store, generate a
replacement operation, or interpret an exception as proof of noncommit.

Committed is historical metadata and remains readable after authority expiry.
It grants no traffic permission. Pending and ExpiredUncommitted prevent ordinary
session admission. Policy expiry alone cannot establish ExpiredUncommitted: the
target credential or roster must have expired, and the authenticated predecessor
must still be the exact one named by the Pending grant.

A new grant after abandonment must name the actually retained predecessor. A
grant that assumes the abandoned target committed is refused. The previous
abandonment receipt survives staging a different operation, until that operation
commits or is itself abandoned. Completion removes the previous abandonment but
retains its time floor, including for ordinary business calls. The current
completion and at most one abandonment are retained; this is not an unbounded
operation ledger. Missing historical outcomes remain unavailable.

## One journal transaction and a separate lifecycle allocation

`QPREFS08` retains the current local identity, Pending grant, abandonment and
floor in the same encrypted journal as the session. It adds no authority sidecar.
Publication uses the existing exact-target intent, synchronized head and recovery
ordering. The coordinator reads back the durable head before returning a result.
Transactions reject reentrant operations; callbacks may close the owner.
Initialization refuses existing head, intent or authority records before writing.

The header, optional peer identity and original session transcript remain.
Versions seven and eight then encode a local-identity presence byte, the optional canonical
identity, and a coordination record: floor:u64, Pending presence byte, optional
target[40] + grant length:u32 + grant bytes, abandonment presence byte and an
optional 152-byte terminal. The terminal contains operation[32], statement[32],
target[40], observed revision:u64, observed digest[32] and observation time:u64.
Presence fields accept only zero or one. Historical root verification reconstructs
retained grants without granting current traffic authority.

Ordinary creation and generic upgrades still select version five. Version six is
exclusively the required-witness renewal format. Version seven remains readable
with its original bounds; an already Pending version-seven operation commits in
that original format. A new local credential stage explicitly selects version
eight. Older readers refuse its tag rather than interpreting the new allocation
under an old contract. Formats one through six refuse local coordination rather
than silently dropping it. Neither policy profile may fall back to the other.

Versions one through seven and raw journals retain their two-MiB aggregate bound.
Formats one through six retain the 73,728-byte metadata ceiling; version seven
allows at most 213,291 metadata bytes, charged to its business allowance. That
charge can prevent renewal when a previously accepted store is full, even with
a valid new grant. Expired old authority correctly cannot perform ordinary
cleanup to make room.

Version eight gives those same bounded lifecycle records a separate allocation:
two identities, one coordination record and the local presence byte, at most
213,291 bytes. Only their actual encoded bytes may sit outside the unchanged
two-MiB base-state allowance. Business traffic still cannot exceed 2,031,616 bytes,
and the existing 64-KiB control reservation remains. The maximum plaintext image
is 2,310,443 bytes, encrypted head 2,310,571 bytes, and local-session file admission
2,314,539 bytes. Raw and required-witness journal bounds remain unchanged. The
64-MiB directory quota, 128-file limit and exact-target publication engine also
remain. This is bounded additional storage, not a performance or energy result.

Staging still preflights Pending and completed state before publication. It can
now renew an already full original store after credential expiry without clearing
outboxes, inventing delivery outcomes or authorizing work under expired authority.
The grant and policy must be current. Physical storage exhaustion, directory quota
exhaustion or malformed/oversized inputs still fail explicitly and retain state.

## Qualification and remaining scope

`local_credential_checks.py` covers two chained grants, exact Pending/Committed
recovery, credential expiry, roster-only expiry while original authority is live,
abandonment followed by a correctly rooted alternative, durable time floors,
reentrant cancellation and simultaneous local/peer metadata. Four profiles use
148 fresh-process operations and 29 SIGKILL cuts. Original reserved sends, outboxes,
ACKs and four-flight rekey continue in the same session.

`local_credential_capacity_checks.py` fills the entire business allowance with
123 real outbox rows. Two root grants after original credential expiry preserve
every encoded epoch's hash, all outboxes and original ciphertexts, with process
cuts in staging and commit. The second Pending image exceeds the old physical
image ceiling. A further business send remains refused despite unused lifecycle
space. Boundary controls preserve old schema, raw-journal, file and aggregate
limits. Its archived version-seven writer creates a real Pending operation;
current recovery completes it in seven, then a new grant selects eight. The old
reader explicitly refuses eight. The combined profile retains 88,703 actual
metadata bytes; it does not qualify every maximum signed-input combination.

The native traffic counterpart retains fixture time 170; independent calls use
170/190/210/250/310/401 to exercise signed validity bounds. This is a bounded
independent reference, not full native enrollment renewal. Same-account joint
coordination, registration without fixtures, policy/witness or device replacement,
installed/cross-host lifecycle, whole-store rollback protection, power loss,
physical erasure and construction-wide PCS analysis remain separate requirements.
The Python/provider memory limitations in `README.md` continue to apply.
