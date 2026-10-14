# Q-Periapt WASM SDK — 0.2.0 candidate

The product entry verifies ML-DSA-65 signed policy, obtains fresh platform
cryptographic randomness and keeps hybrid private keys in explicit owners.
This is a local prerelease candidate, not a published npm release.

Install the supplied archive with `npm install ./q-periapt-sdk-wasm-0.2.0.tgz`.
It has no npm dependencies, install scripts or native compilation step.
The Node entry requires Node 24 or newer. CommonJS and ESM share one WASM
instance; both support the named exports shown here:

```js
import { QPeriaptRuntime, QPeriaptKeyPurpose } from 'q-periapt-sdk-wasm';
// CommonJS: const { QPeriaptRuntime } = require('q-periapt-sdk-wasm');

// These four Uint8Arrays come from your authenticated policy configuration and
// protected storage. Empty previousState is only for first provisioning.
const runtime = new QPeriaptRuntime(policyBytes, signature, pinnedRoot, previousState, 32, 4);
let key;
try {
  await persistTrustedStateAtomically(runtime.trusted_state());
  key = runtime.generate_key();
  const publicKey = key.public_key();
  // Send publicKey through your authenticated application protocol.
} finally {
  if (key) { key.close(); key.free(); }
  runtime.close(); runtime.free();
}
```

For browser ESM, import from `q-periapt-sdk-wasm/web` and `await initialize()`
before constructing an owner. Bundlers using the standard package exports map
also select this web entry for the root import. For unbundled deployments,
serve the package's `web/` directory with JavaScript and `application/wasm`
MIME types, then import its `index.js` by URL:

```js
import initialize, { QPeriaptRuntime } from '/q-periapt/web/index.js';
await initialize(); // loads q_periapt_sdk_wasm_bg.wasm next to the JS module
```

Concurrent initialization calls share one promise and one instance. A loading,
compilation or initialization failure rejects that promise and stays failed
until the module is loaded in a fresh realm. No automatic retry is performed.
Deploy on HTTPS (localhost is suitable for development) with WebCrypto
`globalThis.crypto.getRandomValues`. Missing or failing entropy rejects key
generation, import and encapsulation; no deterministic or weak fallback exists.

The default exports have no private-key getter, caller coins or raw combiner.
For deliberate plaintext key transfer, separately import `QPeriaptExpert`
from `q-periapt-sdk-wasm/expert` (Node) or `q-periapt-sdk-wasm/web/expert`
(browser). The legacy deterministic/KAT package is separate. These are API
boundaries for ownership and misuse prevention, not isolation from malicious
JavaScript executing in the same realm.

Limits are JS number integers: 1–1024 live keys and 1–64 synchronous operations.
Strings, booleans, fractions and wrapped integers fail. Close owners explicitly,
then call `free()` once to release their wrappers; never use a freed wrapper.
Runtime close revokes its key/secret/derived owners. An exported JS byte array
cannot be revoked or erased by the runtime; protect and erase it yourself.
Use `secret.derive_key(QPeriaptKeyPurpose.Exporter, label, context)` for an owned
HKDF-SHA-256 application key, then explicitly export only when your cipher needs
bytes. Labels are 1–255 printable ASCII bytes; context is at most 65536 bytes.

Policy update is prepare → persist the signed policy and trusted state atomically
→ `activate_after_persist()`. Activation revokes the old epoch. The raw runtime does not supply a persistent session service. The browser
policy store and Continuity lifecycle owner below provide separate persistence
contracts; complete Continuity session bindings remain under development.

`PACKAGE_CONTENTS.json` records candidate bytes and source/tool identities;
distribution signatures are verified separately. `THIRD_PARTY/rust/INVENTORY.json` records
the target-filtered production dependency license closure. Current platform,
security and release gates are documented in the repository's
[release readiness ledger](https://github.com/billlza/q-periapt/blob/main/docs/SDK_0_2_RELEASE_READINESS.md).
# Browser policy storage candidate

`q-periapt-sdk-wasm/web/storage` provides `QPeriaptPolicyStore.create` and `open`.
Supply a stable origin-local `name` and an independently retained policy `root`;
creation also takes the signed `policy` and `signature`. Opening never creates a
missing installation, and creation never replaces an existing one. This browser
entry requires a secure context, IndexedDB with strict transaction durability and
Web Locks. It returns `Unavailable` when a required capability is absent.

The owner supplies `trustedState`, `isEnabled`, `generateKey` and `encapsulate`.
It keeps the raw runtime and update authority private. Use
`replacePolicy(expectedState, policy, signature)` to verify a strictly newer
policy and atomically persist the complete signed image and trusted state before
activation. An invalid signature or caller state leaves the current owner usable.
An I/O, quota, commit or activation failure closes it. Reopen the same name and
root to reconcile actual stored state; a rejected promise does not establish that
a write was absent. No automatic reset, weaker persistence mode or signature
fallback exists.
Opening verifies and reasserts the original signed image in a strict transaction
before exposing a runtime. This also recovers creation interrupted between its
schema/image transaction and strict completion barrier.

Call and await `close()` explicitly. It immediately revokes retained key/secret
owners and releases its origin-wide lease after pending I/O settles. Closing
during replacement prevents returning a new runtime; the signed policy may still
have committed. Other tabs and Workers receive `Busy` while the lease is held.
An operation timeout reports `OpenUnknown` or `CommitUnknown`; it does not count
as an I/O completion receipt. Cleanup waits another ten seconds, then reports
`ClosePending` while retaining the lease until the browser actually settles.
When both operation and cleanup fail, the operation code is preserved and
`error.cause.errors` contains both errors. A rejected `close()` can be called
again to await cleanup; it never grants permission to replace stored state.
Garbage collection is not an owner-lifecycle API.

This is origin-local policy storage, not a Continuity session journal or witness
implementation. Web Locks coordinate cooperating SDK users; they do not isolate
malicious same-origin code. Browser storage can be cleared or evicted, and there
is no rollback guarantee against restoration of a complete old browser profile.
Missing state must be recovered through the application's independently retained
trust/history rather than silently recreated. IndexedDB `strict` requests the
browser's strongest standard transaction durability; it is not a demonstrated
native-filesystem or power-loss equivalence. The schema is explicitly versioned;
unknown or malformed records are refused, not migrated by guesswork.

# Browser Continuity lifecycle

The same web entry exposes `QPeriaptContinuityEnrollment`,
`QPeriaptContinuityDevice`, `QPeriaptContinuityPolicy`,
`QPeriaptContinuityAccountTrust` and `QPeriaptContinuityWitness`.
They reuse the shared native protocol engine and the real `QPeriaptRuntime`;
there is no private fixture-key import or policy-digest-only admission.
The Node entry keeps its existing API and does not load browser storage modules.

Run persistent device operations in a dedicated Worker on a secure origin with
IndexedDB, Web Locks and OPFS synchronous access handles. Use one stable name
(1–96 ASCII letters, digits, underscores or hyphens), an independently retained
32-byte storage ID, and the exact same enrollment intent on reopen. The intent
constructor takes the pinned account root, 16-byte device ID, generation,
32-byte policy family and validity interval. Timestamps, versions and generations must be unsigned 64-bit BigInt values;
wrapping, strings, booleans and coercion objects are refused.
Buffer inputs are Uint8Array and are bounded before copying into WASM. Their real
typed-array length is checked without invoking caller properties. Genuine subclasses
and cross-realm Uint8Arrays are accepted; proxies, detached/out-of-bounds views and
other array kinds are rejected. Invalid input does not strand the owner borrow.

The lifecycle is `create` (or explicit original `resume`) → `request` → authority
registration → `accept` → `prepare` → any required independent witness enrollment
→ `activate`. `open` never creates or replaces missing original state. It returns
an enrollment owner even for an already active installation; call `activate`
with current verified policy and witness configuration to reopen that service.
`activate_local` is available only when the signed policy admits local protection.
Preparation exposes the public witness subject and genesis digest when required;
these are expectations to enroll, not evidence that enrollment already happened.

The owner can generate/recover an original public prekey and prepare a complete
signed advertisement through `QPeriaptContinuityPublicationPlan`. The plan binds
an independently obtained directory checkpoint, validity and ordered key list.
Use `generate` for publication-owned members or `reuse` for an existing available
inventory request with its unchanged role and validity. The complete plan must
include reusable classical and PQ members and satisfy the signed policy's modes.

Retain `next_publication_id()` and the complete original plan before dispatch.
`prepare_publication(id, plan, policy, timeoutMs, trustedClock)` reserves and
recovers that operation; retries return the original signed bytes. `timeoutMs`
is an integer from 1 through 60000. `trustedClock` is a synchronous callback that
returns current trusted Unix seconds as an unsigned 64-bit BigInt. It is sampled
again after blocking work and before release. A thrown error or invalid return
rejects the operation with `InvalidClock`, preserves its cause and closes the owner.
The SDK cannot determine whether a host-supplied clock is trustworthy.

`publication_status(id)` returns an immutable Absent, Reserved, Prepared or Retired
observation with the original intent/manifest/artifact digests when applicable.
`abandon_publication` reconciles a Reserved intent; `retire_publication` retires
the exact prepared public artifact's local history. Neither operation asserts
remote removal, and retiring public history does not revoke its key inventory.
Use the returned `bytes()` as the public distribution artifact only after a
successful preparation; no private key or general signing handle is exported.
Prepared establishes no remote publication receipt or directory freshness.

`prekey_status(policy, requestId)` observes the exact original inventory request:
Absent, Reserved, Available, Consumed, Abandoned or Retired. `retire_prekey` removes
the logical key-recovery command while retaining terminal consumption/retirement
states; a pending response still blocks retirement. These maintenance operations
can use the held policy after its runtime is closed and never grant fresh traffic
authority. Retiring a public advertisement does not retire its inventory, and
retiring inventory does not retract already distributed public bytes or establish
physical/backup erasure.

The session-exchange candidate admits a public bundle with `admit_peer` under a
`QPeriaptContinuityPeerTrust`: exact independently pinned participants, generations,
prekey quality and directory checkpoint. `establish_session` takes one retained
request ID, an explicit endpoint, a finite timeout and a trusted bigint clock.
It authenticates the peer's session acknowledgement before returning a session.
`reopen_session` checks original local state and its archive; it is not a fresh
remote-liveness receipt or a substitute for retrying failed establishment.

Obtain `next_session_message_id`, retain it with the original input, then construct
`QPeriaptContinuityMessage` and call `deliver_session_message`. The input owns a
wipeable SDK plaintext copy; `close`/`free` does not erase host copies or journal
recovery state. `session_message_status` reconciles that original ID after an
unknown outcome. `Confirmed` requires the peer's authenticated consumption prefix;
`PrefixPending` means that prefix does not yet cover the message. Changed input
under an existing ID is refused, and erased history cannot authenticate new input.

`serve_session_exchange` and `serve_session_message` invoke the host consumer with
copies of the session ID, message ID and plaintext only after authenticated inbox
commit. Resolve with `undefined` only after the host effect and deduplication record
are durable together. An unknown outcome must reject; the same ID can be invoked
again. Cancellation/deadline stops the SDK's wait, but cannot undo or stop a host
Promise already running. Such a failure never consumes the inbox. Host plaintext
copies have their own lifetimes. The SDK does not promise global exactly-once effects.

`QPeriaptContinuityEndpoint` requires HTTPS; `for_loopback` permits explicit numeric
HTTP loopback diagnostics. Peer pins remain independent of the untrusted carrier.
Requests omit ambient credentials and redirects, and bound each streamed response
to 32 KiB. Source-integrated APIs still require installed browser/native network
qualification; full identity lifecycle and migration require further browser
integration. The protocol and package remain prerelease candidates.

`session_rekey_progress(session)` reads local confirmed, sending, receiving and
pending epochs. `drive_session_rekey(session, target, exchanges, endpoint,
timeoutMs, trustedClock)` delivers one explicit target; `target` is a BigInt,
`exchanges` is an integer from 1 through 128, and all requests share the same
deadline. There are no implicit retries after network failure. Reopen the same
owner and retry the same target. `ExchangeLimit` preserves pending work and
closes the owner. `serve_session_control` authenticates one control request for
the original session, including final/receipt replays after local completion.
The returned completion's `epoch()` and `exchanges()` describe local journal
completion only; they are not remote receipt or post-compromise recovery proof.
These new control bindings require their own installed runtime qualification.

For same-credential roster maintenance, first await `close()` on the operational
owner and free it, then `open` the original name, storage ID and enrollment intent.
The opened registration coordinates maintenance without exposing its signer or
journal. Do not call `create` or `accept` again. After maintenance, `activate` (or
`activate_local` for a signed local policy) checks current authority before traffic.
A durable `Active` status is not an already activated JavaScript service handle.

An activated device accepts a known **remote** account's newer roster through
`admit_peer_roster(signedRoster, independentlyPinnedAccountTrust, policy, now)`.
The returned checkpoint means that this canonical head is installed locally.
The operation verifies signatures, current policy and local authority, and refuses
unknown accounts, another root/family, rollback and same-version forks. An exact
retry still checks live authority; it is not proof that this invocation first
committed the update. If transport or storage fails, reopen the original device
and retry the same independently signed target. A later head refusing that retry
does not establish whether the older attempt once committed.

For a complete-account message, populate `QPeriaptContinuityAccountTargets` with
one existing session for every required device in the signed recipient roster.
Read `next_account_message_id` once, and retain that ID and one
`QPeriaptContinuityAccountMessage` containing the recipient account, original
plaintext and associated data. `deliver_account_member` takes the entire target
set and one selected index. It commits every required local message together
before dispatching that member. Additional members use the same aggregate input;
calling individual-message delivery is not a replacement for this transaction.

After an error, reopen the original device and retain the same operation, input
and recipient sessions. `account_message_status` distinguishes unreserved,
reserved, committed, abandoning, abandoned and retired progress. For a committed
or accounted batch, `reconcile_account_message` returns all original member IDs
and outcomes without dispatching or completing a reservation. A retained member
confirmation may return from delivery with zero exchanges. PrefixPending,
ResolutionPending, DeliveryUnknown and HistoryRetired are distinct outcomes, not
successful remote consumption. `retire_account_message` only removes aggregate
metadata after every member has been acknowledged or explicitly accounted; its
ID is never reused. Host business effects still need durable deduplication and
are not atomic across recipients. Close/free erases the account-input object's
SDK plaintext copy. These delivery entry points require an activated original
device. Restricted recovery below does not activate an owner; permanent device
or account retirement still needs its distinct witness-proof workflow.

For cleanup after policy/credential expiry or runtime closure, close the old
operational owner and reopen the exact original browser device. Supply the
independently retained `QPeriaptContinuityHistoricalPolicy` for its original
installation. Select the retained aggregate ID with `recover_account_local` or
`recover_account` with the original witness. Required protection refuses a local
call or missing/conflicting witness. This consumes enrollment access into a
cleanup-only owner; activation, renewal and ordinary message operations are
unavailable on it. Status and member reconciliation retain the original IDs.

This does not extend witness authorization. Its effective validity is the
intersection of credential, roster and policy validity. Once that interval ends,
the witness refuses fresh cleanup freezes, acknowledgements and retirement writes,
just as it refuses other new state advances. Historical queries without an
unapplied pending write, and exact confirmation of an already-applied command,
remain possible. A refused write may leave the original intent pending; neither
reopening nor a local fallback may discard or complete it. New writes need
independent current witness authorization; permanent device/account retirement
uses its separate approved workflow. Closing a local runtime while the witness
authorization is still current is a different case and does allow restricted
cleanup. A transport error alone does not prove whether the witness committed.

A reserved batch is abandoned as a whole: call `begin_account_abandonment`,
durably save the complete report with host deduplication, then acknowledge its
exact `report_id`. A committed batch cannot be relabeled as an uncommitted
reservation. Its unsettled sessions instead use `recover_session_local` or
`recover_session`, followed by `begin_session_closure` and explicit host accounting
before `acknowledge_session_closure`. Reopen the original account operation to
reconcile all member outcomes and retire metadata only when every member is
accounted. Closing a handle never acknowledges a report or confirms delivery.

Each loss report's `to_json()` returns a complete metadata snapshot under schema 1.
Byte IDs/digests are lowercase hexadecimal; all `u64` values are decimal strings
so JSON storage cannot round them. Bounded lengths and roles are JSON numbers,
and genuinely absent optional metadata is null. Account reports include every
original session; both report kinds include complete rekey progress, reservations,
epochs, unconfirmed ciphertext identities, unconsumed deliveries and skipped
indices. Save the whole document, not just its ID or a selected member. It contains
no plaintext/private keys and is not a protocol input or traffic authorization.
Unknown commit results require reopening the original owner and reading its exact
report/status. Logical state erasure does not establish erasure of backups or
physical media. These recovery calls do not bypass permanent retirement.

For a permanently retired device generation, retain the independently approved
complete replacement proposal, original subject and witness retirement receipt.
`QPeriaptContinuityRetirement` verifies that receipt against the original witness
pin and your retained proposal; never take the expected proposal from an incoming
receipt. Close the old owner and use `QPeriaptContinuityDevice.open_retired` with
the original name, ID, enrollment intent and verified retirement. This restricted
owner cannot activate, renew or send traffic. It needs no current runtime.

`retirement_inventory` returns the original complete inventory request. Retain its
bytes before sending them to the independently authorized witness controller.
Use its inventory receipt with `prepare_retired_report`, retain that exact report
request and obtain the independent report-retention receipt. `retired_report`
then returns the full report: `to_json()` includes every original source/target
view, pending intent and unknown/lost outcome, while `to_bytes()` is the canonical
host-accounting input. JSON uses hexadecimal bytes and decimal strings for u64
values. These documents contain account/device linkage; store them as private
host metadata. Neither an uncommitted target nor a committed send proves delivery.

Durably account for the complete report, retaining its canonical bytes and request.
Pass the exact read-back bytes and both receipts to
`prepare_retired_host_acknowledgement`, then obtain the separate independent
purpose-21 acknowledgement. Only this receipt permits `erase_retired_journal`.
After authenticated journal erasure, `prepare_retired_signer_erasure` retains the
original signer object's identity and exact encrypted-content fingerprint.
`erase_retired_signer` atomically replaces that same IndexedDB object with its
fixed retirement marker and closes the owner, awaiting actual storage release.
It does not delete or recreate the original path. Native inode plans and browser
catalogue-object plans have distinct encodings; they are not interchangeable.

Reopen the same retired identity and original proof after an unknown result.
The `*_request` methods recover independently saved expectations; `undefined`
means local absence, never witness non-commit. Erasure-status methods authenticate
the same original object or terminal; missing, swapped and malformed objects fail.
Neither logical journal erasure nor signer retirement proves removal from old
pages, backups, archives or previously copied owners. Browser catalogue secret
revision 2 is only the fixed eight-byte signer terminal; older readers reject it.
This device-retirement flow does not implement managed account-root cutover or
repair the separate in-place renewal gap caused by an unapplied ordinary intent
after required-witness authorization expires.

Current roster membership is rechecked before existing-session operations release
data. Accepting a roster which removes a peer therefore blocks that peer's old
sessions. This operation does not distribute the roster, prove remote receipt or
change the local account; local-account updates use the original workflow below.
Retain the original bootstrap bundle/pins for historical session reconstruction;
they do not replace explicit admission of newly received peer rosters.

Credential issuer preparation uses the original registration owner and
`QPeriaptContinuityHistoricalPolicy`. Retain a fresh
`QPeriaptContinuityCredentialRequest.new_operation_id()` before dispatch. Use
`credential_renewal_request(id, originalPolicy)` for signed local protection or
`witnessed_credential_renewal_request(id, originalPolicy, witness)` for required
witnesses; neither route silently changes the protection profile. Close/free an
operational owner and reopen the original registration before this maintenance.

The returned public request exposes the original journal/owner, exact original
and previous credential/roster bytes, predecessor checkpoint/validity, original
policy digest and actual adopted policy checkpoint/authorization. These are
historical issuer materials, including after expiry, not live credentials or a
reservation. Retain the complete request for issuer deduplication. The issuer
must independently authenticate/authorize the account, select trusted roots and
checkpoints, serialize roster versions and preserve its exact grant. Do not build
trust pins from an incoming request or treat it as user authentication. Required
witnesses are contacted through the controlled original signer, which is never
exported. Pending maintenance, unacknowledged completion and reused terminal G
identities are refused.

Policy-only issuer preparation uses a separately retained
`QPeriaptContinuityPolicyRequest.new_operation_id()`, with
`policy_renewal_request(id, originalPolicy)` for local protection or
`witnessed_policy_renewal_request(id, originalPolicy, witness)` for required
witnesses. Close the operational owner and reopen its original registration.
The returned request contains the original journal and owner, original/current
credential commitments and signed credential/roster bytes, current roster
checkpoint, original/previous policy checkpoints and exact previous policy
authorization. The account and policy issuers must independently authenticate
the caller and approve the same exact scope. The request does not authorize a
policy change, reserve an operation or release traffic authority.

These entries preserve native restrictions: pending maintenance must first be
reconciled. A completed plain credential renewal G retains its original receipt
and contributes the actual successor credential/roster to this request, including
under required witnesses. Joint credential/policy continuation remains separate.
A failed witnessed request must not be retried through local protection. Browser
policy renewal uses `QPeriaptContinuityPolicyGrant` to verify separate account
and policy approvals against this original request and independently pinned
original, predecessor and live target policies. The request alone grants no
permission. Close the active owner and reopen the original registration before
`stage_policy_renewal`; keep its exact operation through errors and retries.

For local protection, `reconcile_policy_renewal` commits or reconciles the
original journal. `recover_historical_policy_renewal` acknowledges an exact
already-committed operation without a runtime; `resolve_policy_renewal` resolves
an expired or superseded uncommitted target. For required protection,
`prepare_witnessed_policy_renewal` returns the exact sealed proposal, which the
independent witness must approve. Then use `commit_witnessed_policy_renewal`.
After an unknown result, reopen the same registration and call
`reconcile_witnessed_policy_renewal`. `close_witnessed_policy_renewal` preserves
Applied when commit already won; it cannot undo that result.

`policy_renewal_status` reports local historical intent/completion, while
`witnessed_policy_renewal_progress` retains the original Applied/Closed terminal
and whether ACK/cleanup finished. Remote Unavailable never means uncommitted.
Activate separately with `activate_local_policy_renewal` or
`activate_witnessed_policy_renewal`; activation rechecks current target policy,
credential, roster and required witness before releasing the original owner.
For an already established session after policy activation, construct
`QPeriaptContinuitySessionReopenRequest` from its original bundle, independently
pinned historical P0 and peer expectations, original session ID and role. Pass
that descriptor and the live target policy to `reopen_continued_session`.
The original journal must already contain the exact current authorization;
historical metadata alone cannot create a session or bypass current membership,
archive or witness checks. This does not grant new bootstrap permission.

These entries share the native state machine. Browser lifecycle qualification
and complete maintenance composition remain candidate work.

Verify the independently issued bytes with `QPeriaptContinuityCredentialGrant`,
using an independently retained target account pin, original historical policy
and current trusted time. `stage_credential_renewal` retains that exact grant and
caller-held operation ID. Local protection reconciles it during separate
`activate_local`; an expired local target can be resolved explicitly through
`reconcile_expired_credential_renewal`.

For an atomic credential and policy extension (joint G/T), construct
`QPeriaptContinuityPolicyContinuation` from the combined two-root approvals,
the original public credential request, independently verified credential grant,
original and previous policy histories, and the live target policy. The request
supplies the actual original lineage and predecessor T; received approvals do
not select a new installation or authorize a different predecessor.
Use `stage_policy_continuation`, retaining its original operation and T statement.
Local storage completes through `reconcile_policy_continuation`; after expiry,
`recover_historical_policy_continuation` only finishes an exact existing local
commit and grants no traffic permission. Required protection uses the witness
methods below with the T transaction statement. Activate separately using
`activate_local_policy_continuation` or `activate_witnessed_policy_continuation`,
then reopen the original session through its retained descriptor. A local call
never substitutes for a required witness. Independent P and joint T remain
distinct authorization modes; this interface does not bypass native admission
rules for switching between them.

For required witnesses, `prepare_witnessed_credential_renewal` seals the original
target and returns `QPeriaptContinuityCredentialProposal`. Retain its exact bytes
and obtain independent witness preparation before explicit
`commit_witnessed_credential_renewal`. A transport error or cancellation closes
the owner and may leave the remote outcome unknown. Reopen the original
registration, recover the original proposal if needed, and reconcile the same
operation and statement through `reconcile_witnessed_credential_renewal`.
Historical recovery and `close_witnessed_credential_renewal` require no live runtime.
Close preserves a target that already committed. An unprepared target can use
`prepare_witnessed_credential_cancellation` and independent witness cancellation
approval, followed by original-operation reconciliation; no target is invented.

`credential_renewal_status` reports original historical progress. `Committed`
may be retained while ACK cleanup is still pending; reconciliation must finish
before separate current-policy `activate` releases traffic authority. Reuse the
original journal, identity and operation, including after expiry or unknown
results. Same-key credential extension does not replace the identity key or
establish post-compromise recovery.

For a renewed peer, verify its `QPeriaptContinuityCredentialGrant` using independent
account and original-policy expectations, then explicitly call
`admit_peer_credential_renewal(grant, originalOperationId, currentPolicy, now)` on
the active device. The SDK checks the known original peer history and exact
operation before updating it. This entry cannot renew the local device. A valid
same-account peer roster can revoke this local member and be committed before
the call refuses further use; an error must not be interpreted as non-commit.
After admission, `reopen_session` uses the original bundle and session identity,
and resolves its historical credentials through the retained grant. Peer renewal
does not authorize a fresh bootstrap from an expired original bundle.

`refresh_local_roster` retains an independently pinned, signed target and requires
local protection. Required-witness policy is refused before this path changes state.
`resolve_local_roster_refresh` reconciles an original predecessor/target pair and
retains Committed, ExpiredUncommitted, SupersededUncommitted or SupersededUnknown;
a later head does not prove that the old target never committed.

For required witnesses, create `QPeriaptContinuityRosterTarget` from the original
certificate, new root-signed roster, and independently obtained current account pin.
Retain one `QPeriaptContinuityRosterProposal.new_operation_id()` before calling
`prepare_witnessed_roster_refresh`. Send its canonical `bytes()` to the independently
authorized witness service for preparation. The device SDK does not grant that
server-side authorization. Only then call `commit_witnessed_roster_refresh` with
current policy. Unknown returns require the same proposal; the `recover_*` and
progress APIs read original preparation instead of creating another target.

`reconcile_witnessed_roster_refresh` and `close_witnessed_roster_refresh` use
`QPeriaptContinuityHistoricalPolicy`, verified from the original independent policy
pin and signed statement without constructing a live runtime. They finish original
terminal persistence, acknowledgement and cleanup in the engine's required order.
Close can return Applied if the target had already committed. Unavailable never
means uncommitted. A local progress snapshot distinguishes staged, abandoned before
preparation, reserved, applied and closed, and separately reports completed cleanup.
Only a never-released staged intent can use `abandon_unprepared_roster_refresh`.
These roster bindings require their own installed browser qualification. Credential,
policy and account-root transitions and migrations remain separate integration work.

Await `close()` before releasing the wrapper with `free()`. Close cancels pending
witness traffic and waits for actual storage-release receipts. Concurrent device
operations are refused. An operational failure closes the owner; reopen the same
identity to reconcile the original state. Timeout/cancellation may follow a remote
commit and never authorize reset. Independently pin witness identity and public
key; normal witness configuration requires HTTPS, while `for_loopback` is an
explicit local diagnostic entry. Cross-origin endpoints must permit your origin
and `application/octet-stream` POST through CORS. No automatic retry, redirect,
ambient credential or unanchored fallback is used.

## Original recovery state and errors

Use `await device.status()` after opening the original device. Its immutable
snapshot contains `phase()`, `journal()` and any `roster_refresh()` observation.
The journal is absent only before grant acceptance. Free snapshots and any
returned checkpoint/refresh wrappers after reading them; they own no authority.

| Phase | Next original operation |
| --- | --- |
| Preparing / Requested | Obtain the same signed `request()` and reconcile authenticated registration. |
| Accepted | Repeat `prepare()` to recover original children/genesis, complete any required independent witness enrollment, then activate. |
| Activating / Active | Retry `activate()` under current policy and witness admission. Do not prepare or recreate children. |
| Refreshing / RosterResolved | Preserve the original roster workflow. Use the original local roster refresh/resolution workflow; the snapshot does not authorize traffic. |

Roster observations retain predecessor, target, actual observed checkpoint and
observation time. `SupersededUnknown` stays distinct from the two uncommitted
outcomes. An unresolved observation has no outcome; absence never means that
nothing committed. A status snapshot does not renew expired policy/credentials.

Shared-engine failures expose a stable `code`, retain the original error in
`cause`, and include `ownerClosed` on device-operation failures. `Busy` leaves
that existing owner open; an admitted operation failure closes it. `is_closed()`
reports the handle's state, independently of pending native cleanup or whether
its authority is still current. Input failures before dispatch have no owner
result; inspect the handle if needed. Generated JavaScript argument/type errors
remain ordinary programming errors.

Common codes include `Busy`, `Closed`, `Encoding`, `InvalidInput`, `Scope`,
`Checkpoint`, `Validity`, `PolicyDenied`, `Authentication`, `Corrupt`, `Absent`,
`Capacity`, `Cancelled`, `Deadline`, `WitnessTransport`, `WitnessVerification`,
`WitnessConflict` and `WitnessAuthorityDenied`. Storage-specific codes such as
`CommitUnknown`, `OpenUnknown` and `ClosePending` retain their original cause and
cleanup chain. Do not parse diagnostic messages or treat a code as proof of
non-commit. Reopen the original state and follow the authenticated phase;
never reset identity or recreate a published object in response to an error.
