# Exact ordinary write recovery after authority expiry

Status: unpublished candidate API; protocol and product admission remain open.
This flow resolves one retained ordinary journal write that cannot newly commit
through the device endpoint after its witness authority expires. It does not
extend a credential or policy and does not restore traffic permission.

## Application sequence

1. Open the original `DeviceEnrollment`, installation, journal and archive index
   with their original wrapping key, historical policy and independently pinned
   witness. `pending_write_recovery_request` reads the authenticated source and
   sealed target without replaying either. Retain its proposal, complete metadata
   and signed request. Repeating preparation preserves their meaning and bytes;
   randomized signatures need not be identical.
2. An independent controller calls
   `AnchorPendingWriteRecoveryProposal::inspect_metadata` to inspect both complete
   views, then authenticates the account and intended effect independently. It
   durably retains the exact proposal and complete metadata before invoking
   `AnchorStore::complete_pending_write_recovery`. The historical device signature
   is insufficient authorization. This method belongs to the privileged witness
   control plane; the ordinary device handler rejects its request format.
3. Call `confirm_pending_write_recovery` with the retained proposal and metadata.
   Under the original enrollment, configuration, journal and archive leases, it
   verifies the retained intent and obtains a fresh signed read-only Query. Only
   the exact target head and original Advance command ID permit applying the
   original sealed image and removing the exact pending record atomically.
4. Continue the existing credential/policy/roster or cleanup flow. Locally staged
   approvals remain separate and unchanged. A completed old write is not a new
   runtime, report acknowledgement or authorization to send.

On a missing result, keep the same inputs and reopen the original owners. A
controller retry confirms only the exact current target and original last command.
After local commit, a confirmation retry additionally requires the authenticated
local image to be that exact target. A missing pending record alone is never
success. An intervening head advance conflicts; this interface is not a general
historical receipt service. Do not recreate an absent journal or intent.

## Bound state and authorization

The canonical 393-byte `QPWRPL01` proposal binds the witness, original subject,
source and target heads, actual current credential/roster authority, actual policy
checkpoint and authorization, original pending-record digest, and metadata digest.
`QPWRMD01` carries that same scope and two length-framed complete public record
views using the existing retired-report metadata grammar. It contains no plaintext
or private keys, but account/device linkage, message identifiers and lengths are
private host metadata. Preparation and verification enforce an 8 MiB limit.
The device dual signature uses purpose 26 and cannot substitute for an ordinary
AnchorRequest signature.

`inspect_metadata` returns a `PendingWriteRecoveryInspection` with read-only
`source()` and `target()` descriptions. It checks the metadata commitment and
scope, both view heads, complete bounded framing and record ordering. Unknown
tags, incomplete fields, oversized counts and trailing bytes are refused before
the result is returned. The decoder preserves all record fields, including
unknown delivery outcomes, retained reservations, consumed holes and prior
closure data. Roster and publication public histories remain complete byte fields
for domain-specific verification against independently trusted material.

Inspection performs no I/O, signature verification, witness mutation or device
activation. It is not proof that the supplied descriptions match encrypted
device state or an approved business effect. Keep this distinction when presenting
the views to an operator: a proposed target is not a delivery receipt or an
authorization. The controller's independent approval is still required.

A fresh controller mutation requires an expired witness authority, exact source
head and unchanged authority/policy binding. Frozen or retired subjects and
unacknowledged G/P/R slots are refused. The only mutation is the original target
head and original ordinary Advance command ID. Validity, policy, credential,
roster and writer fence are unchanged. Exact already-applied retries are read-only.

The local path accepts only an ordinary MAC-bound intent. G/T/P/R bound intents,
cancellation intents, account-root fences and missing original storage require
their own flows. Historical policy completion is obtained from the original
sealed enrollment and checked against both images; it is never fabricated from
an adopted-policy digest. The query/apply path grants no new permissions and
retains all pending state when fresh witness evidence is unavailable.

## Security and evidence boundaries

For a still-unapplied write, independent approval is a new decision to complete
this exact intent now. It is not evidence that the intent was created before
expiry. An already-applied original Advance can instead be confirmed with a new
read-only Query; it does not need another approval or a repeated mutation. The
controller's exact already-applied completion is also read-only.

An attacker holding the
old device state or signer may present requests and misleading descriptions.
The controller needs independent knowledge of the account and approved effect;
this flow cannot establish attacker eviction, private-key erasure or PCS. Device
replacement and account-root recovery retain their distinct trust requirements.

Native tests use actual journal/witness storage and signature providers with
explicit fixture clocks. They preserve original message accounting and closure
identity across unknown commit outcomes, staged G/T, and independent P completion.
Separate store tests cover expiry, a competing head, changed authority, a pending
G slot and account freeze. A real child process is terminated after witness
commit but before returning; exact retry observes one mutation. Decoder controls
cover truncation, extension, malformed framing and noncanonical fields.

The browser `QPeriaptContinuityDevice` exposes the same preparation and exact
confirmation through its existing asynchronous operation owner. Preparation
returns `QPeriaptContinuityPendingWriteRequest`: retain `proposal()`, `metadata()`
and `signed_request()` before independent approval. Its `to_json()` supplies the
complete source and target views under schema 1; neither view is labeled committed.
Hexadecimal IDs and decimal-string u64 values preserve the original metadata.
`confirm_pending_write_recovery` takes the exact proposal, complete metadata,
original historical policy and independent witness pin. It creates no runtime.

Installed Chromium Worker checks use actual IndexedDB/OPFS, signed witness
requests, real authority expiry and a separate native control process. They cover
unapplied/already-applied writes, locally staged G/T, cancellation during Query,
Worker loss before confirmation and loss of the host result after local commit.
Each successful cohort retains original unknown-message accounting through G/T
completion and explicit report acknowledgement. Explicit cancellation returns
`Cancelled`; transport failure and cancellation are distinct outcomes. Both
require retaining the original approval and metadata after a missing result.

The C/Swift/Kotlin/Android enrollment bindings expose the same request and exact
confirmation. The [native binding checkpoint](../sdk-alpha1/evidence/20261014-native-pending-write-bindings/README.md)
records installed C/Swift/Kotlin process results and distinct Apple physical
ABI checks. Those results do not establish Android ART recovery behavior.

The [configured Android checkpoint](../sdk-alpha1/evidence/20261014-configured-pending-write-inspection/README.md)
adds actual-archive host JNI and physical API 37 ART execution through the public
configuration entry point. Its signed-TCP/fixed-SDK/unapplied route preserves a
real unknown delivery while independently approving the exact R2 roster write
after policy expiry. Query-only confirmation/retry do not restore activation.
The public controller inspector is checked against the complete original views.

The [Android recovery matrix](../sdk-alpha1/evidence/20261014-android-pending-write-matrix/README.md)
extends actual-package host coverage to all eight signed/TLS, fixed/recoverable
and unapplied/applied combinations. The accepted phone also executes the
TLS/recoverable/applied path, confirming existing history before any privileged
recovery call. Pre-call cancellation retains the original request on fresh-owner
reopen. This does not stand in for cancellation after a Query reaches the witness.

The [Android Query cancellation checkpoint](../sdk-alpha1/evidence/20261014-android-pending-query-cancellation/README.md)
adds held-response cancellation through the public owner, with actual-package
signed/fixed/unapplied and TLS/recoverable/applied routes and the latter on the
accepted phone. Native in-flight cancellation preserves witness218 and its
diagnostic; pre-call cancellation is302. Fresh-owner retries preserve the exact
intent, use fresh Query challenges and grant no expired activation permission.

The [Android process-loss checkpoint](../sdk-alpha1/evidence/20261015-android-pending-process-loss/README.md)
adds real application process exits while Query is withheld and after the public
confirmation returned but before its application result. The latter establishes
lost-result recovery, not a crash inside storage commit. Fresh owners retain the
original intent or authenticate its exact confirmed target; neither pending
absence nor the process exit alone is treated as success. The TLS route also
executes on the accepted phone, and both earlier cancellation routes are rerun.

The [Android continuation checkpoint](../sdk-alpha1/evidence/20261015-android-pending-continuation/README.md)
composes original pending recovery with independently approved protocol-policy
renewal, current-authority activation, original-message confirmation, epoch 1
rekey and a fresh consumed message. The already-applied TLS route also runs on
the accepted phone. Recovery alone still grants no expired traffic permission;
the receiver's separate renewal and both approving roots are part of this flow.

The [physical Swift checkpoint](../sdk-alpha1/evidence/20261015-apple-pending-recovery/README.md)
adds configured pending-write recovery on the offered iPad using the actual Apple
binary package. Its signed-witness fixed/unapplied and recoverable/applied routes
retain a real unknown delivery through expiry, exact confirmation and pre-call
cancellation. All 39 app launches have run-bound startup and terminal receipts.
The [physical Swift interruption checkpoint](../sdk-alpha1/evidence/20261015-apple-pending-interruption/README.md)
adds in-flight Query cancellation and two real process-loss boundaries for both
signed/fixed/unapplied and TLS/recoverable/applied writes. Its 90 distinct app
processes include four actual exits with mandatory container readback. Native
code 218, exact intent, fresh Query challenges and expired-activation rejection
remain intact. The [physical Swift continuation checkpoint](../sdk-alpha1/evidence/20261015-apple-pending-continuation/README.md)
then composes recovery with independently approved policy renewal, current-authority
activation, original-message confirmation, epoch 1 rekey and a distinct consumed
message. Its two fresh routes execute 121 app processes and four real exits;
each native receiver retains exactly the original and new business effects.
This confirms continued traffic, not post-compromise secrecy or power-loss recovery.

These checks share the same protocol engine. They do not establish an independent
implementation, mobile-browser or power-loss equivalence. Storage-internal cuts,
remaining binding process/cancellation and continuation paths, and complete
lifecycle composition remain open alongside the wider 0.2.0 gates.
