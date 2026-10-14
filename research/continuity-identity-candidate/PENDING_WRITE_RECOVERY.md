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
2. An independent controller authenticates the account and intended effect. It
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

Independent approval is a new decision to complete this exact intent now. It is
not evidence that the intent was created before expiry. An attacker holding the
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

Installed browser/foreign bindings, asynchronous cancellation and storage-failure
qualification for this new entry point remain open. Native tests and WASM
compilation do not establish those results or complete the 0.2.0 release gates.
