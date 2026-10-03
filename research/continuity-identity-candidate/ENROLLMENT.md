# Original device enrollment

Status: unpublished native candidate, `qperiapt-enrollment/1`. This coordinates
local request persistence, exact credential admission and the existing installation
state machine. It does not provide an account login service, network enrollment
transport, credential replacement, root replacement or a finished product lifecycle.

## Inputs and first use

The application supplies an independently trusted account root and an approved
`DeviceDescription` (device ID, generation, policy family and finite validity).
These become an `EnrollmentIntent`. The authority verifies a request against its
own approved intent; an incoming request cannot select those expectations.

Explicitly provision the file-backed `JournalKey` once and keep its file outside
journal backups. `EnrollmentPaths::new` binds that existing key file, the future
signer file, enrollment database and three `InstallationPaths` files. All six
paths must be distinct canonical absolute paths with admitted private parents.
`DeviceEnrollment::provision` opens the existing wrapping key and commits a fresh
`SigningKeyId` and exact scope before creating a signer. It refuses existing signer
or installation files. `open` never selects provisioning after an error.

`request(now)` creates or reopens the signer for that committed ID, constructs the
dual-signed proof of possession, commits the exact request, then returns its bytes.
Once the request is committed, retries return those same bytes and public key.
No raw signing seed or wrapping-key accessor is introduced.

On the authority side, `VerifiedEnrollmentRequest::verify` authenticates the exact
approved intent and both key components. The host must independently authenticate
and authorize the user's account action before calling `RootSigningKey::issue_enrollment`.
It must also maintain and sign its current complete roster. Proof of possession
is not account membership, registration approval or a freshness oracle.

The client calls `accept` with the certificate, roster, an independently obtained
current `AccountPin`, and the live verified protocol policy. Both the original
signer and the complete approved description must match. Acceptance commits the
original request, credential, roster/checkpoint, policy binding and one future
journal ID. It neither trusts a checkpoint selected by an untrusted response nor
permits a different accepted credential/roster/policy to replace this transaction.
Equivalent signatures over the same accepted credential body may read back the
original acceptance; they do not replace its stored bytes or journal ID.

## Installation and restart

| Enrollment status | Next action and meaning |
| --- | --- |
| Preparing | Call `request`; only this committed intent may create its absent signer. |
| Requested | Resend the exact request or admit the independently authenticated response. No installation exists yet. |
| Accepted | Call `prepare` to create/reconcile the original empty installation. Retain any required witness genesis and enroll it through the independent authority. |
| Activating | Retry `activate` with the original policy and required witness. Activation may already have committed in the installation. Do not recreate or reprepare children. |
| Active | Reopen/activate the original installation. Missing configuration, journal or archive storage remains an error. |

`prepare` delegates child creation and genesis reconciliation to `DeviceInstallation`.
`anchor_client` constructs the client from the original controlled signer, an
explicit carrier/timeout and the independently pinned witness required by that
policy; callers do not have to reopen signing-key files themselves.
Its retained journal ID is supplied by the already committed acceptance; a failed
or interrupted creation cannot choose another ID. Required witness configuration
cannot become local-only on failure.

Before invoking installation activation, the enrollment owner commits Activating.
After installation activation commits, it commits Active and rechecks the live
policy before returning `EnrolledDevice`. Any failure releases no operational
owner. The enrollment can therefore be Active even when its caller received an
error; reopen the original record and retry the original activation.
`EnrolledDevice::parts` borrows the existing `DeviceService`, signer and verified
local identity. The enrollment lease remains held until this result is closed or
dropped. Operational SDK policy, roster, expiry and traffic checks still apply.

## Formats and trust boundaries

The request has the existing fixed dual-signature envelope. Its body is:
`QPENRQ01 || signing_id[32] || account[32] || device[16] || generation[u64be] ||
valid_from[u64be] || valid_until[u64be] || family[32] || public_key[1985]`.
Its signature purpose is the new value 14. Existing signature-purpose values,
credential/roster formats, SDK KAT inputs and hybrid implicit rejection are unchanged.
The public signing ID is correlation data, not entropy or authorization.

`QPENST01` stores the scope binding, signing ID and phase. Accepted phases retain
bounded request/credential/roster fields, exact roster and policy commitments and
the original journal ID. The image is authenticated with a distinct HKDF-derived
HMAC key under the wrapping owner. Each variable field is capped at 8192 bytes;
the whole image is capped at 24 KiB. Database access uses the shared exclusive
private-file backend and immediate transaction durability.

The enrollment record is trusted local configuration, kept independently of journal
backups. Its MAC detects unauthenticated edits; it is not an anti-rollback witness.
Initial partial wrapping, signer or configuration files are retained and refused.
This version cannot reconstruct a signing seed that never reached complete durable
storage, and does not delete the partial file or generate a replacement identity.
Hardware key storage, atomic first-key publication, independent authority transport,
foreign bindings, current device runs and complete replacement/upgrade remain open.

The regression suite covers actual signature/policy checks, real SDK prekey work,
exact restart, exclusive leases, request/acceptance/activation sync faults, process
interruption after commits, Active child loss and policy closure at final release.
These selected cuts are not physical power-loss or full lifecycle qualification.
