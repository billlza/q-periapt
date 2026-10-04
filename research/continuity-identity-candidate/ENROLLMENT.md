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
| Active | Reopen/activate the original installation and recheck current local and required-witness authority. This persisted phase is not a live authorization receipt. Missing children remain errors. |
| Refreshing | A same-credential roster target and expected predecessor are durable. Reopen and `activate` the original installation; reconcile its original pending journal command, CAS the resulting roster, install the exact target, then complete Active. No replacement lineage or different pending target is allowed. |

`prepare` delegates child creation and genesis reconciliation to `DeviceInstallation`.
`anchor_client` constructs the client from the original controlled signer, an
explicit carrier/timeout and the independently pinned witness required by that
policy; callers do not have to reopen signing-key files themselves.
Its retained journal ID is supplied by the already committed acceptance; a failed
or interrupted creation cannot choose another ID. Required witness configuration
cannot become local-only on failure.

Before invoking installation activation, the enrollment owner commits Activating.
After installation activation commits, it commits Active and rechecks the current
journal roster, live policy and exact required-witness authority before returning
`EnrolledDevice`. All anchored enrollment activations, including first use and
ordinary reopening, require the signed authority-admission operation documented in
[the witness contract](ANCHOR_WITNESS.md); a head query is insufficient. Any failure releases no operational
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
Existing partial wrapping, signer or configuration destinations remain refused.
New immutable wrapping/signing files use complete staged publication, so a crash
before rename cannot expose a partial formal key. In Preparing, the enrollment's
committed original intent may retry an absent unpublished signer with the retained
SigningKeyId; once Requested, it must recover the exact original signer. Private
staging orphans are never selected as keys or swept automatically. Initial enrollment, installation, journal and archive databases now commit in
private staging and publish while retaining their original exclusive Database owner.
A failed initial enrollment publication can be retried only under its original
explicit first-use intent, before any released request or active identity. A
published configuration is always reopened; an active missing identity is never
replaced. Unpublished staging may survive either an error or process interruption. See [signing-owner recovery](SIGNING_OWNERS.md).
Hardware key storage, orphan maintenance, independent authority transport,
all-language archive qualification, Android/WASM persistence, current device runs and
complete replacement/upgrade remain open.

The regression suite covers actual signature/policy checks, real SDK prekey work,
exact restart, exclusive leases, request/acceptance/activation sync faults, process
interruption after commits, Active child loss and policy closure at final release.
These selected cuts are not physical power-loss or full lifecycle qualification.

The archive-shipped ordinary TLS connection now uses this owner from registration
through activation, original-state restart, bidirectional traffic and signed rekey.
The package gate binds public registration materials to the actual connection and
independent database-lease probes; see [installed connection](PACKAGE_CONSUMER.md).
The separate signed-TCP roster-refresh trace still uses the preconfigured
installation API. Expired-bootstrap restoration now retains the enrollment owner
and refreshes its original journal's current roster before reopening the session.
Enrollment still fixes its original credential/root/policy and does not accept
their replacement.

## Continuing an original identity under a current roster

`refresh_roster(previous, roster, pin, policy, now)` begins an explicit update of
an already Active enrollment. The independently supplied current pin and roster
must retain the exact original credential, root, device/generation, key and policy.
The original credential and enrollment intent must still be valid now. An expired
old roster is an expectation stored in authenticated configuration, not renewed
authority; a fresh roster cannot extend an expired credential or replace a key.

The method durably records `Refreshing { journal, previous, next }` before returning.
This reports local progress, not permission to communicate. Exact pending retries
retain the original signed target bytes. An already-current target can be read back;
that observation does not prove which invocation applied it. Different pending
targets, stale predecessors and same-version forks fail closed.

`activate` retains the enrollment lease while opening the original installation.
Opening an anchored journal first reconciles its exact original pending write.
Only then may its resulting roster equal the expected predecessor or exact target.
The existing `install_roster` operation preserves revocation/generation history,
commits the target, and reuses an already-current target without another advance.
After the final registration Active commit, a fresh signed witness check confirms
this exact authority and journal head before any owner is released. An original
pending revocation can therefore commit during recovery and subsequently cause the
refresh CAS to fail. Failure does not imply that the recovered original operation
had no effect. A newer journal head is not silently adopted or reset; conflicting
control-plane updates require explicit resolution and cannot replace this intent.

The witness operator must separately call `AnchorStore::update_roster_authority`
for the original subject and independently verified current device. The SDK's new
read-only check cannot perform that control-plane update. Even when the journal is
already at the target, an old or expired witness grant returns authenticated
`AuthorityDenied`, and no enrolled service is released. A lost confirmation may
leave local Active committed; reopen and obtain a fresh confirmation, never treat
the local phase or a Query reply as evidence of current witness authority.

Refreshing uses phase byte 5 in `QPENST01`, with the usual target admission fields
followed by `previous_version:u64be || previous_digest[32]`. The predecessor must
be strictly older. Existing phase 0–4 encodings are unchanged. Older candidate
readers reject phase 5; do not roll back readers while an update is pending.
This unpublished schema extension is not a general supported-version migration.

For an established session, authenticate its original public bundle with
`request_reopen` and call `DeviceService::reopen_peer` on the service borrowed from
`EnrolledDevice::parts`. This retains the enrollment owner while the existing
journal/archive checks admit the original context against current rosters. Do not
construct a new context to replace the original session or drop the enrollment
lease to call a lower-level installation constructor. The public TLS restoration
trace now exercises this route after both its initial roster and advertisement
expire, including an application effect committed before a lost receipt.

The selected regression cuts cover the registration intent, journal and final
registration commits, typed before/after-sync failures, stale/revoked journal
competition, a pending revocation recovered before CAS, expired/mismatched witness
grants and a lost signed authority confirmation. They do not constitute physical
power-loss qualification, all-language enrollment, credential/root/policy replacement,
or a complete multi-device/upgrade lifecycle.

## C ownership bridge

The unpublished C registration owner delegates this same transaction, from an
approved intent and explicit wrapping-key provision through request, acceptance,
storage preparation, activation and same-credential roster continuation. Successful
activation moves the entire `EnrolledDevice` into the existing device parent;
peer calls borrow its service/signer while its registration lease remains held.
It does not extract those parts into a lower-level installation owner. Missing
registration cannot select a legacy constructor or recreate a key. Failed native
transitions expose their original error and consume the C registration owner;
the caller disposes its handle and resumes the original state, including possibly
committed Active. SDK policy/store, application TLS configuration and independent
authority transport remain application integration inputs. See
[the C entry sequence](../../bindings/c/ContinuityPackageConsumer/README.md#registering-an-original-device)
and its header for input lifetimes, exact disposal and cancellation behavior.

Swift and Kotlin wrap this same C transaction with immutable public inputs and
six-phase status validation. Their setup/registration transfer cell moves one
native owning reference into the device only after successful activation; neither
ARC nor Cleaner owns a second wrapper for the same raw handle. On failed transfer,
the original language reference remains available for disposal. Successful transfer
makes closing an old registration alias harmless to the device. The package gate
requires observed old-wrapper release, separate-process lease exclusion, original
session retry and both witness carriers. These finite checks do not provide
Android/browser persistence or credential/root/policy replacement.
