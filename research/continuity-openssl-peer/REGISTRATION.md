# Original protected registration and borrowed device operations

Status: independent reference implementation, not an installed account service or
final product admission. It uses the existing native `qperiapt-enrollment/1`
request and the existing independent journal/session/renewal implementations.
There is no new network protocol or account-authentication scheme.

## First use and reopening

The host supplies an independently approved `Intent`: account root, exact device
ID/generation, policy family and finite validity. `Intent.from_trusted` decodes
those expectations; the method name is a trust requirement, not authentication of
a received response. An authority must authenticate the user and approve these
values independently before accepting a device's proof of possession.

1. Explicitly provision a private enrollment directory, retain a unique
   registration ID and wrapping key outside session backups, then call
   `Registration.provision`. The original signing identity and both private key
   seeds are committed in the encrypted journal before they can be used in a
   released registration request. The wrapping key is supplied by the host; an
   error or missing file never generates a replacement key.
2. `request(now)` commits and returns the exact dual-signed `QPENRQ01` request,
   using purpose 14. Reopen the same registration and retry the same request
   after an unknown response. Request retries return the original signed bytes,
   even though newly generated signatures would normally be randomized.
3. `accept` verifies the response against the original intent and signer, a
   separately obtained current device/roster pin, and independently pinned live
   SDK/protocol policy inputs. Acceptance commits one future child journal ID.
   A response cannot choose its own checkpoint or replace an accepted operation.
4. `prepare(child_directory, Inputs(...), now)` commits the exact original child
   path, context and complete public bootstrap inputs before creating that child.
   Local preparation returns its scope. Required-witness preparation returns the
   original genesis for separate, independently authorized enrollment; it does
   not grant traffic permission or fall back to local-only storage.
5. `session(now, transport=...)` borrows the original session under the registration
   lifetime. The first successful open commits Active before the borrowed object
   escapes. Use the existing initial/final/activation and message/rekey methods.
   Rekey methods obtain the original controlled signer internally; no test signer
   file or private seed accessor is needed. Every operation retains its existing
   current-authority and output-release checks.

`Registration.open` only opens existing original state. The explicit
`recover_initial=True` option reconciles a revision-one initial creation intent;
it cannot open advanced registration as first use. New device creation reserves
`.stage-initial-intent` for the original sealed transaction. If the process stops
after that complete record is synced but before its formal rename, the creation
reader authenticates its MAC, expected scope, revision-zero predecessor and
revision-one target before publishing exactly those bytes. Partial or corrupted
records fail without replacement. No directory search selects an older random
staging file, and an ordinary active reader never uses this creation slot.
Session/configuration journals keep their existing creation contract. This is
process-recovery evidence, not a newly established power-loss guarantee.

A prepared-but-unpublished
child can complete its original creation. An Active registration never recreates
missing child state. No arbitrary staging orphan is selected as a key or deleted
automatically. Expired inputs cannot authorize a new child creation.

Between acceptance and child preparation, `refresh_roster` can commit a newer
independently pinned roster for the exact same credential and admitted policy.
It checks live signatures, validity and membership, refuses rollback or a
different checkpoint at the same version, and preserves the original request
and future journal ID. Retrying the same checkpoint makes no state write.
Preparation fixes the child context, so refresh refuses after any child intent
has committed. This transition does not renew expired credentials or policy.
The reference-host `adopt_extension` transition described in
[ENROLLMENT_CLIENT.md](ENROLLMENT_CLIENT.md) separately admits a same-key,
explicitly approved extension and independently pinned current policy before any
child intent. It preserves original admission and proof alongside a bounded
successor record; the original future journal ID and signing owner stay fixed.

The original bootstrap inputs are retained inside the authenticated encrypted
registration. Reopening does not need the test issuer directory or a fabricated
old timestamp. Historical reconstruction uses the original context commitment and
actual supplied time; current device/peer/policy/witness gates still belong to the
original session. Persisted Active is progress, not a live permission receipt.

## Lifetime and existing recovery flows

Use borrowed owners in a `with` block or close them explicitly. One child owner is
borrowed at a time. Closing the registration revokes its existing child and signer
capability; reopening the same storage does not revive an older borrowed object.
Revocation happens before child cleanup. If child cleanup raises an exception,
the parent still attempts to release its own journal lease and remains unusable;
the cleanup error is returned to the caller. A fresh owner must reopen the same
original storage to continue.
Calls acquire the registration lease before the child protocol lock. Nested calls
are refused while reentrant close may withhold a result after a committed write.
Errors preserve the original durable state and require explicit fresh-owner retry.

`credential_renewal(operation, now, ...)` delegates to the existing local or joint
coordinator. Local staging/commit and witnessed prepare/independent approval/commit
remain distinct contracts. `pending_write_recovery(now, transport=...)` delegates
to the existing metadata preparation and fresh-Query exact confirmation. The
historical device signature cannot approve that privileged completion. Recovery
alone does not extend validity or restore traffic permission. Original messages,
reservations, epoch history and their unknown outcomes remain in the original
session journal.

## Storage and scope

`QPREGS01` is an unpublished, bounded 128-KiB local payload inside the existing
AESSIV/MAC journal transaction. It retains the signing ID, encrypted seeds,
original signed request, accepted credential/roster/policy commitments, one future
journal ID and the original child installation. `QPREGIN1` bounds complete retained
public inputs to 112 KiB. Those inputs include sensitive account/device metadata;
they are not logged or automatically transmitted. The child wrapping key is derived
under a separate registration/child-scope domain. Existing session formats and
protocol cryptographic domains are unchanged.

Explicit pre-child extension adoption selects `QPREGS02` with a 192-KiB ceiling,
retaining the original `QPREGS01` admission and the latest successor separately.
The old tag and limit remain unchanged for clients that have not adopted an
extension. Old readers refuse the new tag; opening alone performs no upgrade.

The registration configuration is local authenticated state kept outside session
backups. It is not itself a rollback witness, including when its child requires a
witness. Restoring the entire registration and wrapping-key configuration is a
separate threat boundary. Python temporary secret bytes do not promise physical
erasure, and this API is not isolation against a hostile process hosting Python.
There is no public private-key export operation.

This reference currently owns one original pairwise child installation. It does
not establish same-account/multi-session coordination, policy or witness/root/
device replacement, deployed account authentication, power-loss durability,
post-compromise secrecy, final ABI or full 0.2.0 lifecycle admission.

## Qualification control plane

The optional native counterpart `--registration` mode publishes its independently
selected intent before reading the device request. It invokes the real
`VerifiedEnrollmentRequest::verify` and `RootSigningKey::issue_enrollment` APIs
before issuing the credential; an incoming request cannot choose the expectation.
Controller command 38 retries only the original signing identity/public key and
returns the retained original credential. This trusted fixture lane is not an
account login endpoint or ordinary device authorization mechanism.

`registration_checks.py` exercises fresh process owners and real SIGKILL cuts,
actual native issuance and traffic, rekey, same-key renewal, required-witness
expired pending-write recovery, stale child rejection and original-state retry.
The private enrollment/session stores and wrapping configuration remain outside
public captures. Native traffic retains fixture time 170 while the independent
owner and witness cross their signed expiry; that is not both peers' complete
production lifecycle.
