# Local independent enrollment client

The installed reference package includes `enrollment_client.EnrollmentClient`
and `python -m qperiapt_continuity_reference.enrollment_cli`. They prepare one
original device, export its possession proof, reopen its protected state and
accept an externally approved credential. No account login, browser cookie,
Passkey or Q-Periapt account service is required by these interfaces.

This is an unpublished reference consumer on Apple Silicon/macOS and Linux
x86_64, using CPython 3.14 and the pinned OpenSSL provider. It is not the final
0.2.0 product entry point. The API owns one registered child session and exposes
its existing traffic, rekey, credential renewal and exact witnessed recovery
operations. The CLI still exposes enrollment only. Policy updates, device/root
replacement and multi-session coordination remain separate gaps. Do not treat
`Accepted` as traffic authorization.

## Host responsibilities and original state

Before first use, the embedding host supplies:

- A stable nonzero 32-byte local client identifier and a 32-byte wrapping key.
  Retain both across restarts. Assign a distinct identifier to each client;
  neither is inferred from an incoming issuance response.
- The independently authenticated authority profile and original invitation
  described in [ENROLLMENT_EXCHANGE.md](ENROLLMENT_EXCHANGE.md).
- An existing empty directory, owned by the user and mode `0700`, at an absolute
  path without symlink components.

The client stores the original authority, invitation and registration identity
in the existing encrypted `Journal`. A separate existing `Registration` journal
owns the device key and original signed request. The configuration contains no
copy of the signing seed. A parent directory lease serializes this coordination
across processes; child owners retain their own leases and validation.

The API accepts the wrapping key from the host. The CLI reads it from a regular,
singly linked, mode `0600` file in a private `0700` directory. It never accepts a
secret on the command line or prints it. This filesystem profile is not an OS
keystore, rollback witness, hardware key or claim of cryptographic erasure.

## Commands

Use the inspected, locally installed wheel and the pinned provider from the
existing package installation workflow. With that environment's Python:

```text
python -I -B -m qperiapt_continuity_reference.enrollment_cli \
  --provider-root /absolute/provider-site-packages \
  --directory /absolute/private/client \
  --client-id <original-64-hex-character-client-id> \
  --key-file /absolute/private/host/wrapping-key.bin \
  begin --authority /absolute/authority.json --invitation /absolute/invitation.json
```

All commands use the same four global arguments. `begin` is explicit first use
and rejects a nonempty client directory. It commits configuration readiness
before returning any public device identity. After that, use:

```text
... status
... request --output /absolute/private/exports/original-request.bin
... accept --approved /absolute/approved-invitation.json \
  --issued /absolute/issued-response.json --current /absolute/current-membership.json \
  --policy-pins /absolute/policy-pins.json --policy-materials /absolute/policy-materials.json
... refresh-roster --current /absolute/current-membership.json \
  --policy-pins /absolute/policy-pins.json --policy-materials /absolute/policy-materials.json
```

`request` writes the binary format consumed by the reference browser's request
file control. The destination directory must already be private. A destination
file is created exclusively and never overwritten. A failed/partial export is
retained; export to a new filename to retrieve the same committed request. Do not
repeat `begin`. No fresh signing operation is selected when retrying a committed
request. JSON on stdout contains only public status or the export path/digest.

The host/operator separately authorizes that proof. When accepting the result,
the approved invitation is explicitly selected, the current membership comes
from the host's independently authenticated current observation, and policy
pins come from independent provisioning. The issuance response cannot replace
those inputs. Current roster removal, wrong authority, malformed inputs, policy
failure or expired credentials still fail. The CLI uses the host OS clock and
has no time override. The [reference host](../continuity-reference-app/README.md)
provides separate account authorization and protected policy-publisher tools;
test-issued files do not substitute for an actual host authorization ceremony.

Before preparing a child, `refresh-roster` (or the corresponding
`client.refresh_roster(current, policy_pins, policy_materials, now)` API) adopts
a newer independently pinned, signed roster that still includes the exact
accepted credential. It preserves the original device, request, policy and
future journal identity. Lower versions and different digests at the retained
version fail; retrying the same checkpoint verifies current authority without
rewriting state. Once child preparation has committed, this operation refuses
to retarget its context or witness genesis.

Roster refresh does not renew credentials or policy, undo revocation or replace
an account root. Keep expired clients' original state. The separate explicit
extension adoption below handles the reference host's same-key extension;
restarting enrollment, changing the clock or refreshing a roster cannot replace it.

## Extension before a child is prepared

The host must independently authorize and issue a credential extension. Retain
its exact request and original issued-enrollment invitation, including any host
reapproval successor. The initial invitation's operation ID is not necessarily
the operation that issued the accepted credential. The response cannot choose
either approval or the current trust inputs.

```text
... adopt-extension --approved-enrollment /absolute/issued-enrollment-invitation.json \
  --approved-extension /absolute/approved-extension-request.json \
  --issued /absolute/extension-response.json --current /absolute/current-membership.json \
  --policy-pins /absolute/current-policy-pins.json --policy-materials /absolute/current-policy-materials.json
```

The API is `client.adopt_extension(approved_enrollment, approved_extension,
issued, current, policy_pins, policy_materials, now)`. It requires the original
root, device, generation, family and complete signing key, a strictly longer
credential interval, the exact preceding adopted extension, and monotonic roster
and policy checkpoints. The signed target credential, current membership and
independently pinned policy must all be valid at `now`. Root issuance suspension
does not revoke a previously issued result; current roster removal still refuses
adoption. The existing signed policy determines any required witness.

Adoption preserves the original configuration, invitation, proof, accepted
credential and future journal ID. It records the latest extension separately in
`QPREGS02`, bounded at 192 KiB; original `QPREGS01` records retain their 128-KiB
limit and are not rewritten on open. Older readers reject the new tag. Reopening
reconciles the exact journal transaction after an unknown result; retry the same
approval and result. The public status reports the retained extension identity.
Repeated adoption does not accumulate an unbounded list of old extensions.

Only an accepted client with no prepared child may adopt an extension. Once
preparation commits a child context, use its existing lifecycle operations.
`request` still exports only the original time-bound proof and may refuse after
its original interval ends; adoption authenticates that retained proof as history
without making it a new authorization. A separate current policy is necessary
when the old policy has expired. These transitions do not issue the existing
retained-session grant G or authorize old traffic.

The [native enrollment candidate](../continuity-identity-candidate/ENROLLMENT.md#fresh-credential-extension-before-installation)
also supports this transition for positively tracked Unprepared records; legacy
Accepted records still require explicit history reconciliation. The installed
independent client now completes a native durable handshake, bidirectional
traffic, PQ rekey and owner reopen after extension in both local and witnessed
fixtures. Browser approval control and the complete live host-to-peer recovery
path remain open; fixture authorization and clocks do not establish those claims.

## Registered session and recovery API

After acceptance, call `client.prepare(session_directory, inputs, now)` with the
existing independently trusted `registration_inputs.Inputs`. The private child
directory must be outside the client directory and cannot contain it. This
commits its original path, context, public inputs and journal identity before
preparing the child. Retry that same preparation after an unknown result;
never select a different path or create a replacement registration.

`with client.session(now, transport=...) as session` borrows the existing
bootstrap, traffic and rekey operations described in [REGISTRATION.md](REGISTRATION.md).
The client retains the signing owner; callers do not supply a signer or access
private seeds. Required-witness preparation still returns genesis for separate
authorized enrollment. It never falls back to a local session.

After authenticating the reply and exporting the original final flight, close
the borrowed child and pass the received READY session ID and epoch-zero ACK to
`client.confirm_connection(session_id, proof, now, transport=...)`. This method
authenticates the ACK through that original child, then commits the exact public
confirmation inside the encrypted registration journal before returning success.
A locally Active registration or Traffic session alone does not imply this
confirmation: a valid initial ACK at consumption prefix zero need not change
the traffic journal.

Use `client.connection_session(now, transport=...)` to borrow recorded confirmed
traffic. It reopens the same child, checks current authority and required witness,
and verifies the original session ID without activating a pending handshake.
The returned child exposes traffic, control and maintenance operations; it has
no `initial`, `finish` or `activate` capability. This is a local session owner,
not a network liveness probe or a completed network connection facade.
`client.connection_confirmation()` returns a historical session ID, or `None`
when no proof has been recorded. Neither result grants current traffic authority.

Confirmation adds a bounded `QPREGC01` envelope around the unchanged canonical
`QPREGS01` or `QPREGS02` payload: 125 bytes for its tag, length, session ID and
81-byte ACK. Existing images are not upgraded by reading them. Older readers
refuse this envelope; use a reader supporting confirmation once explicitly
recorded. The child session codec and cryptographic domains do not change.
Exact confirmation retries preserve the parent image, including after rekey;
they admit current traffic rather than reauthenticate with retired epoch-zero
keys. A different proof or ID fails. For an old session with no recorded proof,
confirmation still requires the authentic original ACK and its retained epoch
state; no confirmation is inferred from phase, files or later local activity.

After an unknown confirmation result, reopen the original client. An authenticated
formal intent recovers its exact target; unpublished random staging is retained
and does not imply confirmation. If no proof was committed, retry the same
READY. Missing original child traffic fails; reopening never creates replacement
traffic to make the historical parent record appear usable.

The same owner exposes `credential_renewal(operation, now, transport=...)` and
`pending_write_recovery(now, transport=...)`. They retain the existing original
grant, independent approval and fresh-Query requirements. An unresolved send
reservation must be recovered by its original identity before selecting a
different message. Recovery alone does not extend authority or grant traffic.

Client, registration and borrowed operations share one reentrant lock, and every
borrowed operation checks the outer directory lease as well as its own journal.
Closing the client revokes existing children; a new client cannot revive them.
An operation failure closes the owning client and releases its configuration
lease. Reopen the original client explicitly. Reentrant close can withhold a
result after durable commitment; resume that original operation after reopening.
The borrowed-session facade itself changes no session storage format or
cryptographic domain. Explicit pre-child adoption and peer confirmation use the
registration formats described above.

## Owned connection operations

For the supported initiator profile, `client.connect(carrier, run)` coordinates
the original initial/reply/final flights and the authenticated READY commit.
If that commit already exists, it opens the confirmed original child without
another bootstrap. `client.reopen_connection(run)` requires that record and
performs no network exchange. Both accept a separate `witness_transport` for a
required-witness child; the application carrier cannot replace it.

```python
from qperiapt_continuity_reference.connection import Consumption
from qperiapt_continuity_reference.connection_run import Run

with client.connect(carrier, Run(30)) as connection:
    message = connection.next_id(Run())
    # Retain message and original associated data before delivery; a failed
    # invocation may have committed locally or at the peer.
    result = connection.deliver(message, plaintext, associated_data, carrier, Run(30))
    if result is Consumption.PREFIX_PENDING:
        # The authenticated prefix does not yet cover this message.
        result = connection.resume(message, associated_data, carrier, Run(30))
```

`carrier(request, deadline, cancellation)` exchanges one `QPCXCH01` frame and
returns response bytes. Frames are bounded at 32 KiB, matching the native
contract. A carrier supplies neither identity nor commit evidence. It must bound
its own allocations and honor the original absolute monotonic deadline and
one-way cancellation while blocked. Synchronous callbacks cannot be forcibly
interrupted; late results are rejected and the owner is closed. The included
interface is carrier-independent. The explicit `network.TcpTransport` and
`network_server.Server` provide bounded TCP exchange and owned incoming work;
see the [reference network contract](../continuity-reference-app/NETWORK.md).
This carrier exposes public metadata and is never a TLS fallback.

Each `Run` lasts more than zero and at most 120 seconds, uses real OS time by
default, and can receive a trusted host `clock` and `Cancellation` token.
`cancel()` works from another thread and has no reset operation. Every protocol
operation checks cancellation/deadline and current authority around dispatch
and result release. The connection serializes complete operations under the
client's owner lock; reentrant protocol operations fail, while reentrant close
withholds the in-flight result. Closing the connection releases its child borrow;
closing the client revokes all children. An operation error closes the client.

After any unknown delivery result, reopen the original `EnrollmentClient` and
call `reopen_connection`. `connection.status(message)` returns historical
disposition without claiming current permission. `Reserved` or `Committed` can
be resumed with the original ID and associated data; `resume` uses the exact
stored send intent/outbox and does not need replacement plaintext. `Acknowledged`
means that original ID was consumed, not that new plaintext for it is acceptable.
Retired/unknown resolution states require their existing maintenance operations,
after closing this borrow. No error creates a new message, journal or identity.

`connection.rekey(target, carrier, run, exchanges=8)` drives one explicit target,
with an allowance of 1 through 128 request/reply exchanges. It returns the exact
locally confirmed epoch and requests attempted in that successful invocation.
Allowance exhaustion closes the owner and retains the same target for recovery.
The unsigned empty carrier marker is accepted only if the local authenticated
state already proves that target completed. Neither completion nor an ACK
establishes fresh peer liveness or secrecy recovery from prior compromise.

`connection.serve_message(request, consumer, run)` handles the opposite application
direction on this original confirmed session. It authenticates and commits a new
inbox entry before invoking `consumer(session_id, message_id, plaintext)`. The
consumer must atomically commit its actual effect and deduplication by that ID,
then return `None`; errors and unknown outcomes must raise. A false return value
does not count as success. Only afterward does the connection durably consume
the message and release its authenticated ACK. A callback can run again after an
unknown result, so host deduplication is required. Stored host plaintext remains
outside SDK encryption and erasure guarantees.

For an already consumed ID, the connection returns the authenticated consumption
prefix without calling the consumer again. Below the prefix, old keys and input
commitments have been erased: this is historical consumption of the original ID,
not authentication or delivery of replacement bytes in the current request.
Bounded framing, session/direction identity, signed budget, admitted epoch and
receive cutover still apply. For out-of-order consumption still in the inbox,
the retained input commitment must also match. The lower-level
`receive_delivery` exposes explicit `PendingDelivery`/`PreviouslyConsumed`
dispositions; existing `receive` keeps its refusal of consumed plaintext replay.
No new session format or acknowledgement domain is introduced.

`connection.serve_control(request, run)` authenticates one peer rekey flight and
returns the original committed response or the carrier completion marker.
Together with `rekey`, it supports either proposer role after establishment.
Neither server method admits a new bootstrap through a confirmed session.

## Original storage recovery

`open` (used by every command except `begin`) never invokes device provision.
It reopens the configuration and original device, then completes a pending
configuration readiness commit. A missing initial configuration head can be
recovered only from its authenticated original revision-zero intent. A missing
device head can be recovered from the original creation intent only while the
configuration is still preparing. New device creation also has one fixed
`.stage-initial-intent` slot: a complete authenticated initial transaction there
can finish its original publication after a process interruption. Its scope,
MAC, revision-zero predecessor and revision-one target are checked before any
publication. Partial/corrupted contents and other staging filenames are never
selected. An established client cannot switch back to first use.

Real process-kill tests cover synced initial device intent before rename,
formal device-intent publication, configuration readiness-intent publication and
request commitment. Repeated kills during initial publication recovery retain
one exact slot without allocating another orphan. Tests compare the recovered
encrypted device image with the exact target retained before the kill, then
check the original signed request and acceptance across reopen.

There is an explicit unresolved first-use boundary: if the process stops before
any complete original device creation record is available, configuration alone
cannot recreate that device. Missing records fail with `MissingState`; truncated
or invalid records fail validation. Older random-name staging files are retained
but cannot be discovered through this new reserved-slot contract. No device proof
has been exported at these cuts, but this client does not yet provide an
authorized abandonment or restart transition for them. Do not erase them to
make recovery appear to pass. Existing formally published journals keep the same
format and reopen normally; no silent migration of incomplete old attempts occurs.

## Verification

`tests/enrollment_client.py` reuses the exchange test issuer and actual OpenSSL
signatures. It checks CLI subprocesses, exact request export/re-export, no
overwrite, independent policy/membership acceptance, wrong key/client ID,
exclusive ownership, retained authority and original-state recovery/refusal at
real `SIGKILL` cuts, including a committed roster refresh. It also checks roster
rollback/fork refusal and that refresh cannot change policy, restore revoked
membership or extend credential validity. Every private fixture is retained
outside public evidence.
The installed qualification driver binds all three test sources and all package
modules to Git, installs the wheel outside the checkout, and checks installed
bytes before and after the suites. This establishes the stated local behavior,
not real host authorization, physical-device acceptance or the full lifecycle.

`tests/enrollment_extension.py` covers explicit approval, expired original
credentials, current policy, monotonic checkpoints, signing-key/revocation
refusal, repeated adoption, CLI subprocesses, two real SIGKILL cuts and original
history preservation. A signed peer fixture exercises actual child preparation
and exact initial-flight replay after reopen; it does not complete a native peer
handshake after extension.

`enrollment_session_checks.py` additionally drives real native issuance, traffic,
rekey, same-key renewal and exact pending recovery through the public client API
for local and witnessed profiles. It checks parent closure, nested calls,
callback closure after commitment, outer-directory admission and original
ciphertext across reopen/renewal. Its clocks and issuer are explicit test inputs.
The installed-wheel driver runs this suite against the exact selected native
counterpart; this still does not qualify a live account's complete session path.

`enrollment_extension_session.py` covers the additional native interchange after
both the original credential and policy expire at fixture time160. Both peers
bootstrap at210 and exchange traffic/rekey at220. It preserves original issuance,
refuses retargeting after preparation and refuses use after the extended expiry.
Installed receipt schema2 requires both local and required-witness profiles,
including their selected native binary and installed client module identities.
Later G of this extended bilateral session is a separate outstanding check.

`continuity-reference-app/tests/native_exchange.py` connects the separately
supplied native enrollment/session CLIs to the installed independent publication
adapter and original client. Both endpoints generate their own controlled keys;
an explicit test issuer supplies approvals. At real OS time, the workload checks
publication signatures/proofs and independent pins, three-flight establishment,
authenticated consumption after a durable native inbox write, exact response
replay across native process restarts, and one PQ rekey followed by new-epoch
delivery. It also kills an isolated native probe before host commit, after host
commit before SDK consumption, and after SDK consumption before response export.
All three cases retry the original ciphertext/ID through the ordinary CLI. The
recovery gate still refuses old unclean images written without two-phase commits.
This profile uses a file carrier and independent-to-native data flow;
it does not substitute for bidirectional network deployment or the original real
account's complete lifecycle. See the [native session guide](../continuity-reference-app/NATIVE_SESSION.md).
