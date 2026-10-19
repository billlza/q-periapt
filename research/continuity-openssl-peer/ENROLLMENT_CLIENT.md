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
No stored format changes or new cryptographic domain are introduced here.

## Recovery and failure boundaries

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
real `SIGKILL` cuts. Every private fixture is retained outside public evidence.
The installed qualification driver binds both test sources and all package
modules to Git, installs the wheel outside the checkout, and checks installed
bytes before and after both suites. This establishes the stated local behavior,
not real host authorization, physical-device acceptance or the full lifecycle.

`enrollment_session_checks.py` additionally drives real native issuance, traffic,
rekey, same-key renewal and exact pending recovery through the public client API
for local and witnessed profiles. It checks parent closure, nested calls,
callback closure after commitment, outer-directory admission and original
ciphertext across reopen/renewal. Its clocks and issuer are explicit test inputs.
The installed-wheel driver runs this suite against the exact selected native
counterpart; this still does not qualify a live account's complete session path.
