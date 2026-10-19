# Local independent enrollment client

The installed reference package includes `enrollment_client.EnrollmentClient`
and `python -m qperiapt_continuity_reference.enrollment_cli`. They prepare one
original device, export its possession proof, reopen its protected state and
accept an externally approved credential. No account login, browser cookie,
Passkey or Q-Periapt account service is required by these interfaces.

This is an unpublished reference consumer on Apple Silicon/macOS and Linux
x86_64, using CPython 3.14 and the pinned OpenSSL provider. It is not the final
0.2.0 product entry point. Session opening/traffic, ongoing credential renewal,
policy updates, device/root replacement and multi-session coordination are not
yet exposed through this CLI. Do not treat `Accepted` as traffic authorization.

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
has no time override. An operational policy publisher and actual authenticated
browser-to-client ceremony are still outstanding; test-issued policy files do
not substitute for them.

## Recovery and failure boundaries

`open` (used by every command except `begin`) never invokes device provision.
It reopens the configuration and original device, then completes a pending
configuration readiness commit. A missing initial configuration head can be
recovered only from its authenticated original revision-zero intent. A missing
device head can be recovered from the original creation intent only while the
configuration is still preparing. An established client cannot switch back to
first use.

Real process-kill tests cover original device-intent publication, configuration
readiness-intent publication and request commitment. They compare the recovered
encrypted device image with the exact target retained before the kill, then
check the original signed request and acceptance across reopen.

There is an explicit unresolved first-use boundary: if the process stops before
the original device creation intent is formally published, no discoverable
original device journal exists. `open` fails with `MissingState`; it does not
promote an arbitrary staging file or generate a replacement key. Likewise, a
configuration committed before device creation cannot itself recreate a device.
The tests retain these failed directories. No device proof has been exported at
these cuts, but this client does not yet provide an authorized abandonment or
restart transition for them. Do not erase them to make recovery appear to pass.

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
