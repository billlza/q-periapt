# Reference-host enrollment exchange

`qperiapt_continuity_reference.enrollment_exchange` connects the existing
independent `Registration` owner to public JSON exported by the optional native
reference host. It adds no account service, browser-cookie dependency, key export
or replacement crypto implementation. An embedding application can provide its
own authenticated administrator or account-authorization channel.

This adapter is an input/acceptance boundary. A complete installed command-line
consumer, persistent host configuration/bootstrap workflow, operational policy
publisher and real browser-to-device qualification are still being integrated.
The existing test issuer must not be relabelled as production account authority.

## Independent inputs

Keep these inputs separate from an incoming issuance response:

- `HostAuthority.from_trusted(...)` reads the browser's **client authority profile**:
  `schema = "qperiapt-host-authority/1"`, application byte array, root revision,
  public root and policy family. Authenticate this provisioning channel first.
  The method name and file schema are requirements, not proof of authenticity.
- `HostInvitation.decode(..., authority)` checks an invitation against that
  authority. Its existing `Intent` feeds `Registration.provision` or the original
  `Registration.open`. Preserve the same host-retained registration ID, wrapping
  key, intent and private directory; do not generate replacements on open errors.
- `PolicyInputs.from_trusted(pins, materials)` consumes separately provisioned
  policy expectations and signed distribution bytes. `verify(authority, now)`
  authenticates both policy layers and requires the invitation's actual family.
- `CurrentMembership.from_trusted(..., authority)` reads a separately obtained
  current root/complete-roster observation. It must match the same authority and
  supplies the current checkpoint. An old issuance cannot choose this checkpoint.

The policy-pin JSON has exactly `schema = "qperiapt-policy-pins/1"`, `sdk_root`
(1952-byte base64url public key), `sdk_state` (36-byte base64url trusted state),
`policy_root` (1985-byte base64url hybrid key), `policy_version` (integer),
`policy_digest` (32-byte array), and `witness`. `witness` is explicitly null for
the local-only profile, or exactly `{identity: byte-array, key: base64url}` for
the independently pinned witness. The signed policy must permit that selection;
there is no automatic fallback to local-only storage.

The separate material JSON has exactly `schema = "qperiapt-policy-materials/1"`,
`sdk_document`, `sdk_signature` and `policy`, all canonical unpadded base64url.
The existing independent verifier checks the fixed supported SDK profile, both
signature layers, exact pinned versions/digests, current policy validity and
witness binding. This does not add a second policy verifier or mint new pins
from the received material.

All JSON inputs have explicit size bounds, exact field sets, duplicate rejection,
canonical byte encodings and integer type checks. Host revisions preserve the
full unsigned 64-bit range; protocol counter/validity rules remain the existing
candidate's rules. Booleans and fractional values cannot stand in for counters.

## Accepting the original operation

Obtain the original request from the protected `Registration` owner, submit it
through the host's separate approval workflow, and parse the returned JSON with
`IssuedEnrollment.decode`. Then use:

```python
from qperiapt_continuity_reference.enrollment_exchange import accept_issued

journal_id = accept_issued(
    owner, original_invitation, approved_invitation, issued_response,
    independently_current_membership, policy_inputs, trusted_now,
)
```

`approved_invitation` is independently selected by the authorized host/operator.
It may be the original invitation or an explicitly approved successor. It must
retain the original application, root revision and complete device intent; the
response cannot select an operation or silently extend credential validity.

The adapter verifies the historical response's operation, certificate, roster
signature, membership and checkpoint separately. It then calls the existing
`Registration.accept` with the **independent current roster**, original device
signer, live policy and trusted time. The returned child journal ID is retained
preparation state, not permission to send traffic. Existing bootstrap and session
operations retain their own authority checks.

An expired host approval deadline does not invalidate an already committed,
currently valid credential. Issuer suspension fences future issuance; it is not
device revocation. Current roster removal, credential/roster expiry or policy
failure still refuse acceptance. An expired **unissued credential interval**
requires the separate authorized transition still under development; do not
backdate an issuer call, fabricate past acceptance or reset the original owner.

## Verification boundary

`tests/enrollment_exchange.py` uses actual OpenSSL signatures and encrypted
registration journals with fresh test issuers and explicitly selected package
and provider paths. It checks original-owner reopen, current roster removal,
historical/current separation, operation and intent substitutions, invalid policy
signatures/pins, exact integers and malformed input. Its simulated future expiry
input is not an elapsed-time observation. These tests do not establish host login,
native issuer interoperability, real browser approval or an operational policy
publisher. Source and installed-wheel runs are distinct evidence.
