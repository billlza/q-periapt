# Original credential maintenance

The installed `qperiapt_continuity_reference.credential_cli` operates on the
original accepted client and established session. It does not create an account,
replace a device key, reset a journal or approve a witness transaction. Use the
same global `--provider-root`, `--directory`, `--client-id` and `--key-file` as
the [session CLI](SESSION_CLI.md). `--timeout` bounds one invocation to at most
120 seconds, including witness I/O. Operational calls use actual OS time.

This host adapter accepts one device's issuer response. Complete-account
transitions with companion grants remain available through the existing
`stage_account`/`prepare_account` borrowed-owner API; this CLI does not construct
or guess the complete companion set. The original coordinator rejects using the
single-device path for a session governed by complete-account state.

## Export and authorize the original request

Persist a fresh nonzero 32-byte operation ID before starting. IDs use canonical
unpadded base64url; use `--operation=VALUE` because a valid ID can start with `-`.

```text
... request --operation=<original-operation> --witness-address 127.0.0.1 9001 \
  --output /absolute/private/credential-request.json
```

The exported `qperiapt-retained-credential-request/1` comes from the original
protected enrollment, credential, roster and journal. It names the actual
predecessor and adopted policy authorization. Expired original metadata can be
read for recovery; the export creates no current traffic permission. A pending
G/R/P operation must be reconciled first, and a retained G operation ID cannot
be reused for a new request.

The account application independently authenticates the user, selects and
issues the same-key certificate extension, then approves the retained-state
grant. Preserve its exact issued response and independently provision the
current root/roster response through the host's trusted channel. Device key
possession and the exported request are not substitutes for account approval.

## Prepare, commit and recover

```text
... prepare --operation=<original-operation> --witness-address 127.0.0.1 9001 \
  --issued /absolute/issued-grant.json --current /absolute/trusted/current.json \
  --output /absolute/private/credential-preparation.json
... recover-preparation --operation=<original-operation> \
  --witness-address 127.0.0.1 9001 --output /absolute/private/recovered.json
... status --operation=<original-operation> --witness-address 127.0.0.1 9001
... commit --operation=<original-operation> --witness-address 127.0.0.1 9001
... recover --operation=<original-operation> --witness-address 127.0.0.1 9001
```

`prepare` correlates enrollment, root revision, operation, journal and selected
target roster with the original installation. The journal ID in the response
is correlation metadata; the signed grant binds the original device owner.
The coordinator verifies that signature and its declared statement before
retaining a target. It also requires the actual original predecessor and the
currently adopted live policy. A JSON response cannot supply a new trust root.

For the required-witness profile, preparation exports the native
`qperiapt-credential-witness-proposal/1`. The operator must separately authorize
this proposal with the issuer's response and independently selected account and
policy inputs. Until then, `status` reports `Unavailable` and `commit` fails.
`Unavailable` never proves that a commit did not happen.

After issuer, preparation or commit output loss, retain the original operation,
installation and files. `recover-preparation` exports the exact retained proposal
to a new filename while its intent remains present. After intent retirement,
use `status` or `recover` for the exact Applied/Closed outcome. `close-proposal`
requests definitive closure of a Prepared proposal; it cannot undo Applied.
Historical outcomes do not grant a live session.

For a local-only profile, omit `--witness-address`. `prepare` stages Pending;
`commit`, `status` and `reconcile-expired` retain the existing local contract.
Local expiration reconciliation records ExpiredUncommitted and a time floor.
The required-witness profile uses explicit witness closure instead. Supplying
the wrong transport profile fails; there is no automatic fallback.

All public files use exclusive creation in a private directory. Export or
stdout failure can follow a durable write. All successful commands close the
original owner before releasing a result. Once Applied/Committed is observed,
reopen the original session CLI to reconcile messages or rekey under current
authority; do not create a replacement session merely to hide an unknown result.

The host API equivalents are `client.credential_renewal_request(...)` and
`client.prepare_credential_renewal(...)`, followed by the existing lifetime-bound
`credential_renewal` child for commitment and recovery. Direct low-level owners
must explicitly supply their original `Inputs` at open to use the new request
export; omitting them leaves this export unavailable and does not substitute
external identity files for protected state.

## Validation boundary

`host_roster.py --independent-credential-renewal` adds independent G after
independent P to the existing authenticated native R/P/R/G workload. It checks
issuer output loss, mismatched journal/statement rejection before preparation,
exclusive export failure, exact proposal recovery, independent witness approval,
lost commit output, retired-operation rejection, original unknown-ACK recovery,
rekey and bidirectional traffic. Installed host-exchange schema 14 requires this
schema-5 workload. This actual-time flow does not wait for both endpoints to
expire and does not qualify complete-account CLI adoption, mobile acceptance or
post-compromise security.

Existing configuration schema 1 requires the explicit historical
[`bind-issuance`](ENROLLMENT_CLIENT.md#retained-issuance-association-and-existing-configurations)
step before a new issuer request or returned grant is associated with this
client. This preserves reapproval successors and does not renew expired authority.
