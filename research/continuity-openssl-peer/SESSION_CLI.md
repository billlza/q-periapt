# Independent session commands

Use `python -I -B -m qperiapt_continuity_reference.session_cli` from the inspected,
installed reference package. It supports Apple Silicon/macOS and Linux x86_64
with CPython 3.14 and the pinned provider. Complete [enrollment](ENROLLMENT_CLIENT.md)
first; retain that original client directory, ID, wrapping key and public
authorization records. There is no account login or private signing-key export
in this CLI. This remains an unpublished reference consumer.

Each command uses these global arguments before the command name:

```text
python -I -B -m qperiapt_continuity_reference.session_cli \
  --provider-root /absolute/provider-site-packages \
  --directory /absolute/private/client \
  --client-id <original-64-hex-character-client-id> \
  --key-file /absolute/private/host/wrapping-key.bin \
  --timeout 30 <command and arguments>
```

The deadline is finite, at most 120 seconds, and is never restarted internally.
Commands use actual host OS time. Inputs are bounded regular files at absolute
paths; the wrapping key retains the enrollment CLI's private-file requirements.
No command silently initializes or replaces missing state.

## Prepare an independently selected peer

The host provisions this local plan through its trusted configuration channel:

```json
{
  "schema": "qperiapt-independent-publication/1",
  "session_directory": "/absolute/private/session",
  "peer_trust": "/absolute/trusted/peer-trust.json",
  "publication": "/absolute/received/publication.json",
  "credential": {"kind": "enrollment", "path": "/absolute/issued.json"},
  "policy_pins": "/absolute/trusted/policy-pins.json",
  "policy_materials": "/absolute/received/policy-materials.json"
}
```

Create the empty private session directory explicitly. `peer_trust` uses the
same `qperiapt-native-peer-trust/1` format as the [native session](../continuity-reference-app/NATIVE_SESSION.md).
It independently selects the directory ID, both account roots/current signed
rosters, devices and generations. The publication supplies signed advertisement
and proof bytes, never trust roots or filesystem paths. Its roster must match
the selected responder roster. Credential kind `extension` selects an already
adopted same-key extension; selecting its file does not adopt or authorize it.

```text
... prepare --inputs /absolute/trusted/publication-plan.json
```

The original client's accepted credential, exact local key, enrollment operation
and policy still must match. Successful preparation returns the original journal
identity. It does not establish a connection. After preparation, changing files
does not retarget the saved child; use the owner's explicit lifecycle operations.

## Connect, deliver and reconcile

```text
... connect --address 127.0.0.1 9000
... next --session=<session-id>
... deliver --session=<session-id> --message=<message-id> \
  --plaintext /absolute/message.bin --associated-data /absolute/ad.bin \
  --address 127.0.0.1 9000
... message-status --session=<session-id> --message=<message-id>
... resume --session=<session-id> --message=<message-id> \
  --associated-data /absolute/ad.bin --address 127.0.0.1 9000
... rekey --session=<session-id> --target 1 --exchanges 8 \
  --address 127.0.0.1 9000
```

Session/message IDs are canonical unpadded base64url. Use `--session=VALUE` and
`--message=VALUE`: a valid ID can begin with `-`, and a separate argument may be
parsed as an option. Save the exact session,
message ID and original inputs before delivery. Payloads are at most 16384 bytes;
associated data is at most 1024 bytes. Empty payloads and associated data are
valid. The endpoint is an explicit numeric IPv4/IPv6 address and port. The
carrier is **QPCXCH01/TCP**: inner protocol authentication and encryption, with
public routing metadata. It is not TLS and has no implicit fallback.

`connect` reports `peer_confirmation: "Recorded"` only after the owned API has
recorded peer confirmation. Reopening an already confirmed connection can return
this historical result without network I/O; it does not prove present liveness.
Every invocation closes the original owner before printing success. JSON output
contains public identities and outcomes, not plaintext or private keys.

After an error, timeout or interruption, a local or remote commit may already
exist. Query the original message and use `resume` with its original associated
data. `Committed` does not mean confirmed delivery. Resume preserves the original
ciphertext; it never creates a replacement ID to disguise an unknown outcome.
An authenticated historical `PreviouslyConsumed` outcome proves consumption of
that original ID, not authentication of arbitrary replacement bytes. The SDK
does not provide atomicity for arbitrary remote business effects.

Rekey retries retain the original target. Its exchange allowance bounds one
invocation; exhausting it leaves an explicit unfinished operation. Completion
reports an epoch and exchange count, not proof that an attacker lost knowledge.

For a signed required-witness profile, non-prepare commands additionally need
`--witness-address IP PORT`. The owner verifies the pinned witness. Supplying a
witness to a local profile or omitting one from a required profile fails.
The CLI does not enroll a new witness or downgrade its requirement.

This CLI provides the initiating command path. Hosts can use `Connection` and
the bounded `network_server.Server` for inbound durable effects; an independent
inbox daemon, concurrent bidirectional service and complete CLI lifecycle are
still separate work. The qualification uses actual native TCP, separate CLI
processes, durable inbox readback, lost acknowledgements, exact retry and rekey.
Its explicit test authority does not establish real account authorization,
cross-host deployment or positive required-witness CLI qualification.
