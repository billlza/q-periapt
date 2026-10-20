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
For `serve`, it bounds startup and each accepted request; the listener continues
until SIGINT or SIGTERM and joins its actual worker before reporting Stopped.
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
`deliver` and `resume` additionally close their private owners before waiting for
the network, then reopen the same client/session to verify the ACK under current
authority. Their original deadline spans both phases. The public prepared
ciphertext is bound to its original journal/session/message and grants no new
permission. A late cancellation, changed authority or invalid reply leaves an
explicit unknown outcome even when the peer already consumed the message.

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
Each rekey flight closes the private owner before network I/O and reopens it to
authenticate the reply, allowing incoming control to advance the same original
target during the wait. Already-committed receipts remain explicitly replayable.
An empty carrier reply cannot establish completion without authenticated local
history. The original deadline and cancellation cover every phase.

Session commands and receivers allow at most 64 attempts to obtain the original
client's initial directory lease, separated by at most 25 ms and limited by the
same deadline/cancellation. Only actual lease contention is eligible; journal
recovery and protocol operations are never retried implicitly. Exhaustion
returns an explicit busy result. Ordinary `EnrollmentClient.open` remains
nonblocking unless its caller supplies a `Run` for this admission boundary.

For a signed required-witness profile, non-prepare commands additionally need
`--witness-address IP PORT`. The owner verifies the pinned witness. Supplying a
witness to a local profile or omitting one from a required profile fails.
The CLI does not enroll a new witness or downgrade its requirement.

## Receive on the original confirmed connection

Create an empty private directory outside the client and SDK session directories.
Provision a separate host inbox for the original confirmed session:

```text
... provision-inbox --session=<session-id> --inbox-directory /absolute/private/inbox
... serve --session=<session-id> --inbox-directory /absolute/private/inbox \
  --listen 127.0.0.1 9001
... read-inbox --session=<session-id> --inbox-directory /absolute/private/inbox \
  --message=<message-id> --output /absolute/private/new-message.bin
```

`serve` admits only messages and control flights for that original session, never
a new bootstrap. It validates current connection authority and the existing
inbox before printing Listening. Each complete frame reopens original owners
under its acceptance deadline, checks the session, and releases them before the
response. Incomplete frames hold no SDK owner. Exhausted busy/conflicting operations fail;
the service does not queue an unbounded set or retry protocol work implicitly.
Required-witness profiles still need their explicit `--witness-address`.

The reference host effect is storing the exact plaintext under its original
message ID. The existing encrypted exact-target journal commits that effect
before the protocol consumes the message and releases an ACK. Its key derivation
is separated from protocol storage and binds client, journal and session.
Matching retries retain the same effect; different plaintext for a retained ID
fails. The inbox retains at most 1024 deliveries and a 2 MiB aggregate image.
Capacity errors do not evict earlier deliveries. Each write publishes a complete
bounded image; this reference path makes no incremental-storage performance claim.
This inbox is host application data, with its own backup/rollback and wrapping-key
compromise scope. It does not extend SDK erasure guarantees to host effects.

After an interrupted initial inbox publication, use the explicit
`recover-inbox --session=<session-id> --inbox-directory PATH` command. It can
complete only the original authenticated creation intent. Ordinary opening,
serving and reading never initialize missing state. Do not replace a missing
inbox with an empty one. `read-inbox` exports an existing effect to a fresh private
file, without releasing a protocol acknowledgement or claiming current traffic
permission. Its JSON receipt contains identities and byte count, not plaintext.

Installed-package qualification uses actual native TCP and separate CLI
processes in both directions, simultaneous application sends and rekey, durable
inbox readback, lost acknowledgements, receiver SIGKILL/restart, exact retry and
detached control refusal/recovery. Inbox tests additionally cover four
initial-publication and five effect-commit process cuts. Cross-host deployment, positive required-witness CLI
qualification and complete CLI lifecycle acceptance remain separate work.
Explicit test authority does not establish real account authorization.
