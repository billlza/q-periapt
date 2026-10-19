# Native reference session exchange

`q-periapt-native-session` serves the existing `QPCXCH01` owned session interface.
It reopens the device prepared by [the native enrollment CLI](NATIVE_DEVICE.md),
authenticates separately supplied peer expectations and a `QPBNDL01` public bundle,
then handles one explicit bootstrap, message or rekey-control request at current
OS time. It contains no fixture issuer or clock override.

The file carrier lets a host submit and recover an exact exchange without giving
the carrier private keys or treating its response as authentication. This is not
a network listener or the distinct TLS-bound `QPCNET01` carrier. Native outgoing
delivery and a complete bidirectional network service remain separate work.

## Host-owned inbox

The reference application's effect is to retain a received plaintext message in
a private redb inbox. Message contents and deduplication by session/message ID
commit in one Immediate, two-phase transaction, as required by the shared
protected-store recovery contract. Immediate durability alone does not select
that recovery rule. Only after that succeeds may the SDK mark
consumption and release its acknowledgement. An exact retry preserves the bytes;
a conflicting original ID fails. The inbox holds at most 1,024 deliveries of at
most 16 KiB each. Capacity failure does not acknowledge the message.

Provision this application store explicitly once. Supply the original journal ID
from this local device's retained status, never another peer's advertisement:

```sh
q-periapt-native-session provision-inbox "$new_inbox_file" "$local_journal_base64url"
```

Later exchange calls only open this original store and verify its journal binding.
Missing, busy, damaged or mismatched storage fails; it never becomes an empty inbox.
If provisioning reports an unknown outcome, retain its files and original journal
expectation and attempt ordinary open through the same invocation.

The inbox is host application data under private filesystem permissions. Its
plaintext storage and any exported delivery are outside SDK encryption and erasure
guarantees. This contract does not extend to arbitrary external business effects.

An unclean inbox written by the earlier prototype without two-phase commits is
still refused before redb recovery. Do not edit its header bits, fall back to a
stock redb opener, or recreate it. The corrected writer prevents that condition;
it does not repair such an old image. Clean original inboxes retain schema 1 and
can be opened normally; subsequent writes use the required commit protocol.

## Public inputs and one exchange

`PeerTrust` JSON has schema `qperiapt-native-peer-trust/1`, a nonzero 32-byte
`directory` expectation, and explicit `initiator` and `responder` objects. Each
object contains the independently provisioned current `RootInfo` as `current`, a
16-byte `device` array and integer `generation`. The received bundle supplies no
trust pins. This reference entry point selects the explicit reusable classical/PQ
profile and serves as the bootstrap responder.

Invoke `q-periapt-native-session exchange "$invocation_json"`. Its strict JSON has:

- `schema`: `qperiapt-native-exchange/1`.
- Absolute paths `device_directory`, `wrapping_key`, `invitation`, `current_root`,
  `policy_pins`, `policy_materials`, `peer_trust`, `bundle`, `request`, `inbox`, and
  `output_directory`. Input files and the empty output directory must meet the
  existing private-file contract.
- `witness_endpoint`: explicit `none` for a signed local-only policy, or the
  independently selected witness address for a matching required-witness pin.
- `operation`: `{"operation":"bootstrap"}`, or
  `{"operation":"message","session":[...]}`, or
  `{"operation":"control","session":[...]}`. Session arrays contain the original
  32-byte identity. Message/control calls reopen only that established session;
  they cannot admit another bootstrap through historical metadata.

`request` contains one bounded `QPCXCH01` frame. A successful invocation durably
exports `response.bin` into the selected empty directory. The SDK rechecks current
time and authority at its release boundaries, with a 30-second invocation deadline.
Local response export does not prove that the peer received or accepted it.

If the process dies or output export fails after commit, keep the original request,
operation, bundle and trust inputs, then retry the same device using another empty
output directory. Do not create another device, inbox, session or message ID to
make an unknown result look like first use. The initiating implementation must
authenticate the returned epoch/session-specific acknowledgement before reporting
delivery. The unsigned control completion marker alone cannot advance an epoch.

To read this application's actual retained effect into a new private file:

```sh
q-periapt-native-session read-inbox "$inbox_file" "$local_journal_base64url" \
  "$session_base64url" "$message_base64url" "$fresh_output_file"
```

Missing delivery is an error. This read API creates no protocol acknowledgement.

## Independent consumer

The installed independent package exposes `publication.Publication.decode` for
the native CLI's closed advertisement schema. Parsing verifies bounded framing,
correlation and unkeyed artifact consistency. `verify` uses the existing OpenSSL
bootstrap verifier with separately supplied policy, exact device pins, directory
and current time; producer journal and publication IDs never select local state.
`bundle` emits the existing `QPBNDL01` format. `inputs` prepares the corresponding
input object for the original `EnrollmentClient.prepare`, which repeats live
authorization and persistent owner checks.

The qualification workload generates explicit test authorities, uses real OS time,
restarts the native process for each exchange, and checks exact handshake/data retries.
The independent client records the authenticated READY in its original encrypted
registration before reopening confirmed traffic. Tests reject absent or forged
confirmation, conflicting retries and closed owners. Two SIGKILL cuts distinguish
unpublished confirmation staging from a formal recoverable intent; an additional
observer error after recovery commits the head withholds success, then ordinary
reopen reconciles that same target. Exact retries preserve the parent image.
The client reopens confirmed traffic again after one PQ rekey. These checks use
the [registered connection API](../continuity-openssl-peer/ENROLLMENT_CLIENT.md);
they do not treat local Traffic phase as evidence of a completed peer exchange.
The same workload then uses the owned independent `Connection` API for original
message submission and recovery. It distinguishes a valid but incomplete ACK
prefix, lost and forged ACKs, a cancelled result after real peer consumption,
a late carrier result, and reentrant close. It also rejects an unauthenticated
control completion marker, exhausts an explicit exchange allowance, reopens the
same target, completes epoch two and reads the peer's retained application effect.
All this still uses the file carrier; it is not a network-service acceptance.
An isolated `inbox-crash-probe` example delegates to the same public owner and
Mailbox implementations and stops at three points: before host effect commit,
after host effect commit but before SDK consumption, and after SDK consumption
but before response export. The controller checks a live process and exact
PID/stage marker, sends SIGKILL, reads the expected effect state, and retries the
same ciphertext/ID through the ordinary production CLI. The probe is not built
into product entry points. The workload then exchanges data after one PQ rekey. It does
not modify the real user account, grant a new device expiry, demonstrate physical
power-loss recovery, or prove secrecy recovery from a prior compromise.
