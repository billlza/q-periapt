# Native outgoing reference operations

`q-periapt-native-outgoing` reopens the original responder device/session prepared
through [native enrollment](NATIVE_DEVICE.md) and [session exchange](NATIVE_SESSION.md).
It uses the existing enrolled-owner SDK operations for message IDs, historical
message status, authenticated delivery and explicit-target rekeying. It generates
no fixture identities, exposes no signer, and accepts no clock override.

```sh
q-periapt-native-outgoing "$absolute_invocation_json" "$original_session_base64url"
```

The strict invocation schema is `qperiapt-native-outgoing/1`. Supply the same
independently retained inputs used for session exchange: absolute paths
`device_directory`, `wrapping_key`, `invitation`, `current_root`, `policy_pins`,
`policy_materials`, `peer_trust`, and `bundle`, plus `witness_endpoint` (`none` or
the matching pinned witness address). The existing archive/current-authority
checks reopen this exact session. These commands require an admitted active
device; historical status does not bypass expired activation authority.

The `action` object selects one operation; unknown fields are refused:

- `{"operation":"next"}` returns the original next `message` as a 32-byte array.
  Observation reserves no plaintext and grants no permission.
- `{"operation":"status","message":[...]}` reports the original outgoing
  disposition. An acknowledged or retired ID cannot authenticate new input.
- `{"operation":"deliver","message":[...],"plaintext":[...],"associated_data":[...],
  "request_directory":"...","response_directory":"..."}` submits the original
  message ID, at most 16 KiB of plaintext, and at most 1 KiB of associated data.
  Both byte arrays may be empty. The result is `Confirmed` or `PrefixPending`;
  a pending authenticated prefix is not completed delivery.
- `{"operation":"rekey","target":3,"exchanges":4,
  "request_directory":"...","response_directory":"..."}` drives one explicit
  target with an allowance from 1 through 128 exchanges. It reports the locally
  confirmed epoch and requests attempted by the successful invocation, not
  fresh peer liveness or secrecy recovery.

All static payload/carrier options are checked before opening or activating the
device. Errors retain the original operation and close the SDK owner. After an
unknown result, retain every state file and the original message/input or rekey
target; reopen using new empty carrier directories. Do not choose another ID to
hide a failed operation. A lost output may already have committed at either peer.

## Private-file carrier

The two carrier directories must be distinct, empty, absolute private directories.
The command publishes `001.request`, then waits for `001.response`; rekey can
continue with `002` and later numbers. Each file contains one unchanged
`QPCXCH01` frame, bounded at 32 KiB. Files must meet the existing protected input
rules. The receiver must atomically publish a complete response, not expose a
partially written destination file. A malformed, replaced or oversized input is
an error; it is not retried as a missing response.

The carrier retains the SDK session operation's original 30-second deadline and
checks cancellation while waiting. It never retries an exchange implicitly or
resets that deadline for a later frame. Polling a missing response is bounded;
published requests survive errors. The frame alone supplies no authentication:
the SDK checks the exact session/epoch ACK or signed control response.

This carrier supports integration and process-recovery qualification. It is not
a network listener and does not implement the distinct TLS-bound `QPCNET01`
carrier. Deployable network service admission and resource management remain open.

## Independent receiver

The installed independent package's `Connection.serve_message` and `serve_control`
consume these requests on its original confirmed session. The host consumer must
commit the application effect and deduplication together. Historical consumption
below an erased prefix permits an ACK for the original ID; it never authenticates
or delivers replacement bytes. Retained out-of-order commitments still must match.

The qualification workload exercises actual native-to-independent ciphertext,
empty and out-of-order deliveries, failed/unknown application commits, cancelled
results, lost ACKs, and exact retries after five sender SIGKILL interruptions.
The test host uses SQLite transactions and verifies nine retained effects after
eleven consumer calls. It then completes a native-driven third rekey and sends in
both application directions. File transport boundary tests cover cancellation,
deadlines, capacity and original request preservation. These are process-level
observations; they do not establish physical power-loss durability or a deployed
network service, and they do not alter the real user's account or grants.
