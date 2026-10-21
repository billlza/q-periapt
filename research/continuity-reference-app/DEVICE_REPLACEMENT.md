# Account-authorized device replacement

This reference-host operation replaces one currently listed device with fresh
signing keys and the next generation of the same device ID. It is distinct from
same-key credential renewal and recovery of an existing installation. The SDK
still delegates account authentication and replacement authorization to the host.

Back up and retain the existing protected account database and key files before
an explicit `enable-device-replacements <database> <origin>` upgrade. Schema 7
admits replacement operation records; it requires the existing schema-6 policy
approval upgrade. Accounts, roots, keys and earlier records remain unchanged.
Older readers refuse the new schema. No downgrade or automatic reset is provided.

1. Sign in with the original account. Recover the original issued enrollment and
   review the account's current root and roster.
2. Select **Create replacement invitation against displayed roster**. Retain the
   resulting correlation before transmission. The HTTP request is
   `POST /api/enrollment/replace-device` with `request_id`, the original issued
   `enrollment` operation ID and exact `predecessor` checkpoint.
3. Save the new invitation and use the native device first-use procedure in a
   fresh private device directory. Generate fresh keys there; retain the old
   device files. Transfer only the public request to the account host.
4. Review the device, generation, interval and request fingerprint. Explicitly
   approve the request, then issue or recover its credential. Issuance replaces
   exactly that member, preserves all other members and does not shorten the
   previous roster interval. It works with all 32 member slots occupied.
5. If witness protection applies, use the separate
   [witness replacement operator](WITNESS_REPLACEMENT.md) with the approved new
   device trust and complete original predecessor state. Query its exact decision
   after a lost response. Only its commit retires those old witness entries.
6. On an already connected remote native device, explicitly admit the selected
   signed replacement roster using [admit-peer-roster](NATIVE_DEVICE.md#remote-peer-roster).
   Retry that exact target after an uncertain result. Then connect the new device
   from its own fresh installation and retain any previously prepared handshake.
   This remote-account operation does not update surviving devices in the replaced
   device's own account; those need their separate enrollment roster transaction.

The browser never copies the old device proof into the new operation. Its
schema-5 recovery backup includes the original enrollment and all earlier
credential extensions, G and P decisions. Reads do not upgrade old backups;
preparing or importing a replacement does. Keep that backup before clearing
browser data. It contains public authorization materials, not device private keys.

An expired device may be replaced if the independently selected current root
still lists its exact credential. The host verifies that credential against its
own retained signed issuance history, then verifies membership in the selected
current roster. It does not backdate the host clock or turn historical identity
into current traffic permission. If a same-key extension exists, resolution uses
the exact current certificate and its retained issuance, never the newest record
by heuristic. The extension ledger scan is bounded by the existing 512-record
capacity and runs only when the original certificate is no longer current.

An uncertain invitation response is retried with the same complete request.
An uncertain issuance response is recovered by its original operation ID. Both
remain historical results after the account roster changes. Concurrent proposals
do not reserve membership: the first valid issuance advances the roster and later
stale issuances fail without altering it. A new decision requires a newly reviewed
current predecessor. Generic same-intent reapproval is refused for replacement
invitations. An expired pending invitation can be cancelled and a fresh explicit
replacement request prepared from the still-current original issued operation.

The local profile keeps five-minute approval deadlines and one-hour replacement
credentials. It does not transfer old device journals or old session secrets.
The `tests/host_replacement.py` workload uses the actual account HTTP service
with isolated software WebAuthn authenticators. It loses invitation/issuance
responses, kills and restarts the account service, reuses the original Passkeys,
commits witness replacement with lost output, and recovers peer-roster admission.
The surviving native owner exchanges messages with the fresh independent device,
confirms a rekey and sends new traffic after witness/native service restarts.
Old owner operations and cached old traffic remain refused. The installed wheel
qualification runs this same workload and checks the public process receipts.
This is not human Passkey, mobile, cross-host or post-compromise security evidence.
