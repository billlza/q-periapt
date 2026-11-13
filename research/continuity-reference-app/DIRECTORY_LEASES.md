# Accountable one-time prekey directory (unpublished reference)

The operator verifies an entire device publication and issues a signed assignment of
its one-time X25519 and ML-KEM-768 public keys. The candidate SDK verifies the same
assignment under a separately pinned directory identity and hybrid public key.
This is a private, operator-driven service: remote authentication and approval
delivery belong to the embedding host. A user-supplied requester ID is not consent.

## Original service and storage

Keep a wrapping key, service ID, signing owner ID, and current directory pin in
independently provisioned storage. Use absolute paths beneath private directories.
Command-line identifiers are canonical unpadded base64url of 32 nonzero bytes;
identifiers in JSON are arrays of 32 bytes. Public keys in pin JSON are unpadded
base64url. Provision a wrapping file with the existing `q-periapt-native-device
provision-key` command. The directory commands are in `q-periapt-prekey-directory`:

```text
prepare-key SERVICE OWNER WRAPPING SIGNER
show-key    SERVICE OWNER WRAPPING SIGNER
init PIN.json DATABASE CAPACITY
```

The first command provisions the encrypted directory-role key; both key commands
print the public pin JSON. Retain it independently in an owner-only file. Recover
an uncertain key export with **show-key** on the original file. Never treat a
missing database or key as permission to create a replacement. The allowed capacity
is 1 through 4096 original allocations. An honest deployment uses one original
ledger with its service key. Restoring an old ledger snapshot or copying the key
to another ledger can produce conflicting signed receipts; this profile detects
such statements when both are available. It does not promise a nonforkable host.

A service file has schema `qperiapt-directory-service/1` and fields `pin` (the
independent pin object), `database`, `signer`, `wrapping` (absolute paths), and
`signing_id`. An admission file uses schema `qperiapt-directory-admission/1`
with independently supplied `trust`, `plan`, `policy_pins`, and `policy_materials`
objects from the [native publication verifier](NATIVE_DEVICE.md). The untrusted
publication is always a different input.

## Issue, retry, inspect and cancel

```text
inspect PIN.json ADMISSION.json PUBLICATION.json
issue SERVICE.json APPROVAL.json REQUEST.json ADMISSION.json PUBLICATION.json NEW_RECEIPT
lookup PIN.json DATABASE OPERATION NEW_RECEIPT
cancel PIN.json DATABASE OPERATION CANCELLATION_APPROVAL.json
check-receipt PIN.json REQUEST.json ADMISSION.json PUBLICATION.json RECEIPT
check-historical-receipt PIN.json RECEIPT
```

The request consists of `operation`, `requester`, `checkpoint`, `valid_from`
and `valid_until`. Intervals are Unix seconds, start-inclusive/end-exclusive.
The requester is a separately authenticated opaque principal; the publication
cannot choose that principal, the service pin or its policy. The checkpoint must
equal the independently expected checkpoint of the signed manifest. Request
validity fits within the current device, policy, manifest and selected leaves.

The local operator's private approval JSON has schema `qperiapt-directory-approval/1`,
an exact action (`issue` or `cancel`), `service_binding`, `selection_digest`, the
complete approved `request`, and its own `not_before`/`not_after` interval.
`inspect` supplies public selection metadata for review. The embedding host
must authenticate the requester and its administrator before supplying the
approval independently. Do not copy a purported approval from a network request.
Filesystem isolation is from other principals, not hostile code under the same UID.

The original signed wire, operation, and two algorithm-tagged key fingerprints
commit together. A failed output write can follow this commit: look up the
original operation and export its first wire to a **new** output path. A changed
request under the same operation is refused. A second operation reusing either
occupied key is refused across different requesters, manifests and epochs.
Expiry and explicit cancellation do not erase occupancy or reassign a key.
A full ledger rejects fresh assignments and still permits historical readback.
A storage error or unwound callback fences the owner: reopen the original ledger.

`lookup` returns historical bytes with the local cancellation flag. A successful
offline `check-receipt` authenticates the statement and its current inputs; it
does not query a live directory for cancellation or prove actual key consumption.
The responder still performs its own original journal transaction.

`check-historical-receipt` verifies one original signed receipt using only the
independently retained pin and the receipt bytes. It does not open the ledger,
signer or wrapping key, load current policy, or read a current clock. Its JSON
output marks `historical: true` and reports the `original_statement` digest,
signed request, service/manifest/selection bindings and both key fingerprints.
An expired receipt, or the unchanged receipt retained after local cancellation,
can still be authenticated this way. The output establishes the original signed
statement; it does not establish current validity, absence of cancellation,
delivery, or key consumption. Wrong pins and altered signatures are rejected.

This separate command also supports reconciliation when the original private
service is unavailable: an independently retained public pin and receipt suffice.
Protect and authenticate the pin independently of the receipt, using the same
owner-only input-file rules as the other operator commands.

## Public evidence and privacy

```text
prove-conflict PIN.json FIRST_RECEIPT SECOND_RECEIPT EMPTY_PRIVATE_OUTPUT_DIRECTORY
check-conflict PIN.json CONFLICT_FILE
```

The SDK verifies both ML-DSA-65 and P-256 signatures with purpose 39 under one
service pin. Directory signing files use a separate owner role (6). The signed
`QPDLSE01` body covers service binding, requester, operation, checkpoint, full
device/roster and manifest/selection bindings, policy and SDK scope, lease validity,
and both one-time public keys and their fingerprints. A receipt is 5173 bytes.

A `QPDLCF01` proof contains two original receipts in canonical order (10354
bytes total). Different signed assignments that reuse either algorithm's exact
public key are evidence even across nonoverlapping lease windows. The same
statement signed twice, different services or disjoint keys are not a conflict.
Historical evidence verification does not require a live signer, policy, or clock.

Receipts contain public keys and stable signed commitments. Parties holding them
can correlate repeated keys and requester identifiers. Limit distribution and use
pseudonymous requester identifiers where appropriate. Original entries are bounded
but retained for recovery and duplicate prevention; there is no automatic eviction.
Key equality here means the same algorithm and exact public bytes, not every
possible mathematical equivalence of encodings. A conflict proof establishes
inconsistent directory issuance, not receipt delivery or duplicate use by a device.
