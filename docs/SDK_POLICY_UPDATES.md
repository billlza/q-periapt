# Policy preparation, persistence and activation

The unpublished ABI 2 SDK extension supports one in-process policy transition.
Policy signatures, pinned roots, exact-byte digests, monotonic versions and
same-version equivocation checks remain in `q-periapt-policy`. An update does not
accept an unsigned decision or change its runtime's trust root.

## Host sequence

1. Prepare a strictly newer signed document with `prepare_policy_update` /
   `preparePolicyUpdate`. Verification and next-runtime/handle reservation occur
   here. Rejecting or abandoning a candidate leaves the old runtime active.
2. Read the candidate's previous and next trusted states. Each is the existing
   36-byte version/digest encoding. C/WASM return `previous || next` (72 bytes);
   Swift/JVM/Android expose a named state pair.
3. Under the host's root-scoped transition coordination, atomically compare the
   stored state with `previous` and durably persist `next` plus a recoverable copy
   or reference to its signed policy. A failed compare must not activate.
4. Invoke `activate_after_persist` / `activateAfterPersisting`. C's function is
   `q_periapt_sdk_policy_update_activate`. It consumes the candidate and returns
   an independent runtime. Only one candidate can replace a given old runtime.

The SDK cannot inspect or prove step 3. Reading the public state pair is not
authentication or a persistence receipt. Tests that assign these bytes in memory
are explicitly not durable-store evidence. The
[host policy store](SDK_HOST_STORE.md) implements this sequence with real files
and is shared by Rust, C and Swift. Both connection diagnostic peers use it.
The packaged cross-platform reference application remains an open gate.

Rust persistence implementations keep `PolicyOwner` private and lend its
operational `Arc<Runtime>` aliases. Those aliases return `UpdateOwnerRequired`
from manual preparation; the restriction persists in successors and reopened
stores. The owner prepares an `OwnedPolicyUpdate`, exposes its exact state pair
for the host's durable transaction, and returns a new owner only on activation.
There is no conversion from an alias into its owner. `PolicyOwner` itself does
not persist, authenticate storage, or isolate hostile same-process code. A
standalone `Runtime::from_signed_policy` keeps the manual sequence above;
applications using `PolicyStore` call `replace_policy` instead.

For a persistent native runtime, call `q_periapt_sdk_runtime_update_store` or
Swift's `QPeriaptPersistentRuntime.update` instead of the four manual steps.
It verifies, commits and activates, returning a new runtime identity and
revoking the old owner/children. Manual preparation on such a runtime returns
`ERR_STORAGE_REQUIRED`. This operation admits a normal native call before any
write, then reuses the old registry slot, so a full handle table does not prevent
cutover. Concurrent attempts against an old epoch cannot replace its successor.
Unlike already-prepared activation, persistent update is subject to the global
call budget and can fail before mutation when that budget is full.

`ERR_COMMIT_UNCERTAIN` and `ERR_STORE_COMMITTED` both require recovery with the
latest requested signed policy. Swift cancellation waits for the worker and
closes an undelivered successor; it does not undo persistence. Use
`open(at:policy:signature:trustRoot:)` to reconcile the configured policy against
the durable floor before obtaining another runtime.

If persistence fails before committing, discard the preparation. If persistence
committed but activation fails or the process crashes, stop old-runtime use and
recover from the pinned root, latest persisted state and corresponding signed
policy. Never retry with empty/older trusted state. Missing, corrupt or rolled
back host storage is not first installation. A process-local transition does not
revoke other processes, host snapshots or other stores; those require host
coordination and an authoritative storage boundary.

## Disabled policy is an installable state

An authenticated policy that excludes the SDK's fixed suite/profile produces a
disabled runtime. `is_enabled` / `isEnabled` / C `runtime_enabled` explicitly
reports that configuration. It preserves trusted state and accepts newer signed
updates, but key generation, encapsulation and expert import fail `PolicyDenied`
(`ERR_POLICY=-3`). No entropy draw or classic fallback occurs. Initial loading
also supports this state so revocation can be recovered after a restart.

Invalid signatures, wrong roots, malformed documents, rollback and equivocation
remain errors. They never become disabled-but-successful placeholders. The
disabled state comes only from a valid policy's explicit lack of an eligible
suite/profile. A later valid, strictly newer policy can re-enable operations.

## Revocation and resource contract

Activation atomically closes the old runtime. Subsequent old-key, combined-secret
and derived-key operations reject use. Already admitted work may finish with its
old configuration; a protocol requiring strict cutover must fence publication
of those results. Previously exported secret/private bytes cannot be revoked.

The native registry reserves a distinct, never-reused successor ID during
preparation and replaces the candidate's slot on activation. No additional slot
is required after persistence. Prepared activation and close are exempt from
the global call budget so exhaustion cannot prevent revocation. Disposing old
children occurs outside the table lock and may wait for existing borrows.

Old runtime/update wrappers cannot close the successor because it has its own
identity and no old-parent link. Swift/JVM candidates retain the old runtime
wrapper until activation/close; Rust/WASM require the caller to keep it alive.
Native output shape/alias checks still precede any transition; valid outputs are
zeroed on operational failure. JNI/JVM wrapper-allocation failure closes an
undelivered successor and reports the failure; persistence recovery still applies.

Regression coverage includes old-fail/new-pass installation of a signed suite
revocation, recovery and re-enabling, rejected/abandoned preparations, one winner
among concurrent candidates, close racing activation, unchanged output on shape
failure, erased output on state failure, and activation with both native handle
and call budgets full. All six language surfaces exercise the real core locally.
