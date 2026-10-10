# Q-Periapt host policy store

Unpublished Rust host persistence for the owned SDK. `PolicyStore` verifies and
durably stores an exact signed policy/state before exposing its runtime, holds
an exclusive lifetime file lock, and closes retained runtime aliases on failure
or disposal. Its private filesystem implementation is shared with the existing
policy agent. The reviewed host boundary is macOS/Linux. Database genesis is committed in a private staging inode and published through
file sync, NOREPLACE rename and pinned-parent sync before owner release. One
Database and exclusive lock remain alive throughout. Failed attempts never delete
formal or staging files. Previously published state must be reopened with original
expectations; loss of active storage is not first use. Bounded explicit initial
retry and exclusive staging maintenance remain host responsibilities.

The store privately retains the SDK's `PolicyOwner`. A runtime returned by
`runtime()` or `replace_policy()` cannot prepare an in-memory policy update;
it returns `UpdateOwnerRequired`. Apply updates through `replace_policy()` so
the signed image and trusted state commit before successor activation. Reopening
preserves this separation, and store close/drop revokes every operational alias.

See [the API sequence, storage assumptions and actual validation](../../docs/SDK_HOST_STORE.md).
This is neither a cross-process authorization service nor a hardware rollback
counter. Additive C ABI 2 functions and Swift's `QPeriaptPersistentRuntime` now
share this implementation. Installed packages and Linux runtime qualification
remain release gates.

`filesystem::publish_private_bytes` publishes complete immutable key images on
macOS/Linux: private staging write, file sync, NOREPLACE rename, published-inode
validation, parent sync. Existing destinations are never replaced or deleted on
failure. Errors retain the original operation and attempted staging name. Failed attempts
and process crashes can leave unpublished private staging orphans; automatic selection,
sweeping and physical erasure are not provided. Database provisioning now reuses the same internal publication capability. This
does not enable Windows storage admission or migrate old partial formal files.

The opt-in Rust v2 store adds independently pinned online-policy-root recovery.
Provision `PolicyRecoveryTrust` before an incident, with a recovery-key enrollment
proof; retain the exact request and both recovery/incoming-key role signatures.
`recover_authority` persists root, policy, history and receipt before activation;
`open_recovering` reconciles the original operation after an uncertain outcome.
Ordinary updates retain strict monotonicity within the current root. Old roots and
operation IDs are not reusable; the lifetime bound is 4,096 independently authorized
replacements. V1 files and C/Swift constructors are unchanged and do not implicitly
acquire this authority. See the detailed contract above for wire, trust, storage
and integration limits; this is not full Continuity root migration or restored
message-confidentiality evidence.
