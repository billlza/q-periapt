# Host policy persistence (0.2.0 development)

`q-periapt-host-store::PolicyStore` supplies the SDK's persist-before-activate
sequence on macOS/Linux. Rust, three additive C functions and Swift's
`QPeriaptPersistentRuntime` share that implementation. Both peers in the local
connection diagnostic recover persisted state before use. Installed packages
and native Linux execution remain unfinished. **C ABI major stays 2; the SDK
table now has 43 exports.** This crate is unpublished.

## Accepted state and ownership

`provision(path, policy, signature, root, limits)` is explicit first installation.
It verifies the signed document, exclusively creates a new private file and
commits its complete image before returning a runtime owner. It never overwrites
an existing path. `open(path, root, limits)` opens existing state, validates its
schema/root/exact state and re-verifies the stored signed policy. Missing, empty,
corrupt, foreign or unsupported storage does not become first installation.

A failed creation is not proof that no state was installed. Once the private file
has been admitted to the initializer, the shared filesystem layer preserves that
file and the original error, including an unknown commit result. It does not unlink
a potentially committed store or a complete key file already admitted by another
process. A later `provision` still refuses the existing path. Reconcile with the
same independently retained root and configured signed policy; a partial or
malformed store remains an explicit error and must be preserved for diagnosis.
No error path silently resets it or starts a new lineage. Admission failures before
initialization also retain the newly created file. The basename may now refer to
another writer's replacement, so failure cleanup cannot safely unlink it. A
zero-length or partial file remains refused by reopen and exclusive create; no
owner can be opened from it. Safe explicit reconciliation of incomplete
first-install state remains a separate release requirement.

`open_configured(path, policy, signature, root, limits)` also reconciles the
host's configured policy before exposing the runtime: the same exact state is
idempotent, a strictly newer valid policy is durably applied, and an older or
invalid policy is rejected. C and Swift always require this configured form.

`runtime()` returns a shared immutable SDK runtime. Keep the store alive while
using it: store close/drop revokes the runtime and all retained key/connection
aliases before releasing the file lease. Already admitted SDK calls may finish
with their existing leases. A valid disabling policy is stored and recovered as
a disabled runtime; endpoint/key creation then fails. It is never replaced by a
permissive default.

`replace_policy(expected, policy, signature)` performs:

1. Check the caller's expected version/digest and verify a strictly newer signed
   policy under the existing root. Stale inputs, rollback, equivocation and bad
   signatures leave the current runtime unchanged.
2. Re-read the exact current image inside a database write transaction and
   compare its state to `expected`. Write the complete signed image and new
   trusted state atomically.
3. Commit with immediate durability and two-phase commit, then activate the
   prepared runtime and revoke the previous one.

Any storage/commit/activation failure in the mutation phase closes the store and
its old runtime. A commit error has an explicitly uncertain outcome. The host
must retain/reconcile the requested signed policy before serving again; opening
an old-or-new recoverable database is not permission to silently resume old
rights. If persistence succeeded but another thread closed the runtime before
activation, reopening recovers the new stored image. These are distinct outcomes.

The connection diagnostic always reconciles its configured signed policy
against the recovered floor before constructing an endpoint. Reapplying the
same exact policy requires no update; a newer document is committed; an older,
invalid or disabling configuration never opens a listener.

## C and Swift ownership

`q_periapt_sdk_runtime_provision_store` and `q_periapt_sdk_runtime_open_store`
take `QPeriaptStoreOptions`: exact structure size/extension version, UTF-8
absolute path (1..4096 bytes, no NUL), signed policy, signature, pinned root and
runtime limits. The host creates the private parent directory first. These
functions return the same runtime handle type consumed by keys and connections.
On other native platforms these three storage functions return
`ERR_UNSUPPORTED_PLATFORM`; no weaker permission model is selected.

`q_periapt_sdk_runtime_update_store` admits work and reserves a new monotonic
identity before committing. It swaps the old registry slot for the successor,
then removes old children. No filesystem operation runs under the global handle
table lock. It rechecks the old handle after acquiring the store lock, so an
update queued on an obsolete epoch cannot revoke the new store. Direct manual
prepare/activate on a persistent runtime returns `ERR_STORAGE_REQUIRED`.

Existing statuses retain their values. New statuses distinguish insecure or
failed storage (`ERR_STORAGE`), an existing lease (`ERR_STORE_BUSY`), uncertain
commit (`ERR_COMMIT_UNCERTAIN`) and a commit whose runtime could not be delivered
(`ERR_STORE_COMMITTED`). On mutation/publication failure or unwind, the store
and previous epoch are closed. Reconcile the latest requested policy on reopen;
never treat an empty output handle as evidence that disk state did not change.

Swift's async `provision`, `open` and `update` perform disk work on a worker and
wait for admitted native work to finish. Cancellation closes any undelivered
successor before returning; a completed commit remains durable. `update`
returns a new persistent owner whose immutable `.runtime` can create keys and
connections. Old wrappers cannot close that new identity. Child wrappers retain
the runtime and its store lease. Prefer `await persistent.close()` for explicit
cleanup: the synchronous `.runtime.close()` and destructor fallback can block
on storage. Async close completes even when its caller is already cancelled.

## Filesystem and resource boundary

The module reuses the policy agent's descriptor-relative private filesystem
implementation, now shared from this crate. Every absolute directory component
is opened without following symlinks. The final directory must be owned by the
effective user with exact mode 0700; state files require exact 0600. macOS
extended ACLs are rejected through the existing narrow descriptor-ACL adapter.
Linux's mode/ACL mask correspondence is used. Other host platform permission
models are not implemented; they fail closed. File hard links are refused by
the policy store.

The pinned redb 4.3.0 backend is wrapped by `LockedFileBackend`, which takes a nonblocking exclusive whole-file lock for the
entire store lifetime. A second owner, including another process, receives
`Busy`. File size and unclean-header checks run **after** that lock is acquired.
The retained guard rejects unclean files not written with the reviewed two-phase
mode; corruption is not permission to select an older policy manually.

The database backend caps reads, writes and file growth at 64 MiB; its configured
cache is 2 MiB. These are component bounds, not a whole-process OOM guarantee.
The one closed table contains exactly five values: schema
`QPeriapt-Host-Policy-v1`, pinned root (1952 bytes), trusted state (36 bytes),
signed policy (1..65536 bytes), and signature (3309 bytes). No private KEM/TLS
keys or application payloads are stored here. Filesystem sync may block; it is
not forcibly cancelled midway through an update.

The host must protect the directory and storage and use this ownership protocol.
Advisory locks are coordination between cooperating processes, not isolation
from hostile code with the same account/privileges. Durability assumes the
filesystem and storage honor their synchronization guarantees. Restoring an old
valid whole-disk/database snapshot is outside this local boundary and requires
an external monotonic authority. No hardware power-loss qualification or
production IPC authority is claimed.

## Current evidence

Thirteen host-store tests pass: six retained filesystem tests and seven new
policy/store tests. They use real files and subprocesses for exclusive access,
commit/restart, an abrupt process exit after a successful commit, exact state and
root validation, and revocation/re-enabling. An injected sync error uses a real
file backend and requires the old runtime to close; a second injection closes
the runtime during the actual commit and requires recovery of the newer state
after activation fails. This is bounded failure testing, not exhaustive crash
or power-loss proof.

The prior extraction checkpoint passed the agent's 259 tests, its isolated umask
regression, and 90 source-binding/workflow/dependency-contract tests. This work
adds no third-party package version. The latest full workspace run passes 614
tests, with the umask case run separately. A subsequent state-query repair passes
all 40 FFI tests: an unwind had closed the runtime but still allowed its trusted
state to be returned successfully. The retained regression fails before the
repair and now requires `ERR_CLOSED` with erased output. Workspace Clippy,
warning-denied rustdoc, strict Swift concurrency and all eleven Swift tests pass.

Five native persistence tests cover real updates/recovery, output and call-budget
atomicity, full-table slot reuse, queued stale updates, close during publication
and unwind after commit. Three Swift tests cover lifecycle, worker cancellation
after an actual commit, and a child retaining the store lease until disposal.
The macOS test fixture had to use its canonical `/private/var` path: Foundation's
URL normalization retained the `/var` symlink. The store's no-symlink checks
were retained. iOS compilation and four NDK C layout checks pass; neither is a
platform runtime or package qualification.

The actual Swift/Rust socket diagnostic passes twelve cases with persistent
state on both peers. Each peer explicitly provisions once and subsequently
opens its existing store. The last three cases persist a signed revocation,
reject an older configured policy after restart, then persist a newer
re-enabling policy and complete fresh client connections. Executables and the
loaded dylib are frozen and hashed. Native Linux execution remains open.

The current proof-input map adds the shared crate and the agent adapter, growing
from 249 to 254 inputs. The historical 0.1.5 results file is unchanged and is
explicitly rejected as a current initial/installed baseline. No current source
transition, proof, receipt or publication is inferred from the map update.
See the [persistent-binding checkpoint](../research/sdk-alpha1/evidence/20260925-persistent-runtime-bindings/manifest.json)
and [release-readiness ledger](SDK_0_2_RELEASE_READINESS.md).

## Storage dependency refresh

The 0.2.0 candidate now uses redb 4.3.0 and requires Rust 1.90 or newer. New
stores use redb file format v3. Existing redb 2.6 format-v2 files are refused
with the underlying `UpgradeRequired(2)` error; opening never initializes an
empty replacement or automatically migrates a protected store. Preserve the
original file and its independent state/witness material. A separate migration
operation must preserve the application's schema, authenticated head and
rollback policy before a legacy deployment can move to the new producer.

`LockedFileBackend` obtains an exclusive whole-file lock before checking the
inode, extent or recovery header. It supports redb's explicit whole-storage
lock path; shared and byte-range modes are unavailable for protected stores.
The lock remains held through database recovery and transactions that outlive
the `Database` handle. Every write continues to require immediate durability
and two-phase commit; errors setting either storage policy are propagated.
