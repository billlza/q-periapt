# Host policy persistence (0.2.0 development)

`q-periapt-host-store::PolicyStore` supplies the SDK's persist-before-activate
sequence on macOS/Linux. Rust, three additive C functions and Swift's
`QPeriaptPersistentRuntime` share that implementation. Both peers in the local
connection diagnostic recover persisted state before use. Installed packages
and native Linux execution remain unfinished. **C ABI major stays 2; the SDK
table now has 51 exports**, including eight explicit policy-recovery helpers and
entry points. Existing declarations/layouts remain unchanged. This crate is unpublished.

## Accepted state and ownership

`provision(path, policy, signature, root, limits)` is explicit first installation.
It verifies the signed document, initializes a fresh private staging database with
immediate two-phase commit, syncs its complete initial state, then publishes it by
NOREPLACE rename and pinned-parent sync. The same Database and exclusive lock remain
owned throughout; no second backend is constructed from a probe descriptor. Only
after publication does the caller receive its runtime owner. Existing destinations
are never overwritten. `open(path, root, limits)` opens existing state, validates its
schema/root/exact state and re-verifies the signed policy. Missing, empty, corrupt,
foreign or unsupported storage does not become first installation.

A failed creation is not proof that no state was installed. Before publication,
failure can retain a private `.private-publication-*` staging inode while the formal
path remains absent. Only the original explicit first-use intent, before any active
use, can authorize a bounded retry; neither an arbitrary open error nor loss of a
previously active store authorizes it. After publication, an error retains the
formal database and its original state. Reconcile it with the same independently
retained root and configured signed policy. No failure deletes staging or formal
names, and no recovery scans or selects staging files. Exclusive orphan maintenance
and physical erasure are separate host responsibilities.

Existing partial formal databases remain refused without schema initialization or
replacement. An admitted redb open can still update its own allocator/recovery
metadata before application-schema rejection; this is not a promise of byte-for-byte
read-only diagnostics. The low-level unreleased Rust initializer now borrows
`&Database` and returns `()`, while the helper retains and returns the original
Database. Product C/Swift runtime function signatures are unchanged.

`open_configured(path, policy, signature, root, limits)` also reconciles the
host's configured policy before exposing the runtime: the same exact state is
idempotent, a strictly newer valid policy is durably applied, and an older or
invalid policy is rejected. C and Swift always require this configured form.

`runtime()` returns a shared operational SDK runtime without policy-update
authority. The store privately retains `PolicyOwner`; manual
`prepare_policy_update` on its runtime aliases returns `UpdateOwnerRequired`.
Use `replace_policy` below. Successor aliases and reopened stores retain this
restriction, so a consumer cannot bypass the store's commit through an alias.
This is an API capability boundary, not isolation from hostile same-process
code that explicitly bootstraps another runtime. Keep the store alive while
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
its old runtime. The mutation temporarily owns its Active epoch on the stack;
unwinding also drops and revokes it, even if a caller catches the panic. Only a
completed activation restores the store. The panic itself is not swallowed. A commit error has an explicitly uncertain outcome. The host
must retain/reconcile the requested signed policy before serving again; opening
an old-or-new recoverable database is not permission to silently resume old
rights. If persistence succeeded but another thread closed the runtime before
activation, reopening recovers the new stored image. These are distinct outcomes.

The connection diagnostic always reconciles its configured signed policy
against the recovered floor before constructing an endpoint. Reapplying the
same exact policy requires no update; a newer document is committed; an older,
invalid or disabling configuration never opens a listener.

## Independent online-root recovery

The opt-in v2 image adds a fixed independent ML-DSA-65 recovery root. This is a
SDK policy-authority recovery profile exposed through Rust, C and Swift. It does
not implement threshold governance, a remotely authenticated issuer service, or
Continuity identity-root replacement. The original C/Swift constructors retain
v1 behavior and cannot open v2 without its required recovery configuration.

An online root can sign `u32::MAX` and exhaust normal policy updates. A v1 store
cannot recover that condition without explicit enrollment of independently
authorized recovery configuration. In v2, the online key cannot authorize root
replacement or consume its separate recovery-generation budget. Replacing a root
requires an already pinned recovery key and proof of possession by the incoming
online key over the same exact transition. A signature on the candidate policy
alone is insufficient. The initial and every incoming online key must differ from the recovery key,
and an online root already used in this store cannot return later.

1. At explicit first provisioning, independently retain
   `PolicyRecoveryTrust::new(scope, initial_root, recovery_root)`. The 32-byte scope
   must be nonzero. Obtain the recovery key's signature on `enrollment_message()`
   to prove that the configured key is usable, and call `provision_recoverable`.
   Existing v1 files are not silently enrolled. There is no recovery-root rotation
   in this profile; compromise/loss of that key needs a separate trust ceremony.
   Scope is an authorization domain, not a filesystem path or device identifier.
   Stores with the same original trust and exact predecessor/history can accept
   the same authorization. Use independently provisioned distinct scopes when
   per-store approval is required; no Continuity device permission is implied.
2. Generate one nonzero 32-byte operation ID and retain it. Call
   `prepare_authority_recovery` with the exact candidate policy/signature/root.
   It verifies the candidate and returns a statement with the original trust
   commitment, exact previous root and policy, committed history, generation,
   operation and target root/policy. It exposes no candidate runtime and changes
   no persistent state. Concurrent policy advancement makes the statement stale.
3. Independently inspect and authorize that statement. The recovery key signs
   `authorization_message()`; the incoming online key signs `possession_message()`.
   The role domains differ. Preserve the original statement, both signatures and
   exact target policy; assemble `PolicyRecoveryAuthorization` without treating
   that assembly/parsing as verification.
4. `recover_authority` verifies both role signatures and the candidate policy,
   checks exact predecessor/root/history, then atomically commits all nine image
   fields. Only afterwards does its prepared owner revoke old aliases and activate
   the successor. Signature/stale errors leave the old owner usable. Storage,
   uncertain commit or activation failures close the store; no old-policy fallback
   is returned. Allocations and successor preparation precede the commit.
5. After an uncertain outcome, use `open_recovering` with the ORIGINAL trust,
   authorization and target policy. `Applied` means this call committed it;
   `AlreadyApplied` means that exact target remains current;
   `AppliedThenAdvanced` means it committed but a later authorized policy/root is
   current. The last case never restores the older requested policy. An unrelated
   state fails. `open_recoverable_configured` similarly reconciles ordinary policy
   updates under the currently authenticated root before exposing a runtime.

The schema marker is `QPeriapt-Host-Policy-v2` in the existing policy table. In
addition to schema/root/policy/signature/state, it stores the original recovery
trust, enrollment signature, bounded authority history and latest signed receipt.
Every history entry is root SHA-256, operation ID and request digest (96 bytes);
genesis uses zero operation/request fields. The latest independent signature
commits the complete predecessor history. Reopening checks the external original
trust, enrollment, unique historical roots/operations, latest receipt signatures,
root, and current policy at or above that receipt's floor. The signed policy is
reverified before a runtime can be returned.

The generation must increase by exactly one; callers cannot jump it to a maximum.
There are at most **4,096 root replacements** per provisioned store. This explicit
lifetime/storage bound is not consumed by online policy updates. No history pruning
or capacity reset is supplied. The independent recovery authority remains trusted;
this is not a claim to survive its compromise or an unlimited sequence of changes.
The underlying SDK KATs, raw KEM format and 68-byte root/policy binding are unchanged.
Never reusing a historical online root prevents a local authority epoch from
recreating that old root identity. Possession proofs do not prove that a key is
fresh, uncompromised or unknown to an attacker; issuers must supply appropriate keys.

The canonical request is 2,168 bytes, in this order:

| Field | Bytes |
| --- | ---: |
| `QPRCV001` | 8 |
| SHA-256 trust commitment | 32 |
| Recovery generation, big-endian | 8 |
| Original operation ID | 32 |
| SHA-256 predecessor root | 32 |
| Previous `TrustedPolicyState` | 36 |
| SHA-256 predecessor history commitment | 32 |
| Incoming ML-DSA-65 root | 1,952 |
| Target `TrustedPolicyState` | 36 |

The authorization appends the 3,309-byte recovery signature and 3,309-byte incoming
possession signature, totaling 8,786 bytes. Domain strings and canonical encodings
are in `policy/recovery.rs`; parsing rejects truncated/trailing or out-of-bound
containers. Public digests, IDs and parsed statements are never authority tokens.

Protected-file storage still cannot detect restoration of an entire older disk
image. This path does not erase exported keys or retained backups, authorize an
expired Continuity credential, change a policy family, retire remote sessions,
or establish post-compromise message confidentiality. Continuity's family is
bound to its own policy signing key, and its renewal fixes family, signer and SDK
binding. That migration, installed product qualification and
independent security review remain release work; they must not be replaced with
weaker comparisons or an implicit new installation.

## C and Swift ownership

### Explicit enrollment of an existing v1 policy image

First retain the exact current signed policy/state, original online root, an
independently chosen recovery root and scope, and its recovery-key enrollment
proof. These trust inputs must come from host authorization outside incoming
policies; the proof establishes possession, not that a peer may appoint a root.
Close the previous store owner before enrollment. Rust calls
`PolicyStore::enroll_recovery(path, expected_state, trust, proof, limits)`;
C calls `q_periapt_sdk_runtime_enroll_recovery_store` with the original signed
policy in `QPeriaptRecoverableStoreOptions`; Swift calls `enrollRecovery`.

Enrollment opens the existing protected file under its exclusive lease. It
authenticates the original policy and compares its exact root/version/digest to
the retained input. One immediate two-phase transaction adds the four recovery
fields and v2 schema marker while preserving the existing root, signed policy
and floor, including `u32::MAX` and a disabled policy. No runtime is returned
before persistence. Missing/corrupt files are never created or replaced.

Retry an error, lost result or cancellation with the same inputs. An identical
initial v2 configuration succeeds without another write; success states that
the configuration is present, not that this call performed a fresh commit.
The original retry rejects later policy/root changes and conflicting trust or
proofs instead of clearing history. Rust reports a stale expected state as
`StoreError::Stale`; its existing C mapping is `ERR_CLOSED`. Reconcile later
ordinary policy or root operations using their corresponding configured/recovery
entry points. Swift cancellation closes an undelivered owner while retaining
the durable enrollment. The old owner and its keys remain closed.

This upgrades the policy image inside a file readable by the current redb
backend. It does not migrate redb file format 2 to 3, reset rollback state,
rotate the recovery key, or migrate a Continuity account root.

### Recovery owner transfer

The additive recovery API uses `QPeriaptRecoverableStoreOptions`: the same
size/version prefix, path, candidate signed policy, runtime limits, and explicit
original scope/initial/recovery roots. `enrollment_signature` is required
for explicit provisioning and enrollment; both other open functions
require its canonical empty form. The enrollment-message and recovery-signing-
messages helpers produce canonical public statements without granting authority.
`q_periapt_sdk_runtime_prepare_recovery` changes no state. Retain its exact
request and collect both signatures before `q_periapt_sdk_runtime_recover_authority`.

An `APPLIED` mutation returns a new runtime handle and revokes the old epoch.
`ALREADY_APPLIED` and `APPLIED_THEN_ADVANCED` return **zero successor handle** and
preserve the current owner and children. They must not be treated as new owners.
`q_periapt_sdk_runtime_open_recovering_store` always returns an owner on success
because it acquires a new store lease, including when the receipt was already
applied. A post-commit publication failure reports `ERR_STORE_COMMITTED`; reopen
using the original authorization instead of assuming rollback. A v1 store reports
`ERR_RECOVERY_REQUIRED` and is never automatically enrolled.

Swift exposes `QPeriaptPolicyRecoveryTrust`, `QPeriaptPolicyRecoveryRequest`,
`QPeriaptPolicyRecoveryAuthorization`, and the corresponding persistent runtime
methods. `recoverAuthority` returns `.applied(owner)`, `.alreadyApplied`, or
`.appliedThenAdvanced`. Cancellation waits for admitted work and disposes only a
newly returned owner; cancelling a successful replay leaves the current owner
usable. Parsing or assembling these public containers is not signature verification.
The original trust, signed request and exact requested policy must be available
after process restart. Public test vectors are examples, never deployment roots.

Recovery storage is currently implemented on macOS/Linux. Other platforms expose
the C symbols but return `ERR_UNSUPPORTED_PLATFORM` for storage operations.

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

For the original five-field host policy image, the optional
[`qperiapt policy-store-upgrade` maintenance command](../crates/q-periapt-cli/README.md#offline-host-policy-store-upgrade)
provides explicit format conversion on macOS/Linux with an independently
retained root and exact expected state. Ordinary SDK opens remain unchanged.
This command does not migrate Continuity state or enroll recovery authority.

The [format-upgrade investigation](../research/sdk-alpha1/evidence/20261008-storage-format-upgrade/README.md)
records successful interrupted policy-image conversions and continuous-lock
handoffs, plus legacy-parser and corrupt-header counterexamples. In particular,
`UpgradeRequired(2)` alone is not sufficient authority to invoke an old parser.
Those fixture-only programs are not a deployment migration interface.

`LockedFileBackend` obtains an exclusive whole-file lock before checking the
inode, extent or recovery header. It supports redb's explicit whole-storage
lock path; shared and byte-range modes are unavailable for protected stores.
The lock remains held through database recovery and transactions that outlive
the `Database` handle. Every write continues to require immediate durability
and two-phase commit; errors setting either storage policy are propagated.
