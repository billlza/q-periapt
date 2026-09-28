# SDK internal implementation review

This record tracks internal code, security-boundary and maintainability checks
for the 0.2.0 work. The inspected product source is
`0e2a670b8e63584632190d50b308e2d8e4eabf7a`; ABI major remains 2. Each conclusion
below names the implementation boundary it covers. Remaining review items are
kept separate from completed observations.

## Owned runtime and C boundary

| Contract | Inspected implementation | Observation |
| --- | --- | --- |
| Runtime configuration must originate from signature/root/state verification | `crates/q-periapt-sdk/src/lib.rs`, `Runtime::from_signed_policy` | Lengths and limits are checked before signed monotonic policy loading. Only the explicitly authenticated absence of a supported suite becomes a disabled runtime; other resolution errors return `PolicyDenied`. No SDK runtime constructor takes a serialized 40-byte decision. |
| Closing between admission checks must release its budget | `State::begin_control`, `Operation::drop`, `Runtime::generate_with` | The operation lease is constructed immediately after reservation and before the second open check. Error/unwind releases the counter. The key lease is likewise established before entropy acquisition and backend preparation. |
| Handles must not wrap or expose unpublished owners | `crates/q-periapt-ffi/src/sdk/registry.rs`, `Registry::reserve`, `Reservation::publish` | IDs use checked increment. Reserved slots remain pending; publication rechecks the live runtime parent. A dropped unpublished reservation removes only its matching pending ID and drops the object after releasing the table lock. |
| Poisoned state must not become usable state | `Object::close`, `Registry::lock`, `Reservation::drop` | Normal acquisition returns `ERR_INTERNAL` on poison. Recovery of the inner value is confined to disposal; the poison flag remains. Key/secret cleanup reports the internal error. |
| Failure must not publish partial C outputs | `crates/q-periapt-ffi/src/sdk.rs`, `execute_with_admission`, `OutputGuard` | Bounds/null/alias checks precede initialization. The output guard commits only on `Ok`; operation errors and caught panics leave its cleanup armed. Public C pointer validity remains the caller's memory contract. |
| Policy activation must have one winner and remain possible at capacity | `crates/q-periapt-sdk/src/policy_update.rs`, `PolicyUpdate::activate_after_persist`; registry activation | Preparation verifies a strictly newer policy using the pinned root and trusted state. Activation uses the previous runtime's atomic close as its admission boundary, with resources reserved before persistence. The raw runtime API's documented host compare/persist obligation is distinct from activation itself. |

Relevant regression names in `crates/q-periapt-ffi/src/sdk/tests.rs` include
`bounds_aliases_and_panics_do_not_publish_success_fragments`,
`unpublished_reservations_are_bounded_and_revocation_prevents_late_publication`,
and `purpose_key_handles_enforce_shapes_type_separation_and_runtime_revocation`.
The Apple workload also exercises actual owner calls, pairwise named-purpose
separation, signed revocation, quota recovery, pre-cancellation and concurrent
asynchronous decapsulation. Its policy-update slot is in-memory; durable-store
review uses the separate host-store implementation and its process tests.

## Durable host policy storage

`crates/q-periapt-host-store/src/policy.rs` opens a descriptor-backed
`FileBackend`, holds its exclusive lifetime lock, and re-reads the same inode's
metadata after lock acquisition. `replace_policy` compares the expected signed
state inside the write transaction, commits policy/signature/root/state together
with immediate durability and two-phase commit, then activates the replacement.
Storage, uncertain commit and post-commit activation failures close the store;
dropping its active state closes retained runtime aliases. `open_configured`
reconciles the application's configured signed policy before returning a runtime.

`filesystem.rs` uses descriptor-relative private-file admission. An unclean redb
image without the two-phase flag is refused before recovery. This is tied to the
documented redb 2.6 format and does not provide a hardware rollback counter.
The existing 15 host-store tests pass on macOS with
`cargo test --locked --offline -p q-periapt-host-store`. They include real commit
failure, persisted activation failure, a competing process lock and a committed
revocation surviving a child process exit that bypasses Rust cleanup. These
observations cover the implemented macOS/Linux store's checked paths; Android
and iOS durable application storage are separate integration responsibilities.

The following product paths were inspected at `99fb979`. Their bytes match
`0e2a670`; the runtime-harness changes have separate validation. These findings
cover the named boundaries and do not imply unrun target execution.

## Foreign asynchronous ownership

- Swift `runOwnedOperation` checks cancellation before dispatch, before native
  work and after its result. The parent awaits the detached worker. Captured
  owners remain retained until the call finishes; cancellation discards result
  wrappers, whose `OwnedHandle.deinit` closes the native handle. `OwnedHandle.use`
  extends both wrapper and parent lifetime through native calls.
- JVM `submitOwned` uses the atomic `CompletableFuture.complete` result. If the
  consumer has already cancelled, the worker closes its undelivered owner.
  `finally` cleans the captured input; failures that cannot be delivered to a
  cancelled future are logged. Native work is not interrupted.
- Android `OwnedTask` serializes `cancel` and result publication, forces
  `cancel(false)` for native work, closes an undelivered result and logs disposal
  failure. Its one-winner `started` guard prevents repeated `run` calls from
  erasing input still used by the admitted worker. The supplied executor retains
  responsibility for bounded queues and execution. Input snapshots are bounded
  before cloning.
- The existing tests `testCancellationDiscardsCompletedNativeOwnerAndReturnsQuota`
  and `cancellationDisposesUndeliveredNativeOwnerAndReturnsQuota` stop workers
  after native generation and before publication; they check cancellation and
  quota recovery. They do not claim forced interruption inside a primitive.

## Transcript and secret storage

- `combine_policy_bound` feeds the same ordered, eight-byte big-endian
  length-prefixed fields as `encode_policy_bound_context`. It emits the outer
  context length before the domain, policy digest and caller context, with
  checked bounded lengths. No field is replaced by a shorter digest.
- `StreamingSha3_256Xof` uses the pinned RustCrypto core and padding. The wrapper
  wipes the complete residual block on drop; `sha3` has its `zeroize` feature.
  Compiler and provider internal copies remain outside owner-level erasure.
- `PreparedMlKem768Key` borrows the paired public field at the fixed expanded-key
  offset, checks generated public output, uses checked/PCT expert import and
  retains native expanded-key validation for every decapsulation.
- Purpose derivation binds the suite, ContextBound profile, trusted policy state,
  root digest, global direction/purpose, protocol label, context and output
  length. The returned PRK is explicitly wiped; HMAC/SHA-256 zeroize features
  are enabled. Export remains an explicit caller-owned copy.

## Reference connection authentication and failure

- `standard::provider` offers only TLS 1.3 suites and X25519MLKEM768. Client and
  server require trusted certificates, disable resumption/early data, and create
  fresh handshakes. The reference engine additionally checks full handshake,
  negotiated group, ALPN and exact peer certificate digest.
- Before application readiness, both roles check policy/root state, application
  context and ordered peer identities against a TLS exporter binding. The
  exporter value uses constant-time equality; confirmation frame types are
  role-specific. The stored binding is dropped after confirmation.
- `Live::check` enforces the absolute current phase deadline and runtime state.
  `Connection::finish` closes on wire/protocol/state failures; failed encrypted
  output is cleared. Framing rejects malformed lengths/sequence/replayed
  confirmations. EOF cannot become an empty successful message.
- Existing connection tests cover missing confirmation/ALPN, cross-session
  exporter replay, exact leaf pinning, fragmentation/reconnect, independent
  policy/context mismatches, capacity, revocation, deadlines and EOF. Actual
  Swift/macOS-to-Rust/Linux execution still requires its selected endpoints.

## Product WASM boundary

The product is `q-periapt-sdk-wasm`; the separate `q-periapt-wasm` crate retains
its existing expert/KAT contract. The product constructor checks original JS
numeric limit types and bounded `Uint8Array` lengths before copying into linear
memory, then calls the shared signed-policy constructor. The SDK enables the
`getrandom` WASM JS backend; entropy failure remains an error. The default web
entry point exports owner APIs, while private transfer has an explicit expert
entry point. Initialization retains a rejected promise after failure. Host policy
persistence, same-realm trust and exported copies retain their documented scope.

## Release cohort and installation

The existing SDK package classifier validates twelve publishable Rust crates
and their production dependency order. Inspecting actual offline Cargo metadata
confirms that the historical ten-crate 0.1.5 uploader lacks `q-periapt-sdk` and
`q-periapt-host-store`; its old order also places `q-periapt-ffi` before its new
`q-periapt-rustls` dependency. That uploader must retain its historical contract.

The SDK package producer already has the required dependency-safe order:

1. `q-periapt-mlkem-native-sys`
2. `q-periapt-core`
3. `q-periapt-kem`
4. `q-periapt-sig`
5. `q-periapt-backends`
6. `q-periapt-policy`
7. `q-periapt-sdk`
8. `q-periapt-host-store`
9. `q-periapt-rustls`
10. `q-periapt-ffi`
11. `q-periapt-wasm`
12. `q-periapt-cli`

The active SDK producers and consumers now select `0.2.0` and `sdk-020`.
This coordinated transition includes exact internal dependencies, archive names,
installed consumers, C contract metadata and the native CBOM profile. Its
source/package qualification and release procedure remain required; the frozen
0.1.5 publisher order cannot publish the twelve-crate cohort.

The SDK now has a separate coordinator and receipt schema for this order.
It shares the existing persistent lock, intent/outcome journal, exact API+sparse
observations and explicit unknown-outcome retry mechanism. Inspection covers
source/report/archive resampling after lock acquisition, complete source-input
maps, exact internal dependency pins and rejection of mixed release receipts.
Source `57334d4` passes 2,311 complete artifact tests and its real hosted package
consumer and coordinator dry-run. No registry upload is part of that check.

The uploader's directory transition has a retained real-filesystem counterexample:
replacing the selected parent previously redirected the output. The repair pins
the private directory descriptor, uses the shared no-replace writer and checks
bytes plus inode before enabling execution. At `a07789f`, CLI output authority
comes from a closed profile and the selected report digest. Its 214 affected
tests pass, the real twelve-crate hosted uploader is materialized, and the
Python scan removes the eleven preceding path warnings without new alerts.
The remaining 41 IDs/rules and thirteen location-file blobs match `10de0c7`;
these existing dispositions retain their prior scope.

## Validation and remaining review

The clean source passes 2,268 artifact tests in 453.901 seconds without skips,
with its pre/post source gate and the 43-export ABI 2 contract check. The actual
host workload, iOS executable linkage and unsigned app build pass locally. The
new host/iOS CI step also passes at run `36345633624`, artifact `10940517353`
(SHA-256 `ce567e45fd0e4ecf771735a898ad5b332823d2c7d97089ee6ef98a1de0b9e1df`).
This artifact contains host/build logs; device execution has its own capture.

The same source completes all 36 CI jobs in run `36345633624` and all six
CodeQL analyses in run `36345633631`. Its PR merge
`06db6468429b8097f2af0bb9087b49e0e2b55962` has the same tree as the inspected
source. The 41 open alerts retain the preceding IDs and rules; all thirteen
files containing their reported locations have unchanged Git blobs. Existing
internal dispositions therefore retain their source scope. No alert is
dismissed or suppressed, and analysis completion alone is not a security proof.

The named ownership, persistence, asynchronous disposal, transcript/erasure,
WASM and reference-authentication paths now have internal inspection records.
The completed `99fb979` analysis retains the same 41 alert IDs/rules. Twelve of
thirteen location files are unchanged; the three path findings in the changed
AGP consumer were rechecked against its caller-selected directory, fixed bundle
names, bounded readers and exact closure. The new runtime selector does not
construct filesystem paths. Later harness changes still require their own
source-specific analysis. Platform execution, controlled performance and the
coordinated release transaction remain in the
[readiness ledger](SDK_0_2_RELEASE_READINESS.md).
