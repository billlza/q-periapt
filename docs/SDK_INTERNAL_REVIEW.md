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

The active SDK producers and consumers still select `0.2.0-alpha.1` and
`sdk-alpha1`. A coordinated 0.2.0 version/package transition and its release
procedure remain work to complete; changing only the root Cargo version or
reusing the old publication order would be incomplete.

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

Remaining focused review covers foreign asynchronous disposal/cancellation,
transcript/erasure boundaries and
reference-connection authentication/failure handling. These are the next code
review boundaries, not additional language or protocol features. Platform
execution, controlled performance and the coordinated release transaction remain
in the [readiness ledger](SDK_0_2_RELEASE_READINESS.md).
