# Shared C admission test isolation

For branch head f4b35dcb, PR jobs 113860182035 (Swift-labelled) and 113860181877
(Kotlin-labelled) both failed in the native C release admission suite before
foreign-language execution. `prepared_open_is_cancelable_single_use_and_capacity_bounded`
observed an empty owner table but `CALLS == 1` at its final zero-call assertion.
The test registry mutex was then poisoned, causing three secondary failures.
The actual PR merge checkout was 6c1e01a6e6a5f9251d4b15558c98965ada234a53; every C consumer source hash matches branch head f4b35dcb. Successful push-triggered jobs remain separate evidence.

The two publication tests that invoke C entry points had not acquired the existing
`TEST_REGISTRY` mutex. Even rejected arguments reserve a global `CallPermit` before
validation, so these tests can overlap an otherwise isolated zero-call observation.
Other tests checking shared registry/call capacity already hold that mutex.
The change adds the same guard to those two publication tests. Production FFI,
resource limits, existing assertions and parallel test execution are unchanged.

The isolated, identical scheduling probe invokes the actual publication test bodies
from a worker while another thread owns `TEST_REGISTRY`. Old source completes the
header case inside that scope and fails the probe; repaired source waits until
release and completes both header and bounds cases. Probe code is retained here
only and removed from the product test source. No debugger or process-memory
inspection was used.

An uninstrumented seven-test subset ran with 16 test threads for 100 processes
before and 100 after the change. Both sets passed locally. Thus local stress did
not reproduce the exact CI timing; the observed CI failures and the controlled
scope experiment are distinct evidence. The CI interleaving itself was not logged.

Full 39-test Debug/Release admission, strict Clippy/format and final source-gate
results are recorded separately. Current CI remains required before calling the
platform qualification complete. Do not treat these test results as a new
production runtime security proof.

The `.rs.txt` files are exact textual diagnostic snapshots, not additional product
Rust modules. The retained drivers ran from `target/configuration-integration-current`
with its normalized consumer/package graph; their prerequisite paths are explicit
in the command receipts.
