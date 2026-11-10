# Original-message recovery after two foreign policy adoptions

The existing C/Swift/Kotlin second-adoption test previously checked G2/T2 commit,
activation and the exact T1 predecessor, separately from original-session traffic.
It now establishes the original session under P0, commits an application effect
and loses its acknowledgement when the receiver exits with code 77, then carries
that unresolved message through both G1/T1 and G2/T2. A final retry uses the
original session and message IDs. The receiver's effect file retains its device,
inode, length and modification time; there is exactly one application effect,
and a fresh client process observes the actual Acknowledged state.

The independently signed wrong predecessor still fails, preserving the prior
Committed result and original owner. During that refusal check, current-message
inspection selects the actually adopted P1 public document; P2 is selected again
only for the subsequent valid stage. Original P0, signer, wrapping key, journal,
bootstrap bundle and session identity remain unchanged.

All nine renewal regressions passed for each selected consumer:

| Consumer | Tests | Observed suite duration |
| --- | ---: | ---: |
| C | 9 | 498.36 s |
| Installed Swift dynamic package | 9 | 504.27 s |
| Installed Kotlin, Serial GC | 9 | 549.16 s |
| Installed Kotlin, G1 GC | 9 | 549.16 s |

These durations include real expiry waits and are not application performance
measurements. The C and Swift focused two-test checks also passed. Fourteen
artifact-reader tests, scoped Rust formatting and strict enrollment Clippy passed.
The existing installed CI collectors select the same nine tests in Debug and
Release. This local Debug qualification does not replace their current CI runs.

The Swift package was archived, installed outside the checkout, and verified
member by member. Its executable checks the exact loaded native library path.
The engine uses the standard package `@rpath` install name and was built from the
retained SDK source package. Kotlin uses the previously installed archive and
unchanged runtime JAR/native bytes, with distinct Serial/G1 launchers. C uses the
retained client and its actual loaded development library. Exact executable,
package, source and runtime hashes are retained; all producer inputs were checked
before and after each accepted execution. These are wrappers over the same native
protocol implementation on one macOS arm64 host.

The initial C and Kotlin runs each passed eight regressions and rejected the new
fixture with `Scope`: it incorrectly tried to extend a 3600-second P0 with a
2400-second P1. The corrected fixture derives increasing policy lifetimes without
changing the protocol guard. Swift setup failures separately exposed the wrong
static/dynamic consumer pairing, a development-library absolute install name and
an unresolved SPM build-path alias. The original failed receipts and source are
retained in `CAPTURE.zip`; neither loader nor evidence-path validation was relaxed.

The shared `policy_session.rs` helper now owns session setup, lost reply, message
status and effect-preserving retry assertions. The original traffic test falls
from 221 to 55 lines, and its parent file from 1094 to 961 lines. The 232-line
helper is reused by both single- and two-generation scenarios. This reduces
duplicated test logic; no product runtime speedup is claimed.

No production API or protocol implementation changed. No accepted device or
protected historical cohort was reopened. Physical-device, independent protocol
implementation, PCS, broader lifecycle/performance and release requirements keep
their separate status. In particular, the browser adapters still lack joint G/T
stage/reconcile/activate entry points; ordinary G and independent P evidence does
not establish that product capability.
