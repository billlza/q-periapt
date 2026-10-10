# Kotlin persistent policy and authority recovery

The host JVM product now exposes fixed-authority provision/open/update and
independently authorized recovery provision/open/enrollment/prepare/recover/reopen
through the existing 51-export native ABI. No Rust persistence, cryptography,
C export or Continuity protocol was added. Immutable public recovery containers
preserve signer roles. Async operations snapshot mutable input before dispatch.
Cancellation disposes a newly returned owner; successful ownerless replay leaves
the current runtime and children intact.

The original shared JVM handle retained its parent even after successful close.
With only a closed key alias retained, an abandoned persistent runtime therefore
kept the database busy. The unchanged real-store regression failed with `-20`
before the fix and reopened successfully after it, using the same native library
and test-source digest. Successful close now detaches the parent. In-flight
calls snapshot and fence that parent through native calls and output adoption.
Additional cases cover decapsulated/derived secret ownership and a controlled
JVM-boundary close race that transfers a real native owner. The latter is not an
injected Rust race or a process-crash test. Cleaner timing remains unspecified
by the API; the bounded collection rounds are test conditions, not a deadline
promised to applications. The design follows the JDK 25
[reachabilityFence](https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/lang/ref/Reference.html#reachabilityFence(java.lang.Object))
and [Cleaner](https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/lang/ref/Cleaner.html)
contracts.

The prototype's 29 tests passed with both Debug and Release native libraries and
explicit G1 and Serial collectors. Its implementation matches the integrated
product; the final product adds recovery-reopen documentation and a negative
case for substituting a newer policy. Final packaging reran all 29 tests against
the actual C release archive. Recovery cases cover `u32::MAX`, independent root
replacement, disabled/newly enabled policy, replay after later advancement,
explicit v1 enrollment, mutable input snapshots, and cancellation after a real
commit or replay. The shared async handoff is controlled in the late-cancel
tests; these do not substitute for native fault injection or process cuts.

The final producer staged a Maven archive and installed it into a project outside
the checkout. It resolved the SDK, stdlib and annotations outside the checkout,
ran six consumer groups including durable update, authority recovery and existing
store enrollment, and passed the Java module-path probe and six loading/access
negative controls. Native package preparation independently passed its CMake,
pkg-config and frozen-header consumer checks. Strict dependency verification,
warning denial, exact native source matching and archive readback stayed enabled.
Twenty related JVM/Continuity packaging tests passed.

Three earlier package attempts remain captured: (1) an old C archive was rejected
for differing source inputs; a clean `a671719e` native package replaced it;
(2) the installed consumer incorrectly supplied the later policy to original
recovery reconciliation, correctly receiving `-3`; the consumer now retries the
original policy while receiving the stored current runtime, with documentation
and negative controls; (3) all six consumer groups passed, but dependency paths
still pointed into a checkout-local Gradle cache. Moving the dependency cache
outside the checkout allowed the unchanged path guard to pass in attempt 4.

`CAPTURE.zip` contains source snapshots, test XML, exact commands, original
failures, build/consumer logs and manifests. `INSTALLED_CONSUMER.json` identifies
the archive and its digest. This is macOS arm64/JDK 25 evidence. Linux CI for the
new facade, broader physical/minimum-OS checks, Continuity integration, crash and
security/performance gates remain separate. This is not release qualification
or a public Maven publication.
