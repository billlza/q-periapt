# Installed Kotlin: issuer request and G after independent P

Kotlin now exposes local and witnessed credential-renewal issuer snapshots with
owned public fields. The original owner, P0 and original credentials remain
fixed; current policy authorization and the acknowledged predecessor come from
the actual resumed enrollment. Exporting a request neither reserves a journal
nor authenticates/authorizes an issuer decision. The public wrapper copies and
checks native lengths, reserved words, record tails, validity and unsigned
checkpoints. It exposes no private key material.

The extended proposal/cancellation decoder now accepts the native 03 format for
G carrying independent P. `independentPolicyStatement` has the policy-renewal
statement type; the joint-T `policyStatement` remains null. Version 03 cannot
request adoption. Existing 01 and 02 behavior and old fixed-width credential
metadata remain unchanged. The new codec and consumer dispatch live in separate
small files; the existing FFM boundary adds layout, symbol and invocation entries
without duplicating the renewal state machine.

## Executed evidence

- 75 Kotlin tests passed against the actual native library, with strict Gradle
  dependency verification, JDK 25, and compiler warnings treated as errors.
- The same actual native QPCRNP03 proposal was run through an isolated test before
  and after changing only `PolicyContinuation.kt`: the old parser failed with
  malformed native metadata; the new parser passed. Both reports are retained.
- A fresh Maven/native candidate archive was extracted outside the repository.
  Its native license inventory, Maven artifacts, pinned consumer dependencies and
  complete runtime closure were verified. The independent consumer compiled from
  that installed archive; it did not use workspace source paths.
- Eight fresh installed JVM routes passed: Serial and G1 collectors, each with
  signed and mutual-TLS witnesses under fixed and recoverable trust. Each route
  verifies original registration, actual P0 expiry, independent P, issuer request,
  same-key G, rejection of a bad grant signature, the actual lost committed reply,
  exact historical recovery, peer admission, and acknowledgement of the original
  session/message with one business effect. Historical recovery sends no fresh
  G Commit/Close. The next issuer request preserves P0/original credentials and
  advances the acknowledged predecessor.
- Every route also verifies closed/released account-authority refusal, observable
  JVM collection and the expected native slot reclamation. No accepted cohort
  was reopened. This is bounded Serial/G1 coverage, not a universal GC guarantee.

`CAPTURE.zip` contains the actual public records, terminal outputs, executable and
source identities, Maven closure, launchers, test reports, and the parser's
before/after regression. Its SHA-256 is
`f902826fd6b8aefc9748422310c7f5435f62aa7a0acb26371862bf086effab31`.
`CAPTURE.json` records the eight distinct original sessions/requests. Private
journals and issuer keys are not exported.

The tested archive SHA-256 is
`355b77f401c3589e735f83021244f9489e70000f3638b329e6ba39bd8b4fcc7d`;
its Maven JAR SHA-256 is
`20a0ab53c827157244956cc6a1625c7afa4c1c0424181b7f240fd75ca15ab015`.
A subsequent README-only archive adds the issuer/recovery guidance. Its extraction,
license and Maven inventories were verified and every runtime entry is byte
identical to the tested archive. `DOCUMENTATION_SUCCESSOR.json` inside the capture
records this comparison; it does not claim another runtime execution.

## Qualification pipeline and retained failures

An initial offline build lacked a cached Kotlin standard library. Strict pinned
resolution supplied it; no checksum verification was relaxed. A first consumer
built inside the repository was correctly rejected by the runtime-location gate.
A fresh external archive installation then passed that unchanged gate.

The new P/G CI qualifier initially omitted the collector from its output prefix.
A routing-only regression reproduced the second collector reusing the first
collector's filename. After all protocol producers were terminal and their inputs
were sealed, the qualifier gained distinct Serial/G1 prefixes and strict collector
selection. The same regression passed, alongside actual receipt checks and
negative controls for GC evidence and policy/credential bindings. All 30 affected
artifact tests pass; routing stubs are not presented as protocol execution.
Existing CI globs retain both collectors' public outputs and all Kotlin suites.

## Limits

This checkpoint uses the actual debug native C/Rust engine and installed Kotlin
JVM bindings on macOS ARM64. It does not claim an independent protocol
implementation, a new Android device run, full release-profile/package admission,
product-path performance, or completed 0.2.0 release readiness. Those remain part
of the wider goal. The snapshot interfaces expose both local and witnessed paths;
the full newly executed P/G matrix here is the required-witness matrix.
