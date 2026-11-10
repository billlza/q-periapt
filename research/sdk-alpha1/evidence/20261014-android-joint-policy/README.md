# Android local joint credential and policy renewal

Android now exposes `stagePolicyContinuation` and `activatePolicyContinuation`
over the existing C G/T coordinator. Previously the adapter exposed local
reconciliation and historical recovery without these matching entry points.
The new JNI selectors copy and validate the complete independent grant, account
pin, both policy approvals, historical predecessor and optional adopted T. No
native protocol, journal format or cryptographic engine changed.

The accepted physical API 37 phone completes this device acceptance scope. Intel
Mac is outside the requested platform scope.

| Execution | Applied | Pending | Total fresh processes |
|---|---:|---:|---:|
| Host Java/JNI, fixed trust | 33 | 26 | 59 |
| Host Java/JNI, recoverable trust | 33 | 26 | 59 |
| Physical Android, recoverable trust, installed R8 APK | 33 | 26 | 59 |

Every route generates a fresh original registration, communicates over an actual
session and observes real P0 and target-policy expiry. Applied routes stage and
reopen the exact G/T, commit it, transfer the original owner, admit the independent
account grant at the C counterparty and retry the original uncertain message. The
application effect remains single. The original identity and journal remain exact.
After target expiry, two historical recoveries return that same commit; current
policy selection is refused. Reusing the completed G operation is refused, while
a new operation exports the actual adopted credential, roster and T predecessor.

Pending routes repeat preparation and reopen before expiry. Two historical
recovery attempts after expiry return Suspended and leave the original Pending
metadata intact. They do not invent a commit, abandon the operation or publish a
device. Their original message remains uncertain; these routes do not claim a
successful retry. Each accepted phone route uninstalls the test app and removes
its owned ADB reverse mappings. Final direct checks found neither the app nor any
remaining reverse mapping.

`CAPTURE.zip` contains the six public executions, process receipts, source hashes,
package provenance, selected build logs and retained failure records. It contains
no private journals, wrapping keys or device signing keys. Its SHA-256 is
`a9fe5800b6841fd195a60bac4fc89ce2c2e0a548a4dbfd2def25cecebab35b98`.
`CAPTURE.json` records individual results and hashes. Runtime Java/JNI sources
match the host and Android builders; the host JAR equals the AAR's `classes.jar`.
The README link was updated after packaging; documentation is not an AAR member.

- AAR SHA-256: `0e013023191c68c0be74a4a5e8be55c6a928f26b037edb367675ace02627c3df`.
- Installed APK SHA-256: `29e3e3e7cf3c08030af6a37a36a780d83609b4ef5ce54d6084b7dcad73fed122`.
- Runtime JAR SHA-256: `2b887662a81dd652519b83d5a70d1a73f5946dd69307d754f944530045657d03`.

`CHECKS.json` and `artifact-controls.stderr` record 53 passing artifact and workflow
controls, including five tests reading these actual captures and rejecting changed
policy/predecessor/operation fields, fake terminal outcomes, missing process
receipts, false expiry and duplicate effects. Java, JNI and Android compilation
used warnings as errors, as did the native harness. Scoped Rust formatting and Git
whitespace checks pass. Full-workflow actionlint reports the same two preexisting
unknown `ubuntu-26.04` labels before and after the change; it is not reported as a
clean full-workflow lint result.

The retained unsuccessful attempts identified test-fixture issues:

- An original-policy scope with a non-null preceding T is a Checkpoint error
  (105), before signature-scope comparison. The initial fixture expected 103.
- A new issuer request cannot reuse a completed G operation. The corrected case
  explicitly requires rejection (211), then generates a fresh operation.
- The first phone retry assembled an 86,559-byte recorded ADB command by resending
  already retained grant/approval inputs alongside the peer bundle. A harmless
  `shell true` control succeeded at 65,000 argument bytes and failed at 66,000 and
  86,500 with the same `error: closed`. The fixture now provisions immutable
  grant/approval files at staging, reuses them for later calls, and bounds the
  command before invoking ADB. SDK checks and the AAR remained byte-identical.

These failed cohorts are not relabeled as passes or reopened. The accepted host
pending routes precede the additional applied-only next-request control; their
pending path and production adapter are unchanged. Both physical routes run the
final harness and APK.

The CI matrix now runs Android and Kotlin installation qualification as independent
jobs, preserving all native prerequisites, both Debug/Release profiles and existing
command bounds. This repeats native prerequisites in the separate jobs, while
avoiding one ever-growing sequential language matrix. Both independent P/G and
joint G/T public records are retained. Full hosted execution of this source remains
pending; the prior Rust CodeQL run was still active when these checks completed.

This is local G/T acceptance. Required-witness joint G/T end-to-end Android routes
remain a distinct workflow; existing independent P-then-G witness evidence does
not substitute for them. The C counterparty uses the same protocol engine, so this
is cross-language and physical-device evidence, not independent-implementation
security evidence or a full 0.2.0 release claim. Broader lifecycle, protocol/recovery
analysis, performance, independent-host/implementation and release gates remain.
