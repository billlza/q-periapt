# Current Apple package: physical continued recovery

A fresh iPad Pro 11-inch (M4), iPadOS 27.0.1 cohort completes both continued-recovery routes using the Apple package containing the bounded historical roster decode cache. Each route preserves the original identity, session and pending operation across actual policy expiry, independently authorized renewal, rekey epoch 1 and newly consumed business traffic.

| Witness / trust / original write | Recovery calls | Renewal and traffic calls | Deliberate process exits |
| --- | --- | --- | --- |
| Signed TCP / fixed / unapplied | 24 | 37 | 2 |
| Mutual TLS / recoverable / applied | 23 | 37 | 2 |

The 121 calls use 121 distinct application processes with explicit startup admission, structured termination and container receipts. Four deliberate exits return 77; 117 return zero. These are application process interruption cuts at the held Query and after confirmation, not physical power-loss or arbitrary storage-internal cuts. Each route's first three enrollment/authority preparation calls use the signed setup carrier; the TLS route then retains mutual TLS. The exact phase and carrier census includes 74 policy-renewal and traffic calls.

Recovery preserves the original pending request through cancellation and both interruption cuts. Completing the old write cannot activate expired P0. Independent account and policy authorities approve P1 for the original renewal request; incorrect approval signatures, substituted operation identities, missing target selection and missing live registry are refused. Lost commit responses and exact retries retain one operation. The receiver adopts P1 independently before continued traffic.

The native receiver harness reads the actual synthetic application effect files, checks the original effect is unchanged and checks the exact count is two per route after fresh traffic. It exports those bytes before its temporary responder state is removed. The separate public reader verifies those exported effects against the session/message identities, expected payloads and successful receiver process outputs. It does not reopen the responder's private state. Both routes produce a distinct new message after epoch 1; no duplicate original business effect is observed.

The cohort uses new application, identity, store and output paths. SDK package source is `9d396755c3f872d3a59932c6fe106b2b5e1b2e59`; qualification source is `5a03bbdb6ccd90824b7adfc3a54ee687c4cd2944`. The intervening commits contain evidence/review documentation only. The reference host engine remains hash-pinned at source `610234b0b684e4e39bad97a953f5c66e74df2e91`; preparation verifies that its only candidate implementation difference is the five-file roster-cache change. This is cross-version integration using a shared protocol implementation, not an independent implementation.

| Artifact | SHA-256 |
| --- | --- |
| Apple package | `5cbaba4b10e5c779a362f3bf20f09d687ed31fabce78579e95ff8ea32c4315e7` |
| Packaged iOS static library | `a2b313e80919c6179492131ddc5ebe55acc64589a1f2ddda1057fe950ec0bea8` |
| Signed iPad application | `77097a1eacd7c5859b4b030c0d41d5c7c74408fffaa1c76c807653d73cae0b28` |
| Public capture | `28dbda3d373697694eee036b0d85dce7fd697c24e726f4159281692cd59651ee` |

The public capture contains 4128 members. Extraction verifies every member hash and reruns both public readers. Four census tests reject carrier substitutions at all 121 positions, missing/extra calls and substituted identity/mode/profile fields. Sixteen additional mutations of this cohort's public copies reject wrong effects/counts, unrelated identity, false expiry acceptance, absent rekey and invalid receiver results. These are evidence-reader controls, not cryptographic security experiments.

The original outer driver exited 1 after the successful physical producer because the separate census test launch omitted the repository Python bootstrap. No tests ran in that failed control invocation. A new public-only invocation supplies the explicit repository and helper source paths; all four unchanged census tests pass. Both command receipts are retained, and no device/private state is rerun.

The owned app is removed and absence verified. The capture excludes private runtime stores, signing keys and provisioning profiles; private PEM framing is checked, including decoded JSON strings. Hardware/signing identifiers are redacted. The earlier failed iPad startup and successful iPhone pre-SDK startup remain in the [package checkpoint](../20261015-apple-roster-cache-package/README.md); neither is relabelled as this successful SDK run. Activation after the user's readiness confirmation does not establish the earlier startup failure's root cause. Connection resets observed in this accepted run: 2; the existing bounded relay records them without retrying SDK calls or fabricating responses.

This closes current-cache Apple physical recovery qualification for the two stated routes. It does not establish post-compromise secrecy, physical power-loss behavior, background/Data Protection behavior, independent protocol interoperability, performance/energy guarantees or overall release readiness. The [cache checkpoint](../20261015-roster-decode-cache/README.md) and [Apple package qualification](../20261015-apple-roster-cache-package/README.md) retain their measured scope. Current-source hosted CI/CodeQL, remaining platform qualification, construction analysis, maintenance/freeze and external review remain separate gates. One accepted Android phone remains sufficient for its stated scope; no Intel Mac target is added.
