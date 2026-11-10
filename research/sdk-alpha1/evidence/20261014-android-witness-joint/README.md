# Android required-witness joint policy lifecycle

The existing public Android G/T APIs now have end-to-end qualification with
independent signed TCP and mutual-TLS witnesses. The matrix covers fixed and
recoverable SDK trust, and both Applied and Closed outcomes. Production Java/JNI,
native protocol and journal formats are unchanged from the local G/T milestone.
The shared fixture prepares the original enrollment, grant and dual policy
approvals once; witness authorization and terminal handling have separate modules.

| Accepted execution | Applied | Closed | Processes |
|---|---:|---:|---:|
| Host signed TCP, fixed/recoverable | 2 × 49 | 2 × 42 | 182 |
| Host mutual TLS, fixed/recoverable | 2 × 49 | 2 × 42 | 182 |
| Physical API 37, recoverable | TLS: 49 | signed TCP: 42 | 91 |
| Local-journal regression after shared fixture extraction | 33 | — | 33 |

The accepted single phone satisfies this device acceptance scope. Each route uses
fresh registration, identities and storage. The host and phone invoke real owned
APIs in separate processes, use real signatures and observe actual P0 and target
policy expiry. No private journal or signing-key mutation creates the outcomes.

Applied routes prepare QPCRNP02 and independently authorize the complete G/T at
the witness. The witness durably applies Commit but drops its reply; the client
returns Anchor failure while retaining Pending. An explicit Close from that
unknown state sends exactly one Close and returns the original Committed outcome,
without another Commit. Current admission then transfers the original owner and
retries the original application message against the independently updated C
counterparty; its business effect remains single. After policy expiry, the same
terminal history remains readable. Reusing the completed operation is rejected;
a new request reports the actual adopted credential, roster and T.

Closed routes reserve QPCRNC02 without preparing a sealed target. Reservation
permits neither Commit nor activation. After target expiry, the independent witness
verifies the historical grant and both T approvals before authorizing closure.
The client observes and retires this exact Closed transaction. Its next issuer
request retains the original credential, roster and P0, with no uncommitted T
adopted. These routes leave the original application message uncertain and do not
claim a successful retry.

Active Close and passive observation are distinct. A first explicit Close may
send that requested command. Later observation/replay must send neither a new
Commit nor Close. A previously persisted terminal result may be read entirely
locally; an empty transcript is allowed only for that tested cached-Applied case.
First Closed completion requires actual witness exchanges. Local-only request,
reconciliation and historical-recovery paths cannot downgrade the witness.

`CAPTURE.zip` retains ten public witness executions, a fresh local regression,
process receipts, raw witness traces, build provenance, source hashes and earlier
unsuccessful attempts. Its SHA-256 is
`e87a4f7868511f2d49098ef487e85e6a19e1a7f6e8a8f17409316df4bac26c25`.
Private journals, wrapping keys, signing keys and TLS private keys are excluded.
Each phone route verifies its installed APK hash and distinct ART process IDs;
the application and owned ADB reverse mappings are removed afterward. Direct final
checks confirmed cleanup.

- AAR: `0e013023191c68c0be74a4a5e8be55c6a928f26b037edb367675ace02627c3df`.
- APK: `0c8747829a5dd4054aa1566fab2ccee6260466ced2c238a9b62b9b24747801a4`.
- Runtime JAR: `2b887662a81dd652519b83d5a70d1a73f5946dd69307d754f944530045657d03`.
- Native host harness: `ee955614ad6f8cec0a73e4d9ecf3972069775fc913185adcdc2c23b3ceab7f63`.

The host runtime JAR equals the AAR's classes; runtime Java/JNI sources match both
builders. The SDK AAR remains byte-identical to the earlier local G/T acceptance.
The README link was updated after packaging and is not an AAR member.

`CHECKS.json` records 58 passing artifact/workflow controls, including adversarial
mutations of these actual captures. They distinguish witness binding from subject,
G from T and P, active Close from passive observation, cached Applied from missing
Closed evidence, and the original operation and single business effect. Native,
Java/JNI and Android builds deny warnings. Scoped formatting and whitespace pass.
Local actionlint still reports the same two preexisting unknown `ubuntu-26.04`
runner labels; this is not presented as a clean whole-workflow lint result.

The earlier failures remain visible:

- The first Applied fixture incorrectly forbade Close inside the explicitly
  requested Close interval. The coordinator's Proposal branch legitimately sends
  Close; its Cancellation branch only observes. The corrected fixture captures
  the explicit interval before asserting exactly one Close, then independently
  checks passive history. No SDK behavior was relaxed.
- An initial public reader placed the 96-byte subject at offset 8. The canonical
  record has a 32-byte witness binding at 8..40 and subject at 40..136. Native TLS
  closure had already completed all 42 calls. A separate READBACK.json verifies
  those unchanged native/JNI inputs and corrected public evidence; the original
  failed controller record is retained. The final matrix uses eight fresh runs
  of the corrected harness, so this initial cohort is not counted again.

The Android CI lane runs this entire matrix for Debug and Release and retains its
public traces. Full hosted acceptance of the new source is still pending. The old
Rust CodeQL Analyze step on 986ef66c failed after its 300-minute execution interval;
its job was still performing post-analysis work when local checks completed. Its
failure must be investigated rather than equated with a security finding, a pass,
or an excuse to remove queries.

This qualifies the original G/T Applied/Closed workflow and current-boundary
behavior. It is not independent protocol implementation evidence, a proof of
post-compromise recovery, a performance result or a complete 0.2.0 release claim.
Repeated later G/T generations, broader lifecycle composition, security analysis,
independent hosts/implementations, performance and release gates remain separate.
