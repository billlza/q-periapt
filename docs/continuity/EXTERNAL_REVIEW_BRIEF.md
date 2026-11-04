# External security review preparation

Planning snapshot: 2026-11-04. This prepares the independent review required by
[the 0.2.0 release scope](RELEASE_0_2_SCOPE.md). No reviewer has been selected or
contacted, no price or availability has been confirmed, and no engagement or
release transaction is authorized by this document. The current local source
reference is `6ce866b31088b3215bcc24bcfef84b4075ff5907`; it is not the frozen
review candidate. Re-pin the source, contracts and package identities together
before formal review begins.

The deliverable sought is a construction and implementation assessment of the
declared secure-session contract: authorized establishment and communication,
traffic-independent PQ progress, exact recovery of original operations,
revocation, device replacement and continued authority maintenance. The host's
account login and authorization remain separate from device-key possession.

The [computational recovery note](COMPUTATIONAL_RECOVERY_V1.md) supplies a
concrete root-extraction route and conditional hybrid argument for review. It
does not close the combiner premise, shared-root key-schedule composition or PQ
proof obligations and must not be presented as the completed protocol proof.

## Candidate reviewers

These are candidates for a scope discussion, based on primary sources checked
on the snapshot date. Fit is an inference from their published work, not a
verified commitment by a particular review team.

| Candidate | Relevant primary evidence | Matters to confirm in writing |
| --- | --- | --- |
| Trail of Bits | Its [cryptography service](https://trailofbits.com/services/cryptography) lists post-quantum protocols, Rust implementations, threat-model work and automated protocol verification. This makes a combined construction/implementation engagement worth investigating. | Named expertise in multi-epoch recovery, hybrid/HKDF composition and leakage from retained entropy/signing reservations; coverage of the Rust journal and Witness lifecycle in the same scope. |
| NCC Group | The [Entropy/Rust report](https://www.nccgroup.com/media/bq2gfxb3/_ncc_group_entropycryptography_e008526_report_2023-08-25_v10.pdf) covers Rust cryptographic libraries, specification comparison, signature/serialization findings and timing analysis. The [WhatsApp Contacts report](https://www.nccgroup.com/media/3ckm2llr/ncc_group_metaplatforms_2024-10-11_v11.pdf) covers identity-linked storage, new-device recovery and a key directory, with separate design and implementation phases. | PQ multi-epoch analysis and non-HSM local persistence/unknown-commit recovery. The Contacts report explicitly excludes PQ implementation review (page 46); it is not evidence of that qualification. |
| Least Authority | Its [MDK report of 20 March 2026](https://leastauthority.com/wp-content/uploads/2026/03/Least-Authority-White-Noise-MDK-Final-Audit-Report.pdf) identifies Rust messaging-SDK issues involving identity binding, authorization, stale state, commit races, persistence and retrying the same event ID. | PQ construction-analysis staffing; explicit redb/IndexedDB, crash-boundary and Witness-transfer coverage. That report excludes flexible storage and decentralized communication from its stated scope. Its same-ID retry suggestion was closed through clarified documentation rather than implemented retry (pages 60–61); Q-Periapt's required exact-recovery contract cannot be closed that way. |

Do not infer fees, schedule, acceptance, certification or complete capability
from these sources. A proposal must identify the assigned specialists, methods,
scope exclusions, report terms and fix-verification allowance. No new external
account, repository access, credentials or paid resources should be provisioned
as part of this preparation.

## Proposed technical scope

| Review question | Existing material and implementation entry points | Required finding evidence |
| --- | --- | --- |
| What does recovery mean under the actual attacker view? | [Recovery conditions](RECOVERY_CONDITIONS_V1.md), [secret/state dependencies](RECOVERY_DEPENDENCIES_V1.md), actual rekey [response](../../research/continuity-identity-candidate/src/durable/messages/rekey/response.rs) and [completion](../../research/continuity-identity-candidate/src/durable/messages/rekey/completion.rs). Include captured reservations, wrapping keys, signer files, retained traffic and ongoing acquisition. | State exact compromise, entropy, identity and delivery assumptions. Relate any attack or reduction to actual derived keys and published messages. A progress counter alone is not a recovery condition. |
| Do the symbolic claims support the declared construction? | [Joint replay](../../research/sdk-alpha1/evidence/20261104-multi-epoch-replay/README.md), pinned models, tools and complete query inventory. MAIN and 24 reusable dependencies passed; 13 other queries remain incomplete. | Separate symbolic validity, multi-round execution witnesses, computational composition and implementation correspondence. Preserve unsuccessful branches and the original query contracts. |
| Are bytes bound to the right identity, purpose and operation? | [Wire contract](WIRE_V1.md), [compiled descriptor](../../research/continuity-identity-candidate/src/contract.rs), [signed envelopes](../../research/continuity-identity-candidate/src/crypto.rs), [owner/authority boundaries](PRODUCT_ADMISSION.md). | Identify an accepted wrong encoding, purpose, identity, policy, service, request or operation; or explain the checked construction and its assumptions. Include implicit rejection and old KAT compatibility. |
| Are state changes durable, atomic and recoverable? | [Storage contract](STORAGE_RECOVERY_V1.md), [state machine](STATE_MACHINE_V1.md), [write intents](../../research/continuity-identity-candidate/src/durable/write_intent.rs), [protected storage](../../crates/q-periapt-host-store/src/filesystem.rs). | Trace commit/release ordering, cancellation, concurrent updates and unknown outcomes. Preserve original IDs/results and independently committed application effects. Distinguish injected faults, process termination and physical power-loss claims. |
| Are current authorization and retained history kept distinct? | [Roster admission](../../research/continuity-identity-candidate/src/durable/rosters.rs), [Witness admission](../../research/continuity-identity-candidate/src/durable/anchoring.rs), [directory ledger](../../research/continuity-reference-app/src/directory_ledger.rs), [CLI](../../research/continuity-reference-app/src/bin/q-periapt-prekey-directory.rs). | Check authorization before and after relevant I/O and release. Historical signature validity must not imply current permission, lack of cancellation, consumption or delivery. |
| Does Witness handoff preserve every required stage and original operation? | Existing [handoff implementation](../../research/continuity-identity-candidate/src/anchor/store/handoff.rs), [source](../../research/continuity-identity-candidate/src/anchor/store/handoff_source.rs), [import](../../research/continuity-identity-candidate/src/anchor/store/handoff/import.rs), [retirement](../../research/continuity-identity-candidate/src/anchor/store/handoff/retirement.rs), [activation](../../research/continuity-identity-candidate/src/anchor/store/handoff/import/activation.rs) and [history](../../research/continuity-identity-candidate/src/anchor/store/handoff/history.rs). | Treat source freeze, target import, source retirement, target activation, client persistent choice and current communication authorization separately. Review repeated transfers, root replacement and relevant cancellation/expiry/revocation/unknown-result interleavings. |
| Does the supported API preserve ownership and failure semantics? | [Product admission boundary](PRODUCT_ADMISSION.md), the [candidate C owner](../../bindings/c/ContinuityPackageConsumer/src/lib.rs), [base ABI 2 header](../../crates/q-periapt-ffi/include/q_periapt.h), and the supported language/platform consumers. | Identify concrete owner, thread, cancellation, callback, lifetime or error-mapping violations. Base SDK ABI 2 and an unpublished candidate interface are different admission states. Shared-core evidence may be reused with explicit binding-specific coverage. |
| Can the declared workload be maintained without unsafe reuse? | [Current numeric bounds](BUDGETS_V1.json), [directory operating contract](../../research/continuity-reference-app/DIRECTORY_LEASES.md), capacity tests and the eventual measured resource/maintenance contract. | Establish the declared limit, refusal before exhaustion and safe maintenance path. Do not add unpromised scale or automatic compression as a requirement; do not accept silent key reuse, operation loss or authority resets as maintenance. |

This scope does not add a machine proof of every Rust/FFI/OS component, exhaustive
platform/state permutations, a second Android phone or Intel macOS adaptation.
It does require scrutiny of the platform mechanisms and bindings on which the
actual release promises depend. Resource and platform qualification remain
product acceptance work even when a reviewer considers their security aspects.

## Material package and remaining preparation

1. Fix the review commit and list all source/build/package identities, interfaces,
   platform boundaries, dependency locks and applicable security claims. Keep
   later fixes as explicit diffs for the reviewer's recheck.
2. Supply the documents and source entry points above, a protocol-to-implementation
   correspondence table, public vectors and exact positive/negative cases.
3. Include the [P0 installed OpenSSL records](../../research/sdk-alpha1/evidence/20261104-openssl-witness-census/README.md),
   [P2 real-directory records](../../research/sdk-alpha1/evidence/20261104-directory-cli-crosscheck/README.md),
   proof replay and relevant fault/process/device evidence. Export public test
   artifacts only; exclude live accounts, device storage, private keys and logs
   containing private test pages.
4. Refresh the CI and installed-platform matrix against that candidate. The
   [current CI failure record](../../research/sdk-alpha1/evidence/20261104-ci-runtime-failures/README.md)
   remains incomplete and preserves count-check, guest/transport and artifact-transfer failures. Historical passes
   and the focused source/wheel readback do not qualify the final installation.
5. Finish the product/ABI, capacity/maintenance and resource contracts before
   the formal engagement. The current numeric contract explicitly remains
   unfrozen; the unpublished candidate has not thereby become product ABI 2.
   Keep the computational argument and implementation-correspondence gaps
   visible rather than presenting the symbolic replay as their completion.

The request to a selected reviewer should require a source-bound report with
scope, methods, assumptions, findings, reproducible evidence, impact and fixes;
explicitly record inconclusive areas and remaining risk. Findings affecting a
declared security promise must be fixed and rechecked before release. Agree on
retest coverage and how security-significant changes invalidate earlier review.
Internal analysis, this preparation and a report's mere existence do not satisfy
the external-review gate. Final CI, package identity checks and explicit release
authorization still follow that gate.
