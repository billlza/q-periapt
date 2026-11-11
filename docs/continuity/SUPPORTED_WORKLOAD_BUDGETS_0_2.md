# Continuity 0.2.0 supported-workload budget decision

Prepared on 2026-11-09 against source
`6a2ee33af2d67bb982d339cbeb49f2310c7e7032`, tree
`3df69e936a13213f8b381661a443ea09f82bc32b`.

This decision retains the implemented joint resource limits and selects six
regression budgets for the precisely defined desktop reference workloads below.
Each number is identified as an implementation limit, an observation or a
selected policy value. The retained capacity, original-ID
recovery, complete-interval throughput and explicit fanout retirement results
already provide the corresponding evidence. `BUDGETS_V1.json` remains schema 3
with `frozen_product_contract=false`; this document changes no runtime limit,
platform scope or publication status. The budget selection is complete; final
chosen-artifact verification and coordinated specification/release freezing
remain in the existing admission sequence.

The source map and independently recomputed tables are retained in the
[budget-review packet](../../research/sdk-alpha1/evidence/20261109-workload-budget-review/README.md).
The review reads existing source and observations. It executes no new native
workload and adds no device or baseline requirement.

## 1. Adopt the limits as a joint admission contract

All 21 fields in [BUDGETS_V1.json](BUDGETS_V1.json) match the current Rust constants
and the [compiled descriptor source](../../research/continuity-identity-candidate/examples/contract_report.rs).
They are concurrent admission constraints. In particular, a record-count ceiling
does not reserve space for that many maximum-sized records. Admission succeeds
only while the count, encoded-image, protocol, authority and outstanding-work
checks all permit the operation. This is already the runtime behavior.

| Implemented dimension | Current hard maximum | Scope and release interpretation |
| --- | ---: | --- |
| Application plaintext / associated data | 16,384 / 1,024 bytes | Per message or complete fanout's common input; zero-length plaintext is admitted. |
| Skipped keys / outstanding messages | 128 / 64 | Per direction and retained epoch; the two counters describe different retained state. |
| Retained traffic epochs | 4 | Old epochs retain their existing settlement and resolution conditions. |
| Session/operation records | 128 | Shared operation quota; prekeys and installed rosters have separate count quotas. |
| Retained fanout records | 16 | Also charged to the 128-operation quota. Acknowledgment preserves the slot; explicit terminal retirement releases it. |
| Prekey records / installed account rosters | 1,024 / 64 | Retained prekey identities and separate installed account-roster records. |
| Device-generation history | 256 | Per installed account, with the existing history/renewal admission checks. |
| Encoded aggregate journal image | 2,097,152 bytes | Applies together with every count limit; it is an encoded-image bound, not the physical database-file size. |
| Signed roster devices / manifest prekeys | 32 / 1,024 | Authenticated format/admission bounds. Fanout must include the full required roster; the sending device is excluded for its own account. |
| Signed body / bootstrap container / individual bootstrap field | 16,384 / 65,536 / 8,192 bytes | Exact codec bounds; a complete signed wire also carries its framing/signatures. |
| Control body / complete connection frame | 8,192 / 32,768 bytes | Different carrier layers; a body maximum is not a complete-frame maximum. |
| Native carrier attempts / total invocation interval / one connect attempt | 128 / 120 s / 5 s | Maximum accepted caller parameters. Retry does not refresh the total deadline; these are not observed completion times. |

The [shared constants](../../research/continuity-identity-candidate/src/contract.rs),
[journal admission](../../research/continuity-identity-candidate/src/durable.rs),
[traffic state](../../research/continuity-identity-candidate/src/durable/messages/traffic.rs)
and [fanout admission](../../research/continuity-identity-candidate/src/durable/messages/fanout.rs)
give the implementation mapping. The contract reader separately checks schema,
closed fields and the exact compiled values.

The joint interpretation is necessary and usable. Four epochs each containing
64 maximum-size outgoing ciphertexts would already contain more than 4 MiB of
payload-derived bytes, before other journal state; the 2 MiB image check therefore
becomes active earlier. The release contract should retain these joint predicates
and explicit Capacity outcomes, rather than advertise the Cartesian product of
the individual maxima as simultaneously resident capacity.

### Capacity behavior already executed

The [installed aggregate-capacity workload](../../research/sdk-alpha1/evidence/20261104-installed-resource-baseline/README.md)
at `539845d573ac0af5fe104aabed2f96a86f9eac8b` retains 64 maximum-payload
epoch-zero outboxes and 60 epoch-one outboxes. The next operation reaches the
encoded-image cap. Two original-owner reopens retain the same absent next ID
and Capacity result. Consuming an old message then admits that same ID; all
125 original ciphertext deliveries produce exactly 125 durable business effects
per run. Four runs retain 500 checked effects and 548 rejected altered-evidence
controls. This is concrete evidence for joint capacity and recovery at that source.

The [fanout quota regression](../../research/sdk-alpha1/evidence/20261106-fanout-capacity-contract/README.md)
separately fills all 16 aggregate slots. Refusal preserves the next ID and existing
ciphertexts. Acknowledgment alone leaves capacity full; explicit terminal
retirement followed by reopening frees exactly one slot, while the retired ID
remains retired. Both relevant tests pass in Debug and Release. This establishes
the count and reclamation boundary already used by the implemented policy.

The directory is a separate operator ledger: its configured capacity is
1–4,096 original allocations. Expiry or cancellation retains one-time-key
occupancy; a full ledger rejects new assignments while retaining lookup.
Keep that explicit configuration and original-ledger preservation in the
[service contract](../../research/continuity-reference-app/DIRECTORY_LEASES.md).

## 2. Fix the reference workload and account for its complete interval

The repeated resource and throughput cohorts use source
`5678d1019861fa1b04f3a219ba3fde7e0ddaaba8`, ten actual installed SDK/engine
archives, Rust 1.98.1 Release, and an Apple M4 Max with 16 CPUs and 48 GiB RAM
on macOS 26.7.2. The source-bound observations retain four fresh repetitions per
case, all samples and the original host-condition records. The two earlier
observer-validation cohorts that overlapped other qualification processes stay
separate from these repeated measurements.

The selected reference class preserves the exact existing workload:

| Property | Single session | Account fanout |
| --- | --- | --- |
| Owners and required recipients | Two provisioned owners, one session | Three provisioned owners, two required recipients in a signed peer-account roster |
| Ordinary application work per repeat | 48 confirmed deliveries over two epochs | 12 complete aggregates, 24 confirmed recipient copies, over two epochs |
| Payload / associated-data pairs | 64/0, 1,024/32 and 16,384/1,024 bytes, balanced in each epoch | Same three pairs, balanced in each epoch |
| Independent PQ progress | One completed update between epochs | Each member session completes its independent update |
| Retained-outcome and maintenance work | Surrounding status queries remain in the measured interval | Two retained-outcome reads, explicit retirement and a durable status check per aggregate remain in the interval |
| Protection variants | Local-only; required signed-TCP Witness | Local-only; required signed-TCP Witness |
| Included execution arrangement | Serial operations, real hybrid TLS, durable application effects, all endpoints in one process on the recorded host | Same arrangement, alternating first recipient |

Provisioning, establishment, later original-operation recovery and cancellation
execute in the full cohorts and have their own observations. The ordinary-workload
denominator starts after establishment and ends at the recorded ordinary-workload
boundary. Nested epoch intervals are never added to the enclosing interval.
The [throughput protocol and exact phase data](../../research/sdk-alpha1/evidence/20261106-installed-throughput/README.md)
retain that boundary, the independent controls and every surrounding query.

### Existing complete-interval results

| Reference workload | Complete interval per repeat, observed range | Pooled confirmed deliveries/s | Plaintext KiB/s | Witness exchanges in one complete interval |
| --- | ---: | ---: | ---: | ---: |
| Single session, local | 8.062–8.334 s | 5.815563 | 33.076 | 0 |
| Single session, required Witness | 14.331–14.627 s | 3.311877 | 18.836 | 1,243 |
| Two-recipient fanout, local | 4.372–4.584 s | 5.367943 | 30.530 | 0 |
| Two-recipient fanout, required Witness | 8.123–8.296 s | 2.931603 | 16.673 | 914 |

Each pooled rate divides the total delivered count by the total complete interval
over four repetitions. Fanout's aggregate rates are half its recipient-delivery
rates. Required-Witness phase traffic is 9,124,863 framed bytes per single-session
repeat and 6,709,674 per fanout repeat, including both endpoints' Witness work.
These counts exclude TCP overhead and application TLS traffic. The full cohorts,
including setup and recovery, retain 1,410 and 1,203 Witness exchanges respectively.

Dropping surrounding work from the denominator would overstate the four rates by
1.150%, 1.700%, 0.478% and 0.659% in the displayed order. The current table uses the
complete intervals. In particular, fanout retirement and the retained-outcome
reads are already paid for in its reported ordinary service rate.

### Lifecycle and recovery observations

The [repeated resource observations](../../research/sdk-alpha1/evidence/20261106-resource-repeats/README.md)
retain 1,560 spans. Representative durations below are milliseconds; the ordinary
delivery rows use epoch one, 1,024-byte plaintext and 32-byte associated data.

| Operation | Samples per profile | Local median / maximum | Witness median / maximum |
| --- | ---: | ---: | ---: |
| Establish one session | 4 | 400.37 / 408.06 | 772.25 / 835.64 |
| Independent single-session PQ update | 4 | 251.39 / 275.85 | 493.42 / 498.71 |
| Ordinary single-session delivery | 32 | 157.24 / 173.54 | 272.87 / 287.48 |
| Retry original message after reopening | 4 | 60.36 / 65.01 | 118.77 / 123.42 |
| First fanout member delivery | 8 | 163.72 / 177.88 | 298.84 / 325.33 |
| Second fanout member delivery | 8 | 126.43 / 130.90 | 224.66 / 242.80 |
| Retire an ordinary fanout aggregate | 48 | 21.33 / 27.09 | 41.01 / 48.47 |

An ordinary Witness send uses 22 exchanges, its next-ID lookup uses two, and an
independent PQ update uses 43. The fanout first/second member paths use 31/25;
each retained member-outcome read uses three, and explicit retirement uses four.
This operation accounting explains the measured maintenance cost without
substituting an average of the entire run for an individual API operation.

## 3. Keep memory and storage quantities distinct

The ordinary-workload observations sample five stages per run. Their largest
observed resident/physical-footprint values are respectively 15,368,192/9,404,800
bytes for local single session, 16,990,208/10,944,896 for Witness single session,
15,663,104/9,781,608 for local fanout and 17,973,248/11,993,448 for Witness fanout.
The single-session sender/receiver database maxima are 393,216/405,504 bytes;
fanout's sender and two recipient databases reach 851,968/462,848/462,848 bytes.

The separate maximum-payload capacity/recovery fixture has a much larger retained
state: its observed whole-process peak RSS reaches **167,575,552 bytes
(159.8125 MiB)**, and the sender database reaches **12,455,936 bytes
(11.87890625 MiB)**. This distinguishes the actual capacity cost from the smaller
ordinary-workload stage samples. The 2 MiB encoded-image limit is consistent with
both observations: it bounds the authenticated logical image, while the database
retains its own physical allocation history.

CPU observations include the endpoints, optional Witness and observer. Sampled
stage RSS, whole-process peak RSS, physical footprint, database bytes and energy
therefore keep separate units and measurement scopes in the release table.

## 4. Selected reference regression budgets

The selected budgets apply to the recorded desktop reference workloads. Existing
observations and these engineering regression ceilings do not establish a
production service-level promise or production tail-quantile estimate.
The older [desktop](../../research/sdk-alpha1/evidence/20261018-fanout-latency/README.md)
and [hosted](../../research/sdk-alpha1/evidence/20261018-hosted-fanout-latency/README.md)
fanout comparisons keep their original allocation-change question and adverse
p95 observations; they are not pooled into this reference baseline. This scope
statement applies to the whole decision table.

The 0.2.0 budget decision uses **1.25 times the largest retained reference
observation**, rounded upward to one second for a complete interval and one MiB
for a capacity-fixture resource value. The factor 1.25 is the selected engineering
allowance rather than a statistical confidence bound. The six selected values are:

| Selected reference regression budget | Largest retained observation | Selected ceiling | Implied complete-interval service floor |
| --- | ---: | ---: | ---: |
| Single-session local, 48 deliveries | 8.333735250 s | 11 s | 48/11 = 4.364 deliveries/s |
| Single-session Witness, 48 deliveries | 14.626500042 s | 19 s | 48/19 = 2.526 deliveries/s |
| Local fanout, 12 retired aggregates / 24 deliveries | 4.583242625 s | 6 s | 4 deliveries/s; 2 aggregates/s |
| Witness fanout, 12 retired aggregates / 24 deliveries | 8.296023375 s | 11 s | 24/11 = 2.182 deliveries/s; 12/11 aggregates/s |
| Capacity/recovery fixture, whole-process peak RSS | 159.8125 MiB | 200 MiB | Resource quantity for this exact fixture |
| Capacity/recovery fixture, sender database maximum | 11.87890625 MiB | 15 MiB | Physical file quantity for this exact fixture |

The machine-readable receipt stores these six values as `selected_*` fields and
marks the policy decision complete. Their scope is the exact two desktop
fixtures above, including the measured maintenance/retirement work and the
whole-process capacity resource accounting. They supply the regression policy
for the existing final chosen-artifact verification. This document installs no
runtime timer, per-client memory cap or additional CI gate. The agreed platform
functional scope remains in force; larger-recipient quantitative envelopes and
mobile-energy measurements are outside this numerical 0.2.0 reference class and
add no admission requirement.

The signed application-send allowance retains the existing **issuer-selected B**
policy. Its
[implemented range is nonzero u16](SEND_PROGRESS_V1.md), with no unsigned default.
The installed fixture uses **B = 1,024**, but the repeated workload explicitly
updates after 24 messages per single-session epoch or six fanout aggregates per
epoch. This measures that early-control schedule; it does not turn either fixture
number into a hidden product default. The application/connection owner retains
the existing responsibility for advancing required PQ control so application
work can continue within the signed allowance. No new fixed B or control cadence
is selected.
ACK, reopen and retry never refund the allowance.

## 5. Retain the agreed platform stages

Functional/package support and this reference host's numeric cost class are
separate columns of the same release decision. The existing platform scope stays
as agreed in [PRODUCT_ADMISSION.md](PRODUCT_ADMISSION.md).

| Platform evidence | Actual retained stage and source | Budget use |
| --- | --- | --- |
| Apple Silicon macOS | Installed Release operation/resource/throughput cohorts at `5678d101`; capacity/recovery at `539845d5` | Source of the quantitative reference rows above. |
| Hosted installed Rust/C and Swift/Kotlin/host-JNI | Completed source-matched partitions at `228c944f`; six foreign Debug/Release reports accepted by the aggregate reader | Preserve the existing functional installed-cohort qualification and its exact artifacts. |
| Windows | Installed Windows 2022/2025 Debug/Release qualification at `453eef21`; its PR checkout has the same recorded tree | Preserve the accepted Windows functional/runtime stage and original identities. |
| Linux / hosted macOS fanout timing | The two historical hosted producer runs retain their own baseline/candidate binaries and 200 observations per position | Comparative latency observations remain attached to that experiment. |
| Android | The already accepted single API 37 phone; actual minified AAR lifecycle and signed-TCP/mTLS Witness receipts | Preserve the physical-device gate and required software regression scope on that same device. |
| iOS package targets | Four-target Apple package at `e5ceec37`: arm64 device, arm64 simulator and x86_64 simulator build/link; extracted macOS arm64 probe executes | Preserve the declared architecture/package stages. |

Sources are the [hosted readback](../../research/sdk-alpha1/evidence/20261107-ci-release-readback/README.md),
[Android lifecycle](../../research/sdk-alpha1/evidence/20261011-android-continuity/CHECKS.json),
[Android Witness](../../research/sdk-alpha1/evidence/20261011-android-witness/CHECKS.json)
and [Apple matrix](../../research/sdk-alpha1/evidence/20261105-continuity-ios-simulator-matrix/README.md).
No second phone, API 36 device, new simulator requirement or cross-platform
performance equivalence is introduced here.

## 6. Source correspondence and remaining release execution

The current source audit compares all 618 native `src/` paths between the
resource cohort's `5678d101` and the reviewed `6a2ee33a`. **612 are byte-identical.**
Four differences are tests; the two production-file changes extract the existing
`MAX_FANOUTS = 16` constant into the shared contract and import it under the same
name. The complete fanout predicates remain unchanged. The changed host-store
production files are Windows-only modules; the macOS module selectors are
unchanged. The [exact delta and source map](../../research/sdk-alpha1/evidence/20261109-workload-budget-review/SOURCE_MAPPING.json)
make this reuse reviewable while preserving the original measured binaries and
run identities. Packaging/version changes receive the final distribution's own
identity and qualification records.

The source-to-limit mapping, joint-capacity interpretation, complete-interval
rate calculation, retirement accounting and existing platform-stage inventory
are complete. The six desktop regression budgets, reference scope and
issuer-selected B policy are now selected. The remaining work is execution of
the existing release sequence:

| Existing final execution | Result to record |
| --- | --- |
| Verify the final chosen artifact under the existing admission plan | Bind the selected budgets and exact reference-workload definition to the chosen package/source identities and affected installed/replacement receipts. Reuse unchanged-component receipts with their actual provenance and source correspondence. |
| Complete the coordinated specification and release lock | Record the completed verification with the specification/package identities and this selected policy. Set `frozen_product_contract=true` only in that coordinated admission change. |

This is the workload-budget part of the existing
[admission sequence](RELEASE_0_2_ADMISSION_PLAN.md). The independent construction
assessment and package/release work keep their own entries; this decision introduces
no new research or baseline gate.
