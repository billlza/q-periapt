# External security review preparation

Planning snapshot: 2026-11-04. This prepares the independent review required by
[the 0.2.0 release scope](RELEASE_0_2_SCOPE.md). The user identified **魏庄坤教授**
as the designated reviewer on this date. No narrower agreed scope or special
material requirements were supplied, so the proposed scope below follows the
existing release commitments. A source-bound review report, findings and fix
rechecks have not yet been supplied in this task. This task has not contacted the
reviewer or transmitted the materials. Runtime evidence below records separate
source identities, including foundation `4effa8b2b25e7403ab912b65894a7d1e73695542`,
publication maintenance implementation `f560d803c43a24fff222daa5e5e5bd623bfdf874`,
and the later JNI component at `ff072bd66b1f5d3bdbb80171ee39bad15cbc3c20`.
The subsequent locally validated roster-verification implementation is
`1bdb29a20d1d9c68496648f3be91efad710e4b0c`; it changes candidate C/JNI and WASM
package inputs and must remain distinct from the earlier package cohorts.
None is the frozen review candidate. The later Windows test correction changes
the SDK input root. A [matching local SDK producer](../../research/sdk-alpha1/evidence/20261105-current-sdk-producer/README.md)
now passes at source `5678d101`, with twelve archives, four external Rust consumer
tests, strict Clippy and three dependency audits. The [current installed Rust
candidate](../../research/sdk-alpha1/evidence/20261105-current-rust-installed/README.md)
also passes the original Debug and Release gates, with all three consumer tests
per profile and an independent reread of both public traces, the candidate tree
and nine SDK trees. Its same-host signed-TCP Witness and injected-clock scenarios
retain their stated limits. The [current WASM archive and Chromium
gates](../../research/sdk-alpha1/evidence/20261105-current-wasm-browser/README.md)
also pass on macOS arm64, including the same archive on Node 26.10.0 and minimum
24.0.0, actual storage failures, enrollment and native/Witness recovery. Public
transcripts and eight actual native reference binaries are retained. These are
shared-engine, same-host HTTP/TCP observations; current foreign packages and
remaining platform qualification still need their own matching evidence.
Re-pin the source, contracts and package identities together before formal
review begins.

The [current Android arm64 AAR](../../research/sdk-alpha1/evidence/20261106-current-android-aar/README.md)
now has an actual installed-archive build and separate static readback at
`5678d101`: 229 members, 131 Java classes, exact JNI declarations and native
exports, release scans and 16 KiB ELF alignment. An initial diagnostic build's
embedded registry path was rejected and retained; the corrected build applies
the existing account-root remapping policy. This is not an APK/ART/device result
or Continuity ABI 2 admission. The existing accepted phone remains sufficient
for the task's applicable device validation.

The same AAR's [minified AGP consumer](../../research/sdk-alpha1/evidence/20261106-current-android-apk/README.md)
subsequently passes strict compilation, R8 and release packaging. Actual APK
inspection preserves all 23 JNI methods and three callbacks, the original native
library bytes and 16 KiB ZIP alignment. Both failed diagnostic preparations are
retained. This unsigned build contains no runtime input bundle and has not run
under ART or on the phone; it does not complete those separate acceptance steps.

The [current C/OpenSSL pair](../../research/sdk-alpha1/evidence/20261106-current-c-openssl/README.md)
independently replays both completed C components at the same source: server 146,
client 2, native-TLS 146 and four pre-store refusal cases per profile. Actual
installed trees and binaries are bound, and the public capsule replays without
private state. Its 28 altered-evidence controls supplement the original P0
regression. The surrounding JNI runs and final hosted candidate remain separate.

The [current Release host-JNI partition](../../research/sdk-alpha1/evidence/20261106-current-jni-release/README.md)
has now completed at `5678d101`. Its exact 67-test JNI census, actual seven native
binaries, JAR and installed graphs are independently checked. Twenty public
outcome groups replay both from the capsule and from its captured reader source
alone. The [matching Debug partition](../../research/sdk-alpha1/evidence/20261106-current-jni-debug/README.md)
also completes, with the same 67-test census and twenty public groups independently
reproduced from its own capsule and captured reader source. Their source inputs,
adapter sources, SDK/candidate archives and JAR match byte for byte. Both local
host-JNI profiles are now complete at this source; the full foreign-profile join,
Android runtime/device execution and final hosted CI stay separate.

The [historical hosted Swift pair](../../research/sdk-alpha1/evidence/20261105-hosted-swift-pair/README.md)
now has matching package/native-library verification and selected public rereads
at `232ace`, including the Rust 1.90 root lane. Its three arm64 Apple slices have
build evidence; iOS/device execution is not inferred. Both original artifacts
omit publication public bytes, so that independent replay remains unavailable.
The upload-pattern repair is already in the later local branch and still needs
the next permitted source-bound hosted evidence.

The same source's [six-partition coverage join](../../research/sdk-alpha1/evidence/20261105-hosted-profile-coverage/README.md)
now passes independently against all six original report bytes and the pinned
1,393 source inputs. This establishes the historical Swift/Kotlin/host-JNI
Debug/Release receipt union. It does not repair missing public exports, establish
device execution, or transfer acceptance to the later local candidate.

The [historical Kotlin pair](../../research/sdk-alpha1/evidence/20261105-hosted-kotlin-pair/README.md)
also has actual Maven/native package checks, exact 79-test reports in each of two
lanes, 21 selected public reader groups and 26 C2 logs per build profile. Serial/G1
ownership observations remain bounded. Missing publication exports and three
unexported runtime JARs remain explicit; the latter retain original execution
receipts rather than a new local runtime replay.

The [installed operation observer](../../research/sdk-alpha1/evidence/20261105-installed-operation-observer/README.md)
now separates ordinary sends, traffic-independent rekey and original-operation
reopening at source `5678d101`. Its local/Witness functional cohorts and public
archive reread pass, with per-operation Witness counts and exact business effects.
Other qualification processes overlapped both cohorts, so their raw timings are
not an accepted performance budget. Whole-process CPU/memory and the remaining
fanout, maintenance and mobile-energy work retain their stated boundaries.

The [installed two-recipient fanout observer](../../research/sdk-alpha1/evidence/20261106-installed-fanout-observer/README.md)
now passes four local/Witness and own/peer-account functional cohorts at the same
source. Each records 13 aggregates, 26 durable business effects and 89 operation
spans, including independent PQ updates and exact original-operation recovery.
Both Witness cohorts reconcile 1,203 exchanges; a captured-source-only readback
checks all 104 public business files and the altered-input controls. The owners
are pre-provisioned, and concurrent host-JNI work prevents a performance-budget
claim. Larger declared fanout capacity and the remaining resource contract stay
open.

The [subsequent repeated resource baseline](../../research/sdk-alpha1/evidence/20261106-resource-repeats/README.md)
retains sixteen predeclared cohorts after host-JNI completion: 1,560 spans and
600 durable business files, with no other qualification process in the recorded
censuses. All samples remain, including higher-load intervals and the recorder
failure before a verified continuation of the original order. Captured-source
replay independently checks all sixteen cohorts and recomputes ninety operation
and twenty memory groups. This is a host/workload-specific baseline; it does not
freeze budgets, establish production tails or supply the remaining throughput,
maintenance, capacity and mobile measurements.

The [complete-interval throughput baseline](../../research/sdk-alpha1/evidence/20261106-installed-throughput/README.md)
subsequently measures sixteen predeclared repeats at the same installed source,
including surrounding queries and independent PQ updates in the denominator.
The captured-source replay verifies all twenty cohorts including four separate
pilots, 750 business files and 500 new altered-evidence controls, and reproduces
twelve phase groups. Local/Witness single-session rates are 5.816/3.312
confirmed deliveries per second; two-recipient fanout rates are 5.368/2.932,
with retirement included. These are observed serial rates on the recorded Mac.
Declared-load budget acceptance, maintenance/capacity and mobile measurements
remain open; no saturation or release claim follows from these observations.

The deliverable sought is a construction and implementation assessment of the
declared secure-session contract: authorized establishment and communication,
traffic-independent PQ progress, exact recovery of original operations,
revocation, device replacement and continued authority maintenance. The host's
account login and authorization remain separate from device-key possession.

The [computational recovery note](COMPUTATIONAL_RECOVERY_V1.md) supplies a
concrete root-extraction route and conditional hybrid argument for review. It
does not close the combiner premise, shared-root key-schedule composition or PQ
proof obligations and must not be presented as the completed protocol proof.
The [single-root ideal-oracle lemma](SHARED_ROOT_ORACLE_V1.md) supplies a checked
conditional coupling and preserves an initial-state/query-accounting
counterexample. Review must still establish the actual prefix distribution,
implementation correspondence and HMAC instantiation before using it for the
declared protocol claim.

The [shared-root HMAC reduction](SHARED_ROOT_HMAC_V1.md) additionally connects
that joint-use question to the actual short-key HMAC encoding in a single ideal
compression-oracle model. Its restricted reductions have an independent internal
applicability review and pinned dependency encoding checks. This is material for
the designated external review, not its substitute: the actual prefix, leakage
interfaces, concrete-primitive assumptions and full protocol composition remain
to be established.

The [root-extraction corollary](ROOT_EXTRACTION_QROM_V1.md) connects this
conditional primitive calculation to the source's two-call Extract/Expand
shape. It preserves the complete prefix-query accounting and explicitly shows
why an extra raw-PRK disclosure would invalidate that game. Its encoding checks
are separate from its mathematical argument; the actual accepted-prefix and
whole-protocol obligations remain open for review.

The [hidden-record commitment inventory](HIDDEN_RECORD_COMMITMENTS_V1.md)
follows the original image and pending-write bytes into ordinary recovery,
retirement, Witness selection and account-root checkpoints. Its conditional
six-interface nonce argument includes the bound write layouts, distinguishes
target-free cancellations and keeps downstream hashes in the query budget.
It is a single-record result; it does not close cross-record acquisition,
the KEM challenge simulator or the multi-epoch proof.

The [shared-journal copy regression](../../research/sdk-alpha1/evidence/20261105-aggregate-reservation-copy/README.md)
adds a concrete cross-image correspondence check: a sibling session changes the
aggregate nonce/digest while preserving the target's original reservation bytes;
a later capture still decrypts six target messages. Debug and Release include
wrong-key rejection and exact retry after reopen. Review should keep a global
image write, original reservation sampling and per-session `Saved` provenance
distinct; the full refinement and accepted-prefix simulation remain open.

The [ContextBound secret hop](CONTEXTBOUND_SECRET_HOP_V1.md) separately derives
the ideal-SHA3 replacement after a valid component-secret hybrid. A Release
probe executes the actual Rust core encoder and independently checks its 2,639
input bytes, nested policy context and PQ-secret offset. It also distinguishes
the component challenge-ciphertext cache from the complete combiner-input cache.
The probe uses public serialization fixtures; it is neither an ML-KEM run nor
the missing fixed-target reduction.

The subsequent [original-operation KEM adapter](KEM_CHALLENGE_ADAPTER_V1.md)
states a fixed-pair reduction for a defined virtual private-record game. It
keeps correctness failure, pre-release challenge-ciphertext calls, exact retries
and ineligible disclosure events explicit. Its source association uses the
persist-before-sign boundary and the contract's authoritative-history premise.
The full native private-record simulation and adaptive-target lift remain open;
the adapter's mathematical game is not evidence that raw unknown coins can be
serialized or that the actual storage interface may reject an allowed disclosure.

The [adaptive-target accounting note](ADAPTIVE_TARGET_ACCOUNTING_V1.md) supplies
conditional winning-event and centered-score bounds over fixed original
reservation budgets. It preserves the selector and eligibility in each override
world, retains unattributed-origin error, and requires efficiently evaluable
events. Two exact arithmetic examples distinguish the valid calculation from
conditioning away failures or normalizing different guessed worlds. This is a
manual probability reduction; native origin/refinement and the random-component
message/traffic bounds remain open.

The [multi-record commitment note](MULTI_RECORD_COMMITMENTS_V1.md) extends the
conditional nonce-hash calculation across bounded original-record invocations
and preserves exact-copy identity. It verifies that the retained Snapshot rule
outputs encrypted records before any decryption condition, while leaving the
actual acquisition mapping explicit. It also records private-state cleanup MACs
and failed-before-freeze branches that cannot be covered by the digest lemma.

The [conditional body-origin reduction](AUTHENTICATED_BODY_LEMMA_V1.md) isolates
one authentication implication of the actual hybrid verifier and injective
purpose/body encoding. It preserves the chosen-rnd primitive and surrounding
simulation premises, with historical source-bound alias-test evidence. It does
not establish original-wire authenticity or close accepted-flight, authorization,
shared-oracle, whole-state or multi-epoch proof obligations.

The [native rekey alias regressions](../../research/sdk-alpha1/evidence/20261105-rekey-classical-alias/README.md)
now exercise both offer and response classical-signature substitutions with
unchanged bodies/PQ signatures. Debug and Release pass the actual distinct
wire-binding rejection points, original-wire traffic controls and exact retries
after reopen. The first positive-fixture sequencing failure is retained. Only
test code changes; these two cases do not close the general accepted-prefix
reduction or alter any protocol acceptance condition.

The [original-send input note](AEAD_SEND_ORIGIN_V1.md) traces immutable plaintext
and AD through reservation, private encryption, exact commit/retry and terminal
closure. Its source-bound Debug/Release regressions include actual precommit
process cuts and a deliberately unsafe private-state reset that reuses the
keystream while the shipping API refuses replacement. A failed outer marker
reader is retained separately. This supports the send-origin invariant and
query normalization, not distinct message keys or the full AEAD security game.

The [ideal HKDF-Expand table identity](HKDF_EXPAND_TABLE_V1.md) separately gives
an exact prefix-consistent output representation after private-row
idealization, with three explicit counterexamples to broader formulations.
It preserves same-PRK aliases and prior hybrid costs. This manual lemma and
its dependency/source readback do not close multi-root or leakage composition.

The [cleanup-report MAC note](CLEANUP_REPORT_MAC_V1.md) gives a conditional
one-transcript replacement for the report output omitted from the raw-record
digest inventory. It preserves the zero-ID failure and original-report cache,
and explains why the hop must precede the unknown-coin KEM embedding. Six
Debug/Release executions cover private-state tamper rejection, rekey closure
fences and fanout process cuts. Native acquisition and changed-transcript
simulation remain open; this is not a completed computational proof.
The [report-key provenance follow-up](../../research/sdk-alpha1/evidence/20261105-cleanup-record-provenance/README.md)
maps all three report families and reuses nine outcomes from the completed full
Release run. Review the separate fanout key record, the plaintext-returning
closed-epoch report and the earlier resolution keys included in later report
transcripts. These facts prevent assuming a generic Snapshot stop or independent
MAC rows without the corresponding source and acquisition argument.

The [finite two-round execution record](../../research/sdk-alpha1/evidence/20261105-two-round-ground-trace/README.md)
also gives a source-derived exposed-ancestor witness on the unchanged symbolic
model, with a separate internal semantic calculation and negative controls.
Review it alongside the failed Tamarin searches: it is a finite construction,
not a Tamarin certificate or a substitute for the outstanding computational and
implementation correspondence work. The original query inventory is unchanged.

The later [finite delayed-receipt record](../../research/sdk-alpha1/evidence/20261105-delayed-receipt-ground-trace/README.md)
checks the original asymmetric-disclosure query with two semantic calculations
and seven legal countertraces. It identifies exactly why post-Cut confirmation
and one fresh encapsulation cannot replace the post-Cut-generation condition.
Its matching SDK schedule reuses the recorded full Release test; neither a
new Tamarin certificate nor complete implementation correspondence is claimed.

## Handoff to 魏庄坤教授

The handoff should identify one exact review revision and provide a short reading
order: declared security/recovery claims; the symbolic and computational proof
boundaries; wire/state/storage contracts and their implementation correspondence;
then package, process-interruption, platform and resource evidence. The materials
must expose unresolved premises and unsuccessful observations alongside passed
checks. The current preparation is not a record that the designated reviewer
has accepted these claims or completed their assessment.

Record the reviewer's actual assessed scope, methods, assumptions, exclusions,
source revision, findings and subsequent fix rechecks. Retain each finding's
reproduction or reasoning and its disposition. A designation alone does not
close the external-review gate or authorize a release transaction.

## Proposed technical scope

| Review question | Existing material and implementation entry points | Required finding evidence |
| --- | --- | --- |
| What does recovery mean under the actual attacker view? | [Recovery conditions](RECOVERY_CONDITIONS_V1.md), [secret/state dependencies](RECOVERY_DEPENDENCIES_V1.md), actual rekey [response](../../research/continuity-identity-candidate/src/durable/messages/rekey/response.rs) and [completion](../../research/continuity-identity-candidate/src/durable/messages/rekey/completion.rs). Include captured reservations, wrapping keys, signer files, retained traffic and ongoing acquisition. | State exact compromise, entropy, identity and delivery assumptions. Relate any attack or reduction to actual derived keys and published messages. A progress counter alone is not a recovery condition. |
| Do the symbolic claims support the declared construction? | [Joint replay](../../research/sdk-alpha1/evidence/20261104-multi-epoch-replay/README.md), pinned models, tools and complete query inventory. MAIN and 24 reusable dependencies passed; 13 other queries remain incomplete. | Separate symbolic validity, multi-round execution witnesses, computational composition and implementation correspondence. Preserve unsuccessful branches and the original query contracts. |
| Are bytes bound to the right identity, purpose and operation? | [Wire contract](WIRE_V1.md), [compiled descriptor](../../research/continuity-identity-candidate/src/contract.rs), [signed envelopes](../../research/continuity-identity-candidate/src/crypto.rs), [owner/authority boundaries](PRODUCT_ADMISSION.md). | Identify an accepted wrong encoding, purpose, identity, policy, service, request or operation; or explain the checked construction and its assumptions. Include implicit rejection and old KAT compatibility. |
| Are state changes durable, atomic and recoverable? | [Storage contract](STORAGE_RECOVERY_V1.md), [state machine](STATE_MACHINE_V1.md), [write intents](../../research/continuity-identity-candidate/src/durable/write_intent.rs), [protected storage](../../crates/q-periapt-host-store/src/filesystem.rs). | Trace commit/release ordering, cancellation, concurrent updates and unknown outcomes. Preserve original IDs/results and independently committed application effects. Distinguish injected faults, process termination and physical power-loss claims. |
| Can unpublished state be reclaimed without reaching a formal installation? | [Versioned maintenance contract](../PRIVATE_PUBLICATION_MAINTENANCE.md), [continuous attempt lease](../../crates/q-periapt-host-store/src/filesystem/maintenance/attempt.rs), [whole-payload admission](../../crates/q-periapt-host-store/src/filesystem/maintenance/tree.rs), and [installed command evidence](../../research/sdk-alpha1/evidence/20261104-managed-publication-maintenance/README.md). | Check original parent/control/lease/payload identity, exclusive ownership through publication, complete preflight before removal, partial-cleanup recovery and exact result replay. A checksum is not authorization; `NoPayload` does not authorize reprovisioning. Legacy/incomplete controls and actual Windows/NTFS qualification remain separate. |
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
   The maintenance checkpoint supplies fresh SDK archive and executable identities,
   raw original bookkeeping and exact command results. Its failed 600-second
   candidate observations remain retained; they are not complete regression passes
   and are distinct from the repository's existing 90-minute Release-profile job.
   The subsequent [installed-cohort capture](../../research/sdk-alpha1/evidence/20261104-continuity-installed-maintenance/README.md)
   supplies fresh archive-derived Rust and independent-wheel execution, a separate
   complete local Debug/Release regression, and an exact public-file allowlist. Its
   binary exports are unchanged; path-normalized metadata retains original hashes.
   The remaining platform matrix and final hosted CI must still be reconciled
   before the review candidate is frozen.
   The later [complete Rust/C checkpoint](../../research/sdk-alpha1/evidence/20261104-continuity-c-maintenance/README.md)
   adds both full installed profiles, independent OpenSSL carrier execution and
   public archive readback on the same maintenance cohort. It does not substitute
   for the remaining bindings, platform matrix or final source-bound CI.
   The [Apple/Swift maintenance checkpoint](../../research/sdk-alpha1/evidence/20261105-continuity-swift-maintenance/README.md)
   adds full Swift Debug/Release execution and the Rust 1.90 minimum-root
   regression over that same foundation. Its three arm64 Apple targets leave
   the retained x86_64 iOS simulator packaging requirement open; its iOS
   consumer builds do not count as device/simulator execution.
   The subsequent [four-target Apple checkpoint](../../research/sdk-alpha1/evidence/20261105-continuity-ios-simulator-matrix/README.md)
   closes the local simulator packaging gap with actual arm64/x86_64 native
   builds, exact fat-slice readback and both simulator consumer link maps.
   Its source identity is separate; iOS runtime and final hosted CI remain open.
   The [Kotlin/JVM maintenance checkpoint](../../research/sdk-alpha1/evidence/20261105-continuity-kotlin-maintenance/README.md)
   adds both full installed profiles and Serial/G1 lifecycle and GC paths on
   macOS arm64. The source comparison, 79-case owner-test inventory, exact public
   artifacts and 30 expected rejection receipts are retained separately from
   Android device/runtime and final-source qualification.
   The [JNI Release cycle follow-up](../../research/sdk-alpha1/evidence/20261105-android-release-cycle-followup/README.md)
   completes the previously unfinished six-route installed component on the
   exact `ff072bd6` runtime, with 434 foreign processes and full public archive
   readback. It does not turn the retained
   [18,000-second parent timeout](../../research/sdk-alpha1/evidence/20261105-android-parent-timeout/README.md)
   into a completed aggregate. Its direct owner cleanup control is distinct from
   the failed nested-supervisor layout; host JNI execution is distinct from ART,
   device/emulator execution and qualification of the newer SDK source root.
   The later [hosted JNI pair](../../research/sdk-alpha1/evidence/20261105-hosted-jni-pair/README.md)
   supplies completed Debug/Release partitions at the separate `232ace17`
   foundation, with 20 public result groups checked for each. Per profile,
   67 JNI-specific tests execute in 36 commands and three shared Rust fixture
   entries execute in the installed Rust consumer. Source, SDK producer,
   dependency graphs and the retained JAR match; native binary fingerprints
   remain receipt-only because those binaries were not uploaded. The six-way
   foreign-consumer join, ART/AAR, later source qualification and the original
   failed local aggregate remain distinct.
   The [roster-verification checkpoint](../../research/sdk-alpha1/evidence/20261105-renewal-roster-verification/README.md)
   reuses two independently authenticated immutable roster objects within one
   renewal verification while retaining exact input/pin, time, membership and
   all other signature checks. Actual counting removes 7,425 repeated roster
   verifications from the observed 32-member command. The committed source has
   a complete 1,461-case local Release regression, focused Debug/Release and
   Rust 1.90 checks, both local Debug capacity runs and an uninstrumented
   four-profile/two-worker composition. Review the reuse boundaries and possible
   first-error ordering for multiply invalid inputs; the original hosted
   timeouts are retained and are not claimed resolved by these local results.
4. Refresh the CI and installed-platform matrix against that candidate. The
   [current CI failure record](../../research/sdk-alpha1/evidence/20261104-ci-runtime-failures/README.md)
   remains incomplete and preserves count-check, guest/transport and artifact-transfer failures. Historical passes
   and the focused source/wheel readback do not qualify the final installation.
   The 2026-11-05 wave adds separately retained
   [guest ART crash observations](../../research/sdk-alpha1/evidence/20261105-android-guest-art-crashes/README.md)
   and an [independent macOS composition deadline](../../research/sdk-alpha1/evidence/20261105-independent-macos-deadline/README.md).
   Both Android cleanup failures remain failed. An exact-binary isolated
   32-member diagnostic completed, but does not explain or replace the original
   concurrent composition failure. The
   [browser response-observation repair](../../research/sdk-alpha1/evidence/20261105-browser-peer-receipts/README.md)
   and [HTTP early-refusal repair](../../research/sdk-alpha1/evidence/20261105-http-early-refusal/README.md)
   have separate local validation; their affected hosted checks remain pending.
   Keep original failed jobs and local repair evidence alongside the eventual
   final candidate results.
   The [completed macOS installed-wheel readback](../../research/sdk-alpha1/evidence/20261105-independent-installed-macos/README.md)
   confirms the earlier `ff072bd6` installed lane used exactly the same Rust
   counterpart binary, 225 source inputs and provider as the failed source
   lane. Its four composition traces were reread. This is installed Python with
   a source-built Rust counterpart, separate from truly installed Rust and the
   later local candidate changes.
   The [Windows installed-lifecycle readback](../../research/sdk-alpha1/evidence/20261105-windows-installed-lifecycle/README.md)
   retains the completed Windows 2022/2025 Debug/Release archive consumers and
   reproduces both original public readers. It verifies the ten-crate installed
   graph, actual DLLs and input identities at PR merge source `93aa0582`.
   Fifty-two checked inputs differ from the later local source, so this is
   historical platform evidence, not final-source qualification.
5. Finish the product/ABI, capacity/maintenance and resource contracts before
   the formal engagement. The current numeric contract explicitly remains
   unfrozen; the unpublished candidate has not thereby become product ABI 2.
   Keep the computational argument and implementation-correspondence gaps
   visible rather than presenting the symbolic replay as their completion.

The handoff to 魏庄坤教授 should require a source-bound report with
scope, methods, assumptions, findings, reproducible evidence, impact and fixes;
explicitly record inconclusive areas and remaining risk. Findings affecting a
declared security promise must be fixed and rechecked before release. Agree on
retest coverage and how security-significant changes invalidate earlier review.
Internal analysis, this preparation and a report's mere existence do not satisfy
the external-review gate. Final CI, package identity checks and explicit release
authorization still follow that gate.
