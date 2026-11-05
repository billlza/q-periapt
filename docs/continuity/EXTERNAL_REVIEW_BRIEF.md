# External security review preparation

Planning snapshot: 2026-11-04. This prepares the independent review required by
[the 0.2.0 release scope](RELEASE_0_2_SCOPE.md). The user identified **魏庄坤教授**
as the designated reviewer on this date. No narrower agreed scope or special
material requirements were supplied, so the proposed scope below follows the
existing release commitments. A source-bound review report, findings and fix
rechecks have not yet been supplied in this task. This task has not contacted the
reviewer or transmitted the materials. The runtime qualification
source reference is `4effa8b2b25e7403ab912b65894a7d1e73695542`, including
publication maintenance implementation `f560d803c43a24fff222daa5e5e5bd623bfdf874`; it is not the frozen
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

The [conditional body-origin reduction](AUTHENTICATED_BODY_LEMMA_V1.md) isolates
one authentication implication of the actual hybrid verifier and injective
purpose/body encoding. It preserves the chosen-rnd primitive and surrounding
simulation premises, with historical source-bound alias-test evidence. It does
not establish original-wire authenticity or close accepted-flight, authorization,
shared-oracle, whole-state or multi-epoch proof obligations.

The [finite two-round execution record](../../research/sdk-alpha1/evidence/20261105-two-round-ground-trace/README.md)
also gives a source-derived exposed-ancestor witness on the unchanged symbolic
model, with a separate internal semantic calculation and negative controls.
Review it alongside the failed Tamarin searches: it is a finite construction,
not a Tamarin certificate or a substitute for the outstanding computational and
implementation correspondence work. The original query inventory is unchanged.

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
4. Refresh the CI and installed-platform matrix against that candidate. The
   [current CI failure record](../../research/sdk-alpha1/evidence/20261104-ci-runtime-failures/README.md)
   remains incomplete and preserves count-check, guest/transport and artifact-transfer failures. Historical passes
   and the focused source/wheel readback do not qualify the final installation.
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
