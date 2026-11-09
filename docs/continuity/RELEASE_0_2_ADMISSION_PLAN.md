# 0.2.0 Continuity admission change — prepared plan

Prepared against `228c944fc476e3e57d6c08063cacb19bca5b360e` on 2026-11-07.
This is the concrete integration plan for the already agreed
[release scope](RELEASE_0_2_SCOPE.md). Package names and distribution choices
below are proposed changes, with the current implementation and completed
qualification retained as their starting point.

## Implemented checkpoint — 7 November 2026

The [release-manifest identity contract](RELEASE_MANIFEST_V1.md) now has an
executable verifier and a
[real candidate capture](../../research/sdk-alpha1/evidence/20261107-release-manifest/README.md).
The capture checks 16 actual package definitions, the separate 51/158-symbol C
interfaces, and a candidate normative inventory. Its 44 source inputs match
prepared commit `ee625d7a5501be0f3320511682f0fad95906e516` byte-for-byte. That source
also pins the reference application's current engine dependency to `=0.0.0`.

This completes the first executable package/specification identity checkpoint.
The final adapter distribution identities, selected artifacts, compatibility
adoption and coordinated freeze remain in the integration sequence below.
Existing platform receipts retain their original source identities, and the
active PR CI wave is preserved before advancing its head.

The [bootstrap construction/compromise matrix](BOOTSTRAP_COMPROMISE_REVIEW_V1.md)
also completes the stage-specific source and evidence assembly: B0–B7 output
permissions, exact KDF dependencies, identity/prekey/root disclosure cases and
the retained signature-alias and READY regressions. It is indexed in the
[external-review brief](EXTERNAL_REVIEW_BRIEF.md). The construction assessment
and supported-workload budget decision keep their original acceptance roles.

The [terminal-agreement assessment](BOOTSTRAP_TERMINAL_AGREEMENT_V1.md) now
completes the exact signed-wire Final invariant and the conversion from a joint online protected-family
epoch-zero ACK-key schedule to historical responder activation. It supplies a
source-bound theorem and independently executed encoding/alias controls for
the matrix's terminal stages. The remaining construction assessment instantiates
the explicit joint schedule under its chosen component and identity disclosures.

## Adopt the implemented contract

The implementation already provides hybrid identity, independently approved
account and witness inputs, durable bootstrap, v6 hybrid rekey, retained epochs,
signed progress controls, explicit recovery, account/device/root lifecycle,
roster fanout and accountable directory leases. The next admission change
adopts these mechanisms and connects them to a formal distribution.

| Existing protocol decision | Adopted implementation to carry forward | Admission action |
| --- | --- | --- |
| Identity, witness and authority | ML-DSA-65 AND P-256; independent pins/checkpoints; signed rosters; explicit registration and root replacement; caller-supplied trusted time | Record the host's trusted-time and independently approved trust-input responsibilities in the deployment contract. |
| Accountable directory | Signed assignments; durable original-operation recovery; exact retries; retained one-time reservations; cancellation and canonical conflict proofs | Include the existing operator-driven service, approval/configuration input, pin, checkpoint, validity and capacity contract in the service package manifest. |
| Bootstrap authority | Current KDF graph and stage-specific output permissions; epoch-zero root-bound ACK before established | Finish the existing construction review with a stage-specific identity/prekey/session compromise matrix and references to the actual signature, confirmation, ACK and current-authority checks. |
| Ratchet and traffic policy | Existing v6 profile, four retained epochs, signed application-send allowance, explicit no-padding behavior | Adopt the current domains, allowance replenishment and recovery conditions as one versioned product policy. |
| Ownership and maintenance | Device-scoped ownership, original intent, restricted recovery, witnessed state, roster fanout and existing maintenance v2 | Bind current public entry points to the final package/export inventory and the compatibility policy below. |
| Limits and measured cost | Compiled contract schema 3 and current implementation limits; retained lifecycle/fanout/throughput observations | Lock hard limits and select the supported workload cost budgets from the existing measured cohorts. |

The bootstrap review and workload-budget decisions are the remaining substantive
acceptance work in this table. Most other rows concern formal adoption and
package identity. Keep the completed
[2026-11-07 hosted cohort](../../research/sdk-alpha1/evidence/20261107-ci-release-readback/README.md)
attached to its original source and reuse it when the relevant inputs are
unchanged.

## Proposed package and export graph

Use a versioned Continuity companion alongside SDK ABI 2. The engine already
depends on the SDK, so the dependency direction remains SDK → engine → adapters
in build order. Existing browser exports remain in the SDK WASM `/web` surface.

| Surface | Proposed 0.2.0 release identity | Existing contract to retain |
| --- | --- | --- |
| Rust engine | `q-periapt-continuity = 0.2.0` companion | Existing public owner/state API. Cargo aliases can retain existing internal imports during the package rename. |
| Native C companion | Versioned Continuity native archive, `qpc-owner/1` | Existing 158-symbol export inventory, 70 record names and 112 constants, separate from SDK C ABI 2. |
| Swift | Existing `QPeriaptContinuity` product at 0.2.0 | Existing module and four-target XCFramework, including both iOS simulators. |
| Kotlin/JVM | `dev.qperiapt:q-periapt-continuity-kotlin:0.2.0` | Existing `dev.qperiapt.continuity` API and native owner contract. |
| Android | `dev.qperiapt:q-periapt-continuity-android:0.2.0` companion AAR | Existing Java/JNI API, R8 rules and minified consumer. SDK Android keeps its own coordinate. |
| Browser | Existing `q-periapt-sdk-wasm@0.2.0`, `/web` | Existing `QPeriaptContinuity…` JavaScript and TypeScript exports. |
| Directory and witness/reference services | Named executables and configuration contracts in the same release manifest | Existing service binaries, approval inputs, trust pins, checkpoint and storage contracts. |
| Independent Python/OpenSSL implementation | Retained interoperability/testing distribution | Existing independent-reader and peer scope. |

The Rust public package name is a proposal; publication-channel selection will
determine whether it joins the registry publisher topology or ships as a formal
source archive. The release must describe that choice consistently. Existing
twelve-crate SDK publication alone covers the SDK portion of the agreed scope.

Implement the final choice through Cargo manifests and exact dependency versions,
publisher topology where applicable, platform archive metadata, ABI snapshot
identity and a single release manifest. Keep existing cryptographic domain bytes,
table names and storage tags stable during this packaging work.

## Preview and program-replacement policy

Adopt the compatibility edges already implemented and qualified:

- Open the current journal, installation and witness formats specified by the
  final manifest; retain identity, original session and pending operation.
- Keep `continuity_device_candidate_v21` and the current
  `QPVLT021/QPVIMG21` through `024/24` interpretations intact.
- Retain the existing witness-reader compatibility set, including its intentional
  absence of format 005.
- Preserve the implemented same-format program-replacement and maintenance-v2
  paths, including current-authority admission, restricted recovery, persistent
  cleanup intent/result and formal-target refusal.
- For unknown previews, earlier journals without a listed migration edge, and
  incomplete staging residue, retain the state and return the existing explicit
  refusal. A new migration promise is a separate, specific compatibility edge.

The final compatibility table should list exact package/format pairs and link
their retained replacement-process evidence. The already completed same-format
replacement work remains useful after final package identities are assigned.

## Stable specification lock and per-release evidence

Create the normative lock after the package and compatibility choices above
have been applied. Its inputs are:

1. Protocol, wire, state-machine, storage/recovery, metadata, limits and
   upgrade/maintenance contracts, including their normative enrollment,
   bootstrap, directory, authority and witness transaction references.
2. Compiled contract schema 3 descriptor and its exact digest.
3. Separate SDK C ABI 2 and Continuity `qpc-owner/1` interface manifests.
4. Existing wire/profile/domain bytes and storage format identifiers.
5. Final package/export and preview-compatibility manifests.

The lock records paths and SHA-256 digests. A separate release-evidence manifest
records the final source commit/tree, specification-lock digest, toolchains,
archives/binaries and accepted qualification receipts. Keeping these two layers
separate avoids a self-referential source-commit or self-hash requirement and
lets later compatible builds retain the same normative contract.

`BUDGETS_V1.json` and the current contract checker deliberately describe an
unfrozen candidate. Formal adoption must update the mode, compiled descriptor,
lock verification and interface metadata together while retaining the historical
candidate reader behavior.

## Concrete execution order

1. Finish the prepared tooling/deadline repair after the active PR wave reaches
   its recorded endpoint; retain all original successful and failed jobs.
2. Implement the proposed package/export and compatibility manifests as one
   reviewable integration change. Resolve the public Rust distribution choice
   before starting a publication transaction.
3. Complete the stage-specific construction-review matrix and the supported
   workload budget table from existing source, proof and measurement evidence.
   Include these in the existing external-security-review package.
4. Generate the normative lock and final release manifest; run the affected
   contract, packaging, installation and replacement checks on the selected
   source. Preserve unchanged-component receipts with their actual provenance.
5. Use the existing journaled release tooling for dry-run, reconciliation and
   publication of the selected package cohort.

The agreed device and platform scope stays as recorded in
[PRODUCT_ADMISSION.md](PRODUCT_ADMISSION.md): one accepted API 37 phone, Apple
Silicon macOS, and the existing Linux/Windows/iOS simulator targets. JoC paper
baselines and additional paper theorems remain on their research track.
