# Continuity 0.2.0 internal admission assessment

Assessed source: `8abbf8d2e73a27af7794528fd92d13fe3be2942d`, tree
`733e2e6e17be2241d85264ea5e15e07a35f04527`. Prepared on 17 November 2026.
This assessment reads the committed construction, implementation and retained
qualification inputs. Its new execution is the source-identity comparison and
delta inspection described below; it does not rerun historical native workloads
or represent an external security audit.

The implemented Continuity mechanisms, both original-source bootstrap
compositions, terminal connection, retained-state correspondence, workload
selection and compatibility selection can be carried into the admission change.
The inspected construction inputs have no unexplained implementation drift.
Final qualification, current finding reconciliation, selected distribution
binding, coordinated freeze and publication remain distinct work items.

The [current SDK release requirements](../SDK_0_2_RELEASE_READINESS.md) select
internal cryptographic-boundary, ownership/error-path, code-quality and
maintainability review as delivery work. The user manages independent external
review separately. The [external-review brief](EXTERNAL_REVIEW_BRIEF.md) is
retained for that engagement and does not supply an additional automatic gate.

## 1. Declared product and construction

The [agreed scope](RELEASE_0_2_SCOPE.md) includes persistent sessions, fresh-PQ
rekeying, exact-operation disconnect/restart recovery, revocation, continuous
PQ recovery under the declared compromise and delivery assumptions, multi-device
lifecycle and accountable directory leases. The implemented v6 profile keeps
four traffic epochs, signed send allowances and explicit recovery/retirement.
The [admission plan](RELEASE_0_2_ADMISSION_PLAN.md) maps these mechanisms to the
owned Rust/C/Swift/Kotlin/Android/browser surfaces and the directory, Witness
and policy services. SDK C ABI **2** and Continuity **`qpc-owner/1`** remain
separate interfaces.

The following completed analyses are assessment inputs, with their original
proof and execution identities preserved:

| Input | Result carried into admission | Exact boundary retained |
| --- | --- | --- |
| [U1 terminal agreement](BOOTSTRAP_TERMINAL_AGREEMENT_V1.md) | Exact signed-wire Final invariant and conversion from the joint protected-family ACK experiment to historical responder activation. | B0–B7 output permissions, original admitted context, protected signing-family assumptions and exact READY replay. Local activation, historical peer activation and a host business effect remain different events. |
| [Joint bootstrap entry](BOOTSTRAP_JOINT_ENTRY_V1.md) | Hidden-`S1` long Extract and hidden-`S0` short/long entry services, retaining `S0`'s initial-confirmation cross-use and complete effective descriptors. | Shared compression points, actual padding, descriptor aliases and whole-continuation query bounds. |
| [Terminal schedule connection](BOOTSTRAP_TERMINAL_SCHEDULE_CONNECTION_V1.md) | Deferred root-table registration, descriptor/full-class reconciliation and two-sided substitution into U1's ACK-only experiment. | Actual sibling outputs and the explicit compression-collision/pad-alias term. |
| [U2 original reply source](BOOTSTRAP_REPLY_SOURCE_ADAPTER_V1.md) | Original reply generation/encapsulation slots, source-consistent tuple/family assignment, native owner validation and candidate-local pre-protection opening stops. | Available initial/traditional material, protected reply PQ source and responder purpose-6 body ledger; the allowed initiator-identity disclosure remains in the stated profile. |
| [U2 original initial source](BOOTSTRAP_INITIAL_SOURCE_ADAPTER_V1.md) | Original inventory prekey/Initial encapsulation, joint entry before first-allocation localization of the long-PRK table, and the resulting terminal conversion. | Available reply/traditional material and responder identity, protected initial PQ source and initiator purpose-5 body ledger; the later-family count multiplies terminal-tail terms only. |
| [U3 joint schedule and retained state](BOOTSTRAP_JOINT_SCHEDULE_REVIEW_V1.md) | Phase/acquisition correspondence for the aggregate image, pending target, original reservations, prekey inventory/tombstones and separate signer files. | One authoritative history, passive acquisitions and the declared key disclosures; retry, copying, cancellation and later disclosure preserve original source identity. |

Both U2 bounds retain their exact two-endpoint marked-record acquisition terms.
Those terms vanish in the stated acquisition-free branch; they are not silently
removed for a captured-record history. The assessed bootstrap/ACK interface and
its typed sibling observations remain as declared in the two adapters. Broader
captured-byte and closure/fanout-report observations must retain the joint
journal/wrapping-key and additional-report interfaces identified in the
admission plan and [report composition](../../paper/continuity/report-composition.tex).
This adoption does not turn an unrestricted observation interface into a proved
one by changing a release label.

The native signature-randomizer bridge, component comparisons and exact
HKDF/Expand schedule remain the premises named by those analyses. Existing
analytical results are not reopened merely because their files were originally
prepared for the manuscript. Additional JoC baselines or theorems are not new
0.2.0 acceptance requirements.

## 2. Actual correspondence with the selected source

The comparison read each retained `SOURCE_PINS.json` and matched its original
Git blob to `git ls-tree -r` at the selected commit. All pins in each inventory
were compared, including documents and paper inputs. The narrower Rust-source
column below makes the implementation comparison explicit; it includes the
test source named by the U3 inventory.

| Retained inventory | Original assessed source | All pins identical | Rust source pins identical |
| --- | --- | ---: | ---: |
| [Entry](../../paper/continuity/artifacts/bootstrap/entry/SOURCE_PINS.json) | `b1cff2a045d23aecf75aef12122e5080a8419676` | 5 / 7 | 2 / 2 |
| [Terminal](../../paper/continuity/artifacts/bootstrap/terminal/SOURCE_PINS.json) | `360aa8107aa7df502108627a4dcf89f30d106594` | 17 / 18 | 9 / 9 |
| [Reply source](../../paper/continuity/artifacts/bootstrap/reply/SOURCE_PINS.json) | `68549dbc3ae4491d8b5edaa708548dc60743eab7` | 30 / 32 | 17 / 18 |
| [Initial source](../../paper/continuity/artifacts/bootstrap/initial/SOURCE_PINS.json) | `471900bfe8070d1021a1feb67481437d599d80ba` | 33 / 35 | 19 / 20 |
| [U3](../../research/sdk-alpha1/evidence/20261109-bootstrap-joint-schedule-review/SOURCE_PINS.json) | `a4c089570c787522210d16226219c0cc8aa9b05e` | 33 / 36 | 21 / 21 |

Across those inventories there are **26 distinct Rust source paths; 25 retain
their original blob**. The sole changed path is
`crates/q-periapt-backends/src/lib.rs`: original blob
`fdbdc4e99b626f1e87747bce43460ac7b5c00582`, selected blob
`aa2dbf50a30dbcba90c8892aa022d0ed97c52f56`. Its selected SHA-256 is
`a91f2ddb28ee793ea253cc3a44470cde46d8c8bf8ee08eeb569c6ac1c4bb01dd`, exactly
the selected implementation in the
[reserved-staging validation](../../research/sdk-alpha1/evidence/20261110-contextbound-staging/README.md).
That retained execution has 76 passing backend/unit/integration/doctest cases,
strict Clippy and the four new reservation/erasure controls; it is not a new
execution at this assessment's commit.

Inspection of the complete blob diff and current implementation finds the
following preserved invariant. Zero spill capacity selects the initialized
inline transcript. Nonzero capacity selects the complete spill transcript,
including its valid empty state after an initial reservation. A reservation
after inline absorption migrates the prefix once; subsequent reservations do
not duplicate it. The original inline length remains available to erase both
live secret copies, and replacement allocations retain the copy-then-wipe path.
The selected branch changes staging location, while digest bytes, field order,
domain separation and secret-range classification remain the same. This
disposes of the sole Rust pin delta for the two original-source adapters.

The other pin differences are identified rather than treated as byte matches:

- `BOOTSTRAP_JOINT_SCHEDULE_REVIEW_V1.md` adds the subsequently completed entry,
  terminal and both original-source compositions. Its older U2 pending text is
  superseded by those linked results.
- `BOOTSTRAP_COMPROMISE_REVIEW_V1.md` adds the U3 and conditional-schedule
  checkpoint; its historical U2 tracking text keeps its original scope. The
  completed original-source adapters above supply the later disposition.
- `guarded-provenance.tex` adds incremental exposure evaluation and clarifies
  exact copying versus source-preserving rewrapping. The retained
  normalization and cumulative-history argument are preserved.
- The admission-plan and bibliography pins have advanced. Their current bytes
  are not substituted into an old execution receipt. The proof packets retain
  their frozen source copies and original control results.

The comparison does not equate an unchanged source path with an unchanged
dependency graph or binary. Since the workload-selection source, the selected
graph includes the recorded fips204 0.5.0, rustix 1.1.6 and compiler-helper
updates. The [fips204 adapter/lock review](../../research/sdk-alpha1/evidence/20261111-fips204-upgrade/README.md)
retains pure/contextual/hedged/HashML-DSA vector and differential execution and
the explicit prehash API adaptation. The
[rustix review](../../research/sdk-alpha1/evidence/20261111-rustix-security/INDEPENDENT_REVIEW.json)
retains its advisory, exact lock changes and rechecks. Their original scopes
remain intact; the final archive's resolved graph and compiler/runtime checks
must qualify the selected distribution.

## 3. Workload and compatibility decisions

The [workload policy](SUPPORTED_WORKLOAD_BUDGETS_0_2.md) has already selected
the 21 joint implementation limits and six desktop-reference regression ceilings:
11 / 19 seconds for local / required-Witness single-session intervals,
6 / 11 seconds for the matching fanout intervals, 200 MiB peak process RSS and
15 MiB sender database in the declared capacity/recovery fixture. The send
allowance remains issuer-selected; no new default or hidden control cadence is
introduced.

The selected source matches **114 of 116** entries in that policy's
[input inventory](../../research/sdk-alpha1/evidence/20261109-workload-budget-review/SOURCE_INPUTS.json),
including **all 24 Rust source entries**. The two changed entries are the
external-review brief and admission plan. A complete Git tree comparison from
the policy's `6a2ee33af2d67bb982d339cbeb49f2310c7e7032` to the selected source
also finds 614 of 618 Continuity `src/` paths unchanged. The four changed paths
are `durable/tests.rs` and three files in
`enrollment/account_root/transferred_tests/next_attempt`; all are test sources.
Of 27 host-store `src/` paths, 26 match and the remaining change is
`filesystem/maintenance/attempt/tests.rs`. No production Continuity or host-store
source change is hidden by the narrower input-inventory comparison.

The [compatibility policy](COMPATIBILITY_0_2.md) has likewise selected the named
journal, installation, archive, Witness and maintenance-v2 formats, exact
original-state replacement and explicit refusal for unlisted previews or
incomplete residue. Comparing its `e108ff9df704c8a551e9d3b62c0462c88384d18a`
source to the selected source yields the same five test-source differences
across Continuity and host-store, with no budgets-file change. No additional
migration implementation is required by this selection.

These comparisons support reuse of the completed policy decisions and their
source-level behavior. The new dependency graph and chosen binaries still need
their actual installed/replacement and applicable reference-workload evidence.
The existing measured timings are not renamed as measurements of those new
binaries. The numerical reference class does not add mobile-energy,
larger-recipient, second-phone, API 36 or Intel-macOS requirements.

## 4. Internal review coverage and unresolved reconciliation

The [SDK internal implementation review](../SDK_INTERNAL_REVIEW.md) retains
inspected ownership, persistent-state, asynchronous disposal, transcript/erasure,
WASM and reference-authentication paths, along with dependency direction and
journaled publisher boundaries. Its individual source identities and limits
remain applicable only to the inspected inputs. The completed construction
correspondence in this assessment adds the selected-source disposition above.

The [current Python SARIF readback](../../research/sdk-alpha1/evidence/20261116-release020-admission/CODEQL_READBACK.json)
binds run `43964930828` and its actual downloaded archive to the selected source.
The [current bounded-command review](../../research/sdk-alpha1/evidence/20261116-release020-admission/CODEQL_SINK_REVIEW.md)
disposes of all 24 related origins at `bounded_process.py`: the original four
retain identical reviewed source, and the other twenty have their actual tool,
argument, source and artifact authority traced. This closes the specific
untraced-origin item in the 11 November review. It also disposes of two public
synthetic test-fixture findings. No new unauthorized-execution counterexample
was found in that inspected set; explicit tool selection retains its stated
trust boundary.

The full current Python archive has 1,415 raw results. Other findings still
need their applicable source-specific dispositions before the aggregate
internal-review item is closed. Neither a successful analysis job nor the raw
population establishes that each result is a defect or a false positive. The separate
[four matched-auditor path findings](../../research/sdk-alpha1/evidence/20261111-matched-auditor-findings/README.md)
already have a bounded rationale and a fresh ten-control revalidation, retaining
their own source scope.

No new cryptographic or storage counterexample was found in the deltas inspected
here. This statement applies to those deltas and does not classify the
unreconciled analysis population or certify unexecuted package/platform work.

## 5. Finite remaining admission work

| Item | Concrete completion record |
| --- | --- |
| Selected-source qualification | Complete current-source CI, installed Rust/C and six foreign Debug/Release partitions with their aggregate, applicable platform/device software regression, independent interoperability and complete analysis/publication receipts. Preserve unchanged-component evidence with its actual source correspondence. |
| Current internal finding reconciliation | Compare final analysis findings and changed critical paths with retained dispositions; record remaining decisions and required fix/retest results. Use the completed U1/U2/U3 inputs above instead of reopening them as missing proofs. |
| Selected package and policy binding | Retain actual archives, dependency/toolchain identities, installation/replacement checks and applicable reference-workload validation. Join all twelve SDK crates and the agreed companion surfaces in the release manifest, with the selected compatibility and cost policy. Reconcile general SDK performance wording with the selected numerical reference class; unmeasured broad P99/allocation/energy claims are not automatically new acceptance thresholds. |
| Coordinated normative freeze | Update the actual descriptor mode, compiled descriptor, Continuity declaration metadata and normative schema-2 lock together. Verify the separate SDK/Continuity interfaces, package graph and all selected bytes against independently retained identities. |
| Release transaction | Retain the completed current-source Rust dry-run, then perform the final selected cohort's signing where required, reconciliation, authorized registry/platform publication and final receipt checks. The unsigned `sdk-020` Apple candidate needs its own 0.2.0 signing record; a 0.1.5 receipt does not qualify it. |

At the assessed source, `BUDGETS_V1.json`, the compiled `contract_report`
example and the `qpc-owner/1` snapshot still select
`frozen_product_contract=false`. The committed
[7 November manifest capture](../../research/sdk-alpha1/evidence/20261107-release-manifest/VERIFICATION.json)
is a historical candidate inventory. The
[current admission preparation](../../research/sdk-alpha1/evidence/20261116-release020-admission/README.md)
now verifies 21 package rows across all eight agreed roles, with 62 selected
source-file comparisons and a schema-2 inventory. It still selects zero built
artifacts and no compiled descriptor. The separate current-source Rust readback
verifies all twelve actual SDK archives, their hosted dry-run and minimum-Rust
receipt; it does not silently insert them into that candidate manifest. These are concrete
remaining adoption and artifact bindings, rather than missing implementations
of the functional mechanisms listed in section 1.

The release-manifest verifier intentionally reports identity consistency and
keeps `release_claim_eligible=false` and `publication_performed=false`, including
in release mode. Its success must be combined with the qualification and
journaled publication contracts above. Passing PR merge checks alone does not
perform that transaction. This assessment changes no protocol/domain byte,
stored format, ABI, freeze flag, release tag or publication state.
