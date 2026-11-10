# Independent review: native SDK purpose-key table

**Status: PASS.** The length-parameterized entry comparison, native owner correspondence, joint SDK key-table bound, visible-output collision consequence and controlled one-encryption application consequence are ready to integrate under their declared interfaces. No unresolved mathematical or source-correspondence finding remains.

Review date: 2026-11-08. Source pin: `228c944fc476e3e57d6c08063cacb19bca5b360e`. Retained CI checkpoint: `1c68aa666db22d36ee136be1ec712545a9e74f03`. The five retained dependency modules are bound at paper commit `d6723b055cc11bd35a6c48a4216f5ba68664cdcd`.

This is an independent mathematical and source-correspondence review, not a formal machine-checked proof. The review covers the exact final TeX and proof/source note listed below. Subsequent wording changes are recorded separately.

## Result and scope

The source-backed result uses one common protected contribution and all complete effective SDK infos. Repeated full infos share a deterministic key value, while each native derived owner retains its own liveness and runtime guards. The fixed 27-byte salt has an exact 32-byte zero extension; the complete info length is `107 + label length + context length`, and the maximum Expand-message length is 65899 bytes.

The single-class table comparison is $\Delta_{\rm sdk}=\min\{1,\varepsilon_{\rm Hjoint}(1,0,B+2+(2+\ell(L))N,32)+\varepsilon_{\rm Hrow}(N,B+2,L)\}$. The existing five-purpose workload has $N=5$, $L=145$, and ordinary budgets $B+32$ and $B+2$.

The assumptions are localized in the experiment: the protected parent contribution has its KDF interface across its source family; the controller uses available data and finite complete-oracle budgets; and the application target is marked before its first private computation with all aliases sharing the declared key-use interface. Raw export of the protected parent would invalidate this table comparison, as the note demonstrates explicitly.

The one-key AEAD consequence uses the retained application experiment and yields the stated signed-score cost `2 Delta_sdk + 2 epsilon_AEAD`. The durable pending-root theorem retains its own source interface. The new result is a concrete application of the finite entry proof to the existing SDK multiple-output API.

## Statement-by-statement review

| ID | Topic | Decision and reason |
|---|---|---|
| M01 | Retained primitive interfaces | **PASS.** The lemma imports the established shared-HMAC column and adaptive row experiments. It changes the message-length parameter, while preserving the initial independence, private-key interfaces and complete shared-oracle accounting. |
| M02 | Available controller and hidden parent | **PASS.** One uniform protected contribution is initially independent of h and auxiliary state. Its protected source family has the declared derivation interface; returned derived values and all available metadata may drive later requests. |
| M03 | General message lengths | **PASS.** Setting L_i=A_i+1 and lambda_i=ell(L_i) is valid within L_i<=2^61-65. Appending byte 01 is injective across variable-length infos, and SHA-256 offset padding retains the actual message length. |
| M04 | Adaptive class allocation | **PASS.** Classes and their finite N_i/L_i budgets use first-allocation order fixed before execution. Embedding the hidden row key when its class first appears incurs no target-class guessing factor; unallocated classes contribute identical hybrids. |
| M05 | Column query budget | **PASS.** q_S=B+2D+sum_i(2+ell(L_i))*N_i includes external salt-class computation and every real Expand row. The column primitive retains its own public pad-work cost, so external Gamma computation is conservatively counted as well. |
| M06 | Row query budgets | **PASS.** At row i, the earlier classes are private tables, class i is the challenge row and every later real class is simulated with the common h. Hence q_i=B+2D+sum_{k>i}(2+ell(L_k))*N_k covers the full prefix, continuation and terminal test. |
| M07 | Numerical PRK coincidences | **PASS.** Distinct Gamma classes remain separate reduction slots. A locally sampled key that happens to equal the hidden challenge key is evaluated through the same h in the real branch, with that work charged to q_i; no collision-free conditioning is introduced. |
| S01 | Short-salt normalization | **PASS.** The literal salt has 27 bytes. Adding five zero bytes produces a 32-byte representative with the identical 64-byte HMAC key block for every oracle, so this normalization is exact and costs no distinguishing term. |
| S02 | Complete source encoding | **PASS.** The ordered fields match purpose.rs, including suite 1, ContextBound profile 2, 36-byte policy state, 32-byte trust-root digest, purpose code, both length prefixes and BE16(32). The output is the first HKDF block F(F(r0,S),I||01). |
| S03 | Effective identity and parsing | **PASS.** Fixed-width fields and explicit label/context lengths uniquely parse the complete effective info. Runtime/owner identities remain lifecycle metadata; equal digest bytes are treated as equal effective fields, without assuming raw-root digest injectivity. |
| S04 | Lengths and compression counts | **PASS.** The info length is 107+|label|+|context|, with bounds 108..65898. Row messages are 109..65899 bytes, ell(65899)=1031 and a fresh maximum-size HMAC uses at most 1033 compression calls including its two pads. |
| S05 | Existing five-purpose workload | **PASS.** The source fixture has label length 13 and context length 24, yielding five distinct 144-byte infos and 145-byte row messages. Matching peers alias those five entries while retaining separate owners; N=5 gives q_S=B+32 and q_1=B+2. |
| O01 | Value aliases and owner identity | **PASS.** Every repeated full-info derivation has the same deterministic key value, while each accepted native derivation creates its own DerivedKey storage. A descriptor table plus an owner table preserves both facts; owner-indexed independent keys would be distinguishable. |
| O02 | Source and derived close | **PASS.** DerivedKey::close clears only that object. SharedSecret::close removes future access through that source owner; existing derived owners keep their own key storage and runtime reference. |
| O03 | Runtime and admitted operations | **PASS.** Runtime closure makes later open checks fail. Calls already past their relevant final admission/open check retain their native completion behavior, and previously exported copies remain with their recipients. |
| O04 | Resource semantics | **PASS.** DerivedKey has no KeyLease; derivation takes the in-flight operation lease. The theorem fixes a separate lifetime bound N on distinct infos and retains the FFI live/pending-handle budget as metadata. |
| O05 | FFI parent and publication | **PASS.** The inspected FFI derive path reserves under the runtime parent, computes, installs and then publishes. Publication checks parent liveness, and rollback drops unpublished owners, matching the retained registry metadata. |
| O06 | First private computation and retries | **PASS.** A private KDF evaluation allocates its descriptor even when publication subsequently fails. Retrying creates its actual new owner but retrieves the same entry; freshness is tested across all aliases before the first such computation. |
| T01 | Whole owned-API comparison | **PASS.** With D=C=1, the displayed Delta_sdk follows from the length lemma. The induction preserves validation, admission, local liveness and publication; the comparison recomputes adaptive choices, exports and public responses in each game. |
| T02 | Visible-key collision event | **PASS.** The event is equality of exported keys from distinct allocated infos, so it is an efficient available output-bit test. Independent lazy-table values give the adaptive union bound choose(N,2)*2^-256, followed by the Delta_sdk comparison cost. |
| A01 | Fresh selected descriptor | **PASS.** A selected info is marked online before its first private KDF evaluation throughout the protected source family. All its aliases use one retained application-key interface with their native guards; other descriptor values may be exported. |
| A02 | One-encryption application experiment | **PASS.** The consequence invokes the existing one-key AEAD operational game, including its equal-length messages, nonce/associated-data choice and exact-challenge decryption rule. It does not require the SDK purpose key to be a durable root or chain seed. |
| A03 | Qualification and score factors | **PASS.** Qualification uses available classical state and the source ledger, with zero score when there is no marked challenge. Fixing the application bit and then averaging yields 2*Delta_sdk, and fair guessing outside qualification gives 2*epsilon_AEAD. |
| A04 | Preceding ContextBound step | **PASS.** The additional 2*Phi_256(d,Q_H) applies when the stopped execution actually realizes the stated common source family and available controller. Existing component, correctness and projection terms retain their prior definitions and placement. |
| D01 | Durable source scope | **PASS.** The note retains the existing 97-byte pending-root source invariant and its two production call sites. The SDK purpose API supplies the concrete multiple-info instance; the new application consequence is attached to that declared key-use interface. |
| E01 | Pinned source and CI byte parity | **PASS.** Independent git-object comparison passes for all 18 files in source_map.json plus three additional SDK/FFI/dependency files. Each equals the source pin, retained CI checkpoint and inspected worktree; the author-map digests also match. |
| E02 | Finite checks and independent encoding | **PASS.** The reviewer reproduced the author checker: 93/93 pass and both JSON outputs are byte-identical to the frozen evidence. A separately written reviewer checker records 12/12 framing, HMAC KAT, normalization and length-accounting checks; these are finite validations, not a cryptographic proof. |
| E03 | Retained native Rust evidence | **PASS.** The retained job 128494629029 in run 42402999612 records five successful purpose tests on 2026-11-07 at commit 1c68aa6. Their source correspondence and excerpt were inspected; this review started no additional Rust execution. |
| E04 | Precise evidence and attribution | **PASS.** The frozen note separates source inspection, Python checks, retained Rust execution and the reduction argument. Existing HMAC/HKDF definitions and primitive theorems retain their citations; the new contribution is the SDK-specific correspondence and consequence. |

## Evidence layers

- Independent source inspection covers the purpose encoding and Rust source/derived/runtime transitions, the FFI reservation/publication path, and the exact selected test workloads. The note's durable audit retains the previously reviewed source invariant.
- Independent byte-parity checking covers 21 source files: all 18 author-map files plus SDK policy update, the SDK manifest and FFI tests. All agree at the source pin, retained CI checkpoint and inspected worktree.
- The author checker was reproduced in `reproduced/`: 93/93 checks pass, and its two JSON outputs are byte-identical to the frozen originals. The reviewer's separate `encoding_check.py` records 12/12 framing, normalization, KAT and length checks. These finite checks have the scope stated in their receipts.
- Retained Rust evidence records five successful purpose tests from [run 42402999612, job 128494629029](https://github.com/billlza/q-periapt/actions/runs/42402999612/job/128494629029), executed on 2026-11-07. This review matched the receipt/excerpt to the inspected source; it started no new Rust execution.
- The HMAC normalization follows [RFC 2104, section 2](https://www.rfc-editor.org/rfc/rfc2104); the first-block formula follows [RFC 5869, section 2.3](https://www.rfc-editor.org/rfc/rfc5869). The inspected dependency is RustCrypto `hkdf` 0.13.0, whose `expand_multi_info` feeds the info components in order to the same HMAC block.

## Frozen review inputs

| File | SHA-256 |
|---|---|
| `sdk-purpose-connection.tex` | `7d2b287bfff0458e034ff42b7fa8af8053d0f2a59eed034d5ff30183d2de63bc` |
| `source_correspondence.md` | `8a49fd4e3a1da7d15b1de1c5cefacf12cf2cb7d42cd1cd6e0ca5f80ae1dd6b7e` |
| `source_map.json` | `30a054a08435a32816b88e53a45b6855339eb4b4f711fbc377e9971a06887e25` |
| `check_native_root.py` | `b8d424b456f54a53b06a1d7ce556241858eb250559e09955d7c55cdeed3daccf` |
| `validation_report.json` | `2fd0c4b8962b20dd298051eb5af559a806f16662f93f317ae46c3b4b2c61fc91` |
| `native_test_receipt.json` | `4b551fe5cffd470abe8c4bb7abe7acb2e33587e7219741d212853a59c1b5a5b6` |
| `native_test_excerpt.log` | `c8d7a6b30996d7ef2f329b56e11cfb837cbfb03b6fb3eec2bedf97c8b8abc188` |
| `README.md` | `b1d4a493a97a57309c70bdb96451b2949a1b4c5cfae57a6a94ae322576be8ddb` |
| `FREEZE.json` | `d25f0bd18fc7f90b019d0b079b388de839463b73002f48c0bbbc7a1e35a83f75` |

## Retained mathematical dependencies

These hashes identify the Git objects at `d6723b055cc11bd35a6c48a4216f5ba68664cdcd`. They keep this mathematical review separate from the subsequent editorial diff.

| Module | SHA-256 |
|---|---|
| `multiple-root-entry.tex` | `60f842d35f1a86c7e478bb7c60358ab7944aa78c5388b1c5d7305eb77d921e34` |
| `joint-primitive-bounds.tex` | `728694d237734b071496d355c13c359825aef219d918ed54810f97d2457e9dbd` |
| `joint-continuation.tex` | `d6c980912918b309c33f4c9f8116d6835dd521be639d5c866b198496a9dd3bcb` |
| `primitive-inputs.tex` | `78c4c40bfa0a4d2d9f441ac59f40df436863583ab5bdf538beb6fd5fc59e43aa` |
| `contextbound-connection.tex` | `4d437b36d9ccdaae04cb8b1326b350a4d5d185ac6eec818eb905a56bd046c235` |

## Reviewer evidence

| File | SHA-256 |
|---|---|
| `encoding_check.py` | `36b7565c3c240fb167ee39ebc19894c6ec471c662f56bbde94410c7843b8f074` |
| `encoding_receipt.json` | `e8a8247a6c743d2b0f3b84ae44dbcef7a7ff3fe3bca3e5c12158ca2aea4770d3` |
| `source_parity.json` | `c30545e40fc5c14046b472ba6f3b05707ca8d48e2fbb2702910783f1e8e11ba8` |
| `reproduced/source_map.json` | `30a054a08435a32816b88e53a45b6855339eb4b4f711fbc377e9971a06887e25` |
| `reproduced/validation_report.json` | `2fd0c4b8962b20dd298051eb5af559a806f16662f93f317ae46c3b4b2c61fc91` |

**Disposition:** integrate the exact reviewed manuscript module and source note. Preserve the declared source-family, available-controller and selected-application interfaces. No manuscript or source file was modified by this review.
