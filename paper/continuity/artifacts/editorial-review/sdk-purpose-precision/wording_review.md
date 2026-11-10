# Independent semantic review: wording precision

**Status: PASS.** The final eight-file wording revision preserves the existing conditions, quantifiers, cryptographic interfaces, accounting budgets and result strength. The opaque-ciphertext sentence and quantum-prefix sentence incorporate the requested precision fixes. No unresolved semantic issue remains.

Review date: 2026-11-08. This record covers 14 logical wording edits in 13 diff hunks across eight files. It is separate from `independent_review.md/.json`, which freezes the new SDK result. No manuscript/source edits, build review or native execution were performed by this review.

## Semantic checks

| ID | Topic | Decision and reason |
|---|---|
| W01 | Retrospective attribution and quantum prefix | **PASS.** The final index remains a retrospective score attribution, while online monitors use only the available classical ledger. The final wording explicitly retains native quantum-state transformations and oracle access up to the local stop; it asserts no equality between divergent post-stop continuations. |
| W02 | Asymmetric confirmation counterexample | **PASS.** The same exposed epoch and retained-input derivation witness remain. Each endpoint keeps its own confirmation counter, so the counterexample and the proposed bound it refutes are unchanged. |
| W03 | Actual-key identities | **PASS.** Equal actual key bytes still define one equivalence class across API objects. This is the guarded-readability key identity, and it does not merge the distinct owner/liveness records used in the SDK correspondence. |
| W04 | Entire hybrid regeneration | **PASS.** Each hybrid generates all outputs from its own root and subsequent schedule. The joint continuation, all downstream uses and the full-query accounting retain their original scopes. |
| W05 | Terminal-test access | **PASS.** The hidden value remains accessed through its stated primitive interfaces and, together with the private tables, remains internal throughout terminal testing. Initial oracle/key/auxiliary independence and counted preparation are unchanged; the terminal test gains no raw hidden-value channel. |
| W06 | Equality from explicit nonces | **PASS.** The final sentence permits coincident private blocks and ciphertext components while assigning complete-image separation to their explicit distinct nonces. This precisely matches the proof and avoids asserting that fixed-key/nonce encryption may fail plaintext injectivity. |
| W07 | Immutable report key and transcript | **PASS.** Copy, retry, failed-after-commit and crash/resume retain each report key and its immutable original transcript. The selected row is still queried on its original message, with recomputation counts and actual durable state preserved. |
| W08 | Entropy origin and sampling | **PASS.** Independence remains an assumption at the original sampling event. Retained tapes and exact retries preserve that origin, while the following unchanged sentences count failed draws and distinguish fresh origins despite coincident public outputs. |
| W09 | Immutable record subject | **PASS.** The subject remains the session represented by the record version. An enclosing-journal write, including a sibling-session write, preserves that subject; preparation/save and new-version rules remain unchanged. |
| W10 | Hash/MAC record-acquisition paths | **PASS.** The empty path set refers to the public hash/MAC constructor output in the typed recipe model. It does not erase other intact records in an enclosing aggregate, and public outputs, statuses and ordinary cryptographic work remain present. |
| W11 | Attribution separate from eligibility | **PASS.** Attr remains a source/authentication obligation and its failure may occur on an eligible run. The unchanged eligibility formula and residual accounting therefore continue to charge attribution failure instead of silently filtering it away. |
| W12 | Acquisition time and readability | **PASS.** Protected record bytes enter the acquisition ledger when obtained; readability remains a separately evaluated set that can grow after key disclosure. The eligibility test still concerns original saved versions in C_T and does not wait for decryption. |
| W13 | Adaptive target selection | **PASS.** The selector chooses from the observed interaction. The retained adjacent conditions still identify the challenge accepted logical send, prohibit moving its test bit, and recompute selection and eligibility within each comparison. |
| W14 | Reservation event and endpoint counters | **PASS.** A pre-cut reservation remains pre-cut after delayed computation or receipt. The explicit eligibility reference retains the original reservation-time inequalities and each endpoint retains its separate counter. |
| W15 | Exact mathematical preservation | **PASS.** All 20 formal definition/theorem/lemma/corollary/proposition blocks and 67 display-math blocks are byte-identical. Inline math and labels also match, and all final snapshots exactly match their integrated manuscript files. |

## Precision fixes verified

- The opaque-record proof now states that private block values and ciphertext components may coincide, while explicit nonces distinguish complete images. This is exactly the argument used by the structural-equality lemma.
- The local-stop proof now identifies the preserved native quantum-state transformations and oracle-query interface **up to the local stop**, retaining the classical-prefix-instrument argument and its correct temporal scope.
- The primitive preamble retains internal hidden values and private tables throughout terminal testing, together with the previously stated interfaces and counted independent setup.

## Exact preservation

All 20 formal statement blocks and 67 display-math blocks in the eight files are byte-identical between the retained snapshots. All inline mathematical expressions and labels also agree. The final `after` snapshots match the integrated manuscript files exactly. This byte comparison supports the manual semantic review; it is not a new proof of the retained theorems.

## Reviewed diff

`wording_precision.diff` — SHA-256 `8b5b3f3ca87d5237f6865b4edc368a17ffb0ea1e185b60c69e4156e344edc3e6`.

## Snapshot bindings

| File | Before SHA-256 | After SHA-256 |
|---|---|---|
| `candidate-local-accounting.tex` | `4a38c6bb00c70f2611c2395aec754c0af6b8231a8e3f94e027cf1a17b657865d` | `4b1249b0f7bb8937e0b1018dff1e66826ab9a6fb97d1add16e5bb06cd332f2ad` |
| `construction.tex` | `0bc19554764a4029df2375722a20397dd5b45bb71d133ecbf5f49b017099a9f9` | `8613314bfb5d15b417e1ea12a9ed8c949dbecbe28d2896b0f01f5276c2640a44` |
| `guarded-provenance.tex` | `f7b36ef86bdd4733af0b882c9f192e52ad40ef041ae22046e63e1584e2c897ca` | `129d36e1b1b30e7377e76552ab20567d4710a1c1975498844a4b07fbba418136` |
| `joint-continuation.tex` | `d6c980912918b309c33f4c9f8116d6835dd521be639d5c866b198496a9dd3bcb` | `f16c3bd881258885a819b67104719422e6dab4812fb1a8511ecfe469735fa5ab` |
| `joint-primitive-bounds.tex` | `728694d237734b071496d355c13c359825aef219d918ed54810f97d2457e9dbd` | `4fcfd80a023ee703938a042cc88507379d580f8cdec41d956354da224d710ecb` |
| `opaque-rendering.tex` | `178f6ab0c486b053d9f8447ca09bce60ab5d5cb35bbc7a0ac881d2fb138f64fe` | `31855e812d80d2f6cc4afada05db5e33ca8e039eace89e9a13ba791b43849298` |
| `report-composition.tex` | `3f1a5922e095d154433caf2e92673018796de4c629a0fa7a7bc16edfc2ab9186` | `b5c46a2c69bcb7d9dee8d460cdc55bf8ec8b691d612e8d33ccef1679408b45d3` |
| `security-model.tex` | `9d79088958d146971df8eaf9df983d6fabdfa033ce5de259d753f6d5f89cd0e6` | `4d78ea142a89805869c76b7d8b47c1d2e5f9c410185f40e709c7c22b161e58b7` |

The companion JSON records complete paths, byte counts, exact preservation checks and the integrated-file match for each snapshot. The SDK mathematical freeze and its input hashes remain separate from this editorial record.
