# Independent review: reverse-order report composition

**Verdict:** approved for the declared finite typed interface. No substantive mathematical error remains identified in the reviewed note or compact manuscript module. This review confirms a completed dependent-report composition result, rather than treating reverse ordering as a proposed proof strategy.

## Frozen reviewed artifacts

| Artifact | Version / SHA-256 |
| --- | --- |
| `multi_report_theorem.md` | v0.3 — `7416c2ccb8147a67e0fb3b1f8456970f1537aaf7985cbfbec196a502e2b19027` |
| `report-composition.tex` | `c6358c7b39dba17db00e8a1f08eb226af834a253b2c04aea4504288e9d161653` |
| Supporting native map | `native_interface_map.md` — `6bccd3b423e3a1b729b229534be9e7d334006a128e35bf7cfcfb7d02012fb448` |
| Machine-readable native map | `map.json` — `d8eb3e433a388514fe5a9c0f7446a50a4b2d2543d1c9b6c9812f165030290e06` |

The source anchor is `228c944fc476e3e57d6c08063cacb19bca5b360e`. The earlier opaque renderer remains v1.2, SHA-256 `98e0df8b8536d5d43cd191a0a9851676345e8c20aebe82a298c4d86dd6b8035e`.

## 1. Result established by the proof

The report layer admits bounded chronological fresh-key invocations, immutable transcript recipes, exact original-row replay and validation, and the declared dependency/observation interfaces. A later transcript may use an earlier report's raw key and returned tag. The note gives an explicit reduction for each selected row and composes those reductions in reverse creation order. The resulting bit gap is bounded by the sum of the existing one-row errors; the signed-score gap is bounded by twice that sum.

The full real game retains its actual fragment disclosures and original target eligibility. An explicitly stopped analysis game is connected to it by the exact eligibility-sensitive residual. No batch-only key fragment is reclassified as a selected-session Snapshot, and no new eligibility condition is silently inserted.

## 2. Independent checks

| Check | Finding |
| --- | --- |
| Online protection flags | `P_i` is computed from source/key-origin dependencies before using `K_i`; returned tags are available values. Each hybrid recomputes the rule in its own history. An adaptive tag-dependent decision about later reports is therefore preserved, rather than inherited from a fixed real transcript. |
| Adjacent-hybrid prefix | `H_i` and `H_(i-1)` use the same rules before slot i. Earlier rows are real in both. The selected slot's existence/protection is decided by that actual common prefix, and the reduction runs the full preparation rather than receiving oracle-dependent advice. Absent or unprotected selected slots create no gap. |
| Selected real transcript | During the report hop the source atoms X are still available; all earlier report keys are locally sampled; the grammar excludes the selected key and its own tag from its immutable transcript. The reduction can therefore submit the genuine selected transcript without the challenged key. |
| Future real-row computability | If a future transcript depends directly or through a computed value on the selected protected raw key, forward closure makes that row protected. Its index is later, so it is already ideal in both adjacent hybrids. Every future unprotected real row is therefore computable without the unknown key. This is the central constructive invariant. |
| Exact replay and failed attempts | A retry of a retained original uses one invocation, one immutable transcript and one cached tag. A fresh draw after definite absence has a new index, including later zero-ID/encoding/persistence failure. The proof retains the actual zero-tag branch and does not resample to force success. Failure after commit preserves the committed original. |
| Ordinary query budgets | Each q_i is a uniform bound for the whole derived algorithm: prefix, continuation, other real report rows, shared-oracle work, adversary and terminal test. The stated T_i >= 1 and length regime are inherited from the existing one-row lemma. Skipped or unused rows can have conservative public bounds without creating extra distinguishing cost. |
| Accidental key equality | Other independently drawn keys remain locally known byte strings in the reduction. Their real HMAC evaluations through the same public h automatically have the correct behavior if one happens to equal K*. Such guesses/evaluations belong in q_i. No distinct-key conditioning or equality test against the unknown key is used. |
| Intentional aliases | Copies/retries of one original draw share its row/cache. Intentional reuse of one key under another transcript is excluded from this immutable-row grammar and explicitly assigned to a multi-query keyed-function interface. The note does not confuse this case with random equal-value draws. |
| Actual disclosure event | Bad_rep is detected from the successful projection's origin dependency before returning unknown bytes. A read error, available tag alone, or projection without a protected-key dependency keeps its normal behavior. The full real experiment still returns allowed fragments; only the explicitly defined analysis game stops. |
| Adaptive target selection | The full real game continues after disclosure and may choose its target from the resulting view. The residual uses that game's actual final eligibility. The coupling identity remains valid without fixing the final target in advance. Eliminating a residual on a particular acquisition surface still requires permanent failure for the original scored event. |
| Score coefficient | Real-to-stopped comparison changes a bad-path score from Z to 0, so the cost is E[abs(Z) 1_Bad], with coefficient one. The report bit bound becomes a [-1,1] score bound via a test with acceptance probability (1+Z)/2, giving coefficient two. These terms are not interchanged. |
| Stopped terminal tests | The application score is zero at the common stopped state. A common terminal-bit postprocessing may still use that state's available metadata and its own coins, including the randomized test needed for the score conversion. It cannot read a protected key/transcript or a hidden record nonce. The TeX module explicitly preserves this distinction. |
| Quantum/common-oracle handling | The reductions forward the adversary's actual quantum queries to the same public compression oracle and introduce no measurement. Other honest real-row computations use their available inputs and are charged. The proof does not replace an entire prior quantum history by uncounted auxiliary state. |
| Private-buffer omission | Section 9 permits omission only for deterministic private evaluations whose outputs have no remaining observable use except already ideal commitments, structural identity, or a disclosure stopped before return. For fixed public oracle functions, those private oracle calls are reads and do not modify the oracle. Observable validation results, report MACs, timing/error branches admitted by the interface, or raw outputs cannot be discarded by this observation. Earlier cryptographic reductions retain their own query accounting. |

## 3. Residual and composition algebra

Under the coupling through the first observed Bad_rep event,

```text
E_G[Z] - E_Gstop[Z] = E_G[Z * 1_Bad_rep].
```

Consequently the first comparison costs `eta_rep(Z) = E_G[abs(Z) * 1_Bad_rep]`. For the centered message score it is exactly `Pr_G[Eligible AND Bad_rep]`. Combining with the report hybrids gives

```text
abs(E_G[Z] - E_Sstop[Z]) <= eta_rep(Z) + 2 epsilon_sum.
```

The corresponding cap of two is correct. The separate bound on `abs(E_G[Z])` is capped at one because `abs(Z) <= 1`. For an eligible winning event, the one-sided bound uses `Pr_G[W AND Bad_rep]` and the bit error `epsilon_sum`, also correctly.

Version 0.3 states an unambiguous native composition order:

1. Define the actual origin-mapped disclosure event in the original full native game and charge its native eligible-exposure residual.
2. Establish a separate storage/source correspondence for that explicitly stopped native game.
3. Apply the reverse-order report hybrids to the resulting report interface.

This gives `eta_rep_native + epsilon_store_score + 2 epsilon_sum`. If storage is abstracted first instead, the residual must be evaluated in the resulting real-report game or transferred with an explicit additional comparison. A residual cannot be moved silently between these games.

## 4. Source correspondence checked independently

The source audit in `native_interface_map.md` supports the exact report grammar at the following matched locations:

- Closure authenticates the whole session-state payload while canonicalizing only its own final 64-byte report/key tail. This excludes its own key/tag while retaining earlier traffic/report fields.
- Fanout authenticates each member's complete payload; its own report/key tail is in a different Batch record and excluded from Batch::metadata.
- Traffic encoding stores a pending resolution status/key before the traffic maps; State encoding places all traffic entries and control before the closure tail. Thus the earlier-resolution-to-later-closure/fanout dependency is an actual byte inclusion.
- The normal pending/frozen paths preserve the same row. Existing source fences old resolution operations and closing/abandoning sessions; acknowledgement retains an original terminal tag while removing current logical secret owners.
- Pending report keys are allowed to have the zero value. Canonical empty/acknowledged zero tails are separate state encodings; the report ID, not the pending key, has the nonzero check.
- `resolution_report` returns retained plaintext to its authorized application. It is not a metadata-only observation.
- Native decoders revalidate complete cryptographic state. Arbitrary modified raw-image or changed-transcript inputs need their own precise verification interface; they are not automatically trusted immutable handles.

These are source-level facts and mapping inputs. The review did not execute another native run or a new Tamarin proof.

## 5. Scope clarifications incorporated before approval

The review requested, and v0.3 now contains, the following two clarifications:

**The report layer becomes opaque only for tag generation and immutable tag validation.** Independent source-atom X outputs or application plaintext outputs remain with their declared adapters/acquisition rules. The report-key residual does not also pay for every unknown source output.

**The storage hop remains a separate input for the exact stopped interface.** The original permanent-target-ineligibility condition of opaque renderer v1.2 is not inherited by a batch-only key fragment merely because the new analysis game chooses to stop there. The exposure residual is charged in the full real game, and the subsequent stopped-game storage correspondence is named explicitly.

The compact `report-composition.tex` module retains these conditions, the online flag definition, explicit one-row reduction, common query budget, accidental-alias explanation and disclosure residual. Its mathematical statements agree with the reviewed note. Parent integration still performs the ordinary LaTeX build and document layout check; this review adds no new experimental gate.

## 6. Final approval boundary

The finite dependent immutable-report theorem and its explicit reduction can be included as established results. The native source map supplies concrete creation, encoding, freeze, replay and key-storage facts for its application. A whole native source correspondence, arbitrary raw-input verification, and the probability of each permitted partial acquisition are separate claims with their own already identified inputs. They are not inferred merely from the theorem's hybrid inequality.
